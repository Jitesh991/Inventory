import { put, list } from '@vercel/blob';
import { scryptSync, randomBytes, timingSafeEqual, createHmac } from 'node:crypto';

/**
 * Auth, kept deliberately small.
 *
 * Users live in one JSON file in Blob storage. Sessions are not stored at all —
 * a token is an HMAC of the username, role and expiry, so verifying one is pure
 * computation with no read. That removes the session store, its cleanup and its
 * failure modes, at the cost of not being able to revoke a single token before
 * it expires. Twelve hours, and disabling the account blocks the next sign-in.
 */

const USERS_PATH = 'warehouse/users.json';

/**
 * The Blob token.
 *
 * Vercel calls it BLOB_READ_WRITE_TOKEN only when that name is free. Connect a
 * second store, or set a prefix, and it becomes MYSTORE_READ_WRITE_TOKEN — so
 * any variable ending that way is accepted rather than insisting on one name.
 */
export function blobToken() {
  if (process.env.BLOB_READ_WRITE_TOKEN) return process.env.BLOB_READ_WRITE_TOKEN;
  const key = Object.keys(process.env).find(k => /_READ_WRITE_TOKEN$/.test(k) && process.env[k]);
  return key ? process.env[key] : null;
}
const TTL_HOURS = 12;

export const ROLES = {
  admin:   { label: 'Administrator', description: 'Everything: the map, racks, brands, the catalog, and user accounts.' },
  scanner: { label: 'Inventory scanner', description: 'Scan stock and place it. Can read the map but cannot change racks, brands or rack assignments.' }
};

export const isAdmin = u => u?.role === 'admin';

/* ---------------------------- passwords ---------------------------- */

export function hashPassword(plain) {
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(plain, salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

export function verifyPassword(plain, stored) {
  try {
    const [scheme, salt, hash] = String(stored).split('$');
    if (scheme !== 'scrypt' || !salt || !hash) return false;
    const got = scryptSync(plain, salt, 64);
    const want = Buffer.from(hash, 'hex');
    return got.length === want.length && timingSafeEqual(got, want);
  } catch { return false; }
}

/** Rules kept modest: this is a warehouse tool, not a bank. */
export function passwordProblem(p) {
  if (typeof p !== 'string' || p.length < 8) return 'Use at least 8 characters.';
  if (!/[0-9]/.test(p)) return 'Include at least one number.';
  return null;
}

/* ----------------------------- tokens ------------------------------ */

const b64 = s => Buffer.from(s).toString('base64url');

function secret() {
  const s = process.env.AUTH_SECRET;
  if (!s) throw new Error('AUTH_SECRET is not set. Add it in Vercel and redeploy.');
  return s;
}

export function makeToken(user) {
  const exp = Date.now() + TTL_HOURS * 3600 * 1000;
  const body = b64(JSON.stringify({ u: user.username, r: user.role, exp }));
  const sig = createHmac('sha256', secret()).update(body).digest('base64url');
  return `${body}.${sig}`;
}

/** Returns { username, role } or null. Never throws on bad input. */
export function readToken(token) {
  try {
    const [body, sig] = String(token || '').split('.');
    if (!body || !sig) return null;
    const want = createHmac('sha256', secret()).update(body).digest('base64url');
    const a = Buffer.from(sig), b = Buffer.from(want);
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (!p.exp || Date.now() > p.exp) return null;
    return { username: p.u, role: p.r };
  } catch { return null; }
}

/* ---------------------------- user store --------------------------- */

export async function loadUsers() {
  const { blobs } = await list({ prefix: USERS_PATH, limit: 1, token: blobToken() });
  const hit = blobs.find(b => b.pathname === USERS_PATH);
  if (!hit) return [];
  const r = await fetch(hit.url, { cache: 'no-store' });
  if (!r.ok) throw new Error(`Could not read the user list (HTTP ${r.status})`);
  return await r.json();
}

export async function saveUsers(users) {
  await put(USERS_PATH, JSON.stringify(users, null, 2), {
    token: blobToken(),
    access: 'public',
    contentType: 'application/json',
    addRandomSuffix: false,
    allowOverwrite: true,
    cacheControlMaxAge: 0
  });
}

/** The signed-in user for a request, re-read from the store so a disabled
    account stops working without waiting for the token to expire. */
export async function currentUser(req) {
  const claim = readToken(req.headers['x-session']);
  if (!claim) return null;
  const users = await loadUsers();
  const u = users.find(x => x.username === claim.username);
  if (!u || u.active === false) return null;
  return u;
}

export function publicUser(u) {
  return { username: u.username, name: u.name, role: u.role,
    active: u.active !== false, lastLoginAt: u.lastLoginAt || null };
}

/** Guard used by every protected route. Returns the user, or writes the error. */
export async function requireUser(req, res, { adminOnly = false } = {}) {
  if (!blobToken()) {
    res.status(500).json({ error: 'No Blob store is connected. Open /api/health to see which '
      + 'environment variables the function can actually see.' });
    return null;
  }
  let u;
  try { u = await currentUser(req); }
  catch (e) { res.status(500).json({ error: e.message }); return null; }
  if (!u) { res.status(401).json({ error: 'Sign in again.', reauth: true }); return null; }
  if (adminOnly && !isAdmin(u)) {
    res.status(403).json({ error: 'Only an administrator can do that.' });
    return null;
  }
  return u;
}
