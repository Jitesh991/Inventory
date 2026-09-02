import { put, list } from '@vercel/blob';
import { requireUser, isAdmin, blobToken } from './_auth.js';

/**
 * The entire warehouse map as one JSON document.
 *
 * GET  /api/state -> { state, savedAt }
 * PUT  /api/state -> { ok, size, guarded }
 *
 * Roles are enforced here, not only in the interface. A scanner's save is
 * merged over the stored copy so the structural parts — racks, brand
 * assignments, the brand list, locks — come from what is already saved and
 * cannot be replaced by whatever the browser sent. Hiding the buttons is not
 * the same as refusing the write.
 */

const PATH = 'warehouse/state.json';

/** Only an administrator may change these. */
const STRUCTURAL = ['racks', 'assign', 'brands', 'locks', 'kinds', 'labels'];

async function readState() {
  const { blobs } = await list({ prefix: PATH, limit: 1, token: blobToken() });
  const hit = blobs.find(b => b.pathname === PATH);
  if (!hit) return { state: null, savedAt: null };
  const r = await fetch(hit.url, { cache: 'no-store' });
  if (!r.ok) throw new Error(`Could not read the saved file (HTTP ${r.status})`);
  return { state: await r.json(), savedAt: hit.uploadedAt };
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  const me = await requireUser(req, res);
  if (!me) return;

  try {
    if (req.method === 'GET') {
      const { state, savedAt } = await readState();
      return res.status(200).json({ state, savedAt });
    }

    if (req.method === 'PUT') {
      const incoming = typeof req.body === 'string' ? JSON.parse(req.body || 'null') : req.body;
      if (!incoming || typeof incoming !== 'object') {
        return res.status(400).json({ error: 'Empty body — refusing to overwrite with nothing.' });
      }

      let toSave = incoming;
      const guarded = [];
      if (!isAdmin(me)) {
        const { state: current } = await readState();
        if (current) {
          toSave = { ...incoming };
          for (const k of STRUCTURAL) {
            if (k in current) {
              // Only report the ones the browser actually tried to change.
              if (JSON.stringify(incoming[k]) !== JSON.stringify(current[k])) guarded.push(k);
              toSave[k] = current[k];
            }
          }
        }
      }

      const body = JSON.stringify(toSave);
      await put(PATH, body, {
        token: blobToken(),
        access: 'public',
        contentType: 'application/json',
        addRandomSuffix: false,
        allowOverwrite: true,
        cacheControlMaxAge: 0
      });
      return res.status(200).json({ ok: true, size: body.length, guarded });
    }

    res.setHeader('Allow', 'GET, PUT');
    return res.status(405).json({ error: 'Use GET or PUT.' });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
}
