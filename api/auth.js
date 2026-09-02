import {
  ROLES, loadUsers, saveUsers, hashPassword, verifyPassword, passwordProblem,
  makeToken, currentUser, publicUser
} from './_auth.js';

/**
 * GET  /api/auth  -> { signedIn, user?, roles, needsSetup }
 * POST /api/auth  -> { action: 'login' | 'bootstrap' | 'change-password', ... }
 */
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');

  if (!process.env.BLOB_READ_WRITE_TOKEN) {
    return res.status(500).json({ error: 'No Blob store is connected. In Vercel: Storage → create a Blob store → connect it to this project, then redeploy.' });
  }

  const roles = Object.entries(ROLES).map(([id, r]) => ({ id, ...r }));

  try {
    const users = await loadUsers();

    if (req.method === 'GET') {
      const me = await currentUser(req).catch(() => null);
      return res.status(200).json({
        signedIn: Boolean(me),
        user: me ? publicUser(me) : null,
        roles,
        needsSetup: users.length === 0
      });
    }

    if (req.method !== 'POST') {
      res.setHeader('Allow', 'GET, POST');
      return res.status(405).json({ error: 'Use GET or POST.' });
    }

    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const action = body.action;

    /* ---- first run: create the administrator ---- */
    if (action === 'bootstrap') {
      if (users.length) return res.status(400).json({ error: 'Accounts already exist. Sign in instead.' });
      const want = process.env.SETUP_TOKEN;
      if (!want) return res.status(500).json({ error: 'SETUP_TOKEN is not set. Add it in Vercel and redeploy.' });
      if (body.setupToken !== want) return res.status(401).json({ error: 'Wrong setup code.' });

      const username = String(body.username || '').trim().toLowerCase();
      if (!/^[a-z0-9._-]{3,32}$/.test(username)) {
        return res.status(400).json({ error: 'User ID: 3–32 characters, letters, numbers, dot, dash or underscore.' });
      }
      const bad = passwordProblem(body.password);
      if (bad) return res.status(400).json({ error: bad });

      const admin = {
        username, name: String(body.name || '').trim() || username,
        role: 'admin', active: true,
        password: hashPassword(body.password),
        createdAt: new Date().toISOString(), lastLoginAt: new Date().toISOString()
      };
      await saveUsers([admin]);
      return res.status(200).json({ token: makeToken(admin), user: publicUser(admin), roles });
    }

    /* ---- sign in ---- */
    if (action === 'login') {
      const username = String(body.username || '').trim().toLowerCase();
      const u = users.find(x => x.username === username);
      // One message for both wrong-user and wrong-password, so the form does
      // not confirm which user IDs exist.
      const ok = u && u.active !== false && verifyPassword(body.password, u.password);
      if (!ok) return res.status(401).json({ error: 'Wrong user ID or password.' });

      u.lastLoginAt = new Date().toISOString();
      await saveUsers(users);
      return res.status(200).json({ token: makeToken(u), user: publicUser(u), roles });
    }

    /* ---- change your own password ---- */
    if (action === 'change-password') {
      const me = await currentUser(req);
      if (!me) return res.status(401).json({ error: 'Sign in again.', reauth: true });
      if (!verifyPassword(body.currentPassword, me.password)) {
        return res.status(400).json({ error: 'Current password is wrong.' });
      }
      const bad = passwordProblem(body.newPassword);
      if (bad) return res.status(400).json({ error: bad });

      const i = users.findIndex(x => x.username === me.username);
      users[i].password = hashPassword(body.newPassword);
      await saveUsers(users);
      return res.status(200).json({ ok: true });
    }

    return res.status(400).json({ error: 'Unknown action.' });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
}
