import { ROLES, requireUser, loadUsers, saveUsers, hashPassword,
         passwordProblem, publicUser } from './_auth.js';

/**
 * Administrator-only. Passwords are stored as one-way hashes, so a forgotten
 * one is replaced, never recovered.
 *
 * GET    -> { users, roles }
 * POST   -> create   { username, name, role, password }
 * PATCH  -> update   { username, name?, role?, password?, active? }
 */
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  const me = await requireUser(req, res, { adminOnly: true });
  if (!me) return;

  const roles = Object.entries(ROLES).map(([id, r]) => ({ id, ...r }));

  try {
    const users = await loadUsers();

    if (req.method === 'GET') {
      return res.status(200).json({ users: users.map(publicUser), roles });
    }

    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const username = String(body.username || '').trim().toLowerCase();

    if (req.method === 'POST') {
      if (!/^[a-z0-9._-]{3,32}$/.test(username)) {
        return res.status(400).json({ error: 'User ID: 3–32 characters, letters, numbers, dot, dash or underscore.' });
      }
      if (users.some(u => u.username === username)) {
        return res.status(400).json({ error: 'That user ID is taken.' });
      }
      if (!ROLES[body.role]) return res.status(400).json({ error: 'Pick a role.' });
      const bad = passwordProblem(body.password);
      if (bad) return res.status(400).json({ error: bad });

      const u = { username, name: String(body.name || '').trim() || username,
        role: body.role, active: true, password: hashPassword(body.password),
        createdAt: new Date().toISOString(), lastLoginAt: null };
      users.push(u);
      await saveUsers(users);
      return res.status(200).json({ user: publicUser(u) });
    }

    if (req.method === 'PATCH') {
      const u = users.find(x => x.username === username);
      if (!u) return res.status(404).json({ error: 'No such user.' });

      // Locking yourself out is the one mistake with no way back through the UI.
      if (u.username === me.username) {
        if (body.active === false) return res.status(400).json({ error: 'You cannot disable your own account.' });
        if (body.role && body.role !== 'admin') return res.status(400).json({ error: 'You cannot remove your own administrator role.' });
      }
      if (body.role && !ROLES[body.role]) return res.status(400).json({ error: 'Unknown role.' });
      if (body.password) {
        const bad = passwordProblem(body.password);
        if (bad) return res.status(400).json({ error: bad });
        u.password = hashPassword(body.password);
      }
      if (typeof body.name === 'string' && body.name.trim()) u.name = body.name.trim();
      if (body.role) u.role = body.role;
      if (typeof body.active === 'boolean') u.active = body.active;

      // The last active administrator must stay one, or nobody can manage users.
      if (!users.some(x => x.role === 'admin' && x.active !== false)) {
        return res.status(400).json({ error: 'That would leave no active administrator.' });
      }
      await saveUsers(users);
      return res.status(200).json({ user: publicUser(u) });
    }

    res.setHeader('Allow', 'GET, POST, PATCH');
    return res.status(405).json({ error: 'Use GET, POST or PATCH.' });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
}
