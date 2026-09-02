import { put, list } from '@vercel/blob';

/**
 * The entire warehouse map as one JSON document in Blob storage.
 *
 * One file, two verbs. There is no database, no schema and no migration
 * step: whatever shape the front end saves is the shape it reads back, so
 * adding a feature to the tool never needs a change here.
 *
 * GET  /api/state  -> { state: {...} | null }
 * PUT  /api/state  -> { ok: true, size }
 */

const PATH = 'warehouse/state.json';

/** Optional shared password. Unset in Vercel and the app is simply open. */
function authed(req) {
  const want = process.env.APP_PASSWORD;
  if (!want) return true;
  const got = req.headers['x-app-password'];
  return typeof got === 'string' && got === want;
}

export default async function handler(req, res) {
  // The browser must never hold a stale copy: a cached GET straight after a
  // save is how a write appears to have vanished.
  res.setHeader('Cache-Control', 'no-store, max-age=0');

  if (!process.env.BLOB_READ_WRITE_TOKEN) {
    return res.status(500).json({
      error: 'No Blob store is connected. In Vercel: Storage → create a Blob store → '
        + 'connect it to this project, then redeploy.'
    });
  }
  if (!authed(req)) {
    return res.status(401).json({ error: 'Wrong password.' });
  }

  try {
    if (req.method === 'GET') {
      // Find the blob, then read it. Listing by exact prefix keeps this to one
      // small call even once the store holds other things.
      const { blobs } = await list({ prefix: PATH, limit: 1 });
      const hit = blobs.find(b => b.pathname === PATH);
      if (!hit) return res.status(200).json({ state: null });

      const r = await fetch(hit.url, { cache: 'no-store' });
      if (!r.ok) throw new Error(`Could not read the saved file (HTTP ${r.status})`);
      return res.status(200).json({ state: await r.json(), savedAt: hit.uploadedAt });
    }

    if (req.method === 'PUT') {
      const body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
      if (!body || body === 'null') {
        return res.status(400).json({ error: 'Empty body — refusing to overwrite with nothing.' });
      }
      const saved = await put(PATH, body, {
        access: 'public',
        contentType: 'application/json',
        addRandomSuffix: false,   // same path every time, so it overwrites
        allowOverwrite: true,
        cacheControlMaxAge: 0
      });
      return res.status(200).json({ ok: true, size: body.length, url: saved.url });
    }

    res.setHeader('Allow', 'GET, PUT');
    return res.status(405).json({ error: 'Use GET or PUT.' });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
}
