import { requireUser, isAdmin, readBlob, writeBlob } from './_auth.js';

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

/**
 * Only an administrator may change these.
 *
 * The document now holds one entry per warehouse, so the guarded keys live
 * inside each site rather than at the top level. The brand palette is shared
 * across sites and is guarded too; the SKU master is not, because scanners
 * legitimately add barcodes and pack sizes while counting.
 *
 * Locks are deliberately absent: a lock guards the layout from stray clicks,
 * painting is already refused for scanners, and reverting it server-side made
 * their unlock snap back and blocked scanning.
 */
const SITE_STRUCTURAL = ['racks', 'assign', 'kinds', 'labels'];

/**
 * Fold a save into what is already stored, slot by slot, for stock counts.
 *
 * Every browser holds the whole document and writes the whole document, so
 * without this the last save wins: two people counting different slots at the
 * same time would erase each other, silently, with no way to tell which
 * figures were lost. Counts are the one place where that is certain to happen,
 * because a count runs for days with several people keying at once.
 *
 * Slots are independent — nobody counts the same slot twice — so taking what
 * is stored as the base and laying the incoming slots over it is both safe and
 * enough. A slot is only ever added or re-counted, never removed.
 */
function mergeCounts(incoming, current) {
  if (!current || !current.sites) return incoming;
  const merged = [];

  for (const [siteId, site] of Object.entries(incoming.sites || {})) {
    const was = current.sites[siteId];
    if (!was || !Array.isArray(was.counts) || !Array.isArray(site.counts)) continue;

    site.counts.forEach(count => {
      const stored = was.counts.find(c => c.id === count.id);
      if (!stored || !stored.slots) return;
      for (const [loc, slot] of Object.entries(stored.slots)) {
        if (!(loc in (count.slots || {}))) {
          count.slots = count.slots || {};
          count.slots[loc] = slot;
          merged.push(`${siteId}:${count.id}:${loc}`);
        }
      }
    });

    // A count someone else started while this browser was open.
    was.counts.forEach(stored => {
      if (!site.counts.some(c => c.id === stored.id)) {
        site.counts.push(stored);
        merged.push(`${siteId}:${stored.id} (whole count)`);
      }
    });
  }
  return incoming;
}

/** Replace the parts a scanner may not change with what is already stored. */
function guardForScanner(incoming, current) {
  const guarded = [];
  if (!current) return { toSave: incoming, guarded };

  const out = { ...incoming };

  // Shared half: the brand palette only.
  out.shared = { ...(incoming.shared || {}) };
  if (current.shared && 'brands' in current.shared) {
    if (JSON.stringify(out.shared.brands) !== JSON.stringify(current.shared.brands)) {
      guarded.push('brands');
    }
    out.shared.brands = current.shared.brands;
  }

  // Each site's layout.
  out.sites = { ...(incoming.sites || {}) };
  for (const [id, site] of Object.entries(out.sites)) {
    const was = current.sites && current.sites[id];
    if (!was) { guarded.push(`new site ${id}`); delete out.sites[id]; continue; }
    const merged = { ...site };
    for (const k of SITE_STRUCTURAL) {
      if (k in was) {
        if (JSON.stringify(site[k]) !== JSON.stringify(was[k])) guarded.push(`${id}.${k}`);
        merged[k] = was[k];
      }
    }
    merged.name = was.name;            // renaming a warehouse is an admin act
    out.sites[id] = merged;
  }
  // A site the browser dropped is kept: scanners never delete warehouses.
  for (const [id, was] of Object.entries(current.sites || {})) {
    if (!out.sites[id]) { out.sites[id] = was; guarded.push(`removed site ${id}`); }
  }
  return { toSave: out, guarded };
}

async function readState() {
  const state = await readBlob(PATH);
  return { state, savedAt: null };
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

      // Read what is stored once, and use it both to merge counts and to
      // hold a scanner to what they may change.
      const { state: current } = await readState();

      let toSave = mergeCounts(incoming, current);
      let guarded = [];
      if (!isAdmin(me)) {
        ({ toSave, guarded } = guardForScanner(toSave, current));
      }

      const body = JSON.stringify(toSave);
      await writeBlob(PATH, toSave);
      return res.status(200).json({ ok: true, size: body.length, guarded });
    }

    res.setHeader('Allow', 'GET, PUT');
    return res.status(405).json({ error: 'Use GET or PUT.' });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
}
