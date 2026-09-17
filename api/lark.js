import { requireUser } from './_auth.js';

/**
 * Send a pullout to Lark.
 *
 * Called from the server rather than the browser for two reasons: the webhook
 * URLs stay out of the page, and Lark does not allow cross-origin posts from a
 * browser anyway.
 *
 * Set LARK_WEBHOOK_1 and, if you want a second bot, LARK_WEBHOOK_2.
 */

const money = n => Number(n || 0).toLocaleString();

/** Lark's interactive card — the coloured-header format. */
function buildCard(d) {
  const lines = (d.lines || []);
  const totalPcs = lines.reduce((a, l) => a + (Number(l.qty) || 0), 0);

  // Two columns of facts, then the SKU list, then a footer note.
  const facts = [
    ['Truck', d.truck], ['Driver', d.driver],
    ['Contact', d.contact], ['Destination', d.destination]
  ].filter(([, v]) => v).map(([k, v]) => ({
    is_short: true,
    text: { tag: 'lark_md', content: `**${k}**\n${v}` }
  }));

  facts.push({ is_short: true, text: { tag: 'lark_md', content: `**Pulled out**\n${d.at}` } });
  facts.push({ is_short: true, text: { tag: 'lark_md', content: `**Released by**\n${d.by}` } });

  // The slot is deliberately left out: whoever reads this in Lark cares what
  // went on the truck, not which shelf it came off.
  const rows = lines.map(l =>
    `**${l.sku}**  ·  ${money(l.qty)} pcs${l.boxes ? ` (${money(l.boxes)} box${l.boxes === 1 ? '' : 'es'})` : ''}`
  ).join('\n');

  const elements = [
    { tag: 'div', fields: facts },
    { tag: 'hr' },
    { tag: 'div', text: { tag: 'lark_md',
      content: `**${lines.length} SKU${lines.length === 1 ? '' : 's'}  ·  ${money(totalPcs)} pieces**` } },
    { tag: 'div', text: { tag: 'lark_md', content: rows || '_no lines_' } }
  ];

  if (d.note) {
    elements.push({ tag: 'hr' });
    elements.push({ tag: 'div', text: { tag: 'lark_md', content: `**Notes**\n${d.note}` } });
  }
  elements.push({ tag: 'note', elements: [
    { tag: 'plain_text', content: `Sunbeams Impex · Warehouse · ${d.ref}` } ] });

  return {
    msg_type: 'interactive',
    card: {
      config: { wide_screen_mode: true },
      header: {
        template: 'orange',
        title: { tag: 'plain_text', content: `Pullout · ${d.truck || 'no truck'}` }
      },
      elements
    }
  };
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');

  // Inside the try as well: an exception here used to escape the handler and
  // become a bare platform 500 with no body for the browser to report.
  let me;
  try {
    me = await requireUser(req, res);
  } catch (e) {
    return res.status(500).json({ error: 'Sign-in check failed: ' + (e.message || String(e)) });
  }
  if (!me) return;

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Use POST.' });
  }

  const hooks = [process.env.LARK_WEBHOOK_1, process.env.LARK_WEBHOOK_2].filter(Boolean);
  if (!hooks.length) {
    return res.status(200).json({ sent: 0, skipped: true,
      results: [{ ok: false, error: 'No LARK_WEBHOOK_1 set, so nothing was sent. The pullout is still saved.' }] });
  }

  try {
    const d = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const card = buildCard(d);

    const results = await Promise.all(hooks.map(async (url, i) => {
      try {
        const r = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(card)
        });
        const out = await r.json().catch(() => ({}));
        // Lark answers 200 with a non-zero code when it rejects the card.
        const ok = r.ok && (out.code === 0 || out.StatusCode === 0 || out.code === undefined);
        return { bot: i + 1, ok, error: ok ? null : (out.msg || out.StatusMessage || `HTTP ${r.status}`) };
      } catch (e) {
        return { bot: i + 1, ok: false, error: e.message };
      }
    }));

    return res.status(200).json({ sent: results.filter(r => r.ok).length, results });
  } catch (e) {
    return res.status(500).json({
      error: 'Building or sending the card failed: ' + (e && e.message ? e.message : String(e)),
      where: e && e.stack ? String(e.stack).split('\n')[1]?.trim() : undefined
    });
  }
}
