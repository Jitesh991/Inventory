/**
 * Deliberately imports nothing.
 *
 * If the other endpoints return FUNCTION_INVOCATION_FAILED, the crash happens
 * while loading a module, before any handler code runs — so their own error
 * handling cannot report it. This one has no imports, so if it answers, the
 * runtime is fine and the fault is a dependency or an environment variable.
 */
export default function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');

  // Names only. A token's value must never appear in a response.
  const tokenVars = Object.keys(process.env)
    .filter(k => /_READ_WRITE_TOKEN$/.test(k) && process.env[k]);

  const env = {
    blobTokenFound: tokenVars.length > 0,
    blobTokenVariableNames: tokenVars,
    AUTH_SECRET: Boolean(process.env.AUTH_SECRET),
    SETUP_TOKEN: Boolean(process.env.SETUP_TOKEN)
  };

  // Loaded one at a time, so the response names the exact module that fails.
  const imports = {};
  Promise.allSettled([
    import('@vercel/blob').then(() => imports.blob = 'ok',
      e => imports.blob = 'FAILED — ' + e.message),
    import('node:crypto').then(() => imports.crypto = 'ok',
      e => imports.crypto = 'FAILED — ' + e.message),
    import('./_auth.js').then(() => imports.authLib = 'ok',
      e => imports.authLib = 'FAILED — ' + e.message)
  ]).then(() => {
    const missing = [];
    if (!env.blobTokenFound) missing.push('a Blob token (BLOB_READ_WRITE_TOKEN)');
    if (!env.AUTH_SECRET) missing.push('AUTH_SECRET');
    if (!env.SETUP_TOKEN) missing.push('SETUP_TOKEN');
    const broken = Object.entries(imports).filter(([, v]) => v !== 'ok').map(([k]) => k);

    let verdict;
    if (broken.includes('blob')) {
      verdict = 'The @vercel/blob package is not installed. package.json is probably missing from '
        + 'the repository root, or it is not at the same level as the api folder.';
    } else if (broken.includes('authLib')) {
      verdict = 'api/_auth.js is missing or failed to load. Check it sits next to api/auth.js.';
    } else if (missing.length) {
      verdict = 'Missing: ' + missing.join(', ')
        + '. Add them in Settings → Environment Variables with the Production box ticked, then '
        + 'redeploy — saving a variable does not redeploy on its own.';
    } else {
      verdict = 'Everything needed is present. If sign-in still fails, the error will now come '
        + 'back as readable JSON from /api/auth.';
    }

    res.status(200).json({
      node: process.version,
      env,
      imports,
      verdict
    });
  });
}
