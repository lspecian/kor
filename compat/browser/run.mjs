// Serves the bundled SDK pages and runs them in headless Chrome against a Kor
// server. Suites:
//   sdk   Firestore web SDK over streaming WebChannel and forced long polling
//   auth  Firebase Auth web SDK against Kor's sign-in bridge, rules enforced,
//         including Entra-style sign-in through a mock OIDC provider
// Usage: KOR_HOST=127.0.0.1 KOR_PORT=5002 KOR_SUITES=sdk,auth node run.mjs
// The auth suite needs kord started with -auth -identity-project
// $KOR_AUTH_PROJECT -emulator and -oidc-issuer/-oidc-audience/-oidc-jwks
// pointing at this runner's mock provider (KOR_IDP_PORT, default 5199).
import { createServer } from 'node:http';
import { generateKeyPairSync, randomBytes, sign as rsaSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import puppeteer from 'puppeteer';

const host = process.env.KOR_HOST || '127.0.0.1';
const port = Number(process.env.KOR_PORT || 5002);
const suites = (process.env.KOR_SUITES || 'sdk').split(',');
const modes = (process.env.KOR_MODES || 'streaming,long-polling').split(',');
const authProject = process.env.KOR_AUTH_PROJECT || 'kor-auth-test';
const idpPort = Number(process.env.KOR_IDP_PORT || 5199);
export const IDP_ISSUER = 'https://login.microsoftonline.com/00000000-0000-0000-0000-000000000001/v2.0';
export const IDP_AUDIENCE = 'api://kor-test';

// Rules for the auth suite: each user owns notes/{uid}.
const AUTH_RULES = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{owner} {
      allow read, write: if request.auth != null && request.auth.uid == owner;
    }
  }
}`;

function startMockIdp() {
  // An Entra-shaped OIDC provider: JWKS plus a token endpoint for tests.
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = randomBytes(6).toString('hex');
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' };
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    res.setHeader('access-control-allow-origin', '*');
    if (url.pathname === '/jwks') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ keys: [jwk] }));
    }
    if (url.pathname === '/token') {
      const now = Math.floor(Date.now() / 1000);
      const sub = url.searchParams.get('sub');
      const unsigned = `${b64({ alg: 'RS256', kid, typ: 'JWT' })}.${b64({
        iss: IDP_ISSUER, aud: IDP_AUDIENCE, sub, oid: sub, tid: '00000000-0000-0000-0000-000000000001',
        preferred_username: url.searchParams.get('email'), email: url.searchParams.get('email'),
        iat: now, nbf: now, exp: now + 600,
      })}`;
      const sig = rsaSign('RSA-SHA256', Buffer.from(unsigned), privateKey).toString('base64url');
      res.writeHead(200, { 'content-type': 'text/plain' });
      return res.end(`${unsigned}.${sig}`);
    }
    res.writeHead(404);
    res.end();
  });
  return new Promise((resolve) => server.listen(idpPort, '127.0.0.1', () => resolve(server)));
}

const page = (script) => `<!doctype html><meta charset="utf-8"><title>kor</title><script type="module" src="/${script}"></script>`;
const bundles = {
  '/sdk-page.js': readFileSync(new URL('./dist/sdk-page.js', import.meta.url)),
  '/auth-page.js': readFileSync(new URL('./dist/auth-page.js', import.meta.url)),
};
const server = createServer((req, res) => {
  const path = new URL(req.url, 'http://x').pathname;
  if (bundles[path]) {
    res.writeHead(200, { 'content-type': 'text/javascript' });
    return res.end(bundles[path]);
  }
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end(page(path === '/auth' ? 'auth-page.js' : 'sdk-page.js'));
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${server.address().port}`;

const idp = suites.includes('auth') ? await startMockIdp() : null;
const browser = await puppeteer.launch({ headless: true });
let failed = 0;

function report(title, results) {
  console.log(title);
  for (const r of results) {
    if (!r.ok) failed++;
    console.log(`  ${r.ok ? 'PASS' : 'FAIL'} ${r.name} (${r.ms} ms)${r.ok ? '' : ` — ${r.detail}`}`);
  }
}

try {
  if (suites.includes('sdk')) {
    // The SDK suite runs unauthenticated; on a server with -auth, give its
    // project allow-all rules (a server without -emulator ignores this).
    await fetch(`http://${host}:${port}/emulator/v1/projects/kor-browser-test:securityRules`, {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ rules: { files: [{ name: 'firestore.rules', content:
        "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    match /{document=**} {\n      allow read, write: if true;\n    }\n  }\n}" }] } }),
    }).catch(() => {});
    for (const mode of modes) {
      const tab = await browser.newPage();
      tab.on('pageerror', (e) => console.error(`  [${mode}] page error: ${e.message}`));
      await tab.goto(origin, { waitUntil: 'load' });
      await tab.waitForFunction(() => typeof window.runSuite === 'function', { timeout: 30000 });
      report(`browser Firestore SDK over ${mode}:`, await tab.evaluate(
        (args) => window.runSuite(args), { host, port, forceLongPolling: mode === 'long-polling' },
      ));
      await tab.close();
    }
  }
  if (suites.includes('auth')) {
    const rulesRes = await fetch(`http://${host}:${port}/emulator/v1/projects/${authProject}:securityRules`, {
      method: 'PUT', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ rules: { files: [{ name: 'firestore.rules', content: AUTH_RULES }] } }),
    });
    if (!rulesRes.ok) throw new Error(`loading auth rules: HTTP ${rulesRes.status} ${await rulesRes.text()}`);
    const tab = await browser.newPage();
    tab.on('pageerror', (e) => console.error(`  [auth] page error: ${e.message}`));
    await tab.goto(`${origin}/auth`, { waitUntil: 'load' });
    await tab.waitForFunction(() => typeof window.runAuthSuite === 'function', { timeout: 30000 });
    report('browser Firebase Auth SDK against the sign-in bridge:', await tab.evaluate(
      (args) => window.runAuthSuite(args), { host, port, project: authProject, idp: `http://127.0.0.1:${idpPort}` },
    ));
    await tab.close();
  }
} finally {
  await browser.close();
  server.close();
  idp?.close();
}
console.log(failed ? `${failed} browser check(s) failed` : 'all browser checks passed');
process.exit(failed ? 1 : 0);
