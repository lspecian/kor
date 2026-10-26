// Runs the fixture functions codebase under the functions runner against a
// Kor server and checks each trigger kind end to end: Firestore document
// triggers (created, updated with before/after, deleted, written on a
// subcollection), the v1 Auth onCreate trigger from the sign-in bridge, a
// callable function with the caller's auth, the codebase's .env, and that a
// function's stray rejection does not stop the runner.
//
// Usage: KOR_URL=http://127.0.0.1:5002 PROJECT=kor-emulator-test node run.mjs
// kord needs -auth -admin-tokens owner -allow-unsigned-tokens
// -identity-project $PROJECT -identity-emulator-tokens (callable functions
// verify the caller's token the way the Admin SDK does against an emulator).
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';

const KOR = (process.env.KOR_URL || 'http://127.0.0.1:5002').replace(/\/$/, '');
const PROJECT = process.env.PROJECT || 'kor-emulator-test';
const fixture = fileURLToPath(new URL('./fixture', import.meta.url));
const runnerPath = fileURLToPath(new URL('../runner.js', import.meta.url));
const DOCS = `${KOR}/v1/projects/${PROJECT}/databases/(default)/documents`;
const run = Math.random().toString(36).slice(2, 8);

if (!existsSync(`${fixture}/node_modules`)) {
  await new Promise((resolve, reject) => spawn('npm', ['ci', '--silent'], { cwd: fixture, stdio: 'inherit' })
    .on('exit', (code) => (code ? reject(new Error(`npm ci: ${code}`)) : resolve())));
}

const port = await new Promise((resolve) => {
  const s = createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
});
let runnerLog = '';
const runner = spawn(process.execPath, [runnerPath], {
  env: { ...process.env, FUNCTIONS_DIR: fixture, PROJECT, KOR_URL: KOR, PORT: String(port), POLL_MS: '100' },
});
runner.stdout.on('data', (d) => { runnerLog += d; });
runner.stderr.on('data', (d) => { runnerLog += d; });
let runnerExited = null;
runner.on('exit', (code) => { runnerExited = code; });

const value = (v) => (typeof v === 'number' ? (Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v })
  : typeof v === 'boolean' ? { booleanValue: v } : v === null ? { nullValue: null } : { stringValue: String(v) });
const plain = (doc) => Object.fromEntries(Object.entries(doc.fields || {}).map(([k, v]) => {
  const [type, raw] = Object.entries(v)[0];
  return [k, type === 'integerValue' ? Number(raw) : raw];
}));
const admin = { authorization: 'Bearer owner', 'content-type': 'application/json' };
async function put(path, data) {
  const res = await fetch(`${DOCS}/${path}`, { method: 'PATCH', headers: admin,
    body: JSON.stringify({ fields: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, value(v)])) }) });
  if (!res.ok) throw new Error(`write ${path}: HTTP ${res.status} ${await res.text()}`);
}
async function del(path) {
  const res = await fetch(`${DOCS}/${path}`, { method: 'DELETE', headers: admin });
  if (!res.ok) throw new Error(`delete ${path}: HTTP ${res.status}`);
}
async function waitFor(path, pred, what) {
  const deadline = Date.now() + 15000;
  let last = null;
  while (Date.now() < deadline) {
    const res = await fetch(`${DOCS}/${path}`, { headers: admin });
    if (res.ok) {
      last = plain(await res.json());
      if (pred(last)) return last;
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`${what}: ${path} is ${JSON.stringify(last)}`);
}
const assert = (cond, msg) => { if (!cond) throw new Error(msg); };

const results = [];
async function check(name, fn) {
  try {
    await fn();
    results.push(true);
    console.log(`  PASS ${name}`);
  } catch (e) {
    results.push(false);
    console.log(`  FAIL ${name} — ${e.message}`);
  }
}

try {
  const started = Date.now();
  while (!runnerLog.includes('HTTP functions on') && runnerExited === null && Date.now() - started < 30000) {
    await new Promise((r) => setTimeout(r, 100));
  }
  assert(runnerLog.includes('HTTP functions on'), `runner did not start:\n${runnerLog}`);
  console.log('functions runner against Kor:');

  await check('discovers the fixture\'s triggers', async () => {
    assert(/5 document triggers, 1 auth triggers, 1 HTTP\/callable functions/.test(runnerLog), runnerLog.split('\n')[0]);
  });
  await check('onDocumentCreated, with the codebase\'s .env', async () => {
    await put(`orders/a-${run}`, { qty: 2, price: 5 });
    const r = await waitFor(`receipts/a-${run}`, (d) => d.total === 10, 'receipt');
    assert(r.greeting === 'hello from .env', `greeting ${r.greeting}`);
    assert(r.document === `orders/a-${run}`, `event.document ${r.document}`);
  });
  await check('onDocumentUpdated sees before and after', async () => {
    await put(`orders/a-${run}`, { qty: 3, price: 5 });
    await waitFor(`audits/a-${run}`, (d) => d.from === 2 && d.to === 3, 'audit');
  });
  await check('onDocumentDeleted sees the deleted data', async () => {
    await del(`orders/a-${run}`);
    await waitFor(`tombstones/a-${run}`, (d) => d.qty === 3, 'tombstone');
  });
  await check('onDocumentWritten on a subcollection', async () => {
    // Like Cloud Functions, no order across documents: count both.
    await put(`rooms/r-${run}/messages/m1`, { text: 'one' });
    await put(`rooms/r-${run}/messages/m2`, { text: 'two' });
    await waitFor(`rooms/r-${run}`, (d) => d.count === 2 && ['m1', 'm2'].includes(d.lastMessage), 'room summary');
  });
  await check('a stray rejection does not stop the runner', async () => {
    await put(`explode/x-${run}`, { boom: true });
    await put(`orders/b-${run}`, { qty: 1, price: 7 });
    await waitFor(`receipts/b-${run}`, (d) => d.total === 7, 'receipt after the rejection');
    assert(runnerExited === null, `runner exited with ${runnerExited}`);
    assert(runnerLog.includes('stray rejection from onExplode'), 'rejection not logged');
  });

  let idToken;
  await check('Auth onCreate (v1) fires for a bridge sign-up', async () => {
    const res = await fetch(`${KOR}/identitytoolkit.googleapis.com/v1/accounts:signUp?key=test`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: `fn.${run}@example.com`, password: 'fixture-pass', returnSecureToken: true }),
    });
    const body = await res.json();
    assert(res.ok, JSON.stringify(body));
    idToken = body.idToken;
    await waitFor(`profiles/${body.localId}`, (d) => d.email === `fn.${run}@example.com`, 'profile');
  });
  await check('a callable function gets the caller\'s auth', async () => {
    const call = (headers) => fetch(`http://127.0.0.1:${port}/${PROJECT}/us-central1/whoami`, {
      method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify({ data: {} }),
    });
    const res = await call({ authorization: `Bearer ${idToken}` });
    const body = await res.json();
    assert(res.ok && body.result?.email === `fn.${run}@example.com` && body.result.greeting === 'hello from .env', JSON.stringify(body));
    const anon = await call({});
    assert(anon.status === 401, `anonymous call: HTTP ${anon.status}`);
  });
} finally {
  runner.kill();
}
const failed = results.filter((ok) => !ok).length;
if (failed) console.log(`runner log:\n${runnerLog.split('\n').slice(-30).join('\n')}`);
console.log(`  ${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
