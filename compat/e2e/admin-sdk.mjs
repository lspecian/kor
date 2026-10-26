// Firebase Admin SDK for Node against Kor, as Cloud Functions code uses it:
// user management on the sign-in bridge (getUser, updateUser,
// setCustomUserClaims, revokeRefreshTokens, listUsers, deleteUser,
// generatePasswordResetLink, createCustomToken), verifyIdToken with
// checkRevoked, and Firestore as an admin.
//
// Usage: KOR_HOST=127.0.0.1 KOR_PORT=5002 PROJECT=kor-auth-test node admin-sdk.mjs
// Needs kord with -identity-project $PROJECT -admin-tokens owner
// -identity-trust-unsigned-custom-tokens (the SDK signs nothing against an
// emulator).
import { createRequire } from 'node:module';
const require = createRequire(new URL('../browser/package.json', import.meta.url));

const host = process.env.KOR_HOST || '127.0.0.1';
const port = process.env.KOR_PORT || '5002';
const project = process.env.PROJECT || 'kor-auth-test';
process.env.FIREBASE_AUTH_EMULATOR_HOST = `${host}:${port}`;
process.env.FIRESTORE_EMULATOR_HOST = `${host}:${port}`;
const { initializeApp } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore } = require('firebase-admin/firestore');

const app = initializeApp({ projectId: project }, `admin-${Math.random()}`);
const auth = getAuth(app);
const run = Math.random().toString(36).slice(2, 8);
const email = `node.${run}@example.com`;
const results = [];
let uid;

const assert = (cond, msg) => { if (!cond) throw new Error(msg); };
async function rest(op, body) {
  const res = await fetch(`http://${host}:${port}/identitytoolkit.googleapis.com/v1/accounts:${op}?key=test`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}
async function signIn(password = 'first-pass') {
  const { status, body } = await rest('signInWithPassword', { email, password, returnSecureToken: true });
  assert(status === 200, `sign-in HTTP ${status}: ${JSON.stringify(body)}`);
  return body.idToken;
}
async function rejects(promise, code) {
  try {
    await promise;
  } catch (e) {
    assert(e.code === code, `expected ${code}, got ${e.code}: ${e.message}`);
    return;
  }
  throw new Error(`expected ${code}, but it succeeded`);
}
async function check(name, fn) {
  try {
    await fn();
    results.push({ name, ok: true });
    console.log(`  PASS ${name}`);
  } catch (e) {
    results.push({ name, ok: false });
    console.log(`  FAIL ${name} — ${e.message}`);
  }
}

console.log('Firebase Admin SDK for Node:');
await check('createUser, getUser, getUserByEmail', async () => {
  uid = (await auth.createUser({ email, password: 'first-pass', displayName: 'Node' })).uid;
  assert((await auth.getUser(uid)).email === email, 'getUser');
  assert((await auth.getUserByEmail(email)).uid === uid, 'getUserByEmail');
});
await check('verifyIdToken with checkRevoked', async () => {
  const decoded = await auth.verifyIdToken(await signIn(), true);
  assert(decoded.uid === uid && decoded.email === email, JSON.stringify(decoded));
});
await check('setCustomUserClaims reach ID tokens', async () => {
  await auth.setCustomUserClaims(uid, { role: 'admin' });
  assert((await auth.getUser(uid)).customClaims?.role === 'admin', 'customClaims');
  assert((await auth.verifyIdToken(await signIn(), true)).role === 'admin', 'claim in token');
});
await check('updateUser disables a user; their token is refused', async () => {
  const token = await signIn();
  await auth.updateUser(uid, { disabled: true, displayName: 'Disabled' });
  try {
    await rejects(auth.verifyIdToken(token, true), 'auth/user-disabled');
    const { body } = await rest('signInWithPassword', { email, password: 'first-pass' });
    assert(body.error?.message === 'USER_DISABLED', JSON.stringify(body));
  } finally {
    await auth.updateUser(uid, { disabled: false });
  }
});
await check('revokeRefreshTokens revokes earlier ID tokens', async () => {
  const token = await signIn();
  await new Promise((r) => setTimeout(r, 1100));
  await auth.revokeRefreshTokens(uid);
  await rejects(auth.verifyIdToken(token, true), 'auth/id-token-revoked');
  await auth.verifyIdToken(await signIn(), true);
});
await check('createCustomToken, then sign in with it', async () => {
  const token = await auth.createCustomToken(uid, { tier: 'gold' });
  const { status, body } = await rest('signInWithCustomToken', { token, returnSecureToken: true });
  assert(status === 200, JSON.stringify(body));
  assert((await auth.verifyIdToken(body.idToken)).tier === 'gold', 'developer claim');
});
await check('listUsers and generatePasswordResetLink', async () => {
  assert((await auth.listUsers(1000)).users.some((u) => u.uid === uid), 'listed');
  assert((await auth.generatePasswordResetLink(email)).includes('oobCode='), 'link');
});
await check('Firestore as an admin (rules do not apply)', async () => {
  const db = getFirestore(app);
  await db.doc(`admin_sdk/${run}`).set({ uid });
  assert((await db.doc(`admin_sdk/${run}`).get()).data().uid === uid, 'read back');
});
await check('deleteUser', async () => {
  await auth.deleteUser(uid);
  await rejects(auth.getUser(uid), 'auth/user-not-found');
});

const failed = results.filter((r) => !r.ok).length;
console.log(`  ${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
