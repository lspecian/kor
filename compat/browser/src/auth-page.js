// Runs the official Firebase Auth and Firestore web SDKs against Kor's
// sign-in bridge, with security rules enforced: email/password accounts,
// token refresh, and the Entra/OIDC path (provider token -> exchange ->
// custom token -> signInWithCustomToken).
import { initializeApp } from 'firebase/app';
import {
  connectAuthEmulator, createUserWithEmailAndPassword, getAuth, signInWithCustomToken,
  signInWithEmailAndPassword, signOut,
} from 'firebase/auth';
import { connectFirestoreEmulator, doc, getDoc, initializeFirestore, setDoc } from 'firebase/firestore';

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

async function denied(promise, what) {
  try {
    await promise;
  } catch (e) {
    if (e && e.code === 'permission-denied') return;
    throw new Error(`${what}: expected permission-denied, got ${e && e.code}`);
  }
  throw new Error(`${what}: expected permission-denied, but it succeeded`);
}

function claims(token) {
  return JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
}

export async function runAuthSuite({ host, port, project, idp }) {
  const app = initializeApp({ projectId: project, apiKey: 'test-api-key', authDomain: `${project}.local` }, `auth-${Math.random()}`);
  const auth = getAuth(app);
  connectAuthEmulator(auth, `http://${host}:${port}`, { disableWarnings: true });
  const db = initializeFirestore(app, {});
  connectFirestoreEmulator(db, host, port);
  const run = Math.random().toString(36).slice(2, 8);
  const email = `ada.${run}@example.com`;
  const results = [];
  let uid;

  async function check(name, fn) {
    const started = performance.now();
    try {
      const detail = await fn();
      results.push({ name, ok: true, detail: detail ?? '', ms: Math.round(performance.now() - started) });
    } catch (e) {
      results.push({ name, ok: false, detail: String(e && e.message || e), ms: Math.round(performance.now() - started) });
    }
  }

  await check('sign up with email and password', async () => {
    const cred = await createUserWithEmailAndPassword(auth, email, 'correct horse battery');
    uid = cred.user.uid;
    const c = claims(await cred.user.getIdToken());
    assert(c.sub === uid && c.email === email && c.aud === project, JSON.stringify(c));
  });

  await check('rules: own document allowed, another user\'s denied', async () => {
    await setDoc(doc(db, `notes/${uid}`), { text: 'mine' });
    assert((await getDoc(doc(db, `notes/${uid}`))).data().text === 'mine', 'read own');
    await denied(setDoc(doc(db, 'notes/someone-else'), { text: 'not mine' }), 'write other');
  });

  await check('sign out, then anonymous reads are denied', async () => {
    await signOut(auth);
    await denied(getDoc(doc(db, `notes/${uid}`)), 'anonymous read');
  });

  await check('wrong password is rejected', async () => {
    try {
      await signInWithEmailAndPassword(auth, email, 'wrong');
    } catch (e) {
      assert(e.code === 'auth/invalid-credential' || e.code === 'auth/wrong-password', e.code);
      return;
    }
    throw new Error('wrong password accepted');
  });

  await check('sign in again, token refresh', async () => {
    const cred = await signInWithEmailAndPassword(auth, email, 'correct horse battery');
    assert(cred.user.uid === uid, 'same uid');
    const first = await cred.user.getIdToken();
    await new Promise((r) => setTimeout(r, 1100));
    const refreshed = await cred.user.getIdToken(true);
    assert(refreshed !== first && claims(refreshed).sub === uid, 'refreshed token');
    assert((await getDoc(doc(db, `notes/${uid}`))).exists(), 'read after refresh');
  });

  await check('Entra/OIDC sign-in through the exchange', async () => {
    await signOut(auth);
    const idpToken = await (await fetch(`${idp}/token?sub=entra-${run}&email=grace.${run}@contoso.com`)).text();
    const res = await fetch(`http://${host}:${port}/kor/v1/auth:exchange`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id_token: idpToken }),
    });
    assert(res.ok, `exchange HTTP ${res.status}`);
    const { customToken } = await res.json();
    const cred = await signInWithCustomToken(auth, customToken);
    const c = claims(await cred.user.getIdToken());
    assert(c.email === `grace.${run}@contoso.com` && c.firebase.sign_in_provider === 'custom', JSON.stringify(c));
    await setDoc(doc(db, `notes/${cred.user.uid}`), { text: 'from entra' });
    assert((await getDoc(doc(db, `notes/${cred.user.uid}`))).data().text === 'from entra', 'entra user writes own note');
    await denied(getDoc(doc(db, `notes/${uid}`)), 'entra user reading another user');
  });

  await check('a forged provider token is refused', async () => {
    const forged = 'eyJhbGciOiJub25lIn0.' + btoa(JSON.stringify({ iss: 'https://evil', sub: 'x' })) + '.';
    const res = await fetch(`http://${host}:${port}/kor/v1/auth:exchange`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id_token: forged }),
    });
    assert(res.status === 401, `HTTP ${res.status}`);
  });

  await signOut(auth);
  return results;
}

window.runAuthSuite = runAuthSuite;
