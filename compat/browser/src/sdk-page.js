// Runs the official Firebase web SDK against a Firestore-compatible server
// from inside a real browser, so it exercises WebChannel (Listen and Write
// streams) and the REST calls the SDK makes for transactions and counts.
import { initializeApp } from 'firebase/app';
import {
  addDoc, arrayUnion, collection, connectFirestoreEmulator, deleteDoc, deleteField,
  doc, getCountFromServer, getDoc, getDocs, increment, initializeFirestore, limit,
  onSnapshot, orderBy, query, runTransaction, serverTimestamp, setDoc, updateDoc,
  where, writeBatch,
} from 'firebase/firestore';

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function nextSnapshot(ref, { count = 1, timeoutMs = 15000 } = {}) {
  // Resolves with the next `count` snapshots of a query or document.
  return new Promise((resolve, reject) => {
    const seen = [];
    const timer = setTimeout(() => { unsub(); reject(new Error(`timed out after ${seen.length} snapshot(s)`)); }, timeoutMs);
    const unsub = onSnapshot(ref, (snap) => {
      seen.push(snap);
      if (seen.length >= count) { clearTimeout(timer); unsub(); resolve(seen); }
    }, (err) => { clearTimeout(timer); reject(err); });
  });
}

function watch(ref) {
  // Streams snapshots into a queue; next() waits for the following one.
  const queue = [];
  const waiters = [];
  let failure = null;
  const unsub = onSnapshot(ref, (snap) => {
    const w = waiters.shift();
    if (w) w.resolve(snap); else queue.push(snap);
  }, (err) => { failure = err; waiters.splice(0).forEach((w) => w.reject(err)); });
  return {
    next(timeoutMs = 15000) {
      if (failure) return Promise.reject(failure);
      if (queue.length) return Promise.resolve(queue.shift());
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('timed out waiting for a snapshot')), timeoutMs);
        waiters.push({ resolve: (s) => { clearTimeout(timer); resolve(s); }, reject: (e) => { clearTimeout(timer); reject(e); } });
      });
    },
    stop: unsub,
  };
}

const ids = (snap) => snap.docs.map((d) => d.id);

export async function runSuite({ host, port, project = 'kor-browser-test', forceLongPolling = false }) {
  const app = initializeApp({ projectId: project, apiKey: 'test-api-key' }, `suite-${Math.random()}`);
  const db = initializeFirestore(app, forceLongPolling ? { experimentalForceLongPolling: true } : {});
  connectFirestoreEmulator(db, host, port);
  const run = Math.random().toString(36).slice(2, 8);
  const col = (name) => collection(db, `${name}_${run}`);
  const results = [];

  async function check(name, fn) {
    const started = performance.now();
    try {
      const detail = await fn();
      results.push({ name, ok: true, detail: detail ?? '', ms: Math.round(performance.now() - started) });
    } catch (e) {
      results.push({ name, ok: false, detail: String(e && e.message || e), ms: Math.round(performance.now() - started) });
    }
  }

  await check('setDoc + getDoc', async () => {
    const ref = doc(col('docs'), 'a');
    await setDoc(ref, { n: 1, s: 'héllo ✓', tags: ['x'], nested: { k: 1 } });
    const snap = await getDoc(ref);
    assert(snap.exists() && snap.data().n === 1 && snap.data().s === 'héllo ✓', JSON.stringify(snap.data()));
  });

  await check('updateDoc transforms', async () => {
    const ref = doc(col('docs'), 'a');
    await updateDoc(ref, { n: increment(2), tags: arrayUnion('y'), ts: serverTimestamp(), s: deleteField(), 'nested.j': 2 });
    const d = (await getDoc(ref)).data();
    assert(d.n === 3 && d.tags.join() === 'x,y' && !('s' in d) && d.ts && d.nested.j === 2, JSON.stringify(d));
  });

  await check('addDoc + query getDocs', async () => {
    const c = col('items');
    for (const n of [3, 1, 2]) await addDoc(c, { n, kind: n % 2 ? 'odd' : 'even' });
    const snap = await getDocs(query(c, where('kind', '==', 'odd'), orderBy('n'), limit(5)));
    const ns = snap.docs.map((d) => d.data().n);
    assert(ns.join() === '1,3', `got ${ns}`);
  });

  await check('onSnapshot query: added, modified, removed', async () => {
    const c = col('live');
    await setDoc(doc(c, 'a'), { n: 1 });
    const w = watch(query(c, where('n', '>', 0), orderBy('n')));
    try {
      assert(ids(await w.next()).join() === 'a', 'initial');
      await setDoc(doc(c, 'b'), { n: 2 });
      let s = await w.next();
      assert(ids(s).join() === 'a,b' && s.docChanges().some((ch) => ch.type === 'added' && ch.doc.id === 'b'), `added: ${ids(s)}`);
      await updateDoc(doc(c, 'a'), { n: 5 });
      s = await w.next();
      assert(ids(s).join() === 'b,a' && s.docChanges().some((ch) => ch.type === 'modified'), `modified: ${ids(s)}`);
      await updateDoc(doc(c, 'b'), { n: -1 });
      s = await w.next();
      assert(ids(s).join() === 'a' && s.docChanges().some((ch) => ch.type === 'removed' && ch.doc.id === 'b'), `left query: ${ids(s)}`);
      await deleteDoc(doc(c, 'a'));
      s = await w.next();
      assert(s.empty, `deleted: ${ids(s)}`);
    } finally {
      w.stop();
    }
  });

  await check('onSnapshot document, written by another client', async () => {
    // A second, independent client does the writes, so every update the
    // listener sees must come from the server's push, not local latency
    // compensation.
    const otherApp = initializeApp({ projectId: project, apiKey: 'test-api-key' }, `writer-${Math.random()}`);
    const other = initializeFirestore(otherApp, forceLongPolling ? { experimentalForceLongPolling: true } : {});
    connectFirestoreEmulator(other, host, port);
    const path = `profiles_${run}/p1`;
    const w = watch(doc(db, path));
    try {
      assert(!(await w.next()).exists(), 'initially missing');
      await setDoc(doc(other, path), { name: 'Ada' });
      let s = await w.next();
      assert(s.exists() && s.data().name === 'Ada', 'created');
      await updateDoc(doc(other, path), { name: 'Grace' });
      s = await w.next();
      assert(s.data().name === 'Grace', 'updated');
      await deleteDoc(doc(other, path));
      s = await w.next();
      assert(!s.exists(), 'deleted');
    } finally {
      w.stop();
    }
  });

  await check('runTransaction (REST)', async () => {
    const ref = doc(col('counters'), 'c');
    await setDoc(ref, { v: 0 });
    await Promise.all([1, 2, 3].map(() => runTransaction(db, async (tx) => {
      const s = await tx.get(ref);
      tx.update(ref, { v: s.data().v + 1 });
    })));
    const v = (await getDoc(ref)).data().v;
    assert(v === 3, `v=${v}`);
  });

  await check('writeBatch', async () => {
    const c = col('batch');
    const b = writeBatch(db);
    b.set(doc(c, 'x'), { v: 1 });
    b.set(doc(c, 'y'), { v: 2 });
    await b.commit();
    const snap = await getDocs(c);
    assert(snap.size === 2, `size=${snap.size}`);
  });

  await check('getCountFromServer (REST)', async () => {
    const c = col('items');
    const n = (await getCountFromServer(query(c, where('kind', '==', 'odd')))).data().count;
    assert(n === 2, `count=${n}`);
  });

  await check('deleteDoc', async () => {
    const ref = doc(col('docs'), 'a');
    await deleteDoc(ref);
    assert(!(await getDoc(ref)).exists(), 'still exists');
  });

  return results;
}

window.runSuite = runSuite;
window.__nextSnapshot = nextSnapshot;
