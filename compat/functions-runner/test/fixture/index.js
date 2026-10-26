// Each trigger kind the functions runner serves, written as any Firebase
// Functions codebase would be; run.mjs checks their effects through Kor.
const { onDocumentCreated, onDocumentDeleted, onDocumentUpdated, onDocumentWritten } = require('firebase-functions/v2/firestore');
const { HttpsError, onCall } = require('firebase-functions/v2/https');
const functionsV1 = require('firebase-functions/v1');
const { initializeApp } = require('firebase-admin/app');
const { FieldValue, getFirestore } = require('firebase-admin/firestore');

initializeApp();
const db = () => getFirestore();

exports.onOrderCreated = onDocumentCreated('orders/{orderId}', async (event) => {
  const order = event.data.data();
  await db().doc(`receipts/${event.params.orderId}`).set({
    total: order.qty * order.price,
    greeting: process.env.FIXTURE_GREETING || null,
    document: event.document,
  });
});

exports.onOrderUpdated = onDocumentUpdated('orders/{orderId}', async (event) => {
  const before = event.data.before.data();
  const after = event.data.after.data();
  if (before.qty === after.qty) return;
  await db().doc(`audits/${event.params.orderId}`).set({ from: before.qty, to: after.qty });
});

exports.onOrderDeleted = onDocumentDeleted('orders/{orderId}', async (event) => {
  await db().doc(`tombstones/${event.params.orderId}`).set({ qty: event.data.data().qty });
});

exports.onRoomMessage = onDocumentWritten('rooms/{roomId}/messages/{messageId}', async (event) => {
  if (!event.data.after.exists) return;
  await db().doc(`rooms/${event.params.roomId}`).set(
    { lastMessage: event.params.messageId, count: FieldValue.increment(1) }, { merge: true });
});

// A stray promise, as real codebases have (a fetch nobody awaits); the
// runner must keep serving the other functions.
exports.onExplode = onDocumentCreated('explode/{id}', () => {
  Promise.reject(new Error('stray rejection from onExplode'));
});

exports.onUserCreated = functionsV1.auth.user().onCreate(async (user) => {
  await db().doc(`profiles/${user.uid}`).set({ email: user.email || null });
});

exports.whoami = onCall((request) => {
  if (!request.auth) throw new HttpsError('unauthenticated', 'sign in first');
  return { uid: request.auth.uid, email: request.auth.token.email, greeting: process.env.FIXTURE_GREETING };
});
