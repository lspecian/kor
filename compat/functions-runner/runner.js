// Runs an unmodified Firebase Functions codebase against Kor, replacing the
// Cloud Functions runtime and the Functions emulator:
//
//   - Firestore document triggers (v2: created/updated/deleted/written,
//     optionally withAuthContext) fire from Kor's change events, with the
//     same CloudEvent shape the runtime delivers (JSON encoding).
//   - The v1 Auth onCreate trigger fires when Kor's sign-in bridge creates a
//     user.
//   - Callable and HTTP functions are served at /{project}/{region}/{name},
//     the Functions emulator's URL scheme, so connectFunctionsEmulator works.
//
// Storage triggers are not wired (no object-change events yet); they are
// listed at start-up as skipped.
//
// Environment: FUNCTIONS_DIR (the functions package, built), PROJECT,
// KOR_URL (default http://127.0.0.1:5002), KOR_ADMIN_TOKEN (default owner),
// PORT (default 5001), CURSOR_FILE (optional, to resume after a restart).
// The codebase's own .env files load as the Firebase CLI loads them.
// Tests: test/run.mjs runs a fixture codebase through every trigger kind.
'use strict';

const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const FUNCTIONS_DIR = path.resolve(process.env.FUNCTIONS_DIR || '');
const PROJECT = process.env.PROJECT;
const KOR_URL = (process.env.KOR_URL || 'http://127.0.0.1:5002').replace(/\/$/, '');
const ADMIN_TOKEN = process.env.KOR_ADMIN_TOKEN || 'owner';
const PORT = Number(process.env.PORT || 5001);
const CURSOR_FILE = process.env.CURSOR_FILE || '';
const POLL_MS = Number(process.env.POLL_MS || 250);
const AUTH_USERS = '__kor_auth_users';
const DOC_PREFIX = `projects/${PROJECT}/databases/(default)/documents/`;

if (!PROJECT || !fs.existsSync(path.join(FUNCTIONS_DIR, 'package.json'))) {
  console.error('set PROJECT and FUNCTIONS_DIR (a built Firebase Functions package)');
  process.exit(2);
}

// The functions' own configuration, as the Firebase CLI loads it: .env, then
// .env.<project>, then .env.local (emulator only); later files win, and
// variables already set in the runner's environment win over all of them.
function parseDotenv(text) {
  const out = {};
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!m) continue;
    let v = m[2];
    if (/^(['"]).*\1$/.test(v)) v = v.slice(1, -1).replace(/\\n/g, '\n');
    else v = v.replace(/\s+#.*$/, '');
    out[m[1]] = v;
  }
  return out;
}
const dotenv = {};
for (const file of ['.env', `.env.${PROJECT}`, '.env.local']) {
  const p = path.join(FUNCTIONS_DIR, file);
  if (fs.existsSync(p)) Object.assign(dotenv, parseDotenv(fs.readFileSync(p, 'utf8')));
}
for (const [k, v] of Object.entries(dotenv)) if (process.env[k] === undefined) process.env[k] = v;

// A function's stray promise must not take the other functions down; the
// emulator's worker logs these too.
process.on('unhandledRejection', (e) => console.error(`  unhandled rejection in a function: ${e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : e}`));
process.on('uncaughtException', (e) => console.error(`  uncaught exception in a function: ${e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : e}`));

// The environment the Cloud Functions runtime (or emulator) provides.
const korHost = new URL(KOR_URL).host;
const env = process.env;
env.GCLOUD_PROJECT ||= PROJECT;
env.GCP_PROJECT_ID ||= PROJECT;
env.FIREBASE_CONFIG ||= JSON.stringify({ projectId: PROJECT, storageBucket: `${PROJECT}.appspot.com` });
env.FIRESTORE_EMULATOR_HOST ||= korHost;
env.FIREBASE_AUTH_EMULATOR_HOST ||= korHost;
env.FUNCTIONS_EMULATOR ||= 'true';

process.chdir(FUNCTIONS_DIR);
const pkg = JSON.parse(fs.readFileSync(path.join(FUNCTIONS_DIR, 'package.json'), 'utf8'));
const fromFunctions = (m) => require(require.resolve(m, { paths: [FUNCTIONS_DIR] }));
const functions = require(path.join(FUNCTIONS_DIR, pkg.main || 'index.js'));

const docTriggers = [];
const authCreate = [];
const httpFunctions = new Map();
const skipped = [];
for (const [name, fn] of Object.entries(functions)) {
  const ep = fn && fn.__endpoint;
  if (!ep) continue;
  const trig = ep.eventTrigger;
  if (ep.callableTrigger || ep.httpsTrigger) {
    httpFunctions.set(name, fn);
  } else if (trig && trig.eventType.startsWith('google.cloud.firestore.document.v1.')) {
    const pattern = (trig.eventFilterPathPatterns && trig.eventFilterPathPatterns.document)
      || (trig.eventFilters && trig.eventFilters.document);
    const [, , , , , kind, auth] = trig.eventType.split('.');
    docTriggers.push({ name, fn, type: trig.eventType, kind, withAuth: auth === 'withAuthContext', pattern });
  } else if (trig && trig.eventType === 'providers/firebase.auth/eventTypes/user.create') {
    authCreate.push({ name, fn });
  } else {
    skipped.push(`${name} (${trig ? trig.eventType : 'unknown trigger'})`);
  }
}
console.log(`functions runner: ${docTriggers.length} document triggers, ${authCreate.length} auth triggers, ${httpFunctions.size} HTTP/callable functions`);
if (skipped.length) console.log(`  not wired: ${skipped.join(', ')}`);

function matches(pattern, rel) {
  if (!pattern) return false;
  const ps = pattern.split('/');
  const ds = rel.split('/');
  for (let i = 0; i < ps.length; i++) {
    if (/^\{[^}]+=\*\*\}$/.test(ps[i])) return true;
    if (i >= ds.length) return false;
    if (/^\{[^}]+\}$/.test(ps[i])) continue;
    if (ps[i] !== ds[i]) return false;
  }
  return ps.length === ds.length;
}

function kindOf(ev) {
  if (!ev.before && ev.after) return 'created';
  if (ev.before && !ev.after) return 'deleted';
  return 'updated';
}

function cloudEvent(t, ev, rel) {
  const raw = {
    specversion: '1.0',
    id: ev.id,
    // The JSON decoder resolves non-existent snapshots from `source`, so it
    // carries the document's resource name.
    source: `${DOC_PREFIX}${rel}`,
    type: t.type,
    time: ev.commitTime,
    subject: `documents/${rel}`,
    datacontenttype: 'application/json; charset=utf-8',
    project: PROJECT,
    database: '(default)',
    namespace: '(default)',
    document: rel,
    location: 'us-central1',
    data: { value: ev.after || undefined, oldValue: ev.before || undefined },
  };
  if (t.withAuth) {
    raw.authtype = 'unknown';
    raw.authid = '';
  }
  return raw;
}

async function invoke(label, call) {
  const started = Date.now();
  try {
    await call();
    console.log(`  ${label} ok (${Date.now() - started} ms)`);
  } catch (e) {
    console.error(`  ${label} failed: ${e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : e}`);
  }
}

async function dispatch(ev) {
  if (!ev.document.startsWith(DOC_PREFIX)) return;
  const rel = ev.document.slice(DOC_PREFIX.length);
  const kind = kindOf(ev);
  const work = [];
  for (const t of docTriggers) {
    if ((t.kind === 'written' || t.kind === kind) && matches(t.pattern, rel)) {
      work.push(invoke(`${t.name} ${rel}`, () => t.fn(cloudEvent(t, ev, rel))));
    }
  }
  if (kind === 'created' && rel.startsWith(`${AUTH_USERS}/`) && rel.split('/').length === 2) {
    const f = ev.after.fields || {};
    const created = new Date(ev.commitTime).toUTCString();
    const user = {
      uid: rel.split('/')[1],
      email: f.email && f.email.stringValue,
      displayName: (f.displayName && f.displayName.stringValue) || undefined,
      emailVerified: false,
      disabled: false,
      metadata: { creationTime: created, lastSignInTime: created },
      providerData: [],
    };
    for (const t of authCreate) {
      const context = {
        eventId: ev.id, timestamp: ev.commitTime, eventType: 'providers/firebase.auth/eventTypes/user.create',
        resource: { service: 'firebaseauth.googleapis.com', name: `projects/${PROJECT}` }, params: {},
      };
      work.push(invoke(`${t.name} ${user.uid}`, () => t.fn(user, context)));
    }
  }
  await Promise.all(work);
}

async function readEvents(cursor) {
  const url = `${KOR_URL}/kor/v1/events?limit=200&cursor=${encodeURIComponent(cursor)}`;
  const res = await fetch(url, { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } });
  if (!res.ok) throw new Error(`events: HTTP ${res.status} ${await res.text()}`);
  return res.json();
}

// startCursor resumes from CURSOR_FILE, or starts at the head of the log:
// like a deployment, the runner handles changes made after it starts.
async function startCursor() {
  if (CURSOR_FILE && fs.existsSync(CURSOR_FILE)) {
    const saved = fs.readFileSync(CURSOR_FILE, 'utf8').trim();
    if (saved) return saved;
  }
  for (;;) {
    try {
      return (await readEvents('')).cursor;
    } catch (e) {
      console.error(`waiting for Kor: ${e.message}`);
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
}

async function pump(cursor) {
  const seen = new Map(); // event id -> time first seen (de-duplicates replays)
  for (;;) {
    try {
      const { events, cursor: next } = await readEvents(cursor);
      const fresh = events.filter((e) => !seen.has(e.id));
      const now = Date.now();
      for (const e of fresh) seen.set(e.id, now);
      for (const [id, t] of seen) if (now - t > 10 * 60 * 1000) seen.delete(id);
      // Different documents run in parallel; one document's events run in order.
      const byDoc = new Map();
      for (const e of fresh) {
        if (!byDoc.has(e.document)) byDoc.set(e.document, []);
        byDoc.get(e.document).push(e);
      }
      await Promise.all([...byDoc.values()].map(async (list) => {
        for (const e of list) await dispatch(e);
      }));
      cursor = next;
      if (CURSOR_FILE) fs.writeFileSync(CURSOR_FILE, cursor);
      if (events.length === 0 || fresh.length === 0) await new Promise((r) => setTimeout(r, POLL_MS));
    } catch (e) {
      console.error(`event pump: ${e.message}`);
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
}

// Callable and HTTP functions, at the Functions emulator's URLs.
const express = fromFunctions('express');
const app = express();
app.use(express.json({ limit: '10mb', verify: (req, _res, buf) => { req.rawBody = buf; } }));
// Web apps may probe the root cross-origin to see whether the emulator is up;
// functions answer CORS themselves (onCall, or onRequest's cors option).
app.get('/', (_req, res) => res.set('Access-Control-Allow-Origin', '*').send('ok'));
app.all('/:project/:region/:name', (req, res) => {
  const fn = httpFunctions.get(req.params.name);
  if (!fn) return res.status(404).json({ error: { status: 'NOT_FOUND', message: `no function ${req.params.name}` } });
  const started = Date.now();
  res.on('finish', () => console.log(`  ${req.params.name} HTTP ${res.statusCode} (${Date.now() - started} ms)`));
  return fn(req, res);
});
// Ready once the start position is fixed, so no change made after the ready
// line is missed.
startCursor().then((cursor) => {
  http.createServer(app).listen(PORT, '127.0.0.1', () => {
    console.log(`functions runner: HTTP functions on http://127.0.0.1:${PORT}, events from ${KOR_URL}`);
    pump(cursor);
  });
});
