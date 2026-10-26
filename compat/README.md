# Firebase compatibility

This fork extends Kor so that applications built on Firebase run against it
unchanged: web apps with the Firebase JS SDK, backends with the Admin
SDKs and Google's Firestore clients, and Cloud Functions code. Data lives in
PostgreSQL or Azure Cosmos DB.

| Firebase piece | Served by |
|---|---|
| Firestore (gRPC, REST, the web SDK's WebChannel, live listeners) | `kord`, one port for every SDK |
| Firestore security rules | `kord -rules` (rules v2 evaluator) |
| Firebase Auth: client sign-in, token refresh, password reset | `kord -identity-project` (sign-in bridge) |
| Firebase Auth: Admin SDK user management | the same bridge, for admin callers |
| Microsoft Entra ID / any OIDC provider | `POST /kor/v1/auth:exchange` → custom token |
| Cloud Functions: Firestore and Auth triggers, callable and HTTP functions | `compat/functions-runner/runner.js` |
| Cloud Storage | not served; Storage triggers are not wired |

## Run an app locally on Kor

`compat/emulators.sh` stands in for `firebase emulators:start`. It starts
PostgreSQL (a container), `kord` on 5002 (Firestore) and 9099 (Auth) with
your rules, and the functions runner on 5001 with your functions:

```bash
compat/emulators.sh path/to/functions path/to/firestore.rules
```

Point the app at the emulators as usual (`connectFirestoreEmulator`,
`connectAuthEmulator`, `FIRESTORE_EMULATOR_HOST`,
`FIREBASE_AUTH_EMULATOR_HOST`).

## End-to-end tests

```bash
compat/e2e/run.sh                 # every suite
compat/e2e/run.sh browser admin   # some suites
```

| Suite | What it proves |
|---|---|
| `go` | Kor's whole Go module on PostgreSQL (in Docker), and the e2e package on Cosmos DB |
| `probe` | the Firestore operations backends commonly use, through `google-cloud-firestore` for Python (24 checks) |
| `browser` | the Firestore web SDK over streaming and long-polling WebChannel; the Firebase Auth web SDK against the bridge with rules enforced, including Entra sign-in through a mock provider; with signed and with emulator-style tokens |
| `admin` | the Firebase Admin SDKs for Node and Python against the bridge: user management, custom claims, disable and revoke checks, custom tokens |
| `functions` | the runner on a fixture codebase: created/updated/deleted/written triggers, the v1 Auth trigger, a callable with the caller's auth, `.env`, surviving a stray rejection |
| `hook` | your application's own suites, from `KOR_E2E_HOOK` (see the top of `run.sh`) |

All but `go` run once per backend: PostgreSQL always, and Cosmos DB when its
emulator is up (`COSMOS=start` starts it). Logs land in `compat/e2e/out/`.

The Cosmos DB emulator, if you start it yourself:

```bash
docker run -d --name kor-cosmos -e PROTOCOL=http -p 127.0.0.1:18081:8081 \
  mcr.microsoft.com/cosmosdb/linux/azure-cosmos-emulator:vnext-preview
```

## Development-only switches

Everything `emulators.sh` and the tests turn on to match the Firebase
emulators must stay off in a deployment:

- `-allow-unsigned-tokens` accepts `alg: none` tokens, so anyone can claim any
  identity.
- `-identity-emulator-tokens` makes the bridge issue unsigned ID tokens. The
  Node Admin SDK pointed at an emulator accepts nothing else.
- `-identity-trust-unsigned-custom-tokens` accepts custom tokens without a
  signature.
- `-emulator` serves the endpoints that load rules and wipe a database.

In a deployment, backends verify the bridge's signed ID tokens against its
JWKS (`/kor/v1/jwks`) rather than through an Admin SDK in emulator mode,
which skips signature checks.
