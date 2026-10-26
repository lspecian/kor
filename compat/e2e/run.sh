#!/usr/bin/env bash
# Runs the end-to-end suites of this fork and prints a summary.
#
# Usage: compat/e2e/run.sh [suite ...]        (default: every suite)
#
# Suites
#   go         Kor's Go tests: the whole module on PostgreSQL (in Docker), and
#              the e2e package on Cosmos DB
#   probe      the Firestore operations backends commonly use, through
#              google-cloud-firestore for Python
#   browser    Firestore and Firebase Auth web SDKs in headless Chrome
#              (streaming and long-polling WebChannel, sign-in bridge, Entra
#              exchange through a mock OIDC provider, rules enforced)
#   admin      Firebase Admin SDKs for Node and Python against the bridge
#   functions  the functions runner: each trigger kind of a fixture codebase
#   hook       your application's own suites (KOR_E2E_HOOK, below)
#
# probe, browser, admin, functions and hook run once per backend, each
# against kord instances this script starts:
#   postgres   always; a throwaway postgres:16-alpine container unless
#              KOR_PG_DSN names a database
#   cosmos     when the Cosmos emulator answers at COSMOS_ENDPOINT (default
#              http://127.0.0.1:18081; COSMOS_KEY defaults to the emulator's
#              published key). COSMOS=start starts the emulator if needed;
#              COSMOS=off skips it.
#
# KOR_E2E_HOOK names an executable run once per backend, for an
# application's own suites (a security-rules suite, say). It gets
# KOR_BACKEND, KOR_HOST, KOR_PORT (kord with signed tokens and the
# -emulator endpoints, so it can load rules and clear data) and
# KOR_EMULATOR_PORT (kord issuing emulator-style tokens), and fails the run
# by exiting non-zero.
#
# Other settings: OUT_DIR (default compat/e2e/out), BASE_PORT (default
# 15200).
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="${OUT_DIR:-$here/out}"
base_port="${BASE_PORT:-15200}"
cosmos_endpoint="${COSMOS_ENDPOINT:-http://127.0.0.1:18081}"
# The Cosmos emulator's well-known key (published by Microsoft; not a secret).
cosmos_key="${COSMOS_KEY:-C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw==}"
idp_port="${KOR_IDP_PORT:-5199}"
hook="${KOR_E2E_HOOK:-}"
idp_issuer="https://login.microsoftonline.com/00000000-0000-0000-0000-000000000001/v2.0"
suites=("$@")
[ ${#suites[@]} -eq 0 ] && suites=(go probe browser admin functions hook)

mkdir -p "$out"
rm -f "$out"/*.log
summary=()
failed=0
pids=()
containers=()

cleanup() {
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  for c in "${containers[@]:-}"; do [ -n "$c" ] && docker rm -f "$c" >/dev/null 2>&1; done
}
trap cleanup EXIT

want() { local s; for s in "${suites[@]}"; do [ "$s" = "$1" ] && return 0; done; return 1; }
record() { # record <name> <PASS|FAIL|SKIP> [detail]
  summary+=("$(printf '%-4s  %-34s %s' "$2" "$1" "${3:-}")")
  [ "$2" = FAIL ] && failed=$((failed + 1))
  return 0
}
run_suite() { # run_suite <name> <command...>: logs to $out/<name>.log
  local name="$1"; shift
  local log="$out/${name//[^A-Za-z0-9_.-]/_}.log"
  echo "== $name"
  if "$@" >"$log" 2>&1; then
    record "$name" PASS
  else
    record "$name" FAIL "see $log"
    tail -20 "$log" | sed 's/^/   | /'
  fi
}
wait_http() { # wait_http <url> <seconds>
  local i
  for ((i = 0; i < $2 * 2; i++)); do curl -s -o /dev/null "$1" && return 0; sleep 0.5; done
  return 1
}

echo "building kord"
go -C "$repo" build -o "$out/kord" ./cmd/kord || { echo "build failed"; exit 1; }

needs_kord=0
for s in probe browser admin functions; do want "$s" && needs_kord=1; done
want hook && [ -n "$hook" ] && needs_kord=1

# Backends.
backends=()
pg_dsn="${KOR_PG_DSN:-}"
if [ $needs_kord = 1 ]; then
  if [ -z "$pg_dsn" ]; then
    name="kor-e2e-pg-$$"
    docker run -d --rm --name "$name" -e POSTGRES_USER=kor -e POSTGRES_PASSWORD=kor -e POSTGRES_DB=kor \
      -p 127.0.0.1::5432 postgres:16-alpine >/dev/null && containers+=("$name")
    for _ in $(seq 1 60); do docker exec "$name" pg_isready -U kor -d kor -q 2>/dev/null && break; sleep 0.5; done
    sleep 1
    pg_port="$(docker port "$name" 5432/tcp | head -1 | sed 's/.*://')"
    pg_dsn="postgres://kor:kor@127.0.0.1:$pg_port/kor?sslmode=disable"
  fi
  backends+=(postgres)
  if [ "${COSMOS:-}" != off ]; then
    if ! curl -s -o /dev/null "$cosmos_endpoint" && [ "${COSMOS:-}" = start ]; then
      echo "starting the Cosmos DB emulator"
      docker run -d --name kor-e2e-cosmos -e PROTOCOL=http -p "127.0.0.1:${cosmos_endpoint##*:}:8081" \
        mcr.microsoft.com/cosmosdb/linux/azure-cosmos-emulator:vnext-preview >/dev/null && containers+=(kor-e2e-cosmos)
      wait_http "$cosmos_endpoint" 180
    fi
    if curl -s -o /dev/null "$cosmos_endpoint"; then
      backends+=(cosmos)
    else
      record "cosmos backend" SKIP "no emulator at $cosmos_endpoint (COSMOS=start starts one)"
    fi
  fi
fi

# start_kord <backend> <port> <log> <flags...>
start_kord() {
  local backend="$1" port="$2" log="$3"; shift 3
  local args=(-listen "127.0.0.1:$port" -metrics "" -log warn -emulator -auth -allow-unsigned-tokens -admin-tokens owner)
  if [ "$backend" = postgres ]; then
    args+=(-pg-dsn "$pg_dsn")
  else
    args+=(-backend cosmos -cosmos-endpoint "$cosmos_endpoint" -cosmos-database kor-e2e -cosmos-create
      -customer-id "e2e-$$-$port")
  fi
  KORD_COSMOS_KEY="$cosmos_key" "$out/kord" "${args[@]}" "$@" >"$log" 2>&1 &
  pids+=($!)
  wait_http "http://127.0.0.1:$port/" 60 || { echo "kord ($backend) did not start; see $log"; return 1; }
}

# Go tests.
if want go; then
  run_suite "go: module on postgres" "$here/go-in-docker.sh" "$repo" ./...
  if curl -s -o /dev/null "$cosmos_endpoint" && [ "${COSMOS:-}" != off ]; then
    run_suite "go: e2e on cosmos" env KOR_E2E_BACKEND=cosmos KOR_E2E_COSMOS_ENDPOINT="$cosmos_endpoint" \
      KOR_E2E_COSMOS_KEY="$cosmos_key" go -C "$repo" test -count=1 -race ./e2e/
  else
    record "go: e2e on cosmos" SKIP "no emulator at $cosmos_endpoint"
  fi
fi

if [ $needs_kord = 1 ] && { want browser || want admin; }; then
  if [ ! -d "$repo/compat/browser/node_modules" ]; then
    (cd "$repo/compat/browser" && npm ci --silent) >"$out/npm.log" 2>&1
  fi
  (cd "$repo/compat/browser" && npm run --silent build) >>"$out/npm.log" 2>&1
fi

offset=0
for backend in "${backends[@]}"; do
  # kord A: production-like tokens (signed, trusted through the bridge's
  # issuer), Entra exchange against the browser runner's mock provider.
  # kord B: the Auth emulator's conventions the Admin SDKs require.
  port_a=$((base_port + offset)); port_b=$((base_port + offset + 1)); offset=$((offset + 10))
  start_kord "$backend" "$port_a" "$out/kord-$backend-a.log" \
    -identity-project kor-auth-test -identity-key "$out/identity-a.pem" \
    -oidc-issuer "$idp_issuer" -oidc-audience api://kor-test -oidc-jwks "http://127.0.0.1:$idp_port/jwks" || {
    record "kord on $backend" FAIL "see $out/kord-$backend-a.log"; continue; }
  if want admin || want functions || want browser || { want hook && [ -n "$hook" ]; }; then
    start_kord "$backend" "$port_b" "$out/kord-$backend-b.log" \
      -identity-project kor-emulator-test -identity-key "$out/identity-b.pem" \
      -identity-trust-unsigned-custom-tokens -identity-emulator-tokens \
      -oidc-issuer "$idp_issuer" -oidc-audience api://kor-test -oidc-jwks "http://127.0.0.1:$idp_port/jwks" || record "kord (emulator tokens) on $backend" FAIL
  fi

  if want probe; then
    run_suite "probe: Python client ($backend)" env FIRESTORE_EMULATOR_HOST="127.0.0.1:$port_a" \
      GOOGLE_CLOUD_PROJECT=kor-local uv run -q --no-project --with google-cloud-firestore \
      python "$here/firestore_probe.py" "$backend"
  fi
  if want browser; then
    run_suite "browser: web SDKs ($backend)" env KOR_HOST=127.0.0.1 KOR_PORT="$port_a" KOR_SUITES=sdk,auth \
      KOR_AUTH_PROJECT=kor-auth-test KOR_IDP_PORT="$idp_port" node "$repo/compat/browser/run.mjs"
    # A local Firebase setup: the bridge issues emulator-style tokens.
    run_suite "browser: Auth SDK, emulator tokens ($backend)" env KOR_HOST=127.0.0.1 KOR_PORT="$port_b" KOR_SUITES=auth \
      KOR_AUTH_PROJECT=kor-emulator-test KOR_IDP_PORT="$idp_port" node "$repo/compat/browser/run.mjs"
  fi
  if want admin; then
    run_suite "admin: Node Admin SDK ($backend)" env KOR_HOST=127.0.0.1 KOR_PORT="$port_b" PROJECT=kor-emulator-test \
      node "$here/admin-sdk.mjs"
    run_suite "admin: Python Admin SDK ($backend)" env FIREBASE_AUTH_EMULATOR_HOST="127.0.0.1:$port_b" \
      PROJECT=kor-emulator-test uv run -q --no-project --with 'firebase-admin>=7.5,<8' python "$here/admin_sdk.py" "$backend"
  fi
  if want functions; then
    run_suite "functions: runner triggers ($backend)" env KOR_URL="http://127.0.0.1:$port_b" PROJECT=kor-emulator-test \
      node "$repo/compat/functions-runner/test/run.mjs"
  fi
  if want hook && [ -n "$hook" ]; then
    run_suite "hook: $(basename "$hook") ($backend)" env KOR_BACKEND="$backend" KOR_HOST=127.0.0.1 \
      KOR_PORT="$port_a" KOR_EMULATOR_PORT="$port_b" "$hook"
  fi
done

echo
echo "Summary"
printf '%s\n' "${summary[@]}"
[ $failed -eq 0 ] && echo "all suites passed" || echo "$failed suite(s) failed"
exit $((failed > 0))
