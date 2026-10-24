#!/usr/bin/env bash
# Stands in for `firebase emulators:start` (Firestore, Auth, Functions) with
# Kor: kord serves Firestore on 5002 and the Auth emulator port 9099 with
# your security rules, and the functions runner serves your functions
# codebase on 5001 from Kor's change events. The ports are the ones apps
# commonly configure for the emulators.
#
# Usage: compat/emulators.sh <functions-dir> <rules-file>
#   functions-dir   a Firebase Functions codebase; built with `npm run build`
#                   when it has no build output yet
#   rules-file      a firestore.rules file
# Settings: PROJECT (default demo-project), KOR_PG_DSN (default: a Postgres
# container, kor-emulators-pg, whose data persists in the kor-emulators-data
# volume), STATE_DIR (default ~/.kor-emulators: signing key, functions
# cursor, logs).
# Ctrl-C stops everything this script started.
#
# Development only: unsigned tokens are accepted and issued, as the Firebase
# emulators do.
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 <functions-dir> <rules-file>" >&2
  exit 2
fi
repo="$(cd "$(dirname "$0")/.." && pwd)"
functions_dir="$(cd "$1" && pwd)"
rules="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
project="${PROJECT:-demo-project}"
state="${STATE_DIR:-$HOME/.kor-emulators}"
mkdir -p "$state"

pids=()
cleanup() { for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; }
trap cleanup EXIT INT TERM

dsn="${KOR_PG_DSN:-}"
if [ -z "$dsn" ]; then
  if ! docker inspect kor-emulators-pg >/dev/null 2>&1; then
    docker run -d --name kor-emulators-pg -e POSTGRES_USER=kor -e POSTGRES_PASSWORD=kor -e POSTGRES_DB=kor \
      -v kor-emulators-data:/var/lib/postgresql/data -p 127.0.0.1:55433:5432 postgres:16-alpine >/dev/null
  else
    docker start kor-emulators-pg >/dev/null
  fi
  for _ in $(seq 1 60); do docker exec kor-emulators-pg pg_isready -U kor -d kor -q 2>/dev/null && break; sleep 0.5; done
  dsn="postgres://kor:kor@127.0.0.1:55433/kor?sslmode=disable"
fi

echo "building kord"
go -C "$repo" build -o "$state/kord" ./cmd/kord
"$state/kord" -pg-dsn "$dsn" -listen 127.0.0.1:5002 -extra-listen "[::1]:5002,127.0.0.1:9099,[::1]:9099" \
  -metrics "" -emulator -auth -allow-unsigned-tokens -admin-tokens owner -rules "$rules" \
  -identity-project "$project" -identity-key "$state/identity.pem" \
  -identity-trust-unsigned-custom-tokens -identity-emulator-tokens >"$state/kord.log" 2>&1 &
pids+=($!)
for _ in $(seq 1 60); do curl -s -o /dev/null http://127.0.0.1:5002/ && break; sleep 0.5; done
curl -s -o /dev/null http://127.0.0.1:5002/ || { echo "kord did not start; see $state/kord.log"; exit 1; }
echo "Firestore and Auth on 127.0.0.1:5002 and :9099 (log: $state/kord.log)"

if [ ! -d "$functions_dir/node_modules" ]; then (cd "$functions_dir" && npm ci); fi
main="$(node -p "require('$functions_dir/package.json').main || 'index.js'")"
if [ ! -f "$functions_dir/$main" ]; then (cd "$functions_dir" && npm run build); fi
(cd "$functions_dir" && PROJECT="$project" FUNCTIONS_DIR=. KOR_URL=http://127.0.0.1:5002 PORT=5001 \
  CURSOR_FILE="$state/functions.cursor" node "$repo/compat/functions-runner/runner.js") 2>&1 | tee "$state/functions.log" &
pids+=($!)
wait
