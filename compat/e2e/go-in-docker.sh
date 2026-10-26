#!/usr/bin/env bash
# Runs Kor's Go tests inside a postgres:16 container, so pgtest finds initdb
# and pg_ctl (macOS hosts have neither). A missing cluster fails the run
# instead of skipping the database tests.
# Usage: go-in-docker.sh <kor-repo-dir> [go test args...]   (default ./...)
set -euo pipefail
repo="$(cd "$1" && pwd)"; shift
args="${*:-./...}"
go_version="$(sed -n 's/^go \([0-9.]*\).*/\1/p' "$repo/go.mod")"
docker run --rm -v "$repo":/src:ro -v kor-go-cache:/cache postgres:16 bash -c "
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null && apt-get install -y -qq curl ca-certificates >/dev/null 2>&1
  if [ ! -x /cache/go-$go_version/bin/go ]; then
    mkdir -p /cache/go-$go_version
    curl -fsSL https://go.dev/dl/go$go_version.linux-\$(dpkg --print-architecture).tar.gz | tar -C /cache/go-$go_version --strip-components=1 -xz
  fi
  chown -R postgres /cache
  cp -r /src /tmp/kor && rm -rf /tmp/kor/compat/browser/node_modules && chown -R postgres /tmp/kor
  su postgres -c 'cd /tmp/kor && KOR_REQUIRE_PG=1 PATH=/usr/lib/postgresql/16/bin:/cache/go-$go_version/bin:\$PATH GOCACHE=/cache/gocache GOMODCACHE=/cache/gomod GOFLAGS=-buildvcs=false go test -count=1 $args'
"
