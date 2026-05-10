#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export DATABASE_URL="${DATABASE_URL:-postgres://chadex:chadex@localhost:5432/chadex}"
export CHADEX_BIND="${CHADEX_BIND:-127.0.0.1:7781}"
export CHADEX_PUBLIC_BASE_URL="${CHADEX_PUBLIC_BASE_URL:-http://localhost:7781}"
export CHADEX_SERVICE_DID="${CHADEX_SERVICE_DID:-did:web:directory.localhost}"
export CHADEX_ACCEPT_POLICY_KIND="${CHADEX_ACCEPT_POLICY_KIND:-open}"

docker compose up -d postgres

echo "Waiting for PostgreSQL..."
until docker compose exec -T postgres pg_isready -U chadex -d chadex >/dev/null 2>&1; do
  sleep 1
done

echo "Starting chadex on ${CHADEX_BIND}"
exec cargo run
