#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export DATABASE_URL="${DATABASE_URL:-postgres://flagon:flagon@localhost:5432/flagon}"
export FLAGON_BIND="${FLAGON_BIND:-127.0.0.1:7781}"
export FLAGON_PUBLIC_BASE_URL="${FLAGON_PUBLIC_BASE_URL:-http://localhost:7781}"
: "${FLAGON_SERVICE_DID:?set FLAGON_SERVICE_DID to the verified current DID}"
: "${FLAGON_SERVICE_METHOD_HISTORY_HEAD:?set the verified current method-history head}"
: "${FLAGON_SERVICE_VERSION_ID:?set the verified current method version id}"
export FLAGON_SERVICE_DID FLAGON_SERVICE_METHOD_HISTORY_HEAD FLAGON_SERVICE_VERSION_ID

docker compose up -d postgres

echo "Waiting for PostgreSQL..."
until docker compose exec -T postgres pg_isready -U flagon -d flagon >/dev/null 2>&1; do
  sleep 1
done

echo "Starting flagon on ${FLAGON_BIND}"
exec cargo run -p server
