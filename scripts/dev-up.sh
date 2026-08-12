#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export DATABASE_URL="${DATABASE_URL:-postgres://teabay:teabay@localhost:5432/teabay}"
export TEABAY_BIND="${TEABAY_BIND:-127.0.0.1:7781}"
export TEABAY_PUBLIC_BASE_URL="${TEABAY_PUBLIC_BASE_URL:-http://localhost:7781}"
: "${TEABAY_SERVICE_FULL_ID:?set TEABAY_SERVICE_FULL_ID to the verified current full DID}"
: "${TEABAY_SERVICE_METHOD_HISTORY_HEAD:?set the verified current method-history head}"
: "${TEABAY_SERVICE_VERSION_ID:?set the verified current method version id}"
export TEABAY_SERVICE_FULL_ID TEABAY_SERVICE_METHOD_HISTORY_HEAD TEABAY_SERVICE_VERSION_ID
export TEABAY_ACCEPT_POLICY_KIND="${TEABAY_ACCEPT_POLICY_KIND:-open}"

docker compose up -d postgres

echo "Waiting for PostgreSQL..."
until docker compose exec -T postgres pg_isready -U teabay -d teabay >/dev/null 2>&1; do
  sleep 1
done

echo "Starting teabay on ${TEABAY_BIND}"
exec cargo run -p server
