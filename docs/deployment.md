# Deployment

This guide covers local and production-oriented deployment of teabay.

## Prerequisites

- Rust 1.88 or newer.
- PostgreSQL 14 or newer.
- `diesel_cli` with Postgres support for manual database setup.
- The sibling `contrix-rust-sdk` checkout at `../contrix-rust-sdk`, because the
  workspace depends on the SDK by local path.
- Dioxus CLI 0.7.9 or newer when running the admin SPA.

Install the Diesel CLI:

```bash
cargo install diesel_cli --no-default-features --features postgres
```

## Local Development

The quickest local path is:

```bash
scripts/dev-up.sh
```

Manual setup:

```bash
createdb teabay
cp .env.example .env
# Edit .env for DATABASE_URL and TEABAY_SERVICE_DID.
diesel setup
cargo run -p server
```

The service listens on `TEABAY_BIND` and exposes:

- `GET /health`
- `GET /readyz`
- `GET /api/v1/directory/describe`
- `POST /api/v1/directory/{announce,withdraw,subscribe}`
- `POST /api/v1/directory/{search-realms,resolve-realm,...}`
- `GET /.well-known/contrix/openapi.json`
- `GET /.well-known/contrix/openapi.yaml`

Prometheus metrics listen separately on `TEABAY_METRICS_BIND`, default
`127.0.0.1:9095`, at `GET /metrics`.

## Container Build

The Dockerfile expects the local SDK as a named build context:

```bash
docker build --build-context contrix-rust-sdk=../contrix-rust-sdk -t teabay .
```

Do not push images or create tags from local development slices unless the
release owner explicitly asks for that release action.

Local vulnerability scanning uses Trivy against the local image ref:

```bash
scripts/trivy-scan.sh
```

Local SBOM/cosign artifacts are generated without pushing images or tags:

```bash
TEABAY_BUILD_IMAGE=1 scripts/local-artifacts.sh
COSIGN_KEY=cosign.key scripts/local-artifacts.sh
```

The SBOM command writes SPDX JSON files and optional cosign bundles under
`artifacts/`.

## Required Configuration

Set these for every deployment:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection string. |
| `TEABAY_SERVICE_DID` | Directory service DID advertised to resources. |
| `TEABAY_PUBLIC_BASE_URL` | Public URL used in service metadata. |
| `TEABAY_TRUST_DOMAIN` | Typed trust domain advertised by describe. |
| `TEABAY_METRICS_BIND` | Separate Prometheus listener; default `127.0.0.1:9095`. |

`TEABAY_TRUST_DOMAIN` has a local-test fallback in code, but production
deployments should set it explicitly.

## Security Configuration

Recommended production settings:

| Variable | Production guidance |
| --- | --- |
| `TEABAY_DEVELOPMENT_MODE` | `false` or unset. |
| `TEABAY_REQUIRE_HTTP_SIG` | `true` for ingest endpoints. |
| `TEABAY_HTTP_SIG_PUBKEYS` | Comma-separated `keyid=BASE64URL32` Ed25519 keys. |
| `TEABAY_ADMIN_TOKEN` | Non-empty bearer token for `/api/admin/v1/*`. |
| `TEABAY_CORS_ALLOW_ORIGIN` | Exact browser origin, never `*` in production. |
| `TEABAY_ACCEPT_POLICY_KIND` | `open`, `allowlist`, `trust_root_signed`, or `operator_review`. |
| `TEABAY_ALLOWLIST_DIDS` | Resource DID list when accept policy is `allowlist`. |
| `TEABAY_ACCEPT_POLICY_REF` | Optional application or policy reference. |
| `TEABAY_TAKEDOWN_CONTACT` | Optional appeal or operator contact. |

### HTTP Signature Keys

`TEABAY_HTTP_SIG_PUBKEYS` is the boot-time key directory for ingest HTTP
Message Signatures. Each entry is:

```text
keyid=BASE64URL_OF_RAW_32_BYTE_ED25519_VERIFY_KEY
```

Multiple entries are separated by commas:

```text
TEABAY_HTTP_SIG_PUBKEYS=did:web:a.example#ingest-1=BASE64URL32,did:web:b.example#ingest-1=BASE64URL32
```

The request signature `keyid` must match the configured key id exactly. With
`TEABAY_REQUIRE_HTTP_SIG=true`, an unsigned request, unknown key id, malformed
key, or invalid signature is rejected before the announce, withdraw, or
subscribe handler runs.

Provisioning flow:

1. Generate or select the Principal Server's Ed25519 signing key outside the
   teabay repository.
2. Export the matching raw 32-byte verifying key.
3. Base64url-encode it without padding.
4. Add `keyid=encoded_key` to `TEABAY_HTTP_SIG_PUBKEYS`.
5. Restart teabay.
6. Confirm the Principal Server signs ingest requests with the same `keyid`.

### 1.0 Secret Backend Decision

Store secrets outside source control. For 1.0, teabay intentionally supports
environment-variable secret injection only. A Vault, AWS Secrets Manager, or
other runtime secret-provider adapter is out of scope for 1.0 and should be
handled by the deployment platform before process start.

### Admin Token Enforcement

The admin API requires `Authorization: Bearer $TEABAY_ADMIN_TOKEN` for
`/api/admin/v1/*`. The route guard fails closed: if `TEABAY_ADMIN_TOKEN` is
unset or empty, admin requests return `unauthenticated` instead of becoming
anonymous. `/health.hardening.admin_auth_mode` reports `production` only when
development mode is disabled and a non-empty admin token is configured; without
that token it reports `closed`.

## Freshness Configuration

| Variable | Default | Purpose |
| --- | ---: | --- |
| `TEABAY_DEFAULT_TTL_SECONDS` | `86400` | TTL used when announces omit `ttl_seconds`. |
| `TEABAY_MAX_TTL_SECONDS` | `604800` | Operator cap for accepted announce TTLs. |
| `TEABAY_REVALIDATION_GRACE_SECONDS` | `3600` | Grace window before stale rows are marked stale. |
| `TEABAY_AS_OF_SKEW_SECONDS` | `300` | Maximum accepted clock skew for announce `as_of`. |
| `TEABAY_PULL_INTERVAL_SECONDS` | `300` | Pull worker period; `0` disables pull mode. |
| `TEABAY_DIVERGENCE_INTERVAL_SECONDS` | `0` | Divergence worker period; `0` disables it. |

The hard maximum TTL accepted by the server is 30 days.

## Query Privacy Configuration

| Variable | Default | Purpose |
| --- | ---: | --- |
| `TEABAY_QUERY_LATENCY_FLOOR_MS` | `25` | Minimum visible query latency. |
| `TEABAY_QUERY_LATENCY_JITTER_MS` | `10` | Deterministic per-route jitter window. |
| `TEABAY_RATE_LIMIT_PER_RESOURCE_PER_MIN` | `60` | Per-resource query budget. |
| `TEABAY_PRIVATE_CONTACT_DISCOVERY_ENABLED` | `true` | Enables PSI contact discovery endpoint. |
| `TEABAY_MAX_PSI_QUERIES_PER_EPOCH` | `60` | Per-epoch PSI query budget. |
| `TEABAY_PSI_EPOCH_SECONDS` | `604800` | PSI epoch length. |
| `TEABAY_PSI_KEY_RETENTION_SECONDS` | `7776000` | PSI key retention, capped at 90 days. |

## Reverse Proxy

Run teabay behind a TLS-terminating proxy in production. Configure:

- HTTPS and HSTS at the proxy.
- A strict CSP for browser clients that load the admin console.
- Request size limits suitable for discovery state envelopes.
- Access logs with token and signature header redaction.
