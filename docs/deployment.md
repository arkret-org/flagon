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
- `GET /api/v1/directory/describe`
- `POST /api/v1/directory/{announce,withdraw,subscribe}`
- `POST /api/v1/directory/{search-realms,resolve-realm,...}`
- `GET /.well-known/contrix/openapi.json`
- `GET /.well-known/contrix/openapi.yaml`

## Container Build

The Dockerfile expects the local SDK as a named build context:

```bash
docker build --build-context contrix-rust-sdk=../contrix-rust-sdk -t teabay .
```

Do not push images or create tags from local development slices unless the
release owner explicitly asks for that release action.

## Required Configuration

Set these for every deployment:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection string. |
| `TEABAY_SERVICE_DID` | Directory service DID advertised to resources. |
| `TEABAY_PUBLIC_BASE_URL` | Public URL used in service metadata. |
| `TEABAY_TRUST_DOMAIN` | Typed trust domain advertised by describe. |

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

Store secrets outside source control. teabay currently reads secrets from
environment variables; a vault adapter is not implemented.

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
