# Deployment

This guide covers local and production-oriented deployment of teabay.

## Prerequisites

- Rust 1.88 or newer.
- PostgreSQL 14 or newer.
- `diesel_cli` with Postgres support for manual database setup.
- The sibling `cokret-rust-sdk` checkout at `../cokret-rust-sdk`, because the
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
- `GET /_cokret/find/directory/describe`
- `POST /_cokret/find/directory/{announce,withdraw,push/register}`
- `POST /_cokret/find/directory/{search-realms,resolve-realm,...}`
- `GET /.well-known/cokret/openapi.json`
- `GET /.well-known/cokret/openapi.yaml`

Prometheus metrics listen separately on `TEABAY_METRICS_BIND`, default
`127.0.0.1:9095`, at `GET /metrics`.

## Container Build

The Dockerfile expects the local SDK as a named build context:

```bash
docker build --build-context cokret-rust-sdk=../cokret-rust-sdk -t teabay .
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
| `TEABAY_ADMIN_TOKEN` | Development-only bearer token for local `/_cokret/local/admin/*` access. Ignored when `TEABAY_DEVELOPMENT_MODE=false`; production uses rotating HMAC rows in `admin_tokens`. |
| `TEABAY_ADMIN_CSRF_TOKEN` | **Required in production.** Browser callers must echo this on every state-changing admin call via `X-CSRF-Token`. The server `bail!`s at startup if unset and `TEABAY_DEVELOPMENT_MODE=false`. The temporary rotation-only override requires both `TEABAY_ALLOW_MISSING_CSRF=1` and `TEABAY_ALLOW_MISSING_CSRF_UNTIL=<RFC3339 future timestamp>`; while active the server emits an error-level warning and fails closed after expiry. |
| `TEABAY_TRUSTED_PROXY` | Comma-separated list of IPs whose `X-Forwarded-For` the rate-limiter trusts. Unset = trust only the direct `remote_addr`. Set to your TLS-terminating reverse proxy's IPs to avoid spoofed buckets. |
| `TEABAY_RECEIPT_SIGNING_KEY_B64` | Raw 32-byte Ed25519 signing key for operator takedown receipts. |
| `TEABAY_RECEIPT_KEY_ID` | Verification method recorded in signed operator receipts. |
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

The admin API requires an `Authorization: Bearer ...` credential for
`/_cokret/local/admin/*`. In production (`TEABAY_DEVELOPMENT_MODE=false`), use
`Bearer hmac:<key_id>:<ts>:<mac_base64>` backed by an active `admin_tokens` row;
the legacy static `TEABAY_ADMIN_TOKEN` bearer is ignored. In development mode,
`TEABAY_ADMIN_TOKEN` remains available for local tooling. `/health.hardening.admin_auth_mode`
reports `rotating_hmac` on the production path.

### Takedown Receipt Signing

Resource-initiated withdrawals persist the resource governance detached JWS and
the signed withdraw payload in `withdrawals.proof`. Operator takedowns are
service-issued receipts and require `TEABAY_RECEIPT_SIGNING_KEY_B64` so the
stored `receipt_proof` is independently verifiable. See
[`docs/takedown-receipts.md`](takedown-receipts.md) for the JSON shape and
verification procedure.

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
| `TEABAY_MAX_PSI_QUERIES_PER_WINDOW` | `1` | Spec §6.4 anti-enumeration quota: max PSI batches per requester per quota window. Decoupled from the OPRF key epoch. |
| `TEABAY_PSI_QUOTA_WINDOW_SECONDS` | `86400` | Spec §6.4 quota window length (24h default). Independent of `TEABAY_PSI_EPOCH_SECONDS`. |
| `TEABAY_PSI_EPOCH_SECONDS` | `604800` | OPRF key epoch length (key selection only; never resets the quota). |
| `TEABAY_PSI_KEY_RETENTION_SECONDS` | `7776000` | PSI key retention, capped at 90 days. |

## Reverse Proxy

Run teabay behind a TLS-terminating proxy in production. Configure:

- HTTPS and HSTS at the proxy.
- A strict CSP for browser clients that load the admin console.
- Request size limits suitable for discovery state envelopes.
- Access logs with token and signature header redaction.

## Admin SPA Security Headers

The bundled `Dockerfile.admin` nginx config (P5) emits the following headers
on every response:

- `Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self';`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`

If you are fronting the admin SPA with a separate ingress, replicate these
headers there. The `wasm-unsafe-eval` source is required for the Dioxus WASM
runtime; do not remove it.

## P5 Release-Readiness Checklist (Local Evidence)

Before a release, capture the following local-only evidence under `artifacts/`
using `scripts/local-artifacts.sh`:

- SPDX SBOM JSON for the server and admin images.
- Trivy vulnerability scan report (`scripts/trivy-scan.sh`).
- Optional cosign signature bundle (when `COSIGN_KEY` is set).
- A snapshot of `/metrics` exercised against a populated database, including
  the new `teabay_expired_rows_purged_total` and
  `teabay_takedown_notification_failures_total` series.
- A snapshot of `/health` showing the expected hardening block.

No images, tags, or release artifacts are pushed from local automation; the
release owner triggers the push manually after reviewing these files.

## P5 Background Workers

| Variable | Default | Purpose |
| --- | ---: | --- |
| `TEABAY_EXPIRY_INTERVAL_SECONDS` | `1800` | Period for the row-purge worker. 0 disables. |
| `TEABAY_TAKEDOWN_NOTIFIER_INTERVAL_SECONDS` | `60` | Period for the pending-takedown HMAC fanout. 0 disables. |

See [`docs/webhook-retry.md`](webhook-retry.md) and
[`docs/heartbeat.md`](heartbeat.md) for the operator handbook.

## Multi-DC federation + backup procedure (R3)

teabay is the cokret Directory Service. In production it is deployed
across two or more data centers ("DCs") with one primary write region
and one or more standby read regions. The R3 (b47ff6ec) sync did not
change federation semantics, but several operational details should be
captured now that handle-homograph wire-level checks are mandatory.

### Topology

- **Primary DC** — owns the write path: `ingest::announce`,
  `ingest::withdraw`, takedown executor, pending-takedown HMAC notifier.
  Hosts the authoritative Postgres database.
- **Secondary DC** — read-only mirror. Serves `query::resolve_handle`
  and `query::private_contact_discovery` from a streaming-replicated
  Postgres replica. The mirror MUST NOT accept write traffic; the
  ingest routes return `503 read_only` on a secondary node.
- **Federation peers** — other Cokret Directory deployments. Bilateral
  `directory_peer_links` rows configure pull-subscribe / push-announce
  destinations; each peer's `service_did` MUST be on the local
  `directory_peer_trust` allowlist before subscription is honored.

### DR / backup

1. **Primary Postgres** — continuous WAL archiving to object storage
   (S3 / GCS / Azure Blob). Use a retention window ≥ `30d` to cover
   the longest takedown-notify retry tail.
2. **Logical dump cadence** — nightly `pg_dump -Fc` for off-DC restore
   drills. Restore SHOULD be verified at least quarterly using a
   throwaway secondary DC.
3. **Crypto material** — admin HMAC token secrets in `admin_tokens` and the
   takedown HMAC secret (`TEABAY_TAKEDOWN_HMAC_KEY`) MUST be stored in a
   secrets manager (Vault / Doppler / cloud KMS). Rotate every 90 days.

### Failover

1. Promote the standby Postgres to primary (PITR or sync replication
   catch-up). All teabay app pods restart with the promoted DSN.
2. Update the federation peer registry (`directory_peer_links`) to
   advertise the new primary's endpoint. Peers will fall back to the
   secondary endpoint until they refresh.
3. `directory.search_users` cursors are stateless — clients reconnect
   with no extra work. Pull-subscribe cursors are stateful per peer;
   the new primary refuses unknown cursors with `cursor_integrity_invalid`
   and peers re-subscribe from anchor.

### Backup integrity

Run an integrity sweep before each restore drill:

```sh
psql -c "SELECT count(*) FROM directory_entries WHERE proof_payload IS NULL;"
# MUST be 0

psql -c "SELECT count(*) FROM takedown_entries WHERE notified_at IS NULL AND created_at < now() - interval '24h';"
# alerts at >0
```

### R3-specific notes (b47ff6ec)

- Handle homograph wire-level enforcement landed in commit `6d69c63`.
  Pre-R3 announcements that contained script-mixed handles MUST be
  re-validated post-restore — failed re-validation routes to the
  takedown executor automatically (`reason=handle_homograph_forbidden`).
- The `circle` selector kind on `directory.search_users` returns a
  uniform 404 (intra-Realm isolation). No federation change.
