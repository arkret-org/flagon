# teabay

> **Spec target**: [arkret-spec @ c2848a4](../arkret-spec) (R3.4 sync 2026-05-31)

Reference Arkret v1 **Directory Service** implementation.

teabay is the *discovery entry layer* of the Arkret protocol stack: it accepts
signed `ak.{realm,organization,actor,applet,handle}.discovery` state from
resource Principal Servers, indexes the public-metadata projection, and
serves authorized search / resolve queries — all while enforcing the
spec's anti-enumeration filter.

It is **not** a source of truth, an authorization decision point, a join
executor, an identity resolver, a content mirror, a service-topology
authority, nor a global crawler. See `arkret-spec/spec/v1/zh/discovery/discovery-directory.md`
§7.2 for the precise role boundary.

## Realm vs Space

Discovery projections target the **Realm** as the unit of public metadata:

- **Realm:** security boundary — membership, capability, E2EE, federation;
  the unit on which `ak.realm.discovery` announces and `ak.realm.link`
  edges (governed_by / discoverable_from / mirror_of) operate.
- **Space:** navigation container — board, list, section, calendar bucket
  inside a Realm. Spaces are not directly discoverable; they ride along
  their parent Realm.

Per spec, directory discovery uses `ak.realm.discovery`; Space containers are
not independently announced to teabay.

## Protocol surface highlights

- **`/directory/describe` returns `ServiceDescribe`** — 17 required
  fields including `trust_domain` and `plaintext_visibility`.
- **Federation S2S transport signs trust-domain and body bindings** —
  `Source-Trust-Domain` / `Destination-Trust-Domain` and the single RFC 9530
  `Content-Digest` are verified through the HTTP-message-signature transcript.
- **Idempotency `historical_only`** — directory-announce replays after
  source-key revocation return the cached body with
  `reason_code=historical_only`; capability re-check still runs, side
  effects do not.

## Federation idempotency cache key

The idempotency cache key on `ak.find.directory.command.announce.v1`
includes `Source-Service-ID` / `verification_method` /
`service_binding_ref` / `origin_key_state_digest`. The initial schema
migration carries those columns on `ingest_announces`, plus
`realm_destroyed_at` / `reachability_revoked_at` on
`directory_resources`.

## Conformance scope

This implementation targets the `ak.profile.directory_service.v1` profile
defined by the Arkret v1 spec — concretely:

- **§7** Directory Service Role (3-responsibility positioning, 6 invariants)
- **§8** Discovery Ingest Protocol (push announce, 5-step
  verify chain, freshness/TTL/revalidation, 3-path withdrawal, anti-abuse)
- **§9** Service Surface (query + ingest endpoints + §9.1 normative result
  fields: `as_of`, `source_refs`, `policy_revision`, `stale?`, `divergent?`,
  `via_services`)
- **§3 / §11** anti-enumeration (bucketing, blinded `not_found`, timing
  equalization)
- **§12** Conformance test matrix (query face + ingest face)

`ak.directory.describe.limitations` is populated at runtime for conformance
honesty. Current limitations are: pull-mode ingest remains unsupported until
the v1 Directory-specific state-only pull operation and DTO are normative;
Private Contact Discovery is not advertised until its current-v1 exact-batch,
single batched DLEQ, fixed-bucket and delay contract is implemented;
operator takedown webhook fanout is
HMAC-signed best-effort delivery with retry/DLQ status tracking; webhook fanout
from `ak.find.directory.push.command.register.v1` is HMAC-signed best-effort delivery without a
durable retry queue.

## Tech stack

| Layer       | Choice                                                     |
| ----------- | ---------------------------------------------------------- |
| Runtime     | Tokio (multi-thread)                                       |
| HTTP        | [Salvo](https://salvo.rs) 0.93                             |
| ORM         | [Diesel](https://diesel.rs) 2.3 + r2d2 pool                |
| Database    | PostgreSQL 14+                                             |
| Crypto      | `ed25519-dalek`, plus the verify chain from `arkret-sdk`  |
| Migrations  | `diesel_migrations` (auto-applied at boot)                 |
| Admin UI    | Dioxus 0.7 web console in `crates/admin/`                  |

## Quick start

```bash
# Option A: local dev Postgres via Docker Compose
scripts/dev-up.sh

# Option B: manual setup
# 1. Install Rust 1.88+, PostgreSQL 14+, and diesel CLI
cargo install diesel_cli --no-default-features --features postgres

# 2. Provision the database
createdb teabay
cp .env.example .env
# Edit .env: set DATABASE_URL plus the full service DID and its verified
# method-history head/version commitment.

# 3. Run migrations and start
diesel setup
cargo run -p server --release
```

The server then exposes `/_arkret/find/directory/*` per the spec. Liveness is
`GET /health`, readiness is `GET /readyz`, and Prometheus metrics are served on
the separate `TEABAY_METRICS_BIND` listener, default `127.0.0.1:9095`, at
`GET /metrics`. OpenAPI doc at `GET /.well-known/arkret/openapi.{json,yaml}`.

Container builds use the local SDK path dependency as a named context:

```bash
docker build --build-context arkret-rust-sdk=../arkret-rust-sdk -t teabay .
```

Local release-hygiene commands are artifact-only. They build and scan local
image refs, generate SBOM files under `artifacts/`, and optionally sign SBOM
blobs with `COSIGN_KEY`; they do not push images, create tags, or publish
crates.

## Admin console

The Dioxus web console lives in `crates/admin/` and talks to
`/_teabay/admin/{resources,allowlist,takedown,audit}` with the
development-only `TEABAY_ADMIN_TOKEN` bearer token, or a production
rotating HMAC bearer minted from an `admin_tokens` row.

```bash
cd crates/admin
dx serve --platform web --port 8080
```

The `Resources` tab is a data manager for `directory_resources`: operators can
browse, create, update, and delete indexed rows, and every direct mutation is
written to the audit log.

## Observability

teabay exposes process liveness on `/health` and readiness on `/readyz`.
Readiness checks PostgreSQL with `SELECT 1` and confirms enabled background
workers have emitted a recent heartbeat.

Prometheus metrics listen on `TEABAY_METRICS_BIND` separately from public API
traffic. The default is loopback-only:

```bash
TEABAY_METRICS_BIND=127.0.0.1:9095 cargo run -p server
curl http://127.0.0.1:9095/metrics
```

The metrics surface includes ingest outcomes, query latency, anti-enumeration
pad targets, and expiry outcomes. For
OpenTelemetry, run an OTel Collector next to teabay and scrape the Prometheus
endpoint plus stdout/stderr tracing logs.

## Validation

GitHub Actions runs the same checks expected locally:

```bash
cargo +nightly fmt --all -- --check
cargo check --all-targets
cargo test
cargo check --manifest-path crates/testing/Cargo.toml
cargo check --manifest-path crates/admin/Cargo.toml --target wasm32-unknown-unknown
TEABAY_RUN_DOCKER_TESTS=1 cargo test -p server --test it -- --nocapture
cargo deny check
cargo tarpaulin --config tarpaulin.toml --fail-under 70
scripts/trivy-scan.sh
scripts/local-artifacts.sh
```

The Docker-gated conformance test starts PostgreSQL with Testcontainers and
covers describe, query / resolve envelopes, anti-enumeration hidden-result
behavior, `ak.find.directory.push.command.register.v1`, signed push announce against a mock
Principal Server, freshness flags, and takedown audit through the admin operator
surface.

## Architecture

```
                        +----------------------------+
client / SDK  ──────▶   |  Salvo router              |
                        |  /_arkret/find/directory/* |
                        +----------------------------+
                          │                │
                          │ query          │ ingest
                          ▼                ▼
                    +-----------+    +-----------+
                    |  filter   |    |  verify   |
                    | (§3/§11)  |    |  chain    |
                    | bucket /  |    | (§8.5)    |
                    | blinded   |    | 5 steps   |
                    | not_found |    +-----------+
                    +-----------+          │
                          │                ▼
                          │          +-----------+
                          ▼          |  audit    |
                    +-----------+    | (§8.7)    |
                    |  index    |    +-----------+
                    |  store    |◀─────────│
                    | (Postgres)|          │
                    +-----------+    +-----------+
                          ▲          | revalidator|
                          │          | worker    |
                          │          | (§8.6)    |
                          │          +-----------+
                          │                │
                           │  push refresh  │
                           │   announce /   │
                           │    webhook     │
                          ▼                ▼
                  resource Principal Server (soland / other)
```

## Project layout

```
teabay/
├── .github/workflows/ci.yml - fmt/check/test/conformance/supply-chain CI
├── crates/
│   ├── admin/         - Dioxus operator console and data manager
│   ├── server/        - Salvo service, migrations, and integration tests
│   └── testing/       - shared SQL fixtures for teabay and cotest
├── scripts/           - local developer bootstrap helpers
├── Cargo.toml         - workspace manifest
└── diesel.toml        - Diesel CLI config for `crates/server`
```

## Production Deployment Checklist

Before exposing teabay to the public internet, walk every item below.
The same list will be computed at runtime and surfaced on
`/health.hardening` so sodmin's `/hardening` dashboard can flag failing
checks across the whole fleet (see T8.3 for the cross-service shape).

### HTTP signature key provisioning

`TEABAY_REQUIRE_HTTP_SIG=true` is the production ingest default. Provision
ingest signer keys before accepting traffic:

1. For each resource Principal Server that may call
   `/_arkret/find/directory/{announce,withdraw,push/register}`, obtain the Ed25519
   verifying key that corresponds to the HTTP Message Signature `keyid`.
2. Encode the raw 32-byte verifying key with unpadded base64url. Standard
   padded base64 is also accepted, but base64url is preferred for env files.
3. Set `TEABAY_HTTP_SIG_PUBKEYS` to comma-separated
   `keyid=BASE64URL32` pairs, for example
   `did:web:principal.example#directory-ingest-2026=BASE64URL_OF_RAW_32_BYTE_KEY`.
4. Restart teabay so the key directory is rebuilt from the environment.
5. Send a signed ingest request whose signature `keyid` exactly matches the
   configured key id. Unknown, missing, malformed, or mismatched keys are
   rejected by the ingest middleware before handler-level verification.

Rotate keys by adding the new `keyid=key` pair, rolling Principal Servers to
sign with the new key id, then removing the old pair after replay windows have
expired.

### Secret handling for 1.0

teabay 1.0 uses environment-variable secret provisioning only:
`TEABAY_HTTP_SIG_PUBKEYS`, database credentials, and
deployment-specific TLS or proxy secrets are injected by the runtime
environment. A Vault / AWS Secrets Manager adapter is explicitly out of scope
for 1.0; operators should use their orchestrator's existing secret injection
mechanism and keep `.env` files out of source control.

### Admin token enforcement

All `/_teabay/admin/*` handlers call the shared admin guard before touching the
database. In development mode the guard can accept
`Authorization: Bearer $TEABAY_ADMIN_TOKEN`. In production
(`TEABAY_DEVELOPMENT_MODE=false`) that static bearer is ignored; admin callers
must use `Authorization: Bearer hmac:<key_id>:<ts>:<mac_base64>` backed by an
active `admin_tokens` row. `/health.hardening.admin_auth_mode` reports
`rotating_hmac` for the production path.

### Takedown receipts

`withdrawals.proof` carries verifiable receipt material. Resource-initiated
withdrawals store the resource governance detached JWS and signed payload.
Operator takedowns store a service-signed detached JWS receipt and require
`TEABAY_RECEIPT_SIGNING_KEY_B64`; the verification method is
`TEABAY_RECEIPT_KEY_ID` or `$TEABAY_SERVICE_FULL_ID#teabay-receipt-1`.

- [ ] `TEABAY_DEVELOPMENT_MODE=false` (or unset in production builds)
- [ ] TLS enabled at the reverse proxy (teabay itself serves plaintext HTTP)
- [ ] CSP header configured at the reverse proxy
- [ ] CORS limited to the allowed origins for principal-server / sodmin callers
- [ ] Secret env vars injected by the deployment platform, not committed `.env` files
- [ ] Receipt signing key provisioned (`TEABAY_RECEIPT_SIGNING_KEY_B64`)
- [ ] Log redaction enabled (default outside dev mode)
- [ ] Admin auth in production mode (`admin_tokens` rotating HMAC)
- [ ] Rate limit enabled
- [ ] Provider credential rotation scheduled (when applicable)

## License

Apache-2.0.
