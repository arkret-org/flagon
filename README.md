# teabay

Reference Contrix v1 **Directory Service** implementation.

teabay is the *discovery entry layer* of the Contrix protocol stack: it accepts
signed `cx.{realm,organization,actor,applet,handle}.discovery` state from
resource Principal Servers, indexes the public-metadata projection, and
serves authorized search / resolve queries — all while enforcing the
spec's anti-enumeration filter.

It is **not** a source of truth, an authorization decision point, a join
executor, an identity resolver, a content mirror, a service-topology
authority, nor a global crawler. See `contrix-spec/spec/v1/zh/discovery/discovery-directory.md`
§7.2 for the precise role boundary.

## Realm vs Space

After the Phase 1–4 terminology inversion (Round R1.x), discovery
projections target the **Realm** as the unit of public metadata:

- **Realm:** security boundary — membership, capability, E2EE, federation;
  the unit on which `cx.realm.discovery` announces and `cx.realm.link`
  edges (governed_by / discoverable_from / mirror_of) operate.
- **Space:** navigation container — board, list, section, calendar bucket
  inside a Realm. Spaces are not directly discoverable; they ride along
  their parent Realm.

Per spec, the legacy `cx.space.discovery` kind is **hard-rejected** at
verify-time — no serde alias, no quiet rewrite. Emitters must send
`cx.realm.discovery`.

## Round R4 (protocol review closures)

Spec round 4 (`contrix-spec` range `2a4d39b..a77b995`, 8 commits) adds
three directory-service items. See [`CHANGELOG.md`](CHANGELOG.md)
`[Unreleased]` and [`../_todos.md`](../_todos.md) for the canonical
wire-breaking list.

- **`/directory/describe` returns `ServiceDescribe` v2** — 17 required
  fields including `trust_domain` and `plaintext_visibility`.
- **Federation S2S transport adds three signed headers** —
  `Source-Trust-Domain` / `Destination-Trust-Domain` /
  `Request-Canonical-Hash` are verified and folded into the
  HTTP-message-signature transcript.
- **Idempotency `historical_only`** — directory-announce replays after
  source-key revocation return the cached body with
  `reason_code=historical_only`; capability re-check still runs, side
  effects do not.

## Round R2/R3 operator notes

Spec rounds 2+3 (2026-05-20) extended the federation idempotency cache
key on `cx.directory.announce`. The cache key now includes
`Source-Service-DID` / `verification_method` / `service_binding_ref` /
`origin_key_state_hash` — see [`CHANGELOG.md`](CHANGELOG.md)
`[Unreleased]` and
[`../contrix-spec/CHANGELOG.md`](../contrix-spec/CHANGELOG.md) (T14)
for the normative source.

**Operator action on upgrade:** any stale idempotency cache built
against the pre-round-2 key (announce ref only) MUST be cleared on
upgrade, otherwise replayed announces after a peer-service-key
revocation will be served as fresh writes instead of being marked
`historical_only`. The migration `20260520010000_round23` adds the new
columns to `ingest_announces` and the `realm_destroyed_at` /
`reachability_revoked_at` columns to `directory_resources`.

## Conformance scope

This implementation targets the `cx.profile.directory_service.v1` profile
defined by the Contrix v1 spec — concretely:

- **§7** Directory Service Role (3-responsibility positioning, 6 invariants)
- **§8** Discovery Ingest Protocol (push announce + pull subscribe, 5-step
  verify chain, freshness/TTL/revalidation, 3-path withdrawal, anti-abuse)
- **§9** Service Surface (query + ingest endpoints + §9.1 normative result
  fields: `as_of`, `source_refs`, `policy_revision`, `stale?`, `divergent?`,
  `via_services`)
- **§3 / §11** anti-enumeration (bucketing, blinded `not_found`, timing
  equalization)
- **§12** Conformance test matrix (query face + ingest face)

Section 6 (Private Contact Discovery) is implemented with RFC 9497 VOPRF
blind / match flows. Parent Space semantics are represented through scope
filters and membership hints where the Directory profile needs them.

`cx.directory.describe.limitations` is populated at runtime for conformance
honesty. Current limitations are: pull-mode ingest is declared disabled when
`TEABAY_PULL_INTERVAL_SECONDS=0`; operator takedown is audit-backed but
resource-side notification transport is not implemented; webhook fanout from
`cx.directory.subscribe` is HMAC-signed best-effort delivery without a durable
retry queue.

## Tech stack

| Layer       | Choice                                                     |
| ----------- | ---------------------------------------------------------- |
| Runtime     | Tokio (multi-thread)                                       |
| HTTP        | [Salvo](https://salvo.rs) 0.93                             |
| ORM         | [Diesel](https://diesel.rs) 2.3 + r2d2 pool                |
| Database    | PostgreSQL 14+                                             |
| Crypto      | `ed25519-dalek`, plus the verify chain from `contrix-sdk`  |
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
# Edit .env: at minimum set DATABASE_URL and TEABAY_SERVICE_DID

# 3. Run migrations and start
diesel setup
cargo run -p server --release
```

The server then exposes `/api/v1/directory/*` per the spec. Health probe at
`GET /health`. OpenAPI doc at `GET /.well-known/contrix/openapi.{json,yaml}`.

Container builds use the local SDK path dependency as a named context:

```bash
docker build --build-context contrix-rust-sdk=../contrix-rust-sdk -t teabay .
```

## Admin console

The Dioxus web console lives in `crates/admin/` and talks to
`/api/admin/v1/{resources,allowlist,takedown,audit}` with the
`TEABAY_ADMIN_TOKEN` bearer token.

```bash
cd crates/admin
dx serve --platform web --port 8080
```

The `Resources` tab is a data manager for `directory_resources`: operators can
browse, create, update, and delete indexed rows, and every direct mutation is
written to the audit log.

## Validation

GitHub Actions runs the same checks expected locally:

```bash
cargo fmt --all --check
cargo check --all-targets
cargo test
cargo check --manifest-path crates/testing/Cargo.toml
cargo check --manifest-path crates/admin/Cargo.toml --target wasm32-unknown-unknown
TEABAY_RUN_DOCKER_TESTS=1 cargo test -p server --test it -- --nocapture
cargo deny check
```

The Docker-gated conformance test starts PostgreSQL with Testcontainers and
covers describe, query / resolve envelopes, anti-enumeration hidden-result
behavior, `cx.directory.subscribe`, signed push announce against a mock
Principal Server, pull-mode revalidation, freshness flags, PSI blind / match,
and takedown audit through the admin operator surface.

## Architecture

```
                        +----------------------------+
client / SDK  ──────▶   |  Salvo router              |
                        |  /api/v1/directory/*       |
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
                          │     pull-mode  │
                          │   (cx.events.  │
                          │   query)       │
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

- [ ] `TEABAY_DEVELOPMENT_MODE=false` (or unset in production builds)
- [ ] TLS enabled at the reverse proxy (or `TEABAY_TLS_CERT_PATH` / `TEABAY_TLS_KEY_PATH` when terminated in-process)
- [ ] CSP header configured at the reverse proxy
- [ ] CORS limited to the allowed origins for principal-server / sodmin callers
- [ ] Secrets in a secret manager (admin signing keys, database credentials)
- [ ] Log redaction enabled (default outside dev mode)
- [ ] Admin auth in production mode (admin token / DID allowlist)
- [ ] Rate limit enabled
- [ ] Provider credential rotation scheduled (when applicable)

## Cross-project task tracking

Per-project task lists are consolidated upstream — see
[`../_todos.md`](../_todos.md) for the active cross-project task plan.

## License

Apache-2.0.
