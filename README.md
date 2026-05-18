# teabay

Reference Contrix v1 **Directory Service** implementation.

teabay is the *discovery entry layer* of the Contrix protocol stack: it accepts
signed `cx.{space,organization,actor,applet,handle}.discovery` state from
resource Principal Servers, indexes the public-metadata projection, and
serves authorized search / resolve queries — all while enforcing the
spec's anti-enumeration filter.

It is **not** a source of truth, an authorization decision point, a join
executor, an identity resolver, a content mirror, a service-topology
authority, nor a global crawler. See `contrix-spec/spec/v1/zh/discovery/discovery-directory.md`
§7.2 for the precise role boundary.

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

## License

Apache-2.0.
