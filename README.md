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

## Tech stack

| Layer       | Choice                                                     |
| ----------- | ---------------------------------------------------------- |
| Runtime     | Tokio (multi-thread)                                       |
| HTTP        | [Salvo](https://salvo.rs) 0.93                             |
| ORM         | [Diesel](https://diesel.rs) 2.3 + r2d2 pool                |
| Database    | PostgreSQL 14+                                             |
| Crypto      | `ed25519-dalek`, plus the verify chain from `contrix-sdk`  |
| Migrations  | `diesel_migrations` (auto-applied at boot)                 |
| Admin UI    | Dioxus 0.7 web console in `teabay-admin/`                   |

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
cargo run --release
```

The server then exposes `/api/v1/directory/*` per the spec. Health probe at
`GET /health`. OpenAPI doc at `GET /.well-known/contrix/openapi.{json,yaml}`.

Container builds use the local SDK path dependency as a named context:

```bash
docker build --build-context contrix-rust-sdk=../contrix-rust-sdk -t teabay .
```

## Admin console

The Dioxus web console lives in `teabay-admin/` and talks to
`/api/admin/v1/{resources,allowlist,takedown,audit}` with the
`TEABAY_ADMIN_TOKEN` bearer token.

```bash
cd teabay-admin
dx serve --platform web --port 8080
```

## Validation

GitHub Actions runs the same checks expected locally:

```bash
cargo fmt --check
cargo check --all-targets
cargo test
cargo check --manifest-path teabay-testing/Cargo.toml
cargo check --manifest-path teabay-admin/Cargo.toml --target wasm32-unknown-unknown
TEABAY_RUN_DOCKER_TESTS=1 cargo test --test it -- --nocapture
cargo deny check
```

The Docker-gated conformance test starts PostgreSQL with Testcontainers and
covers describe, query / resolve, signed push announce against a mock Principal
Server, PSI blind / match, and the admin operator surface.

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
├── migrations/        - Diesel schema migrations (auto-applied at boot)
├── teabay-admin/      - Dioxus operator console
├── teabay-testing/    - shared SQL fixtures for teabay and cotest
├── src/
│   ├── main.rs        - tokio entry, signal handling
│   ├── lib.rs         - service composition
│   ├── routing.rs     - Salvo router declaration
│   ├── config.rs      - env-driven AppConfig
│   ├── error.rs       - typed ErrorCode enum (incl. ingest-specific codes)
│   ├── state.rs       - shared AppState
│   ├── db.rs          - Diesel pool + migrations runner
│   ├── schema.rs      - Diesel table macros (matches migrations)
│   ├── ids.rs         - cx:announce / cx:withdraw / cx:subscription ULIDs
│   ├── audit.rs       - takedown / withdrawal audit log
│   ├── ingest/
│   │   ├── announce.rs    - POST /directory/announce
│   │   ├── withdraw.rs    - POST /directory/withdraw
│   │   ├── verify.rs      - 5-step verify chain (§8.5)
│   │   └── pull_worker.rs - pull-mode revalidation poller
│   ├── query/
│   │   ├── describe.rs    - GET /directory/describe (incl. §8.9 fields)
│   │   ├── space.rs       - search-spaces / resolve-space
│   │   ├── organization.rs- search-organizations / resolve-organization
│   │   ├── actor.rs       - search-actors / search-users
│   │   ├── handle.rs      - resolve-handle
│   │   └── psi.rs         - private-contact-discovery (PSI)
│   └── filter/
│       ├── enumeration.rs - bucketing, blinded not_found, timing
│       └── result.rs      - §9.1 normative result envelope
└── tests/
    ├── health.rs
    └── it/conformance.rs
```

## License

Apache-2.0.
