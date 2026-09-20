# teabay

Arkret v1 Directory Service candidate for public Realm discovery. In the D2
transition this service is deliberately read-only: it advertises only the
`ak.operation_bundle.directory_service.public_read.v1` three-operation bundle
(`describe`, `search_realms`, `resolve_realm`), not the full Directory profile
or HTTP core profile. The public index starts empty. Older, unverified rows are
never migrated or exposed.

The Directory is a rebuildable discovery hint, not a source of membership,
join, history, capability, or current-governance authority. The centrally
governing Station is authoritative for each Realm. Organization, Actor,
Applet, Handle, private-contact/PSI, source-callback, and exact-event lookup
surfaces are retired. The `announce` and `withdraw` write operations are not
mounted: the current-governance proof and opt-in evidence chain remains open
in `arkret-work/tasks/spec-open/2026-09-21-0350-directory-direct-push-proof-and-currentness-contract-gap.md`.

## Endpoints

- `GET /_arkret/describe` and `GET /_arkret/find/directory/describe`:
  candidate service description and its exact supported operation bundle.
- `POST /_arkret/find/directory/search-realms` and `resolve-realm`:
  public Realm metadata reads. With a fresh database they return no results.
- `GET /_teabay/admin/audit` and `audit/verify`: authenticated, read-only
  operator audit feed and digest-chain verification.
- `GET /health`, `/readyz`, and the separate metrics listener `/metrics`.
- `GET /.well-known/arkret/openapi.{json,yaml}` for the mounted HTTP surface.

No admin route can directly edit the index. No announce, withdraw, PCD, or
non-Realm query route is mounted.

## Local setup

Install Rust and PostgreSQL, copy `.env.example` to `.env`, and set
`DATABASE_URL`, `TEABAY_SERVICE_DID`, plus operator-verified
`TEABAY_SERVICE_METHOD_HISTORY_HEAD` and `TEABAY_SERVICE_VERSION_ID`. These
commitments must not be guessed from the DID text. The fresh-install squash
migration is auto-applied at startup.

```bash
cargo run -p server
```

For a local PostgreSQL container, set the required service identity variables
and run `scripts/dev-up.sh`. The Dioxus operator audit console can be started
from `crates/admin/` with `dx serve --platform web --port 8080`. A static
`TEABAY_ADMIN_TOKEN` is development-only; production audit access uses an
active rotating HMAC key from `admin_tokens` and requires the configured admin
CSRF token.

## Validation

```bash
cargo check --all-targets
cargo test --workspace
cargo test -p server --lib fresh_schema_has_only_empty_public_realm_index -- --include-ignored --nocapture
```

The last test uses Docker/Testcontainers and checks a newly migrated database:
only the empty public Realm index, operator audit, admin credentials, and
Diesel's migration ledger are present. It fails when Docker is unavailable.

## Implementation

`crates/server` contains the Salvo read service, PostgreSQL migration, and
audit-chain verifier; `crates/contracts` contains only audit admin DTOs;
`crates/admin` is the audit-only Dioxus console. Prometheus on
`TEABAY_METRICS_BIND` reports the mounted Realm query operations. The index
does not become a write-admission source until the open protocol proof issue
is resolved and implemented.

Apache-2.0.
