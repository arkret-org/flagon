# flagon

Arkret v1 Directory Service for public Realm discovery. The service is
deliberately read-only: it advertises the read-only Directory profile and the
`ak.operation_bundle.directory_service.public_read.v1` three-operation bundle
(`describe`, `search_realms`, `resolve_realm`). There is no Directory HTTP-core
write bundle. The public index starts empty. Older, unverified rows are never
migrated or exposed.

The Directory is a rebuildable discovery hint, not a source of membership,
join, history, capability, or current-governance authority. The centrally
governing Station is authoritative for each Realm. Organization, Actor,
Applet, Handle, private-contact/PSI, source-callback, and exact-event lookup
surfaces are retired. The old `announce` and `withdraw` operations, their write
DTOs, governance proof, and announce identifier namespace are not current-v1
protocol and remain unknown to this service.

## Endpoints

- `GET /_arkret/describe` and `GET /_arkret/find/directory/describe`:
  service description and its exact supported profile and operation bundles.
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
createdb teabay_test
export TEABAY_TEST_DATABASE_URL=postgres://localhost/teabay_test
cargo check --all-targets
cargo test --workspace
```

Use a dedicated empty PostgreSQL database, separate from the service runtime.
The ordinary schema test applies the current migrations and verifies that
only the empty public Realm index, operator audit, admin credentials, and
Diesel's migration ledger are present. Missing `TEABAY_TEST_DATABASE_URL` fails
explicitly; the test is not skipped and requires no Docker daemon.

## Implementation

`crates/server` contains the Salvo read service, PostgreSQL migration, and
audit-chain verifier; `crates/contracts` contains only audit admin DTOs;
`crates/admin` is the audit-only Dioxus console. Prometheus on
`TEABAY_METRICS_BIND` reports the mounted Realm query operations. The index
can be populated only through deployment-private maintenance that is not an
Arkret interoperability surface and is never advertised by ServiceDescribe.

Apache-2.0.
