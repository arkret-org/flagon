# Current-v1 Capability Migration

Baseline: `4936e76..c42a26c` (the read-only Directory clean break).

Flagon is now a read-only public Realm Directory. It is not a Realm authority,
an ingest verifier, or an operator-controlled index writer. This ledger maps the
former surfaces to either a current production path or an explicit retirement;
it does not preserve compatibility routes.

## Retained current capabilities

| Capability | Current production evidence | Executable evidence |
|---|---|---|
| Describe, public Realm search, and exact Realm resolve | `crates/server/src/routing.rs::{directory_router,router}` mounts only `describe`, `search-realms`, and `resolve-realm`; `crates/server/src/query/{describe,realm}.rs` implements them. | `crates/server/tests/it/read_only.rs::public_read_bundle_is_exactly_the_routed_directory_surface`; query DTO tests in `query/realm.rs`. |
| Closed public metadata and expiry filtering | `query/realm.rs::PublicRealmDirectoryEntry::try_from` rejects legacy join/authority fields; both SQL reads require `expires_at > now()`. | `public_entry_contains_only_closed_metadata_and_local_times`; `old_join_and_authority_projection_is_not_returned`. |
| Exact generated operation advertisement and selector enforcement | `query/describe.rs::SUPPORTED_OPERATION_BUNDLES` advertises only the generated describe/public-read bundles; `routing.rs::operation_selector_middleware` checks the registered selector. | `query/describe.rs` tests and `routing.rs` OpenAPI/selector tests. |
| Authenticated operator audit reads | `routing.rs::admin_router` exposes only `GET audit` and `GET audit/verify`; `middleware/admin_auth.rs` verifies rotating-HMAC credentials (static bearer is development-only). | Admin-auth unit tests; `audit.rs::verify_chain` recomputes the append-only digest chain. |
| Append-only audit storage | The initial schema retains only `directory_audit`, `admin_tokens`, and the public Realm table; `directory_audit_block_update` rejects updates. | `query/realm.rs::fresh_schema_has_only_empty_public_realm_index` checks the exact fresh PostgreSQL table set. |
| Health, readiness, OpenAPI, and bounded query metrics | `routing.rs` mounts health/readiness, OpenAPI, and a separate metrics service; `observability.rs` contains only Realm query operations. | `tests/health.rs`; `observability.rs::only_mounted_realm_queries_are_exposed`. |
| Audit-only web console | `crates/admin/src/shell.rs` calls only `audit` and `audit/verify`; `crates/admin/src/api.rs` has no mutation method. | Native workspace build plus the admin `wasm32-unknown-unknown` check. |

## Explicitly retired capabilities

| Former capability | Disposition and reason | Absence evidence |
|---|---|---|
| `announce` / `withdraw`, federation ingest, source-ref/RealmCommit verification, signed ingest receipts | Retired. A read-only Directory cannot admit or author discovery truth; the governing Station remains authoritative. | No `ingest`, HTTP-signature, DID-resolution, or egress modules are compiled; `read_only.rs` asserts both write paths are absent from OpenAPI. |
| Actor/user/organization/handle/target queries, reverse-handle lookup, requester proofs, PCD, and Circle filtering | Retired. Current-v1 exposes only public Realm metadata and must not retain private or non-Realm discovery indexes. | `query/mod.rs` exports only `admin`, `describe`, `rate_limit`, and `realm`; the fresh-schema test rejects every former PCD/private directory table. |
| Admin resource edits, allowlist, consent revoke, and takedown/moderation | Retired. Operators may inspect audit history but cannot mutate the public index. | `admin_router` contains two GET routes only; the Glory/Sapid console contains no mutation panel or request helper. |
| Expiry/revalidation, PCD maintenance, and takedown-notifier workers | Retired with their writable state. Expiry visibility is enforced directly by read predicates. | No `workers` module is exported; the initial schema has no worker queue or policy table. |
| Discovery subscriptions and outbound webhooks | Retired. They would create a Directory-authored change order beside the governing Station's committed state. | No subscription/webhook route, table, configuration, or worker remains. |

## Deliberate gap: no population path

The server has no production route or worker that inserts
`directory_public_realm_entries`. A fresh database is therefore intentionally
empty, and the Docker isolation test asserts empty search/resolve results. The
read endpoints are reachable and their projection is tested, but this repository
does **not** yet prove a positive end-to-end result on a fresh deployment. Do not
describe Flagon as providing populated public discovery until a formal,
non-Directory-authoritative population mechanism and a positive live test exist.

Likewise, current routes do not append audit rows; the audit API verifies and
reads retained or externally provisioned operational history only.

## Verification

Run from the repository root:

```powershell
cargo +nightly fmt --all -- --check
cargo check --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo check --locked --manifest-path crates/admin/Cargo.toml --target wasm32-unknown-unknown
cargo test --locked -p server --lib fresh_schema_has_only_empty_public_realm_index -- --include-ignored --nocapture
```

The final command is the real PostgreSQL 16 fresh-schema gate and requires
Docker. A skipped default run is not evidence for that gate.

Verified on 2026-09-23 against the adjacent SDK worktree:

- nightly formatting passed;
- all-target check and strict all-feature Clippy passed;
- workspace tests passed: 17 executed, 0 failed, with the Docker test explicitly
  reported as ignored in the default run;
- the admin `wasm32-unknown-unknown` check passed;
- the ignored PostgreSQL 16 gate was then run explicitly: 1 passed, 0 failed.

The checked-in lock was stale relative to that adjacent SDK worktree, so the
local Rust checks used a temporary offline lock re-resolution. `Cargo.lock` was
restored byte-for-byte afterward and is not part of this migration slice.
