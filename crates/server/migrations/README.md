# teabay diesel migrations

This directory holds the Diesel migrations applied by the `teabay-server`
binary. Each migration is a pair of `up.sql` / `down.sql`. Run with:

```sh
cargo run -p teabay-server -- migrate          # forward
cargo run -p teabay-server -- migrate-rollback # reverse one step
```

See `diesel.toml` at the repo root for the migrations directory binding.

## Migrations

| Timestamp | Slug | Intent | Rollback hint |
|---|---|---|---|
| `20260512010000` | `schema` | Fresh-install bootstrap (discovery-directory spec §7-§11). Creates the base directory tables, extensions (`pg_trgm`), enums. | `down.sql` drops the whole schema; safe only on dev/test DBs. **Never roll back in production** — recover from backup instead. |
| `20260520010000` | `round23` | R2/R3 schema extensions; adds `ck.realm.destroy` terminal-state anchor markers and Realm-projection tombstone columns. | `down.sql` removes added columns and indexes. Safe before any Realm has been destroyed; otherwise audit rows for `realm_destroyed_at` first. |
| `20260525010000` | `realm_resource_kind` | No-op retained for historical ordering. Fresh installs already define `'realm'` in the bootstrap `resource_kind` enum; Teabay indexes Realm directory resources, not Space containers. | `down.sql` is intentionally non-destructive; PostgreSQL enum values are not removed on rollback. |
| `20260525010100` | `realm_resource_kind_backfill` | No-op retained for historical ordering. Bootstrap schema owns Realm-only resource rows and Realm-scope lookup indexes. | `down.sql` is intentionally a no-op. |
| `20260526010000` | `add_freshness` | P2E.5 — operator-facing freshness columns (announce refreshes, explicit expiry) layered over the existing `indexed_at + effective_ttl_seconds`. | `down.sql` drops the added columns; downstream operator dashboards that consume the columns will break until redeployed. |
| `20260526020000` | `admin_tokens_and_audit_chain` | A.8.4 — rotating HMAC-SHA256 admin token table (30-min window) plus the append-only `admin_audit_chain` event log. Static `TEABAY_ADMIN_TOKEN` is development-only; production admin writes use rotating HMAC. | `down.sql` drops both tables. **Audit chain is forensic evidence — export before rollback.** |
| `20260526030000` | `pending_takedowns` | B.8.8 — N-of-M multi-approval takedown workflow (`pending_takedowns` + `pending_takedown_approvals`). | `down.sql` drops both tables. Any in-flight takedown proposals are lost; coordinate with operators before rolling back. |
| `20260526040000` | `did_normalization_audit` | Phase P2 (spec `37ce729`) — DID-format normalization audit table; records ingest rows rejected by the tightened DID syntax `^did:[a-z0-9]+:[^\s]+$`. | `down.sql` drops the audit table. Ingest behaviour is unchanged either way — rejection happens in the verify-chain, not via SQL constraint. |
| `20260531010000` | `http_signature_replays` | Stores HTTP Signature nonce/digest replay markers so signed ingest/query surfaces reject reused signatures across workers. | `down.sql` drops replay records; do not roll back while signed traffic may retry. |
| `20260605010000` | `member_count_bucket_residency` | Adds state for member-count bucket hysteresis so public bucket output remains pinned for the required residency window. | `down.sql` drops the residency columns; public projections fall back to stateless bucket output until rebuilt. |
| `20260625010000` | `verified_realm_organizations` | Adds the verified `ck.realm.organization` relationship index used for official organization badges and scoped search. | `down.sql` drops the verified relationship index; organization badges/scoping stop being authoritative. |

## Conventions

- Timestamps are UTC `YYYYMMDDhhmmss`. Two migrations on the same calendar day
  use the suffixed `hhmmss` slot (e.g. `010000` / `010100`) to enforce ordering.
- Enum-value additions land in their own migration (separate transaction)
  before any DML migration that uses the new value — PostgreSQL only commits
  new enum values at COMMIT time.
- Each migration is expected to be reversible on a development database; on
  production the rollback hint above takes precedence over the literal
  `down.sql` contents.
- Add a `metadata.toml` next to large or non-trivial migrations describing
  operator-visible side effects (existing examples: `round23`,
  `realm_resource_kind`).
