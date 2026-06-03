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
| `20260525010000` | `realm_resource_kind` | Adds the dedicated `'realm'` value to the `resource_kind` PostgreSQL enum (committed before the backfill migration that uses it). | Rollback is **destructive** — the enum value cannot be dropped while rows still reference it. Run only after the backfill migration is also rolled back. |
| `20260525010100` | `realm_resource_kind_backfill` | Moves existing security-boundary rows onto `'realm'`, normalizes Realm URI prefixes / projection keys, adds Realm-scoped lookup indexes. | `down.sql` reverts rows back to `'space'` and drops the new indexes. Cross-check with `directory_audit` before rolling back. |
| `20260526010000` | `add_freshness` | P2E.5 — operator-facing freshness columns (heartbeats, explicit expiry) layered over the existing `indexed_at + effective_ttl_seconds`. | `down.sql` drops the added columns; downstream operator dashboards that consume the columns will break until redeployed. |
| `20260526020000` | `admin_tokens_and_audit_chain` | A.8.4 — rotating HMAC-SHA256 admin token table (30-min window) plus the append-only `admin_audit_chain` event log. Legacy static `TEABAY_ADMIN_TOKEN` still accepted. | `down.sql` drops both tables. **Audit chain is forensic evidence — export before rollback.** |
| `20260526030000` | `pending_takedowns` | B.8.8 — N-of-M multi-approval takedown workflow (`pending_takedowns` + `pending_takedown_approvals`). | `down.sql` drops both tables. Any in-flight takedown proposals are lost; coordinate with operators before rolling back. |
| `20260526040000` | `did_normalization_audit` | Phase P2 (spec `37ce729`) — DID-format normalization audit table; records ingest rows rejected by the tightened DID syntax `^did:[a-z0-9]+:[^\s]+$`. | `down.sql` drops the audit table. Ingest behaviour is unchanged either way — rejection happens in the verify-chain, not via SQL constraint. |

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
