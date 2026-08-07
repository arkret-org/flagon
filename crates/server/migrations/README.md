# teabay diesel migrations

This directory holds the Diesel migrations applied by the `teabay-server`
binary. Each migration is a pair of `up.sql` / `down.sql`. Run with:

```sh
cargo run -p teabay-server -- migrate          # forward
cargo run -p teabay-server -- migrate-rollback # reverse one step
```

See `diesel.toml` at the repo root for the migrations directory binding.

## Migration

| Timestamp | Slug | Intent | Rollback hint |
|---|---|---|---|
| `20260512010000` | `schema` | Squashed fresh-install schema containing the complete directory, freshness, administration, takedown, replay-protection, residency, and verified-organization structures through 2026-06-25. | `down.sql` removes the complete schema in reverse dependency order. Safe only on dev/test databases; recover production from backup instead. |

## Conventions

- The current history is intentionally squashed into one initial migration.
  Add a new timestamped migration only for changes that must upgrade an
  already-deployed database; periodically fold unreleased migrations back into
  the initial schema.
- Enum-value additions land in their own migration (separate transaction)
  before any DML migration that uses the new value — PostgreSQL only commits
  new enum values at COMMIT time.
- The migration is expected to be reversible on a development database; on
  production the rollback hint above takes precedence over the literal
  `down.sql` contents.
