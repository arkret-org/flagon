# teabay diesel migrations

This directory holds the Diesel migrations applied by the `server` binary.
Each migration is a pair of `up.sql` / `down.sql`. They are embedded via
`diesel_migrations::embed_migrations!` and run automatically at startup
(`Db::run_migrations`), so there is no separate migrate subcommand.

See `diesel.toml` at the repo root for the migrations directory binding used
by the offline `diesel` CLI (`diesel print-schema`).

## Migration

| Timestamp | Slug | Intent | Rollback hint |
|---|---|---|---|
| `20260512010000` | `schema` | Squashed fresh-install D2 schema: empty public Realm metadata index plus operator audit and admin credentials. Retired ingest, PCD/PSI, and non-Realm resource tables are absent. | `down.sql` removes these structures. Safe only on dev/test databases; recover production from backup instead. |

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
