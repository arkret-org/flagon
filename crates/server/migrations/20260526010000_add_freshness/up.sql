-- P2E.5 — freshness columns.
--
-- `directory_resources.indexed_at + effective_ttl_seconds` already
-- gives us `next_revalidation_after`, but the operator-facing TTL
-- story (heartbeats, explicit expiry) needs two more derived columns:
--
--   * `last_refreshed_at` — most recent successful heartbeat or
--     announce. Equals `indexed_at` on row insert; the heartbeat
--     endpoint bumps it forward without rewriting `discovery_state`.
--   * `expires_at`        — explicit row-level expiry. Equals
--     `last_refreshed_at + effective_ttl_seconds`. A background
--     worker treats rows past `expires_at` as stale and ultimately
--     evicts them (`crate::ingest::pull_worker` already runs on a
--     timer; the eviction job is layered on top).
--
-- Both columns are populated retroactively from the existing
-- `indexed_at` + `effective_ttl_seconds` pair so legacy rows roll
-- forward without manual intervention.

ALTER TABLE directory_resources
    ADD COLUMN last_refreshed_at TIMESTAMPTZ,
    ADD COLUMN expires_at        TIMESTAMPTZ;

UPDATE directory_resources
   SET last_refreshed_at = indexed_at,
       expires_at = indexed_at + (effective_ttl_seconds || ' seconds')::INTERVAL;

ALTER TABLE directory_resources
    ALTER COLUMN last_refreshed_at SET NOT NULL,
    ALTER COLUMN expires_at        SET NOT NULL,
    ALTER COLUMN last_refreshed_at SET DEFAULT now();

-- The background expiry sweep filters by `expires_at < now()` so we
-- want a B-tree index keyed on expiry. Partial index on the rows
-- that haven't already been marked stale to keep the index small.
CREATE INDEX directory_resources_expires_at_idx
    ON directory_resources (expires_at)
    WHERE stale = false;
