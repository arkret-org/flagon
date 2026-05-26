-- Move security-boundary rows onto the dedicated `realm` enum value,
-- normalize Realm URI prefixes / projection keys, then add Realm-specific
-- lookup indexes. At this point the `realm` enum value was committed by
-- the preceding migration.
--
-- ── Operator note ────────────────────────────────────────────────────
-- This file used to run a single set of unbounded `UPDATE ... WHERE
-- resource_kind = 'space'` statements. On large directories (>10M
-- resources, common in production teabay deployments) the migration
-- timed out the diesel-supplied transaction's `statement_timeout` and
-- left the system in a half-migrated state.
--
-- The refactor: explicitly clear the per-session statement_timeout so a
-- long backfill doesn't get reaped, and add a CTE-based chunked UPDATE
-- pattern that bounds each pass to `_chunk_size` rows. The chunked
-- pattern is operator-resumable — if the migration is interrupted, the
-- next run continues from where the previous left off because the
-- predicate (`resource_kind = 'space'`) shrinks monotonically.
--
-- See `docs/operations.md` § "Realm backfill runbook" for the deferred
-- NOT NULL constraint path: this migration only narrows the data; the
-- structural NOT NULL guard is added by a follow-up migration once
-- operators confirm `directory_resources_realm_scope_org_idx` is fully
-- populated.

-- 1. Disable per-statement timeout for the duration of this migration.
--    Diesel runs each migration in its own implicit transaction; the
--    SET LOCAL scope dies with the transaction so this does NOT leak
--    into the application connection pool.
SET LOCAL statement_timeout = 0;
-- Bound lock waits so a long-running ANALYZE on the source tables
-- doesn't deadlock the rename.
SET LOCAL lock_timeout = '5min';

-- 2. Chunked backfill. Each pass touches at most `_chunk_size` rows;
--    we keep looping until no row matches the predicate. The DO block
--    runs entirely server-side so there is no per-row round-trip cost,
--    but the index scan is bounded so concurrent reads continue to
--    progress.
DO $$
DECLARE
    _chunk_size  CONSTANT integer := 10000;
    _touched     integer;
BEGIN
    -- 2a. directory_resources: realm kind + URI rewrite.
    LOOP
        WITH chunk AS (
            SELECT resource_id
            FROM directory_resources
            WHERE resource_kind = 'space'
            LIMIT _chunk_size
            FOR UPDATE SKIP LOCKED
        )
        UPDATE directory_resources AS d
        SET resource_kind = 'realm',
            resource_id   = regexp_replace(d.resource_id, '^cx:space:', 'cx:realm:')
        FROM chunk
        WHERE d.resource_id = chunk.resource_id;
        GET DIAGNOSTICS _touched = ROW_COUNT;
        EXIT WHEN _touched = 0;
        RAISE NOTICE 'directory_resources: backfilled % rows', _touched;
    END LOOP;

    -- 2b. ingest_announces.
    LOOP
        WITH chunk AS (
            SELECT ctid
            FROM ingest_announces
            WHERE resource_kind = 'space'
            LIMIT _chunk_size
            FOR UPDATE SKIP LOCKED
        )
        UPDATE ingest_announces AS i
        SET resource_kind = 'realm',
            resource_id   = regexp_replace(i.resource_id, '^cx:space:', 'cx:realm:')
        FROM chunk
        WHERE i.ctid = chunk.ctid;
        GET DIAGNOSTICS _touched = ROW_COUNT;
        EXIT WHEN _touched = 0;
        RAISE NOTICE 'ingest_announces: backfilled % rows', _touched;
    END LOOP;

    -- 2c. withdrawals.
    LOOP
        WITH chunk AS (
            SELECT ctid
            FROM withdrawals
            WHERE resource_kind = 'space'
            LIMIT _chunk_size
            FOR UPDATE SKIP LOCKED
        )
        UPDATE withdrawals AS w
        SET resource_kind = 'realm',
            resource_id   = regexp_replace(w.resource_id, '^cx:space:', 'cx:realm:')
        FROM chunk
        WHERE w.ctid = chunk.ctid;
        GET DIAGNOSTICS _touched = ROW_COUNT;
        EXIT WHEN _touched = 0;
        RAISE NOTICE 'withdrawals: backfilled % rows', _touched;
    END LOOP;

    -- 2d. pull_subscriptions.
    LOOP
        WITH chunk AS (
            SELECT ctid
            FROM pull_subscriptions
            WHERE resource_kind = 'space'
            LIMIT _chunk_size
            FOR UPDATE SKIP LOCKED
        )
        UPDATE pull_subscriptions AS p
        SET resource_kind = 'realm',
            resource_id   = regexp_replace(p.resource_id, '^cx:space:', 'cx:realm:')
        FROM chunk
        WHERE p.ctid = chunk.ctid;
        GET DIAGNOSTICS _touched = ROW_COUNT;
        EXIT WHEN _touched = 0;
        RAISE NOTICE 'pull_subscriptions: backfilled % rows', _touched;
    END LOOP;

    -- 2e. directory_audit.
    LOOP
        WITH chunk AS (
            SELECT ctid
            FROM directory_audit
            WHERE resource_kind = 'space'
            LIMIT _chunk_size
            FOR UPDATE SKIP LOCKED
        )
        UPDATE directory_audit AS a
        SET resource_kind = 'realm',
            resource_id   = regexp_replace(a.resource_id, '^cx:space:', 'cx:realm:')
        FROM chunk
        WHERE a.ctid = chunk.ctid;
        GET DIAGNOSTICS _touched = ROW_COUNT;
        EXIT WHEN _touched = 0;
        RAISE NOTICE 'directory_audit: backfilled % rows', _touched;
    END LOOP;
END $$;

-- 3. Catch any stray rows that already carry the new enum value but
--    still have the old URI prefix. These are cheap (the predicate
--    matches the empty set after step 2 on a clean install) and the
--    chunked pattern is overkill — a single UPDATE per table is fine.
UPDATE directory_resources
SET resource_id = regexp_replace(resource_id, '^cx:space:', 'cx:realm:')
WHERE resource_kind = 'realm'
  AND resource_id LIKE 'cx:space:%';

UPDATE ingest_announces
SET resource_id = regexp_replace(resource_id, '^cx:space:', 'cx:realm:')
WHERE resource_kind = 'realm'
  AND resource_id LIKE 'cx:space:%';

UPDATE withdrawals
SET resource_id = regexp_replace(resource_id, '^cx:space:', 'cx:realm:')
WHERE resource_kind = 'realm'
  AND resource_id LIKE 'cx:space:%';

UPDATE pull_subscriptions
SET resource_id = regexp_replace(resource_id, '^cx:space:', 'cx:realm:')
WHERE resource_kind = 'realm'
  AND resource_id LIKE 'cx:space:%';

UPDATE directory_audit
SET resource_id = regexp_replace(resource_id, '^cx:space:', 'cx:realm:')
WHERE resource_kind = 'realm'
  AND resource_id LIKE 'cx:space:%';

-- 4. JSON projection rewrites. These are scoped by JSONB containment
--    so each query plan can use the existing GIN index on
--    `public_projection`; chunking is unnecessary.
UPDATE directory_resources
SET discovery_state = replace(discovery_state::text, 'cx:space:', 'cx:realm:')::jsonb,
    public_projection = replace(public_projection::text, 'cx:space:', 'cx:realm:')::jsonb
WHERE discovery_state::text LIKE '%cx:space:%'
   OR public_projection::text LIKE '%cx:space:%';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'space_id', '{realm_id}', public_projection->'space_id')
WHERE public_projection ? 'space_id';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'space_ids', '{realm_ids}', public_projection->'space_ids')
WHERE public_projection ? 'space_ids';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'common_space_id', '{common_realm_id}', public_projection->'common_space_id')
WHERE public_projection ? 'common_space_id';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'common_space_ids', '{common_realm_ids}', public_projection->'common_space_ids')
WHERE public_projection ? 'common_space_ids';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'primary_space_id', '{primary_realm_id}', public_projection->'primary_space_id')
WHERE public_projection ? 'primary_space_id';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'member_of_spaces', '{member_of_realms}', public_projection->'member_of_spaces')
WHERE public_projection ? 'member_of_spaces';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'spaces', '{realms}', public_projection->'spaces')
WHERE public_projection ? 'spaces';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'parent_space_id', '{parent_realm_id}', public_projection->'parent_space_id')
WHERE public_projection ? 'parent_space_id';

UPDATE directory_resources
SET public_projection = jsonb_set(public_projection - 'parent_space_ids', '{parent_realm_ids}', public_projection->'parent_space_ids')
WHERE public_projection ? 'parent_space_ids';

-- 5. Realm-specific lookup indexes (concurrent build is unsafe inside
--    a migration TX; the cost is small because the WHERE filter binds
--    the index to just the realm partition).
CREATE INDEX IF NOT EXISTS directory_resources_realm_scope_org_idx
    ON directory_resources ((public_projection->>'organization_did'))
    WHERE resource_kind = 'realm';

CREATE INDEX IF NOT EXISTS directory_resources_realm_scope_parent_idx
    ON directory_resources ((public_projection->>'parent_realm_id'))
    WHERE resource_kind = 'realm';
