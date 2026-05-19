-- Round R2/R3 (2026-05-20) reversal.

DROP INDEX IF EXISTS ingest_announces_cache_key_idx;
DROP INDEX IF EXISTS directory_resources_reachability_revoked_idx;
DROP INDEX IF EXISTS directory_resources_realm_destroyed_idx;

ALTER TABLE ingest_announces
    DROP COLUMN IF EXISTS historical_only,
    DROP COLUMN IF EXISTS origin_key_state_hash,
    DROP COLUMN IF EXISTS service_binding_ref,
    DROP COLUMN IF EXISTS verification_method,
    DROP COLUMN IF EXISTS source_service_did;

ALTER TABLE directory_resources
    DROP COLUMN IF EXISTS reachability_revoked_reason,
    DROP COLUMN IF EXISTS reachability_revoked_at,
    DROP COLUMN IF EXISTS realm_destroyed_at;

-- enum values cannot be dropped in postgres — leave them in place.
