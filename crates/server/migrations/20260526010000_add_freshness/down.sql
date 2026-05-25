-- P2E.5 — revert freshness columns.
DROP INDEX IF EXISTS directory_resources_expires_at_idx;
ALTER TABLE directory_resources
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS last_refreshed_at;
