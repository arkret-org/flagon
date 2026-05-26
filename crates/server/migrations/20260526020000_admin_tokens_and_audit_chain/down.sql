-- Revert A.8.4 + A.8.5.
DROP TRIGGER IF EXISTS directory_audit_block_update ON directory_audit;
DROP FUNCTION IF EXISTS directory_audit_block_update();

ALTER TABLE directory_audit
    DROP COLUMN IF EXISTS audit_digest,
    DROP COLUMN IF EXISTS prev_digest,
    DROP COLUMN IF EXISTS asserted_operator,
    DROP COLUMN IF EXISTS authenticated_actor,
    DROP COLUMN IF EXISTS authentication_method;

DROP INDEX IF EXISTS admin_tokens_active_idx;
DROP TABLE IF EXISTS admin_tokens;
