-- Revert the squashed read-only Directory schema on a development database.
DROP TRIGGER IF EXISTS directory_audit_block_update ON directory_audit;
DROP FUNCTION IF EXISTS directory_audit_block_update();
DROP TABLE IF EXISTS directory_audit;
DROP TABLE IF EXISTS admin_tokens;
DROP TABLE IF EXISTS directory_public_realm_entries;
DROP TYPE IF EXISTS audit_event_kind;
DROP TYPE IF EXISTS resource_kind;
