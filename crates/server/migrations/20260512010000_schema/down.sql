DROP INDEX IF EXISTS directory_audit_occurred_at_idx;
DROP INDEX IF EXISTS directory_audit_resource_idx;
DROP TABLE IF EXISTS directory_audit;

DROP TABLE IF EXISTS accept_allowlist;

DROP INDEX IF EXISTS directory_invite_revocations_target_idx;
DROP TABLE IF EXISTS directory_invite_revocations;

DROP INDEX IF EXISTS directory_object_access_requesters_gin_idx;
DROP INDEX IF EXISTS directory_object_access_lookup_idx;
DROP TABLE IF EXISTS directory_object_access;

DROP INDEX IF EXISTS psi_contact_tokens_resource_idx;
DROP INDEX IF EXISTS psi_contact_tokens_lookup_idx;
DROP TABLE IF EXISTS psi_contact_tokens;

DROP INDEX IF EXISTS psi_epoch_keys_expires_at_idx;
DROP TABLE IF EXISTS psi_epoch_keys;

DROP INDEX IF EXISTS webhook_subscriptions_subscriber_idx;
DROP TABLE IF EXISTS webhook_subscriptions;

DROP INDEX IF EXISTS pull_subscriptions_next_pull_idx;
DROP TABLE IF EXISTS pull_subscriptions;

DROP INDEX IF EXISTS takedown_appeals_status_idx;
DROP INDEX IF EXISTS takedown_appeals_takedown_idx;
DROP TABLE IF EXISTS takedown_appeals;

DROP INDEX IF EXISTS withdrawals_active_takedown_idx;
DROP INDEX IF EXISTS withdrawals_resource_idx;
DROP TABLE IF EXISTS withdrawals;

DROP INDEX IF EXISTS ingest_announces_request_digest_idx;
DROP INDEX IF EXISTS ingest_announces_resource_idx;
DROP TABLE IF EXISTS ingest_announces;

DROP INDEX IF EXISTS directory_resources_realm_scope_parent_idx;
DROP INDEX IF EXISTS directory_resources_realm_scope_org_idx;
DROP INDEX IF EXISTS directory_resources_search_vector_gin_idx;
DROP INDEX IF EXISTS directory_resources_search_text_trgm_idx;
DROP INDEX IF EXISTS directory_resources_public_projection_gin;
DROP INDEX IF EXISTS directory_resources_next_revalidation_idx;
DROP INDEX IF EXISTS directory_resources_indexed_at_idx;
DROP INDEX IF EXISTS directory_resources_discoverability_idx;
DROP TABLE IF EXISTS directory_resources;

DROP FUNCTION IF EXISTS directory_resource_search_text(jsonb);

DROP TYPE IF EXISTS audit_event_kind;
DROP TYPE IF EXISTS withdrawal_kind;
DROP TYPE IF EXISTS accept_policy_kind;
DROP TYPE IF EXISTS ingest_mode;
DROP TYPE IF EXISTS discoverability;
DROP TYPE IF EXISTS resource_kind;
