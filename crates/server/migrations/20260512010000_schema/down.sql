-- Roll back the squashed teabay schema in reverse dependency order.

-- Squashed from 20260625010000_verified_realm_organizations.
DROP TABLE IF EXISTS verified_realm_organizations;

-- Squashed from 20260605010000_member_count_bucket_residency.
ALTER TABLE directory_resources
    DROP COLUMN IF EXISTS member_count_bucket_since,
    DROP COLUMN IF EXISTS member_count_bucket_locked,
    DROP COLUMN IF EXISTS member_count_real_bucket;

-- Squashed from 20260531010000_http_signature_replays.
DROP INDEX IF EXISTS http_signature_replays_expires_at_idx;
DROP TABLE IF EXISTS http_signature_replays;

-- Squashed from 20260526040000_did_normalization_audit.
-- Phase P2 — revert DID normalization audit CHECK constraints.
ALTER TABLE ingest_announces
    DROP CONSTRAINT IF EXISTS ingest_announces_principal_server_did_shape_chk;
ALTER TABLE ingest_announces
    DROP CONSTRAINT IF EXISTS ingest_announces_resource_id_did_shape_chk;
ALTER TABLE directory_resources
    DROP CONSTRAINT IF EXISTS directory_resources_principal_server_did_shape_chk;
ALTER TABLE directory_resources
    DROP CONSTRAINT IF EXISTS directory_resources_resource_id_did_shape_chk;

-- Squashed from 20260526030000_pending_takedowns.
-- Revert B.8.8.
DROP TABLE IF EXISTS pending_takedown_webhooks;
DROP TABLE IF EXISTS pending_takedown_approvals;
DROP INDEX IF EXISTS pending_takedowns_notification_due_idx;
DROP INDEX IF EXISTS pending_takedowns_status_idx;
DROP TABLE IF EXISTS pending_takedowns;

-- Squashed from 20260526020000_admin_tokens_and_audit_chain.
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

-- Squashed from 20260526010000_add_freshness.
-- P2E.5 — revert freshness columns.
DROP INDEX IF EXISTS directory_resources_expires_at_idx;
ALTER TABLE directory_resources
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS last_refreshed_at;

-- Squashed from 20260520010000_round23.
-- Round R2/R3 (2026-05-20) reversal.

DROP INDEX IF EXISTS ingest_announces_cache_key_idx;
DROP INDEX IF EXISTS directory_resources_reachability_revoked_idx;
DROP INDEX IF EXISTS directory_resources_realm_destroyed_idx;

ALTER TABLE ingest_announces
    DROP COLUMN IF EXISTS historical_only,
    DROP COLUMN IF EXISTS origin_key_state_digest,
    DROP COLUMN IF EXISTS service_binding_ref,
    DROP COLUMN IF EXISTS verification_method,
    DROP COLUMN IF EXISTS source_service_id;

ALTER TABLE directory_resources
    DROP COLUMN IF EXISTS reachability_revoked_reason,
    DROP COLUMN IF EXISTS reachability_revoked_at,
    DROP COLUMN IF EXISTS realm_destroyed_at;

-- enum values cannot be dropped in postgres — leave them in place.

DROP INDEX IF EXISTS directory_audit_occurred_at_idx;
DROP INDEX IF EXISTS directory_audit_resource_idx;
DROP TABLE IF EXISTS directory_audit;

DROP TABLE IF EXISTS accept_allowlist;

DROP INDEX IF EXISTS directory_invite_revocations_target_idx;
DROP TABLE IF EXISTS directory_invite_revocations;

DROP INDEX IF EXISTS directory_object_access_requesters_gin_idx;
DROP INDEX IF EXISTS directory_object_access_lookup_idx;
DROP TABLE IF EXISTS directory_object_access;

DROP INDEX IF EXISTS psi_quota_windows_expires_at_idx;
DROP TABLE IF EXISTS psi_quota_windows;

DROP INDEX IF EXISTS psi_batches_expires_at_idx;
DROP TABLE IF EXISTS psi_batches;

DROP INDEX IF EXISTS psi_contact_tokens_resource_idx;
DROP INDEX IF EXISTS psi_contact_tokens_lookup_idx;
DROP TABLE IF EXISTS psi_contact_tokens;

DROP INDEX IF EXISTS psi_epoch_keys_expires_at_idx;
DROP TABLE IF EXISTS psi_epoch_keys;

DROP INDEX IF EXISTS webhook_subscriptions_subscriber_idx;
DROP TABLE IF EXISTS webhook_subscriptions;

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
