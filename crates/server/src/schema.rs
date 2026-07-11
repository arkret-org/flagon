// @generated automatically by Diesel CLI.
//
// This file is hand-aligned with `migrations/20260512010000_schema/up.sql`.
// Run `diesel print-schema` after every migration to keep it honest.

pub mod sql_types {
    #[derive(diesel::sql_types::SqlType, diesel::query_builder::QueryId)]
    #[diesel(postgres_type(name = "resource_kind"))]
    pub struct ResourceKind;

    #[derive(diesel::sql_types::SqlType, diesel::query_builder::QueryId)]
    #[diesel(postgres_type(name = "discoverability"))]
    pub struct Discoverability;

    #[derive(diesel::sql_types::SqlType, diesel::query_builder::QueryId)]
    #[diesel(postgres_type(name = "ingest_mode"))]
    pub struct IngestMode;

    #[derive(diesel::sql_types::SqlType, diesel::query_builder::QueryId)]
    #[diesel(postgres_type(name = "accept_policy_kind"))]
    pub struct AcceptPolicyKind;

    #[derive(diesel::sql_types::SqlType, diesel::query_builder::QueryId)]
    #[diesel(postgres_type(name = "withdrawal_kind"))]
    pub struct WithdrawalKind;

    #[derive(diesel::sql_types::SqlType, diesel::query_builder::QueryId)]
    #[diesel(postgres_type(name = "audit_event_kind"))]
    pub struct AuditEventKind;
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::{ResourceKind, Discoverability};

    directory_resources (resource_kind, resource_id) {
        resource_kind -> ResourceKind,
        resource_id -> Text,
        principal_server_did -> Text,
        discovery_state -> Jsonb,
        public_projection -> Jsonb,
        discoverability -> Discoverability,
        as_of -> Timestamptz,
        source_refs -> Array<Text>,
        policy_revision -> Text,
        indexed_at -> Timestamptz,
        effective_ttl_seconds -> Int4,
        next_revalidation_after -> Timestamptz,
        stale -> Bool,
        divergent -> Bool,
        via_services -> Array<Text>,
        last_announce_id -> Nullable<Text>,
        // Round R2/R3 — T07 realm terminal state, T17 consent revoke
        // reachability invalidation. See migration 20260520010000_round23.
        realm_destroyed_at -> Nullable<Timestamptz>,
        reachability_revoked_at -> Nullable<Timestamptz>,
        reachability_revoked_reason -> Nullable<Text>,
        // P2E.5 — operator-facing freshness columns. See migration
        // 20260526010000_add_freshness.
        last_refreshed_at -> Timestamptz,
        expires_at -> Timestamptz,
        // Spec §3 member_count bucket hysteresis / minimum residency. See
        // migration 20260605010000_member_count_bucket_residency.
        member_count_real_bucket -> Nullable<Text>,
        member_count_bucket_locked -> Nullable<Text>,
        member_count_bucket_since -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::{ResourceKind, IngestMode};

    ingest_announces (announce_id) {
        announce_id -> Text,
        resource_kind -> ResourceKind,
        resource_id -> Text,
        principal_server_did -> Text,
        ingest_mode -> IngestMode,
        discovery_state -> Jsonb,
        source_refs -> Array<Text>,
        policy_revision -> Text,
        as_of -> Timestamptz,
        indexed_at -> Timestamptz,
        effective_ttl_seconds -> Int4,
        supersedes_announce_id -> Nullable<Text>,
        request_digest -> Bytea,
        // Round R2/R3 T14 — federation idempotency cache key extension.
        source_service_id -> Text,
        verification_method -> Text,
        service_binding_ref -> Text,
        origin_key_state_digest -> Bytea,
        historical_only -> Bool,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::{ResourceKind, WithdrawalKind};

    withdrawals (withdraw_id) {
        withdraw_id -> Text,
        resource_kind -> ResourceKind,
        resource_id -> Text,
        kind -> WithdrawalKind,
        reason -> Text,
        proof -> Jsonb,
        effective_at -> Timestamptz,
        acked_at -> Timestamptz,
        operator -> Nullable<Text>,
        notified_at -> Nullable<Timestamptz>,
        overturned_at -> Nullable<Timestamptz>,
        overturn_appeal_id -> Nullable<Text>,
        overturn_receipt -> Nullable<Jsonb>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::ResourceKind;

    pull_subscriptions (resource_kind, resource_id) {
        resource_kind -> ResourceKind,
        resource_id -> Text,
        principal_server_did -> Text,
        last_revision -> Nullable<Text>,
        last_pulled_at -> Nullable<Timestamptz>,
        next_pull_after -> Timestamptz,
        consecutive_failures -> Int4,
        last_error -> Nullable<Text>,
    }
}

diesel::table! {
    webhook_subscriptions (subscription_id) {
        subscription_id -> Text,
        subscriber_did -> Text,
        resource_filter -> Jsonb,
        webhook_endpoint -> Text,
        secret -> Nullable<Bytea>,
        expires_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    psi_epoch_keys (epoch) {
        epoch -> Text,
        profile -> Text,
        server_key -> Bytea,
        public_key -> Bytea,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
        tokens_indexed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::ResourceKind;

    psi_contact_tokens (epoch, resource_kind, resource_id, token) {
        epoch -> Text,
        token -> Bytea,
        resource_kind -> ResourceKind,
        resource_id -> Text,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    directory_object_access (realm_id, object_kind, strand_id, message_id) {
        realm_id -> Text,
        object_kind -> Text,
        strand_id -> Text,
        message_id -> Text,
        public_projection -> Jsonb,
        allowed_requesters -> Array<Text>,
        required_claims -> Jsonb,
        as_of -> Timestamptz,
        source_refs -> Array<Text>,
        policy_revision -> Nullable<Text>,
        indexed_at -> Timestamptz,
        stale -> Bool,
        divergent -> Bool,
    }
}

diesel::table! {
    directory_invite_revocations (token_payload_digest) {
        token_payload_digest -> Bytea,
        target_digest -> Text,
        revoked_at -> Timestamptz,
        revoked_by -> Text,
        reason -> Nullable<Text>,
        expires_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    accept_allowlist (resource_did) {
        resource_did -> Text,
        added_by -> Text,
        added_at -> Timestamptz,
        note -> Nullable<Text>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::{ResourceKind, AuditEventKind};

    directory_audit (audit_id) {
        audit_id -> Int8,
        occurred_at -> Timestamptz,
        kind -> AuditEventKind,
        resource_kind -> Nullable<ResourceKind>,
        resource_id -> Nullable<Text>,
        actor -> Nullable<Text>,
        detail -> Jsonb,
        // A.8.5 — chained audit digest + operator-credential split.
        authentication_method -> Nullable<Text>,
        authenticated_actor -> Nullable<Text>,
        asserted_operator -> Nullable<Text>,
        prev_digest -> Nullable<Bytea>,
        audit_digest -> Nullable<Bytea>,
    }
}

diesel::table! {
    // A.8.4 — operator rotating HMAC tokens (30-minute window).
    admin_tokens (key_id) {
        key_id -> Text,
        secret -> Bytea,
        label -> Nullable<Text>,
        created_at -> Timestamptz,
        expires_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::ResourceKind;

    // B.8.8 — pending takedown proposals awaiting quorum approval.
    pending_takedowns (pending_id) {
        pending_id -> Text,
        resource_kind -> ResourceKind,
        resource_id -> Text,
        reason -> Text,
        proposed_by -> Text,
        proposed_at -> Timestamptz,
        quorum -> Int4,
        status -> Text,
        expires_at -> Timestamptz,
        executed_at -> Nullable<Timestamptz>,
        executed_withdraw_id -> Nullable<Text>,
        notification_status -> Nullable<Text>,
        next_notification_after -> Timestamptz,
    }
}

diesel::table! {
    pending_takedown_approvals (pending_id, approver) {
        pending_id -> Text,
        approver -> Text,
        approved_at -> Timestamptz,
        note -> Nullable<Text>,
    }
}

diesel::table! {
    pending_takedown_webhooks (webhook_id) {
        webhook_id -> Text,
        endpoint -> Text,
        secret -> Nullable<Bytea>,
        created_at -> Timestamptz,
        expires_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::ResourceKind;

    takedown_appeals (appeal_id) {
        appeal_id -> Text,
        takedown_id -> Text,
        resource_kind -> ResourceKind,
        resource_id -> Text,
        appellant_did -> Text,
        requested_outcome -> Text,
        argument_digest -> Text,
        appeal_packet -> Jsonb,
        status -> Text,
        created_at -> Timestamptz,
        accepted_at -> Timestamptz,
        decided_at -> Nullable<Timestamptz>,
        decided_by -> Nullable<Text>,
        decision -> Nullable<Text>,
        decision_reason -> Nullable<Text>,
        decision_receipt -> Nullable<Jsonb>,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    // TBY-ORG-01/02/03 — verified `ak.realm.organization` relationships. See
    // migration 20260625010000_verified_realm_organizations.
    verified_realm_organizations (realm_id, organization_did, relationship) {
        realm_id -> Text,
        organization_did -> Text,
        relationship -> Text,
        control_scopes -> Array<Text>,
        statement_id -> Text,
        statement_issued_at -> Timestamptz,
        not_before -> Nullable<Timestamptz>,
        expires_at -> Nullable<Timestamptz>,
        realm_frontier_digest -> Nullable<Text>,
        stale -> Bool,
        verified_at -> Timestamptz,
        source_announce_id -> Nullable<Text>,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    directory_resources,
    ingest_announces,
    withdrawals,
    pull_subscriptions,
    webhook_subscriptions,
    psi_epoch_keys,
    psi_contact_tokens,
    directory_object_access,
    directory_invite_revocations,
    accept_allowlist,
    directory_audit,
    admin_tokens,
    pending_takedowns,
    pending_takedown_approvals,
    pending_takedown_webhooks,
    takedown_appeals,
    verified_realm_organizations,
);
