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
        policy_revision -> Nullable<Text>,
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
        as_of -> Timestamptz,
        indexed_at -> Timestamptz,
        effective_ttl_seconds -> Int4,
        supersedes_announce_id -> Nullable<Text>,
        request_digest -> Bytea,
        // Round R2/R3 T14 — federation idempotency cache key extension.
        source_service_did -> Text,
        verification_method -> Text,
        service_binding_ref -> Text,
        origin_key_state_hash -> Bytea,
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
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    directory_resources,
    ingest_announces,
    withdrawals,
    pull_subscriptions,
    webhook_subscriptions,
    psi_epoch_keys,
    accept_allowlist,
    directory_audit,
);
