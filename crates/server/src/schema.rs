//! Diesel mappings for the read-only Directory's operational tables.
//!
//! Public Realm entries use a closed raw-SQL projection in `query::realm`.
//! This file contains only the operator audit and credential tables.

pub mod sql_types {
    #[derive(diesel::sql_types::SqlType, diesel::query_builder::QueryId)]
    #[diesel(postgres_type(name = "resource_kind"))]
    pub struct ResourceKind;

    #[derive(diesel::sql_types::SqlType, diesel::query_builder::QueryId)]
    #[diesel(postgres_type(name = "audit_event_kind"))]
    pub struct AuditEventKind;
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
        actor_id -> Nullable<Text>,
        detail -> Jsonb,
        authentication_method -> Nullable<Text>,
        authenticated_credential_id -> Nullable<Text>,
        asserted_operator_localpart -> Nullable<Text>,
        prev_digest -> Nullable<Bytea>,
        audit_digest -> Nullable<Bytea>,
    }
}

diesel::table! {
    admin_tokens (key_id) {
        key_id -> Text,
        secret -> Bytea,
        label -> Nullable<Text>,
        expires_at -> Nullable<Timestamptz>,
        revoked_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::allow_tables_to_appear_in_same_query!(directory_audit, admin_tokens);
