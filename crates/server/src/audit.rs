//! Append-only operator-readable audit log.
//!
//! Operational audit history is separate from the public Realm index.
//! The local index maintenance process appends on the same transaction as
//! its mutation; HTTP remains audit-read-only. Historical event vocabulary
//! remains readable and verifiable.
//!
//! A.8.5 — every row carries a SHA-256 chained digest computed over the
//! canonical row plus the previous row's digest, so a tamper of any
//! historical row breaks the subsequent chain. The PostgreSQL trigger
//! `directory_audit_block_update` makes that statically observable: the
//! database itself refuses `UPDATE`s on this table.

use arkret_sdk::DidCoreId;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use flagon_contracts::{
    AuditChainVerificationFailure, AuditChainVerificationOutcome, AuthenticatedCredentialId,
};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::schema::directory_audit;
use crate::util::lower_hex;

/// The operational audit may name a Directory resource, but only Realm is
/// a registered public resource kind in current-v1.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    diesel::AsExpression,
    diesel::FromSqlRow,
)]
#[diesel(sql_type = crate::schema::sql_types::ResourceKind)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryResourceKindDb {
    Realm,
}

crate::db_enum::impl_pg_enum!(
    DirectoryResourceKindDb,
    crate::schema::sql_types::ResourceKind,
    { DirectoryResourceKindDb::Realm => "realm" }
);

impl From<flagon_contracts::DirectoryResourceKind> for DirectoryResourceKindDb {
    fn from(value: flagon_contracts::DirectoryResourceKind) -> Self {
        match value {
            flagon_contracts::DirectoryResourceKind::Realm => Self::Realm,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, diesel::AsExpression, diesel::FromSqlRow)]
#[diesel(sql_type = crate::schema::sql_types::AuditEventKind)]
pub enum AuditEventKind {
    IngestAccepted,
    IngestRejected,
    RevalidationSucceeded,
    RevalidationFailed,
    Withdrawal,
    OperatorTakedown,
    AllowlistAdded,
    AllowlistRemoved,
    AdminResourceUpserted,
    AdminResourceDeleted,
    ExpiryPurged,
    /// coland broadcast a `consent_revoke{scope=any}` and the directory
    /// invalidated the actor's reachability projection.
    ConsentRevokeInvalidation,
    /// A `ak.realm.destroy` anchor was observed; the row was flipped to its
    /// tombstone projection.
    RealmDestroyed,
    /// A federation announce request hit the cache after the underlying
    /// service key was revoked. We served the cached body with
    /// `historical_only=true` and skipped side effects.
    IngestHistoricalOnly,
}

crate::db_enum::impl_pg_enum!(AuditEventKind, crate::schema::sql_types::AuditEventKind, {
    AuditEventKind::IngestAccepted => "ingest_accepted",
    AuditEventKind::IngestRejected => "ingest_rejected",
    AuditEventKind::RevalidationSucceeded => "revalidation_succeeded",
    AuditEventKind::RevalidationFailed => "revalidation_failed",
    AuditEventKind::Withdrawal => "withdrawal",
    AuditEventKind::OperatorTakedown => "operator_takedown",
    AuditEventKind::AllowlistAdded => "allowlist_added",
    AuditEventKind::AllowlistRemoved => "allowlist_removed",
    AuditEventKind::AdminResourceUpserted => "admin_resource_upserted",
    AuditEventKind::AdminResourceDeleted => "admin_resource_deleted",
    AuditEventKind::ExpiryPurged => "expiry_purged",
    AuditEventKind::ConsentRevokeInvalidation => "consent_revoke_invalidation",
    AuditEventKind::RealmDestroyed => "realm_destroyed",
    AuditEventKind::IngestHistoricalOnly => "ingest_historical_only",
});

#[derive(Debug, Insertable)]
#[diesel(table_name = directory_audit)]
struct NewAuditRow<'a> {
    occurred_at: DateTime<Utc>,
    kind: AuditEventKind,
    resource_kind: Option<DirectoryResourceKindDb>,
    resource_id: Option<&'a str>,
    /// DID that initiated the audited operation — the resource's
    /// `station_id`, the directory's own `service_id`, or an
    /// operator DID depending on the path. This is NOT a spec Realm `Actor`
    /// object; it is the initiating principal. For credential-vs-claim
    /// Credential and unverified byline metadata live in their dedicated fields.
    actor_id: Option<&'a str>,
    detail: JsonValue,
    authentication_method: Option<&'a str>,
    authenticated_credential_id: Option<&'a str>,
    asserted_operator_localpart: Option<&'a str>,
    prev_digest: Option<Vec<u8>>,
    audit_digest: Option<Vec<u8>>,
}

#[derive(Debug, Queryable)]
struct AuditChainRow {
    audit_id: i64,
    occurred_at: DateTime<Utc>,
    kind: AuditEventKind,
    resource_kind: Option<DirectoryResourceKindDb>,
    resource_id: Option<String>,
    actor_id: Option<String>,
    detail: JsonValue,
    authentication_method: Option<String>,
    authenticated_credential_id: Option<String>,
    asserted_operator_localpart: Option<String>,
    prev_digest: Option<Vec<u8>>,
    audit_digest: Option<Vec<u8>>,
}

/// Principal / local credential / asserted localpart split for chained audit.
#[derive(Debug, Clone, Default)]
pub struct ActorIdentity<'a> {
    pub authentication_method: Option<&'a str>,
    pub authenticated_credential_id: Option<&'a str>,
    pub asserted_operator_localpart: Option<&'a str>,
}

/// Convenience wrapper for callers that do not have separate
/// authentication metadata. The chained-digest write goes through
/// `record_with_identity`.
pub async fn record(
    db: &Db,
    kind: AuditEventKind,
    resource_kind: Option<DirectoryResourceKindDb>,
    resource_id: Option<&str>,
    actor_id: Option<&str>,
    detail: JsonValue,
) -> anyhow::Result<()> {
    record_with_identity(
        db,
        kind,
        resource_kind,
        resource_id,
        actor_id,
        detail,
        ActorIdentity {
            authentication_method: None,
            authenticated_credential_id: None,
            asserted_operator_localpart: None,
        },
    )
    .await
}

/// Chained-digest audit write. Reads the previous `audit_digest` from
/// the most-recent row (NULL on the very first row), computes
/// `sha256(canonical(row) || prev_digest)`, and inserts. A fixed
/// PostgreSQL advisory transaction lock serializes concurrent audit writers
/// before the prev-digest read, so READ COMMITTED cannot fork the chain.
pub async fn record_with_identity(
    db: &Db,
    kind: AuditEventKind,
    resource_kind: Option<DirectoryResourceKindDb>,
    resource_id: Option<&str>,
    actor_id: Option<&str>,
    detail: JsonValue,
    identity: ActorIdentity<'_>,
) -> anyhow::Result<()> {
    let mut conn = db.get().await?;
    conn.transaction::<_, anyhow::Error, _>(async move |conn| {
        record_on_connection(
            conn,
            kind,
            resource_kind,
            resource_id,
            actor_id,
            detail,
            identity,
        )
        .await
    })
    .await
}

/// A shared lock order for local index mutations and their chained audit.
pub(crate) async fn lock_chain(conn: &mut AsyncPgConnection) -> anyhow::Result<()> {
    diesel::sql_query("SELECT pg_advisory_xact_lock(1952805748, 1635018092)")
        .execute(conn)
        .await?;
    Ok(())
}

/// Append within the caller's transaction so index state and audit cannot diverge.
pub(crate) async fn record_on_connection(
    conn: &mut AsyncPgConnection,
    kind: AuditEventKind,
    resource_kind: Option<DirectoryResourceKindDb>,
    resource_id: Option<&str>,
    actor_id: Option<&str>,
    detail: JsonValue,
    identity: ActorIdentity<'_>,
) -> anyhow::Result<()> {
    let actor_id = actor_id.map(DidCoreId::new).transpose()?;
    lock_chain(conn).await?;
    let prev_digest: Option<Vec<u8>> = directory_audit::table
        .order(directory_audit::audit_id.desc())
        .select(directory_audit::audit_digest)
        .first::<Option<Vec<u8>>>(&mut *conn)
        .await
        .optional()?
        .flatten();

    let now = Utc::now();
    let occurred_at = DateTime::<Utc>::from_timestamp_micros(now.timestamp_micros())
        .ok_or_else(|| anyhow::anyhow!("current audit timestamp is out of range"))?;
    let row_digest = compute_row_digest(
        occurred_at,
        kind,
        resource_kind,
        resource_id,
        actor_id.as_ref().map(DidCoreId::as_str),
        &detail,
        &identity,
        prev_digest.as_deref(),
    )?;

    diesel::insert_into(directory_audit::table)
        .values(NewAuditRow {
            occurred_at,
            kind,
            resource_kind,
            resource_id,
            actor_id: actor_id.as_ref().map(DidCoreId::as_str),
            detail,
            authentication_method: identity.authentication_method,
            authenticated_credential_id: identity.authenticated_credential_id,
            asserted_operator_localpart: identity.asserted_operator_localpart,
            prev_digest,
            audit_digest: Some(row_digest),
        })
        .execute(&mut *conn)
        .await?;
    Ok(())
}

pub async fn verify_chain(db: &Db) -> anyhow::Result<AuditChainVerificationOutcome> {
    let mut conn = db.get().await?;
    let rows: Vec<AuditChainRow> = directory_audit::table
        .order(directory_audit::audit_id.asc())
        .select((
            directory_audit::audit_id,
            directory_audit::occurred_at,
            directory_audit::kind,
            directory_audit::resource_kind,
            directory_audit::resource_id,
            directory_audit::actor_id,
            directory_audit::detail,
            directory_audit::authentication_method,
            directory_audit::authenticated_credential_id,
            directory_audit::asserted_operator_localpart,
            directory_audit::prev_digest,
            directory_audit::audit_digest,
        ))
        .load(&mut *conn)
        .await?;

    let checked_rows = rows.len() as i64;
    let mut chain_rows = 0_i64;
    let mut first_audit_id = None;
    let mut last_audit_id = None;
    let mut expected_prev: Option<Vec<u8>> = None;
    let mut head_digest: Option<Vec<u8>> = None;
    let mut chain_started = false;

    for row in rows {
        let Some(actual_digest) = row.audit_digest.as_ref() else {
            if chain_started {
                return Ok(chain_failure(
                    checked_rows,
                    chain_rows,
                    first_audit_id,
                    last_audit_id,
                    head_digest.as_deref(),
                    row.audit_id,
                    "missing audit_digest after chain start",
                    None,
                    None,
                ));
            }
            continue;
        };

        if !chain_started {
            if row.prev_digest.is_some() {
                return Ok(chain_failure(
                    checked_rows,
                    chain_rows,
                    first_audit_id,
                    last_audit_id,
                    head_digest.as_deref(),
                    row.audit_id,
                    "first chained row has non-null prev_digest",
                    None,
                    row.prev_digest.as_deref(),
                ));
            }
            chain_started = true;
            first_audit_id = Some(row.audit_id);
        } else if row.prev_digest.as_deref() != expected_prev.as_deref() {
            return Ok(chain_failure(
                checked_rows,
                chain_rows,
                first_audit_id,
                last_audit_id,
                head_digest.as_deref(),
                row.audit_id,
                "prev_digest does not match previous audit_digest",
                expected_prev.as_deref(),
                row.prev_digest.as_deref(),
            ));
        }

        let actor_id = row.actor_id.map(DidCoreId::new).transpose()?;
        let authenticated_credential_id = row
            .authenticated_credential_id
            .map(AuthenticatedCredentialId::new)
            .transpose()
            .map_err(anyhow::Error::msg)?;
        let identity = ActorIdentity {
            authentication_method: row.authentication_method.as_deref(),
            authenticated_credential_id: authenticated_credential_id
                .as_ref()
                .map(AuthenticatedCredentialId::as_str),
            asserted_operator_localpart: row.asserted_operator_localpart.as_deref(),
        };
        let expected_digest = compute_row_digest(
            row.occurred_at,
            row.kind,
            row.resource_kind,
            row.resource_id.as_deref(),
            actor_id.as_ref().map(DidCoreId::as_str),
            &row.detail,
            &identity,
            row.prev_digest.as_deref(),
        )?;
        if expected_digest.as_slice() != actual_digest.as_slice() {
            return Ok(chain_failure(
                checked_rows,
                chain_rows,
                first_audit_id,
                last_audit_id,
                head_digest.as_deref(),
                row.audit_id,
                "audit_digest does not match recomputed digest",
                Some(expected_digest.as_slice()),
                Some(actual_digest.as_slice()),
            ));
        }

        chain_rows += 1;
        last_audit_id = Some(row.audit_id);
        head_digest = Some(actual_digest.clone());
        expected_prev = Some(actual_digest.clone());
    }

    Ok(AuditChainVerificationOutcome {
        ok: true,
        checked_rows,
        chain_rows,
        first_audit_id,
        last_audit_id,
        head_digest: head_digest.as_deref().map(lower_hex),
        failure: None,
    })
}

/// Canonical digest input. Includes every operator-meaningful field so
/// any tamper (e.g. swapping `detail.reason`, blanking `actor_id`) breaks
/// the chain.
#[allow(clippy::too_many_arguments)]
fn compute_row_digest(
    occurred_at: DateTime<Utc>,
    kind: AuditEventKind,
    resource_kind: Option<DirectoryResourceKindDb>,
    resource_id: Option<&str>,
    actor_id: Option<&str>,
    detail: &JsonValue,
    identity: &ActorIdentity<'_>,
    prev_digest: Option<&[u8]>,
) -> anyhow::Result<Vec<u8>> {
    let canonical = json!({
        "occurred_at": occurred_at.to_rfc3339(),
        "kind": kind.as_pg(),
        "resource_kind": resource_kind.map(DirectoryResourceKindDb::as_pg),
        "resource_id": resource_id,
        "actor_id": actor_id,
        "detail": detail,
        "authentication_method": identity.authentication_method,
        "authenticated_credential_id": identity.authenticated_credential_id,
        "asserted_operator_localpart": identity.asserted_operator_localpart,
    });
    // Use the shared SDK canonical serializer so "canonical row digest" is
    // accurate and matches the rest of the stack. Serialization failure is
    // fatal (fail-loud): a silent empty-bytes fallback would let differing
    // rows collide and break the tamper-evident chain.
    let canonical_bytes = arkret_sdk::canonical::canonical_json_bytes(&canonical)?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical_bytes);
    if let Some(prev) = prev_digest {
        hasher.update(prev);
    }
    Ok(hasher.finalize().to_vec())
}

#[allow(clippy::too_many_arguments)]
fn chain_failure(
    checked_rows: i64,
    chain_rows: i64,
    first_audit_id: Option<i64>,
    last_audit_id: Option<i64>,
    head_digest: Option<&[u8]>,
    audit_id: i64,
    reason: &str,
    expected: Option<&[u8]>,
    actual: Option<&[u8]>,
) -> AuditChainVerificationOutcome {
    AuditChainVerificationOutcome {
        ok: false,
        checked_rows,
        chain_rows,
        first_audit_id,
        last_audit_id,
        head_digest: head_digest.map(lower_hex),
        failure: Some(AuditChainVerificationFailure {
            audit_id,
            reason: reason.to_owned(),
            expected: expected.map(lower_hex),
            actual: actual.map(lower_hex),
        }),
    }
}
