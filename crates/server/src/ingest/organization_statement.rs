//! TBY-ORG-01/03 — ingest, verify, and lifecycle of `ak.realm.organization`
//! relationship statements.
//!
//! The directory never trusts a bare `organization_did` /
//! `owning_organizations` projection hint as an official organization
//! relationship. An official badge, organization scoping, or
//! directory-certifier relationship is only valid once it derives from an
//! `active`, in-validity-window, scope-covering `ak.realm.organization`
//! statement that has passed the canonical SDK verifier
//! ([`arkret_sdk::verify_realm_organization_statement`]).
//!
//! teabay observes these statements through the Realm `ak.realm.discovery`
//! announce body: a Realm whose discovery policy lists organization
//! relationships carries the verified `ak.realm.organization` payloads under
//! `discovery_state.organization_statements[]`. Each payload is verified
//! independently and, on success, projected into the
//! `verified_realm_organizations` index keyed by `(realm_id, organization_did,
//! relationship)` (the spec reducer cell subject).
//!
//! The delegation resolver is injected so the directory shares the exact
//! issuer-role / delegation invariants with soland and cotest. teabay does not
//! host an organization DID delegation store, so it wires the fail-closed
//! [`arkret_sdk::NoDelegationResolver`]: a `governance_service` /
//! `account_authority` statement that requires a delegation_ref cannot be
//! verified here and is rejected until soland exposes a delegation resolution
//! query.

use chrono::{DateTime, Utc};
use arkret_sdk::{
    NoDelegationResolver, RealmId, RealmOrganizationControlScope, RealmOrganizationPayload,
    RealmOrganizationRelationship, RealmOrganizationStatus, verify_realm_organization_statement,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde_json::Value as JsonValue;

use crate::db::Db;

/// Wire field on a Realm `discovery_state` that carries verified
/// `ak.realm.organization` relationship statements awaiting directory-side
/// re-verification.
pub(crate) const ORGANIZATION_STATEMENTS_FIELD: &str = "organization_statements";

/// Canonical snake_case wire form of a relationship discriminator.
fn relationship_as_str(relationship: RealmOrganizationRelationship) -> &'static str {
    match relationship {
        RealmOrganizationRelationship::Owner => "owner",
        RealmOrganizationRelationship::Governance => "governance",
        RealmOrganizationRelationship::Sponsor => "sponsor",
        RealmOrganizationRelationship::DirectoryCertifier => "directory_certifier",
    }
}

/// Canonical snake_case wire form of a control scope.
fn control_scope_as_str(scope: RealmOrganizationControlScope) -> &'static str {
    match scope {
        RealmOrganizationControlScope::OfficialBadge => "official_badge",
        RealmOrganizationControlScope::RealmAdmin => "realm_admin",
        RealmOrganizationControlScope::NotaryControl => "notary_control",
        RealmOrganizationControlScope::PolicyServer => "policy_server",
        RealmOrganizationControlScope::DeliveryBindingPolicy => "delivery_binding_policy",
        RealmOrganizationControlScope::DurabilityPolicy => "durability_policy",
        RealmOrganizationControlScope::ModerationPolicy => "moderation_policy",
        RealmOrganizationControlScope::RetentionPolicy => "retention_policy",
        RealmOrganizationControlScope::DirectoryListing => "directory_listing",
        RealmOrganizationControlScope::PlaintextVisibleService => "plaintext_visible_service",
    }
}

/// A `ak.realm.organization` statement that passed the SDK verifier and is
/// ready to be projected into (or removed from) the verified index.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedStatement {
    pub realm_id: String,
    pub organization_did: String,
    pub relationship: &'static str,
    pub control_scopes: Vec<String>,
    pub statement_id: String,
    pub statement_issued_at: DateTime<Utc>,
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub realm_frontier_digest: Option<String>,
    /// Whether the statement revokes (rather than asserts) the relationship.
    pub is_revocation: bool,
}

/// Why a candidate statement did not enter the verified index.
#[derive(Debug, Clone)]
pub(crate) struct RejectedStatement {
    pub statement_id: Option<String>,
    pub reason: String,
}

/// Outcome of validating the `organization_statements[]` carried by an
/// announce body.
#[derive(Debug, Default)]
pub(crate) struct StatementIngestOutcome {
    pub verified: Vec<VerifiedStatement>,
    pub rejected: Vec<RejectedStatement>,
}

/// Parse + verify the `ak.realm.organization` statements embedded in a Realm
/// `discovery_state`. Statements that are missing proof, expired, not-yet
/// valid, replay an inconsistent revocation flag, or whose issuer-role
/// requires an unresolvable delegation are rejected fail-closed and never
/// enter the verified index (TBY-ORG-01 acceptance).
///
/// `expected_realm_id` is the announce `resource_id` (the Realm the statement
/// MUST bind to). `now` is the evaluation clock.
pub(crate) fn verify_announced_statements(
    discovery_state: &JsonValue,
    expected_realm_id: &str,
    now: DateTime<Utc>,
) -> StatementIngestOutcome {
    let mut outcome = StatementIngestOutcome::default();

    let Ok(realm_id) = RealmId::new(expected_realm_id.to_owned()) else {
        // Only canonical `ak:realm:` resources can own a verified relationship.
        return outcome;
    };

    let Some(items) = discovery_state
        .get(ORGANIZATION_STATEMENTS_FIELD)
        .and_then(JsonValue::as_array)
    else {
        return outcome;
    };

    let resolver = NoDelegationResolver;
    for item in items {
        let payload: RealmOrganizationPayload = match serde_json::from_value(item.clone()) {
            Ok(payload) => payload,
            Err(error) => {
                outcome.rejected.push(RejectedStatement {
                    statement_id: item
                        .get("statement_id")
                        .and_then(JsonValue::as_str)
                        .map(str::to_owned),
                    reason: format!("malformed ak.realm.organization payload: {error}"),
                });
                continue;
            }
        };

        if let Err(error) = verify_realm_organization_statement(&payload, &realm_id, now, &resolver)
        {
            outcome.rejected.push(RejectedStatement {
                statement_id: Some(payload.statement_id.clone()),
                reason: error.to_string(),
            });
            continue;
        }

        outcome.verified.push(VerifiedStatement {
            realm_id: payload.realm_id.as_str().to_owned(),
            organization_did: payload.organization_id.as_str().to_owned(),
            relationship: relationship_as_str(payload.relationship),
            control_scopes: payload
                .control_scopes
                .iter()
                .map(|scope| control_scope_as_str(*scope).to_owned())
                .collect(),
            statement_id: payload.statement_id.clone(),
            statement_issued_at: payload.issued_at,
            not_before: payload.not_before,
            expires_at: payload.expires_at,
            realm_frontier_digest: payload
                .realm_frontier_digest
                .as_ref()
                .map(|digest| digest.to_string()),
            is_revocation: matches!(payload.status, RealmOrganizationStatus::Revoked),
        });
    }

    outcome
}

/// Persist the verified statements for one announce into the
/// `verified_realm_organizations` index.
///
/// Lifecycle (TBY-ORG-03):
///   * an `active` statement upserts the `(realm_id, organization_did, relationship)` row, but only
///     when its `statement_issued_at` is at least as recent as the stored statement — a replayed
///     older `active` statement can never overwrite a newer revocation;
///   * a `revoked` statement removes the row (the badge disappears on the next directory refresh)
///     when it is at least as recent as the stored row.
pub(crate) async fn persist_verified_statements(
    db: &Db,
    statements: &[VerifiedStatement],
    source_announce_id: &str,
) -> anyhow::Result<()> {
    use crate::schema::verified_realm_organizations::dsl as v;

    if statements.is_empty() {
        return Ok(());
    }
    let mut conn = db.get().await?;

    for statement in statements {
        // Read the stored statement_issued_at for the cell subject to enforce
        // monotonic replay protection regardless of insert/revoke direction.
        let prior_issued_at: Option<DateTime<Utc>> = v::verified_realm_organizations
            .filter(v::realm_id.eq(&statement.realm_id))
            .filter(v::organization_did.eq(&statement.organization_did))
            .filter(v::relationship.eq(statement.relationship))
            .select(v::statement_issued_at)
            .first::<DateTime<Utc>>(&mut *conn)
            .await
            .optional()?;

        if let Some(prior) = prior_issued_at
            && statement.statement_issued_at < prior
        {
            // Stale replay: a newer statement already governs this triple.
            continue;
        }

        if statement.is_revocation {
            diesel::delete(
                v::verified_realm_organizations
                    .filter(v::realm_id.eq(&statement.realm_id))
                    .filter(v::organization_did.eq(&statement.organization_did))
                    .filter(v::relationship.eq(statement.relationship)),
            )
            .execute(&mut *conn)
            .await?;
            continue;
        }

        diesel::insert_into(v::verified_realm_organizations)
            .values((
                v::realm_id.eq(&statement.realm_id),
                v::organization_did.eq(&statement.organization_did),
                v::relationship.eq(statement.relationship),
                v::control_scopes.eq(&statement.control_scopes),
                v::statement_id.eq(&statement.statement_id),
                v::statement_issued_at.eq(statement.statement_issued_at),
                v::not_before.eq(statement.not_before),
                v::expires_at.eq(statement.expires_at),
                v::realm_frontier_digest.eq(statement.realm_frontier_digest.as_deref()),
                v::stale.eq(false),
                v::verified_at.eq(Utc::now()),
                v::source_announce_id.eq(Some(source_announce_id)),
            ))
            .on_conflict((v::realm_id, v::organization_did, v::relationship))
            .do_update()
            .set((
                v::control_scopes.eq(&statement.control_scopes),
                v::statement_id.eq(&statement.statement_id),
                v::statement_issued_at.eq(statement.statement_issued_at),
                v::not_before.eq(statement.not_before),
                v::expires_at.eq(statement.expires_at),
                v::realm_frontier_digest.eq(statement.realm_frontier_digest.as_deref()),
                // A fresh active statement clears any prior stale flag.
                v::stale.eq(false),
                v::verified_at.eq(Utc::now()),
                v::source_announce_id.eq(Some(source_announce_id)),
            ))
            .execute(&mut *conn)
            .await?;
    }

    Ok(())
}

/// A verified relationship row as surfaced to the query layer (TBY-ORG-02).
#[derive(Debug, Clone, Queryable)]
pub(crate) struct VerifiedRelationshipRow {
    pub organization_did: String,
    pub relationship: String,
    pub control_scopes: Vec<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl VerifiedRelationshipRow {
    /// Whether the relationship is currently inside its validity window at
    /// `now` (`not_before <= now < expires_at`).
    pub(crate) fn is_effective_active(&self, now: DateTime<Utc>) -> bool {
        if self.not_before.is_some_and(|nbf| now < nbf) {
            return false;
        }
        if self.expires_at.is_some_and(|exp| now >= exp) {
            return false;
        }
        true
    }

    /// Whether the relationship covers a given control scope.
    pub(crate) fn covers_scope(&self, scope: &str) -> bool {
        self.control_scopes.iter().any(|s| s == scope)
    }
}

/// Load the currently fresh (non-stale) verified relationships for a Realm.
/// Expired relationships are filtered at the SQL level; staleness is a stored
/// flag set by [`mark_stale_behind_frontier`].
pub(crate) async fn load_verified_relationships(
    db: &Db,
    realm_id: &str,
    now: DateTime<Utc>,
) -> anyhow::Result<Vec<VerifiedRelationshipRow>> {
    use crate::schema::verified_realm_organizations::dsl as v;
    let mut conn = db.get().await?;
    let rows: Vec<VerifiedRelationshipRow> = v::verified_realm_organizations
        .filter(v::realm_id.eq(realm_id))
        .filter(v::stale.eq(false))
        .filter(v::expires_at.is_null().or(v::expires_at.gt(now)))
        .select((
            v::organization_did,
            v::relationship,
            v::control_scopes,
            v::not_before,
            v::expires_at,
        ))
        .load(&mut *conn)
        .await?;
    Ok(rows)
}

/// TBY-ORG-03 — sweep expired verified relationships out of the index. Called
/// by the freshness worker; removing the row makes the official badge
/// disappear on the next directory refresh.
pub(crate) async fn purge_expired_relationships(
    db: &Db,
    now: DateTime<Utc>,
) -> anyhow::Result<usize> {
    use crate::schema::verified_realm_organizations::dsl as v;
    let mut conn = db.get().await?;
    let deleted = diesel::delete(
        v::verified_realm_organizations
            .filter(v::expires_at.is_not_null())
            .filter(v::expires_at.le(now)),
    )
    .execute(&mut *conn)
    .await?;
    Ok(deleted)
}

/// TBY-ORG-03 — mark a Realm's verified relationships stale when the live
/// Realm control frontier digest has advanced past the digest the
/// organization evaluated. A stale relationship stops surfacing as an
/// effective verified badge (it is filtered by `load_verified_relationships`)
/// without losing the audit row.
pub(crate) async fn mark_stale_behind_frontier(
    db: &Db,
    realm_id: &str,
    current_frontier_digest: &str,
) -> anyhow::Result<usize> {
    use crate::schema::verified_realm_organizations::dsl as v;
    let mut conn = db.get().await?;
    let updated = diesel::update(
        v::verified_realm_organizations
            .filter(v::realm_id.eq(realm_id))
            .filter(v::stale.eq(false))
            .filter(v::realm_frontier_digest.is_not_null())
            .filter(v::realm_frontier_digest.ne(current_frontier_digest)),
    )
    .set(v::stale.eq(true))
    .execute(&mut *conn)
    .await?;
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    const REALM: &str = "ak:realm:0196419b-0000-7000-8000-000000000010";
    const ORG: &str = "did:webvh:example.test:orgs:org1";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 25, 12, 0, 0).unwrap()
    }

    fn active_statement(relationship: &str, scopes: &[&str]) -> JsonValue {
        json!({
            "statement_id": "org-stmt-1",
            "realm_id": REALM,
            "organization_id": ORG,
            "relationship": relationship,
            "status": "active",
            "control_scopes": scopes,
            "issued_at": "2026-06-25T00:00:00Z",
            "authorization": {
                "issuer": ORG,
                "issuer_role": "organization_did",
                "verification_method": format!("{ORG}#k1"),
                "signed_at": "2026-06-25T00:00:00Z",
                "proof": "c2ln"
            }
        })
    }

    #[test]
    fn active_owner_statement_is_verified() {
        let discovery = json!({
            ORGANIZATION_STATEMENTS_FIELD: [active_statement("owner", &["official_badge", "realm_admin"])]
        });
        let outcome = verify_announced_statements(&discovery, REALM, now());
        assert_eq!(outcome.verified.len(), 1);
        assert!(outcome.rejected.is_empty());
        let verified = &outcome.verified[0];
        assert_eq!(verified.relationship, "owner");
        assert!(
            verified
                .control_scopes
                .iter()
                .any(|s| s == "official_badge")
        );
        assert!(!verified.is_revocation);
    }

    #[test]
    fn missing_proof_statement_is_rejected() {
        let mut statement = active_statement("owner", &["official_badge"]);
        statement["authorization"]["proof"] = json!("   ");
        let discovery = json!({ ORGANIZATION_STATEMENTS_FIELD: [statement] });
        let outcome = verify_announced_statements(&discovery, REALM, now());
        assert!(outcome.verified.is_empty());
        assert_eq!(outcome.rejected.len(), 1);
    }

    #[test]
    fn expired_statement_is_rejected() {
        let mut statement = active_statement("owner", &["official_badge"]);
        statement["expires_at"] = json!("2026-06-25T06:00:00Z");
        let discovery = json!({ ORGANIZATION_STATEMENTS_FIELD: [statement] });
        let outcome = verify_announced_statements(&discovery, REALM, now());
        assert!(outcome.verified.is_empty());
        assert_eq!(outcome.rejected.len(), 1);
    }

    #[test]
    fn realm_id_mismatch_is_rejected() {
        let discovery = json!({
            ORGANIZATION_STATEMENTS_FIELD: [active_statement("owner", &["official_badge"])]
        });
        let outcome = verify_announced_statements(
            &discovery,
            "ak:realm:0196419b-0000-7000-8000-000000000099",
            now(),
        );
        assert!(outcome.verified.is_empty());
        assert_eq!(outcome.rejected.len(), 1);
    }

    #[test]
    fn revoked_statement_is_marked_revocation() {
        let mut statement = active_statement("owner", &["official_badge"]);
        statement["status"] = json!("revoked");
        statement["revokes_statement_id"] = json!("org-stmt-0");
        let discovery = json!({ ORGANIZATION_STATEMENTS_FIELD: [statement] });
        let outcome = verify_announced_statements(&discovery, REALM, now());
        assert_eq!(outcome.verified.len(), 1);
        assert!(outcome.verified[0].is_revocation);
    }

    #[test]
    fn delegated_role_without_resolver_fails_closed() {
        let mut statement = active_statement("governance", &["official_badge"]);
        statement["authorization"]["issuer_role"] = json!("governance_service");
        statement["authorization"]["delegation_ref"] =
            json!("ak:grant:01904100-0000-7000-8000-000000000001");
        let discovery = json!({ ORGANIZATION_STATEMENTS_FIELD: [statement] });
        let outcome = verify_announced_statements(&discovery, REALM, now());
        assert!(outcome.verified.is_empty());
        assert_eq!(outcome.rejected.len(), 1);
    }

    #[test]
    fn effective_active_respects_validity_window() {
        let row = VerifiedRelationshipRow {
            organization_did: ORG.to_owned(),
            relationship: "owner".to_owned(),
            control_scopes: vec!["official_badge".to_owned()],
            not_before: None,
            expires_at: Some(Utc.with_ymd_and_hms(2026, 6, 25, 6, 0, 0).unwrap()),
        };
        assert!(!row.is_effective_active(now()));
        assert!(row.covers_scope("official_badge"));
        assert!(!row.covers_scope("realm_admin"));
    }
}
