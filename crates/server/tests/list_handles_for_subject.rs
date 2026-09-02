//! Conformance suite for `ak.find.directory.read.list_handles_for_subject.v1` (DIR-TBY-5,
//! R3.2 / arkret-spec @ b56cab1).
//!
//! These exercise the directory's reverse-handle-lookup response assembly
//! (disclosure / issuer_id-trust / audience / subject_id-mismatch filters, cursor
//! pagination, and the `claims[].subject_id == response.subject_id` invariant)
//! against the pure `assemble_response` core, so they run in CI without a
//! Postgres container. The full HTTP-path smoke (with seeded rows) lives in
//! the Docker-gated `tests/it/conformance.rs` harness.
//!
//! Cases (per the R3.2 task list):
//!   1. happy path — subject_id with 1 active claim returns 1 item.
//!   2. claim subject_id mismatch — response drops the foreign claim (and a response that would
//!      still carry a mismatch fails closed).
//!   3. audience-out-of-scope claim is filtered.
//!   4. issuer_id/domain outside the Realm's `handle_issuer_policy` is filtered.
//!   5. cursor pagination boundary.

use arkret_models_identity::primary_handle::{HandleIssuerAuthorityClass, HandleIssuerPolicyEntry};
use arkret_models_identity::{
    HANDLE_CLAIM_PROOF_DOMAIN, HANDLE_CLAIM_STATUS_DOMAIN, HandleClaim, HandleClaimCore,
    HandleClaimStatus, HandleClaimVariant, HandleVisibility,
};
use arkret_sdk::DirectoryListHandlesForSubjectRequestBody;
use chrono::{TimeZone, Utc};
use serde_json::json;
use server::ingest::DiscoverabilityDb;
use server::query::handles_for_subject::{SubjectHandleRow, assemble_response};

fn subject_id() -> arkret_sdk::DidCoreId {
    arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap()
}

fn account_id() -> arkret_sdk::AccountId {
    arkret_sdk::AccountId::new(
        subject_id(),
        arkret_sdk::DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
    )
}

fn req(
    realm_id: Option<&str>,
    requester_id: Option<&str>,
) -> DirectoryListHandlesForSubjectRequestBody {
    DirectoryListHandlesForSubjectRequestBody {
        account_id: account_id(),
        realm_id: realm_id.map(|r| arkret_sdk::RealmId::new(r.to_owned()).unwrap()),
        intent: None,
        requester_id: requester_id.map(|r| arkret_sdk::DidCoreId::new(r.to_owned()).unwrap()),
        proof_challenge: None,
        proofs: Vec::new(),
        as_of: None,
        cursor: None,
        limit: None,
    }
}

fn placeholder_proof(
    purpose: arkret_sdk::PayloadProofPurpose,
    domain: &str,
    created_at: chrono::DateTime<Utc>,
    audience: Option<&str>,
) -> arkret_sdk::PayloadProof {
    arkret_sdk::PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: arkret_sdk::DidUrl::new(
            "did:web:issuer_id.tea#assertion-1".to_owned(),
        )
        .unwrap(),
        payload_digest: arkret_sdk::Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        created_at,
        domain: Some(domain.to_owned()),
        audience: audience.map(|value| arkret_sdk::Audience::Single(value.to_owned())),
        proof_purpose: Some(purpose),
        jws: "header..signature".to_owned(),
    }
}

fn row(projection: serde_json::Value, disc: DiscoverabilityDb) -> SubjectHandleRow {
    let subject = projection["subject_id"].as_str().unwrap();
    let handle = projection["handle"].as_str().unwrap();
    let issuer = projection["issuer_id"]
        .as_str()
        .unwrap_or("ak:did_core:web:issuer_id.tea");
    let audience = projection["audience"].as_str();
    let issued_at =
        chrono::DateTime::parse_from_rfc3339(projection["created_at"].as_str().unwrap())
            .unwrap()
            .with_timezone(&Utc);
    let expires_at = chrono::DateTime::parse_from_rfc3339(
        projection["expires_at"]
            .as_str()
            .unwrap_or("2027-05-20T00:00:00.000Z"),
    )
    .unwrap()
    .with_timezone(&Utc);
    let as_of = issued_at + chrono::Duration::minutes(1);
    let mut core = HandleClaimCore {
        schema: HandleClaimCore::SCHEMA.to_owned(),
        handle: arkret_sdk::Handle::parse(handle).unwrap(),
        handle_aliases: Vec::new(),
        subject_account_id: arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new(subject.to_owned()).unwrap(),
            account_id().station_id,
        ),
        issuer_id: arkret_sdk::DidCoreId::new(issuer.to_owned()).unwrap(),
        claim: HandleClaimVariant::HandleBinding,
        visibility: if audience.is_some() {
            HandleVisibility::Restricted
        } else {
            HandleVisibility::Public
        },
        audience: audience.map(str::to_owned),
        issued_at,
        expires_at: Some(expires_at),
        source_refs: Vec::new(),
        proofs: [
            placeholder_proof(
                arkret_sdk::PayloadProofPurpose::IssuerAttestation,
                HANDLE_CLAIM_PROOF_DOMAIN,
                issued_at,
                audience,
            ),
            placeholder_proof(
                arkret_sdk::PayloadProofPurpose::HolderAcceptance,
                HANDLE_CLAIM_PROOF_DOMAIN,
                issued_at,
                audience,
            ),
        ],
    };
    let claim_digest = core.claim_digest().unwrap();
    for proof in &mut core.proofs {
        proof.payload_digest = claim_digest.clone();
    }
    let mut claim = HandleClaim {
        schema: HandleClaim::SCHEMA.to_owned(),
        claim: core,
        status: HandleClaimStatus::Verified,
        as_of,
        verifier_id: arkret_sdk::DidCoreId::new(issuer.to_owned()).unwrap(),
        verified_at: Some(as_of),
        revocation: None,
        fresh_until: as_of + chrono::Duration::minutes(5),
        status_proof: placeholder_proof(
            arkret_sdk::PayloadProofPurpose::StatusAttestation,
            HANDLE_CLAIM_STATUS_DOMAIN,
            as_of,
            audience,
        ),
    };
    claim.status_proof.payload_digest = claim.status_digest().unwrap();
    SubjectHandleRow::for_test(
        serde_json::to_value(claim).unwrap(),
        disc,
        Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
    )
}

/// Case 1 — happy path: a single active, directory-visible claim for the
/// subject_id returns exactly one claim whose subject_id equals the response
/// subject_id, and the primary handle is populated from the verified claim.
#[test]
fn happy_path_single_active_claim() {
    let rows = vec![row(
        json!({
            "subject_id": "ak:did_core:web:alice.example",
            "handle": "alice:example.com",
            "verified": true,
            "created_at": "2026-05-20T00:00:00.000Z"
        }),
        DiscoverabilityDb::Public,
    )];

    let response = assemble_response(&req(None, None), rows, None, 0, 20, None)
        .expect("happy path must not fail closed");

    assert_eq!(response.claims.len(), 1);
    assert_eq!(
        response.account_id.principal_id.as_str(),
        "ak:did_core:web:alice.example"
    );
    assert_eq!(
        response.claims[0]
            .claim
            .subject_account_id
            .principal_id
            .as_str(),
        "ak:did_core:web:alice.example"
    );
    assert_eq!(
        response.primary_handle.as_ref().unwrap().canonical(),
        "alice:example.com"
    );
    assert!(!response.has_more);
    assert!(response.next_cursor.is_none());
    // The SDK schema validator agrees the invariant holds.
    assert!(response.validate().is_ok());
}

/// Case 2 — claim subject_id mismatch: a row that asserts a DIFFERENT subject_id
/// than the request is dropped, so the response carries only the matching
/// claim (or none). Every surviving claim's subject_id equals response.subject_id.
#[test]
fn subject_mismatch_claim_is_dropped() {
    let rows = vec![
        row(
            json!({ "subject_id": "ak:did_core:web:eve.example", "handle": "eve:example.com", "created_at": "2026-05-20T00:00:00.000Z" }),
            DiscoverabilityDb::Public,
        ),
        row(
            json!({ "subject_id": "ak:did_core:web:alice.example", "handle": "alice:example.com", "created_at": "2026-05-20T00:00:00.000Z" }),
            DiscoverabilityDb::Public,
        ),
    ];

    let response = assemble_response(&req(None, None), rows, None, 0, 20, None)
        .expect("matching claim survives, foreign claim dropped");

    assert_eq!(response.claims.len(), 1);
    for claim in &response.claims {
        assert_eq!(
            claim.claim.subject_account_id.principal_id.as_str(),
            "ak:did_core:web:alice.example",
            "every surviving claim's subject_id must equal response.subject_id"
        );
    }
    assert!(response.validate().is_ok());
}

/// Case 2b — fail-closed: if a foreign-subject_id row is the ONLY candidate, the
/// response collapses to an empty claim set rather than ever surfacing a
/// claim whose subject_id differs from the response subject_id.
#[test]
fn subject_mismatch_only_candidate_returns_empty() {
    let rows = vec![row(
        json!({ "subject_id": "ak:did_core:web:eve.example", "handle": "eve:example.com", "created_at": "2026-05-20T00:00:00.000Z" }),
        DiscoverabilityDb::Public,
    )];

    let response = assemble_response(&req(None, None), rows, None, 0, 20, None)
        .expect("empty-but-valid response, not fail-closed");

    assert!(response.claims.is_empty());
    assert!(response.primary_handle.is_none());
    assert!(response.validate().is_ok());
}

/// Case 3 — audience filter: a claim that pins an `audience` mutually
/// exclusive with the requester_id context is filtered out.
#[test]
fn audience_out_of_scope_is_filtered() {
    let rows = vec![
        row(
            json!({
                "subject_id": "ak:did_core:web:alice.example",
                "handle": "scoped:example.com",
                "audience": "ak:did_core:web:someone-else.example",
                "created_at": "2026-05-20T00:00:00.000Z"
            }),
            DiscoverabilityDb::Public,
        ),
        row(
            json!({
                "subject_id": "ak:did_core:web:alice.example",
                "handle": "open:example.com",
                "created_at": "2026-05-20T00:00:00.000Z"
            }),
            DiscoverabilityDb::Public,
        ),
    ];

    // Requester is tea-org; the scoped claim's audience is someone-else, so it
    // is filtered; the unpinned claim survives.
    let body = req(None, Some("ak:did_core:web:tea-org.example"));
    let response = assemble_response(&body, rows, None, 0, 20, None).expect("ok");

    assert_eq!(response.claims.len(), 1);
    assert_eq!(
        response.claims[0].claim.handle.canonical(),
        "open:example.com"
    );
}

/// Case 3b — audience match: when the pinned audience equals the requester_id,
/// the claim is retained.
#[test]
fn audience_matching_requester_is_retained() {
    let rows = vec![row(
        json!({
            "subject_id": "ak:did_core:web:alice.example",
            "handle": "scoped:example.com",
            "audience": "ak:did_core:web:tea-org.example",
            "created_at": "2026-05-20T00:00:00.000Z"
        }),
        DiscoverabilityDb::Public,
    )];

    let body = req(None, Some("ak:did_core:web:tea-org.example"));
    let response = assemble_response(&body, rows, None, 0, 20, None).expect("ok");
    assert_eq!(response.claims.len(), 1);
}

/// Case 4 — issuer_id trust: with a Realm domain-scoped policy, claims whose
/// issuer_id is absent or whose domain is outside the entry are filtered.
#[test]
fn issuer_or_domain_outside_policy_is_filtered() {
    let rows = vec![
        row(
            json!({
                "subject_id": "ak:did_core:web:alice.example",
                "handle": "trusted:example.com",
                "issuer_id": "ak:did_core:web:issuer_id.tea",
                "created_at": "2026-05-20T00:00:00.000Z"
            }),
            DiscoverabilityDb::Public,
        ),
        row(
            json!({
                "subject_id": "ak:did_core:web:alice.example",
                "handle": "untrusted:example.com",
                "issuer_id": "ak:did_core:web:issuer_id.rogue",
                "created_at": "2026-05-20T00:00:00.000Z"
            }),
            DiscoverabilityDb::Public,
        ),
        row(
            json!({
                "subject_id": "ak:did_core:web:alice.example",
                "handle": "wrong:rogue.example",
                "issuer_id": "ak:did_core:web:issuer_id.tea",
                "created_at": "2026-05-20T00:00:00.000Z"
            }),
            DiscoverabilityDb::Public,
        ),
    ];

    let policy = vec![HandleIssuerPolicyEntry {
        issuer_id: arkret_sdk::DidCoreId::new("ak:did_core:web:issuer_id.tea").unwrap(),
        authorized_handle_domains: vec!["example.com".to_owned()],
        issuer_class: HandleIssuerAuthorityClass::DomainAuthority,
    }];
    // RealmId is a strict typed id carrying the complete 44-character token.
    let body = req(
        Some("ak:realm:AY0Z0alJlPB4P2wAIOCSTs_yNX_lm1mM5r3mhhQuKIFb"),
        None,
    );
    let response = assemble_response(&body, rows, Some(&policy), 0, 20, None).expect("ok");

    assert_eq!(response.claims.len(), 1);
    assert_eq!(
        response.claims[0].claim.issuer_id.as_str(),
        "ak:did_core:web:issuer_id.tea"
    );
}

/// Case 5 — cursor pagination: with three claims and a page size of 2, the
/// first page returns 2 + `has_more`, and the second page returns the
/// remaining 1 with `has_more=false`. Cursor minting is exercised through the
/// HTTP integration path because the pure assembler has no binding authority.
#[test]
fn cursor_pagination_boundary() {
    let rows = vec![
        row(
            json!({ "subject_id": "ak:did_core:web:alice.example", "handle": "a:example.com", "created_at": "2026-05-20T00:00:00.000Z" }),
            DiscoverabilityDb::Public,
        ),
        row(
            json!({ "subject_id": "ak:did_core:web:alice.example", "handle": "b:example.com", "created_at": "2026-05-20T00:00:00.000Z" }),
            DiscoverabilityDb::Public,
        ),
        row(
            json!({ "subject_id": "ak:did_core:web:alice.example", "handle": "c:example.com", "created_at": "2026-05-20T00:00:00.000Z" }),
            DiscoverabilityDb::Public,
        ),
    ];

    // First page (offset 0, limit 2).
    let page1 = assemble_response(&req(None, None), rows.clone(), None, 0, 2, None).expect("ok");
    assert_eq!(page1.claims.len(), 2);
    assert!(page1.has_more);
    assert!(page1.next_cursor.is_none());
    assert_eq!(page1.claims[0].claim.handle.canonical(), "a:example.com");
    assert_eq!(page1.claims[1].claim.handle.canonical(), "b:example.com");

    // The handler resolves the opaque cursor to offset 2 before invoking the
    // pure assembler.
    let body2 = req(None, None);
    let page2 = assemble_response(&body2, rows, None, 2, 2, None).expect("ok");
    assert_eq!(page2.claims.len(), 1);
    assert!(!page2.has_more);
    assert!(page2.next_cursor.is_none());
    assert_eq!(page2.claims[0].claim.handle.canonical(), "c:example.com");
}

/// A non-directory-visible (e.g. secret) row is dropped by the disclosure
/// gate even though its subject_id matches.
#[test]
fn non_visible_row_is_dropped_by_disclosure_gate() {
    let rows = vec![row(
        json!({ "subject_id": "ak:did_core:web:alice.example", "handle": "secret:example.com", "created_at": "2026-05-20T00:00:00.000Z" }),
        DiscoverabilityDb::Secret,
    )];

    let response = assemble_response(&req(None, None), rows, None, 0, 20, None).expect("ok");
    assert!(response.claims.is_empty());
}

/// A restricted handle stays invisible on this surface. The §9 operation table
/// gives `list_handles_for_subject` no `claim_presentations[]` input, and
/// `allowed_discoverers` selectors are claim-shaped, so there is no way to
/// satisfy them here — fail closed rather than disclose.
#[test]
fn restricted_claim_handle_is_never_disclosed_on_this_surface() {
    let rows = vec![row(
        json!({
            "subject_id": "ak:did_core:web:alice.example",
            "handle": "restricted:example.com",
            "created_at": "2026-05-20T00:00:00.000Z",
            "allowed_discoverers": [{
                "type": "claim",
                "claim_kind": "organization_membership",
                "issuer_id": "ak:did_core:web:issuer_id.tea",
                "organization_id": "ak:did_core:web:tea-org.example"
            }]
        }),
        DiscoverabilityDb::Restricted,
    )];

    let body = req(None, Some("ak:did_core:web:alice.example"));
    let response = assemble_response(&body, rows, None, 0, 20, None).expect("ok");

    assert!(response.claims.is_empty());
    assert!(response.primary_handle.is_none());
}
