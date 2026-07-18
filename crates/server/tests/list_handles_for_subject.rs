//! Conformance suite for `ak.find.directory.query.list_handles_for_subject` (DIR-TBY-5,
//! R3.2 / arkret-spec @ b56cab1).
//!
//! These exercise the directory's reverse-handle-lookup response assembly
//! (disclosure / issuer-trust / audience / subject-mismatch filters, cursor
//! pagination, and the `claims[].subject == response.subject` invariant)
//! against the pure `assemble_response` core, so they run in CI without a
//! Postgres container. The full HTTP-path smoke (with seeded rows) lives in
//! the Docker-gated `tests/it/conformance.rs` harness.
//!
//! Cases (per the R3.2 task list):
//!   1. happy path — subject with 1 active claim returns 1 item.
//!   2. claim subject mismatch — response drops the foreign claim (and a response that would still
//!      carry a mismatch fails closed).
//!   3. audience-out-of-scope claim is filtered.
//!   4. issuer not in the Realm's `accepted_issuers` is filtered.
//!   5. cursor pagination boundary.

use arkret_sdk::DirectoryListHandlesForSubjectRequestBody;
use chrono::{TimeZone, Utc};
use serde_json::json;
use server::filter::discoverers::VerifiedRestrictedClaims;
use server::ingest::DiscoverabilityDb;
use server::query::handles_for_subject::{SubjectHandleRow, assemble_response};

fn subject() -> arkret_sdk::Did {
    arkret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap()
}

fn req(
    realm_id: Option<&str>,
    requester: Option<&str>,
) -> DirectoryListHandlesForSubjectRequestBody {
    DirectoryListHandlesForSubjectRequestBody {
        subject: subject(),
        realm_id: realm_id.map(|r| arkret_sdk::RealmId::new(r.to_owned()).unwrap()),
        intent: None,
        requester: requester.map(|r| arkret_sdk::Did::new(r.to_owned()).unwrap()),
        proof_challenge: None,
        proofs: Vec::new(),
        as_of: None,
        cursor: None,
        limit: None,
    }
}

fn row(projection: serde_json::Value, disc: DiscoverabilityDb) -> SubjectHandleRow {
    SubjectHandleRow::for_test(
        projection,
        disc,
        Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
    )
}

/// Case 1 — happy path: a single active, directory-visible claim for the
/// subject returns exactly one claim whose subject equals the response
/// subject, and the primary handle is populated from the verified claim.
#[test]
fn happy_path_single_active_claim() {
    let rows = vec![row(
        json!({
            "did": "did:web:alice.example",
            "handle": "alice:example.com",
            "verified": true
        }),
        DiscoverabilityDb::Public,
    )];

    let response = assemble_response(
        &req(None, None),
        rows,
        &[],
        &VerifiedRestrictedClaims::default(),
        0,
        20,
        None,
    )
    .expect("happy path must not fail closed");

    assert_eq!(response.claims.len(), 1);
    assert_eq!(response.subject.as_str(), "did:web:alice.example");
    assert_eq!(
        response.claims[0].subject.as_ref().unwrap().as_str(),
        "did:web:alice.example"
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

/// Case 2 — claim subject mismatch: a row that asserts a DIFFERENT subject
/// than the request is dropped, so the response carries only the matching
/// claim (or none). Every surviving claim's subject equals response.subject.
#[test]
fn subject_mismatch_claim_is_dropped() {
    let rows = vec![
        row(
            json!({ "did": "did:web:eve.example", "handle": "eve:example.com" }),
            DiscoverabilityDb::Public,
        ),
        row(
            json!({ "did": "did:web:alice.example", "handle": "alice:example.com" }),
            DiscoverabilityDb::Public,
        ),
    ];

    let response = assemble_response(
        &req(None, None),
        rows,
        &[],
        &VerifiedRestrictedClaims::default(),
        0,
        20,
        None,
    )
    .expect("matching claim survives, foreign claim dropped");

    assert_eq!(response.claims.len(), 1);
    for claim in &response.claims {
        assert_eq!(
            claim.subject.as_ref().unwrap().as_str(),
            "did:web:alice.example",
            "every surviving claim's subject must equal response.subject"
        );
    }
    assert!(response.validate().is_ok());
}

/// Case 2b — fail-closed: if a foreign-subject row is the ONLY candidate, the
/// response collapses to an empty claim set rather than ever surfacing a
/// claim whose subject differs from the response subject.
#[test]
fn subject_mismatch_only_candidate_returns_empty() {
    let rows = vec![row(
        json!({ "did": "did:web:eve.example", "handle": "eve:example.com" }),
        DiscoverabilityDb::Public,
    )];

    let response = assemble_response(
        &req(None, None),
        rows,
        &[],
        &VerifiedRestrictedClaims::default(),
        0,
        20,
        None,
    )
    .expect("empty-but-valid response, not fail-closed");

    assert!(response.claims.is_empty());
    assert!(response.primary_handle.is_none());
    assert!(response.validate().is_ok());
}

/// Case 3 — audience filter: a claim that pins an `audience` mutually
/// exclusive with the requester context is filtered out.
#[test]
fn audience_out_of_scope_is_filtered() {
    let rows = vec![
        row(
            json!({
                "did": "did:web:alice.example",
                "handle": "scoped:example.com",
                "audience": "did:web:someone-else.example"
            }),
            DiscoverabilityDb::Public,
        ),
        row(
            json!({
                "did": "did:web:alice.example",
                "handle": "open:example.com"
            }),
            DiscoverabilityDb::Public,
        ),
    ];

    // Requester is tea-org; the scoped claim's audience is someone-else, so it
    // is filtered; the unpinned claim survives.
    let body = req(None, Some("did:web:tea-org.example"));
    let response = assemble_response(
        &body,
        rows,
        &[],
        &VerifiedRestrictedClaims::default(),
        0,
        20,
        None,
    )
    .expect("ok");

    assert_eq!(response.claims.len(), 1);
    assert_eq!(
        response.claims[0].handle.as_ref().unwrap().canonical(),
        "open:example.com"
    );
}

/// Case 3b — audience match: when the pinned audience equals the requester,
/// the claim is retained.
#[test]
fn audience_matching_requester_is_retained() {
    let rows = vec![row(
        json!({
            "did": "did:web:alice.example",
            "handle": "scoped:example.com",
            "audience": "did:web:tea-org.example"
        }),
        DiscoverabilityDb::Public,
    )];

    let body = req(None, Some("did:web:tea-org.example"));
    let response = assemble_response(
        &body,
        rows,
        &[],
        &VerifiedRestrictedClaims::default(),
        0,
        20,
        None,
    )
    .expect("ok");
    assert_eq!(response.claims.len(), 1);
}

/// Case 4 — issuer trust: with a Realm `accepted_issuers` set, claims whose
/// issuer is not in the set are filtered.
#[test]
fn issuer_not_in_accepted_issuers_is_filtered() {
    let rows = vec![
        row(
            json!({
                "did": "did:web:alice.example",
                "handle": "trusted:example.com",
                "issuer": "did:web:issuer.tea"
            }),
            DiscoverabilityDb::Public,
        ),
        row(
            json!({
                "did": "did:web:alice.example",
                "handle": "untrusted:example.com",
                "issuer": "did:web:issuer.rogue"
            }),
            DiscoverabilityDb::Public,
        ),
    ];

    let accepted = vec!["did:web:issuer.tea".to_owned()];
    // RealmId is a strict typed id (canonical lowercase UUIDv7 suffix).
    let body = req(Some("ak:realm:0196419b-0000-7000-8000-000000000000"), None);
    let response = assemble_response(
        &body,
        rows,
        &accepted,
        &VerifiedRestrictedClaims::default(),
        0,
        20,
        None,
    )
    .expect("ok");

    assert_eq!(response.claims.len(), 1);
    assert_eq!(
        response.claims[0].issuer.as_deref(),
        Some("did:web:issuer.tea")
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
            json!({ "did": "did:web:alice.example", "handle": "a:example.com" }),
            DiscoverabilityDb::Public,
        ),
        row(
            json!({ "did": "did:web:alice.example", "handle": "b:example.com" }),
            DiscoverabilityDb::Public,
        ),
        row(
            json!({ "did": "did:web:alice.example", "handle": "c:example.com" }),
            DiscoverabilityDb::Public,
        ),
    ];

    // First page (offset 0, limit 2).
    let page1 = assemble_response(
        &req(None, None),
        rows.clone(),
        &[],
        &VerifiedRestrictedClaims::default(),
        0,
        2,
        None,
    )
    .expect("ok");
    assert_eq!(page1.claims.len(), 2);
    assert!(page1.has_more);
    assert!(page1.next_cursor.is_none());
    assert_eq!(
        page1.claims[0].handle.as_ref().unwrap().canonical(),
        "a:example.com"
    );
    assert_eq!(
        page1.claims[1].handle.as_ref().unwrap().canonical(),
        "b:example.com"
    );

    // The handler resolves the opaque cursor to offset 2 before invoking the
    // pure assembler.
    let body2 = req(None, None);
    let page2 = assemble_response(
        &body2,
        rows,
        &[],
        &VerifiedRestrictedClaims::default(),
        2,
        2,
        None,
    )
    .expect("ok");
    assert_eq!(page2.claims.len(), 1);
    assert!(!page2.has_more);
    assert!(page2.next_cursor.is_none());
    assert_eq!(
        page2.claims[0].handle.as_ref().unwrap().canonical(),
        "c:example.com"
    );
}

/// A non-directory-visible (e.g. secret) row is dropped by the disclosure
/// gate even though its subject matches.
#[test]
fn non_visible_row_is_dropped_by_disclosure_gate() {
    let rows = vec![row(
        json!({ "did": "did:web:alice.example", "handle": "secret:example.com" }),
        DiscoverabilityDb::Secret,
    )];

    let response = assemble_response(
        &req(None, None),
        rows,
        &[],
        &VerifiedRestrictedClaims::default(),
        0,
        20,
        None,
    )
    .expect("ok");
    assert!(response.claims.is_empty());
}

/// A restricted handle with claim-gated discoverers is invisible unless the
/// caller supplied a verified restricted-claim presentation.
#[test]
fn restricted_claim_handle_requires_verified_presentation() {
    let rows = vec![row(
        json!({
            "did": "did:web:alice.example",
            "handle": "restricted:example.com",
            "allowed_discoverers": [{
                "type": "claim",
                "claim_type": "organization_membership",
                "issuer": "did:web:issuer.tea",
                "organization": "did:web:tea-org.example"
            }]
        }),
        DiscoverabilityDb::Restricted,
    )];

    let body = req(None, Some("did:web:alice.example"));
    let response = assemble_response(
        &body,
        rows,
        &[],
        &VerifiedRestrictedClaims::default(),
        0,
        20,
        None,
    )
    .expect("ok");

    assert!(response.claims.is_empty());
    assert!(response.primary_handle.is_none());
}
