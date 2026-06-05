//! Conformance suite for `ck.find.directory.list_handles_for_subject` (DIR-TBY-5,
//! R3.2 / cokret-spec @ b56cab1).
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

use chrono::{TimeZone, Utc};
use cokret_sdk::DirectoryListHandlesForSubjectReqBody;
use serde_json::json;
use server::ingest::DiscoverabilityWire;
use server::query::handles_for_subject::{SubjectHandleRow, assemble_response};

fn subject() -> cokret_sdk::Did {
    cokret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap()
}

fn req(realm_id: Option<&str>, requester: Option<&str>) -> DirectoryListHandlesForSubjectReqBody {
    DirectoryListHandlesForSubjectReqBody {
        subject: subject(),
        realm_id: realm_id.map(|r| cokret_sdk::RealmId::new(r.to_owned()).unwrap()),
        intent: None,
        requester: requester.map(|r| cokret_sdk::Did::new(r.to_owned()).unwrap()),
        proof_challenge: None,
        proofs: Vec::new(),
        as_of: None,
        cursor: None,
        limit: None,
    }
}

fn row(projection: serde_json::Value, disc: DiscoverabilityWire) -> SubjectHandleRow {
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
        DiscoverabilityWire::Public,
    )];

    let response = assemble_response(&req(None, None), rows, &[], 0, 20, None)
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
            DiscoverabilityWire::Public,
        ),
        row(
            json!({ "did": "did:web:alice.example", "handle": "alice:example.com" }),
            DiscoverabilityWire::Public,
        ),
    ];

    let response = assemble_response(&req(None, None), rows, &[], 0, 20, None)
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
        DiscoverabilityWire::Public,
    )];

    let response = assemble_response(&req(None, None), rows, &[], 0, 20, None)
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
            DiscoverabilityWire::Public,
        ),
        row(
            json!({
                "did": "did:web:alice.example",
                "handle": "open:example.com"
            }),
            DiscoverabilityWire::Public,
        ),
    ];

    // Requester is tea-org; the scoped claim's audience is someone-else, so it
    // is filtered; the unpinned claim survives.
    let body = req(None, Some("did:web:tea-org.example"));
    let response = assemble_response(&body, rows, &[], 0, 20, None).expect("ok");

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
        DiscoverabilityWire::Public,
    )];

    let body = req(None, Some("did:web:tea-org.example"));
    let response = assemble_response(&body, rows, &[], 0, 20, None).expect("ok");
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
            DiscoverabilityWire::Public,
        ),
        row(
            json!({
                "did": "did:web:alice.example",
                "handle": "untrusted:example.com",
                "issuer": "did:web:issuer.rogue"
            }),
            DiscoverabilityWire::Public,
        ),
    ];

    let accepted = vec!["did:web:issuer.tea".to_owned()];
    // RealmId is a strict typed id (canonical lowercase UUIDv7 suffix).
    let body = req(Some("ck:realm:0196419b-0000-7000-8000-000000000000"), None);
    let response = assemble_response(&body, rows, &accepted, 0, 20, None).expect("ok");

    assert_eq!(response.claims.len(), 1);
    assert_eq!(
        response.claims[0].issuer.as_deref(),
        Some("did:web:issuer.tea")
    );
}

/// Case 5 — cursor pagination: with three claims and a page size of 2, the
/// first page returns 2 + `has_more` + a `next_cursor`, and the second page
/// returns the remaining 1 with `has_more=false`.
#[test]
fn cursor_pagination_boundary() {
    let rows = vec![
        row(
            json!({ "did": "did:web:alice.example", "handle": "a:example.com" }),
            DiscoverabilityWire::Public,
        ),
        row(
            json!({ "did": "did:web:alice.example", "handle": "b:example.com" }),
            DiscoverabilityWire::Public,
        ),
        row(
            json!({ "did": "did:web:alice.example", "handle": "c:example.com" }),
            DiscoverabilityWire::Public,
        ),
    ];

    // First page (offset 0, limit 2).
    let page1 = assemble_response(&req(None, None), rows.clone(), &[], 0, 2, None).expect("ok");
    assert_eq!(page1.claims.len(), 2);
    assert!(page1.has_more);
    let cursor = page1
        .next_cursor
        .clone()
        .expect("next_cursor on partial page");
    assert_eq!(
        page1.claims[0].handle.as_ref().unwrap().canonical(),
        "a:example.com"
    );
    assert_eq!(
        page1.claims[1].handle.as_ref().unwrap().canonical(),
        "b:example.com"
    );

    // Second page — decode the opaque cursor by feeding it back as `cursor`.
    let mut body2 = req(None, None);
    body2.cursor = Some(cursor);
    // The handler decodes the cursor; here we replicate the offset it carries
    // (2) by passing it directly so the pure assembler can be exercised.
    let page2 = assemble_response(&body2, rows, &[], 2, 2, None).expect("ok");
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
        DiscoverabilityWire::Secret,
    )];

    let response = assemble_response(&req(None, None), rows, &[], 0, 20, None).expect("ok");
    assert!(response.claims.is_empty());
}
