use serde_json::json;
use teabay_contracts::DirectoryDiscoveryState;

use super::federation::{FederationCacheKeyInputs, verify_federation_trust_domain_headers};
use super::projection::{derive_public_projection, validate_handle_claim_ingest};
use crate::error::ApiErrorCode;
use crate::ingest::DiscoverabilityDb;

fn inputs_with_pair(
    source_trust_domain: &str,
    destination_trust_domain: &str,
) -> FederationCacheKeyInputs {
    FederationCacheKeyInputs {
        source_service_id: "ak:did_core:web:peer.example".to_owned(),
        verification_method: "did:web:peer.example#key-1".to_owned(),
        service_binding_ref: "binding-1".to_owned(),
        origin_key_state_digest: vec![1, 2, 3],
        source_trust_domain: source_trust_domain.to_owned(),
        destination_trust_domain: destination_trust_domain.to_owned(),
    }
}

/// Non-federation announce path: the trust-domain pair
/// is absent and `is_federation_hop()` is false; the verifier is a
/// no-op (`Ok(None)`).
#[test]
fn trust_domain_verifier_skips_non_federation_announce() {
    let inputs = inputs_with_pair("", "");
    assert!(!inputs.is_federation_hop());
    let outcome = verify_federation_trust_domain_headers(&inputs, "ak:trust_domain:teabay.test");
    assert!(matches!(outcome, Ok(None)));
}

/// Federation hop missing one of the two required
/// headers must reject with `cross_domain_replay_rejected`.
#[test]
fn trust_domain_verifier_rejects_partial_pair() {
    let inputs = inputs_with_pair("ak:trust_domain:other.example", "");
    assert!(inputs.is_federation_hop());
    let err =
        verify_federation_trust_domain_headers(&inputs, "ak:trust_domain:teabay.test").unwrap_err();
    assert_eq!(err.0, ApiErrorCode::CrossDomainReplayRejected);
}

#[test]
fn federation_source_service_id_rejects_full_did_authority() {
    let mut inputs = inputs_with_pair(
        "ak:trust_domain:other.example",
        "ak:trust_domain:teabay.test",
    );
    inputs.source_service_id = "did:web:peer.example".to_owned();
    let error = verify_federation_trust_domain_headers(&inputs, "ak:trust_domain:teabay.test")
        .expect_err("full DID must not occupy Source-Service-ID");
    assert_eq!(error.0, ApiErrorCode::CrossDomainReplayRejected);
}

/// Destination trust domain mismatch must reject; a
/// sender from trust domain A cannot replay signed bytes addressed
/// to trust domain B into trust domain C.
#[test]
fn trust_domain_verifier_rejects_destination_mismatch() {
    let inputs = inputs_with_pair(
        "ak:trust_domain:other.example",
        "ak:trust_domain:wrong.example",
    );
    let err =
        verify_federation_trust_domain_headers(&inputs, "ak:trust_domain:teabay.test").unwrap_err();
    assert_eq!(err.0, ApiErrorCode::CrossDomainReplayRejected);
    assert!(err.1.contains("does not match"));
}

/// A fully-populated valid pair returns a signing-transcript fragment
/// that names both headers in
/// RFC 9421 §2.2 lower-case quoted form.
#[test]
fn trust_domain_verifier_emits_transcript_fragment() {
    let inputs = inputs_with_pair(
        "ak:trust_domain:other.example",
        "ak:trust_domain:teabay.test",
    );
    let fragment = verify_federation_trust_domain_headers(&inputs, "ak:trust_domain:teabay.test")
        .expect("pair is valid")
        .expect("fragment emitted for federation hop");
    assert!(fragment.contains("\"source-trust-domain\""));
    assert!(fragment.contains("\"destination-trust-domain\""));
    assert!(fragment.contains("ak:trust_domain:other.example"));
    assert!(fragment.contains("ak:trust_domain:teabay.test"));
}

/// The cache key MUST bind the trust-domain pair: two
/// requests with identical idempotency inputs but different
/// `Source-Trust-Domain` headers MUST produce different cache
/// keys, so a cross-domain replay cannot reuse a cached row.
#[test]
fn cache_key_separates_by_trust_domain() {
    let digest = [0u8; 32];
    let a = inputs_with_pair("ak:trust_domain:a.example", "ak:trust_domain:teabay.test");
    let b = inputs_with_pair("ak:trust_domain:b.example", "ak:trust_domain:teabay.test");
    assert_ne!(a.key(&digest), b.key(&digest));
}

/// HC-TBY-1 — a handle claim announcing the retired `service_handle`
/// class/claim_type is rejected with `claim_type_unsupported`.
#[test]
fn handle_claim_ingest_rejects_service_handle_claim_type() {
    let state = json!({
        "kind": "ak.handle.discovery",
        "claim_kind": "service_handle",
        "subject": "did:web:alice.example",
    });
    let err = validate_handle_claim_ingest(&state).unwrap_err();
    assert_eq!(err.0, ApiErrorCode::SchemaViolation);
    assert!(err.1.contains("claim_type_unsupported"));

    // Also reject retired discriminator fields outright.
    let state = json!({ "class": "service_handle", "subject": "did:web:alice.example" });
    assert!(validate_handle_claim_ingest(&state).is_err());
    let state = json!({ "claim_type": "handle_binding", "subject": "did:web:alice.example" });
    assert!(validate_handle_claim_ingest(&state).is_err());
}

/// HC-TBY-2 — a handle claim whose `subject` is a Realm actor id /
/// account id / non-DID resource id is rejected with
/// `handle_claim_subject_not_principal_did`.
#[test]
fn handle_claim_ingest_rejects_non_principal_subject() {
    for bad in [
        "ak:actor:tea/alice",
        "ak:account:server-local-42",
        "ak:resource:thing",
        "not-a-did",
    ] {
        let state = json!({ "subject": bad, "handle": "alice:example.com" });
        let err = validate_handle_claim_ingest(&state).unwrap_err();
        assert_eq!(err.0, ApiErrorCode::SchemaViolation, "subject {bad}");
        assert!(
            err.1.contains("handle_claim_subject_not_principal_did"),
            "subject {bad}"
        );
    }
}

/// HC-TBY-2 — a holder/principal DID subject is accepted, and a body
/// with no handle-claim fields passes through untouched.
#[test]
fn handle_claim_ingest_accepts_principal_did_and_non_handle_bodies() {
    let ok = json!({ "subject": "ak:did_core:web:alice.example", "handle": "alice:example.com" });
    assert!(validate_handle_claim_ingest(&ok).is_ok());

    // A realm announce with no handle-claim fields is untouched.
    let realm = json!({ "kind": "ak.realm.discovery", "discoverability": "public" });
    assert!(validate_handle_claim_ingest(&realm).is_ok());

    // And the whole projection path accepts the principal-DID claim.
    assert!(
        derive_public_projection(
            &DirectoryDiscoveryState::from_json(ok),
            DiscoverabilityDb::Public,
        )
        .is_ok()
    );
}

#[test]
fn public_projection_separates_directory_preview_from_private_search() {
    let state = json!({
        "kind": "ak.realm.discovery",
        "title": "Tea Time",
        "member_count": 42,
        "anti_enumeration": {
            "member_count_mode": "bucketed"
        },
        "search_policy": {
            "enabled_profile_refs": ["ak.profile.search.blind_index.v1"],
            "allowed_service_ids": ["did:web:search.example"],
            "data_classes": ["encrypted_index", "blind_tokens"],
            "index_retention_ms": 3600,
            "revocation_behavior": "drop_stale"
        },
        "search_index_manifest": {
            "encrypted_index": "ciphertext",
            "blind_tokens": ["tok"],
            "shard_key": "shard-a",
            "epoch_id": 7
        },
        "service_capabilities": [{
            "service_id": "did:web:search.example",
            "profile": "ak.profile.search.blind_index.v1",
            "blind_tokens": ["tok"]
        }]
    });

    let projected = derive_public_projection(
        &DirectoryDiscoveryState::from_json(state),
        DiscoverabilityDb::Public,
    )
    .unwrap();
    assert_eq!(projected["title"], "Tea Time");
    assert_eq!(projected["member_count_bucket"], "11-50");
    assert!(projected.get("member_count").is_none());
    assert!(projected.get("search_policy").is_none());
    assert!(projected.get("search_index_manifest").is_none());
    assert!(
        projected["service_capabilities"][0]
            .get("service_id")
            .is_some()
    );
    assert!(
        projected["service_capabilities"][0]
            .get("blind_tokens")
            .is_none()
    );
}

#[test]
fn public_projection_collapses_circle_directory_preview_to_locked_stub() {
    let state = json!({
        "kind": "ak.realm.discovery",
        "title": "Tea Time",
        "circles": [{
            "circle_id": "ak:circle:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH",
            "realm_id": "ak:realm:AfUOZyPWNBbSVKNRXHMbULldhuzzMwa7DvqrqFSUksz3",
            "title": "Security Council",
            "summary": "private circle summary",
            "display": {
                "short_name": "SEC",
                "color_token": "slate",
                "symbol": { "glyph": "shield" }
            },
            "directory_visibility": "realm_members",
            "member_count": 7,
            "member_count_bucket": "1-10",
            "join_rule": "invite",
            "members": ["did:web:alice.example"],
            "created_by": "did:web:alice.example",
            "join_history": [{ "actor_id": "did:web:alice.example" }]
        }]
    });

    let projected = derive_public_projection(
        &DirectoryDiscoveryState::from_json(state),
        DiscoverabilityDb::Public,
    )
    .unwrap();
    assert_eq!(projected["circles"]["visibility"], "locked");
    assert_eq!(
        projected["circles"]["opaque_commitment"]
            .as_str()
            .unwrap()
            .len(),
        43
    );
    let serialized = projected.to_string();
    for forbidden in [
        "Security Council",
        "private circle summary",
        "short_name",
        "member_count",
        "did:web:alice.example",
        "created_by",
        "join_history",
    ] {
        assert!(!serialized.contains(forbidden), "{forbidden} leaked");
    }
}
