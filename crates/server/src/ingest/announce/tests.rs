use chrono::{DateTime, Utc};
use serde_json::{Value as JsonValue, json};

use super::federation::{
    FederationCacheKeyInputs, hex_lower_sha256, verify_federation_trust_domain_headers,
};
use super::ingest_body::DirectoryAnnounceIngest;
use super::persist::digest_request;
use super::projection::{derive_public_projection, validate_handle_claim_ingest};
use crate::error::ApiErrorCode;
use crate::ingest::{DirectoryResourceKindDb, DiscoverabilityDb};

fn inputs_with_triad(
    source_trust_domain: &str,
    destination_trust_domain: &str,
    request_canonical_digest: &str,
) -> FederationCacheKeyInputs {
    FederationCacheKeyInputs {
        source_service_did: "did:web:peer.example".to_owned(),
        verification_method: "did:web:peer.example#key-1".to_owned(),
        service_binding_ref: "binding-1".to_owned(),
        origin_key_state_digest: vec![1, 2, 3],
        source_trust_domain: source_trust_domain.to_owned(),
        destination_trust_domain: destination_trust_domain.to_owned(),
        request_canonical_digest: request_canonical_digest.to_owned(),
    }
}

/// Round 4 — non-federation announce path: the trust-domain triad
/// is absent and `is_federation_hop()` is false; the verifier is a
/// no-op (`Ok(None)`).
#[test]
fn trust_domain_verifier_skips_non_federation_announce() {
    let inputs = inputs_with_triad("", "", "");
    assert!(!inputs.is_federation_hop());
    let digest = [0u8; 32];
    let outcome =
        verify_federation_trust_domain_headers(&inputs, &digest, "ck:trust_domain:teabay.test");
    assert!(matches!(outcome, Ok(None)));
}

/// Round 4 — federation hop missing one of the three required
/// headers must reject with `cross_domain_replay_rejected`.
#[test]
fn trust_domain_verifier_rejects_partial_triad() {
    let inputs = inputs_with_triad("ck:trust_domain:other.example", "", "");
    assert!(inputs.is_federation_hop());
    let digest = [0u8; 32];
    let err =
        verify_federation_trust_domain_headers(&inputs, &digest, "ck:trust_domain:teabay.test")
            .unwrap_err();
    assert_eq!(err.0, ApiErrorCode::CrossDomainReplayRejected);
}

/// Round 4 — destination trust domain mismatch must reject; a
/// sender from trust domain A cannot replay signed bytes addressed
/// to trust domain B into trust domain C.
#[test]
fn trust_domain_verifier_rejects_destination_mismatch() {
    let digest = [0u8; 32];
    let canonical_hash = format!("sha256:{}", hex_lower_sha256(&digest));
    let inputs = inputs_with_triad(
        "ck:trust_domain:other.example",
        "ck:trust_domain:wrong.example",
        &canonical_hash,
    );
    let err =
        verify_federation_trust_domain_headers(&inputs, &digest, "ck:trust_domain:teabay.test")
            .unwrap_err();
    assert_eq!(err.0, ApiErrorCode::CrossDomainReplayRejected);
    assert!(err.1.contains("does not match"));
}

#[test]
fn trust_domain_verifier_rejects_canonical_digest_mismatch() {
    let digest = [0u8; 32];
    let inputs = inputs_with_triad(
        "ck:trust_domain:other.example",
        "ck:trust_domain:teabay.test",
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    let err =
        verify_federation_trust_domain_headers(&inputs, &digest, "ck:trust_domain:teabay.test")
            .unwrap_err();
    assert_eq!(err.0, ApiErrorCode::CrossDomainReplayRejected);
    assert!(err.1.contains("does not match canonical body digest"));
}

/// Round 4 — a fully-populated valid triad returns a signing-
/// transcript fragment that names each of the three headers in
/// RFC 9421 §2.2 lower-case quoted form.
#[test]
fn trust_domain_verifier_emits_transcript_fragment() {
    let digest = [0u8; 32];
    let canonical_hash = format!("sha256:{}", hex_lower_sha256(&digest));
    let inputs = inputs_with_triad(
        "ck:trust_domain:other.example",
        "ck:trust_domain:teabay.test",
        &canonical_hash,
    );
    let fragment =
        verify_federation_trust_domain_headers(&inputs, &digest, "ck:trust_domain:teabay.test")
            .expect("triad is valid")
            .expect("fragment emitted for federation hop");
    assert!(fragment.contains("\"source-trust-domain\""));
    assert!(fragment.contains("\"destination-trust-domain\""));
    assert!(fragment.contains("\"request-canonical-digest\""));
    assert!(fragment.contains("ck:trust_domain:other.example"));
    assert!(fragment.contains("ck:trust_domain:teabay.test"));
}

/// Round 4 — the cache key MUST bind the trust-domain triad: two
/// requests with identical idempotency inputs but different
/// `Source-Trust-Domain` headers MUST produce different cache
/// keys, so a cross-domain replay cannot reuse a cached row.
#[test]
fn cache_key_separates_by_trust_domain() {
    let digest = [0u8; 32];
    let a = inputs_with_triad(
        "ck:trust_domain:a.example",
        "ck:trust_domain:teabay.test",
        "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    );
    let b = inputs_with_triad(
        "ck:trust_domain:b.example",
        "ck:trust_domain:teabay.test",
        "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    );
    assert_ne!(a.key(&digest), b.key(&digest));
}

/// HC-TBY-1 — a handle claim announcing the retired `service_handle`
/// class/claim_type is rejected with `claim_type_unsupported`.
#[test]
fn handle_claim_ingest_rejects_service_handle_claim_type() {
    let state = json!({
        "kind": "ck.handle.discovery",
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
        "ck:actor:tea/alice",
        "ck:account:server-local-42",
        "ck:resource:thing",
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
    let ok = json!({ "subject": "did:web:alice.example", "handle": "alice:example.com" });
    assert!(validate_handle_claim_ingest(&ok).is_ok());

    // A realm announce with no handle-claim fields is untouched.
    let realm = json!({ "kind": "ck.realm.discovery", "discoverability": "public" });
    assert!(validate_handle_claim_ingest(&realm).is_ok());

    // And the whole projection path accepts the principal-DID claim.
    assert!(derive_public_projection(&ok, DiscoverabilityDb::Public).is_ok());
}

#[test]
fn public_projection_separates_directory_preview_from_private_search() {
    let state = json!({
        "kind": "ck.realm.discovery",
        "title": "Tea Time",
        "member_count": 42,
        "anti_enumeration": {
            "member_count_mode": "bucketed"
        },
        "search_policy": {
            "enabled_profile_refs": ["ck.profile.search.blind_index.v1"],
            "allowed_service_dids": ["did:web:search.example"],
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
            "service_did": "did:web:search.example",
            "profile": "ck.profile.search.blind_index.v1",
            "blind_tokens": ["tok"]
        }]
    });

    let projected = derive_public_projection(&state, DiscoverabilityDb::Public).unwrap();
    assert_eq!(projected["title"], "Tea Time");
    assert_eq!(projected["member_count_bucket"], "11-50");
    assert!(projected.get("member_count").is_none());
    assert!(projected.get("search_policy").is_none());
    assert!(projected.get("search_index_manifest").is_none());
    assert!(
        projected["service_capabilities"][0]
            .get("service_did")
            .is_some()
    );
    assert!(
        projected["service_capabilities"][0]
            .get("blind_tokens")
            .is_none()
    );
}

#[test]
fn announce_digest_uses_canonical_json_body() {
    let as_of = DateTime::parse_from_rfc3339("2026-05-20T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let mut first_state = serde_json::Map::new();
    first_state.insert("kind".to_owned(), json!("ck.realm.discovery"));
    first_state.insert("discoverability".to_owned(), json!("public"));
    first_state.insert(
        "directory_services".to_owned(),
        json!(["did:web:directory.test"]),
    );

    let mut second_state = serde_json::Map::new();
    second_state.insert(
        "directory_services".to_owned(),
        json!(["did:web:directory.test"]),
    );
    second_state.insert("discoverability".to_owned(), json!("public"));
    second_state.insert("kind".to_owned(), json!("ck.realm.discovery"));

    let first = DirectoryAnnounceIngest {
        resource_kind: DirectoryResourceKindDb::Realm,
        resource_id: "ck:realm:tea".to_owned(),
        principal_server_did: "did:web:principal.test".to_owned(),
        discovery_state: JsonValue::Object(first_state),
        source_refs: vec!["evt-1".to_owned()],
        as_of,
        ttl_seconds: Some(3600),
        supersedes_announce_id: None,
        trust_root_attestation: None,
    };
    let second = DirectoryAnnounceIngest {
        discovery_state: JsonValue::Object(second_state),
        ..first.clone()
    };

    assert_eq!(digest_request(&first), digest_request(&second));
}
