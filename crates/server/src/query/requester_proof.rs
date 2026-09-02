//! Directory requester_id-proof verification — `discovery-directory.md` §9.0.1.
//!
//! # One context per object family
//!
//! `directory-operations.schema.json` is a DTO container, not an object family,
//! so there is no context that covers the whole file. Each request family that
//! can carry `proofs[]` owns its own registered proof context and its own
//! `binding_fields` set (`registry/proof-context-registry.json`):
//!
//! | family | operation | context |
//! | --- | --- | --- |
//! | `directory_resolve_target_request_body` | `ak.find.directory.read.resolve_target.v1` | `ak.directory_resolve_target_request_proof.v1` |
//! | `directory_resolve_organization_request_body` | `ak.find.directory.read.resolve_organization.v1` | `ak.directory_resolve_organization_request_proof.v1` |
//! | `directory_resolve_handle_request_body` | `ak.find.directory.read.resolve_handle.v1` | `ak.directory_resolve_handle_request_proof.v1` |
//! | `directory_resolve_agent_selector_request_body` | `ak.find.directory.read.resolve_agent_selector.v1` | `ak.directory_resolve_agent_selector_request_proof.v1` |
//! | `directory_list_handles_for_subject_request_body` | `ak.find.directory.read.list_handles_for_subject.v1` | `ak.directory_list_handles_for_subject_request_proof.v1` |
//!
//! The transcript is NEVER assembled here. Every family's canonical binding
//! object is built by the SDK helper that owns it
//! (`arkret_sdk::Directory*RequestBody::proof_binding_bytes`), which is the only
//! implementation of the §9.0.1 wire form. A signature produced under one
//! family's context therefore cannot verify under another family's recomputed
//! transcript, which is the domain separation the removed over-broad
//! `ak.directory_operation_proof.v1` row could not express.
//!
//! # What the SDK helper already enforces
//!
//! `proof.kind` is the production detached-JWS kind, generic `domain` and
//! `proof_purpose` members are unrepresentable, `audience_id` is a required
//! `did_core_id`, and `proof.payload_digest` byte-equals
//! `SHA-256(JCS(request_without_proofs))`.
//! The family helper also fails closed when the request carries `proofs[]` but
//! omits the family's originator wire field.
//!
//! # What this module adds
//!
//! The two checks that need directory-local state — the 300-second freshness
//! window, and that `audience_id` names *this* directory — plus the signer
//! identity gate (`verification_method` MUST be controlled by the family's
//! originator) and the JWS verification itself.
//!
//! # Failure handling
//!
//! Every caller turns `Err` into its existing blinded `not_found` collapse,
//! inside the anti-enumeration latency budget, so a proof-layer rejection is
//! byte- and timing-indistinguishable from a genuine miss (§9.2). The reason
//! string is for local metrics/logs and MUST NOT reach the wire.
//!
//! # DID-P0-C03 — this path never resolves
//!
//! Like `filter::discoverers`, verification runs against an already accepted
//! binding or the zero-network `did:key` decode. An unknown requester_id DID
//! produces `Err`, which is the same blinded outcome as any other failure.

use arkret_identity::binding::DidBindingPurpose;
use arkret_sdk::{
    DidCoreId, DirectoryListHandlesForSubjectRequestBody, DirectoryRequestProof,
    DirectoryResolveHandleRequestBody, DirectoryResolveOrganizationRequestBody,
    DirectoryResolveTargetRequestBody,
};
use arkret_wire::WireError;
use chrono::{DateTime, Utc};

use crate::did_binding::DidBindingDirectory;
use crate::did_resolver::{verification_method_controller_core_id, verification_method_issuer};
use crate::observability::SIGNATURE_KIND_DIRECTORY_REQUESTER_PROOF;

/// `discovery-directory.md` §9.0.1: a Directory MUST reject a proof whose
/// `created_at` deviates from receipt time by more than 300 seconds. Callers
/// needing a longer window re-issue; a deployment MUST NOT relax the constant,
/// so it is not configurable.
pub const REQUESTER_PROOF_MAX_SKEW_SECONDS: i64 = 300;

/// A directory read request family that can carry §9.0.1 `proofs[]`.
///
/// Implemented for the four families this directory routes. The fifth
/// registered family, `resolve_agent_selector`, is not routed; its impl lands
/// together with the route so the two cannot drift apart.
pub trait DirectoryRequesterProofFamily {
    fn requester_proofs(&self) -> &[DirectoryRequestProof];

    /// The family's canonical §9.0.1 binding object, as JCS bytes. Delegates to
    /// the SDK helper that owns this family's context and `binding_fields`.
    fn requester_proof_binding_bytes(
        &self,
        proof: &DirectoryRequestProof,
    ) -> Result<Vec<u8>, WireError>;

    /// The family's originator wire field, whose value the binding object
    /// carries as the registry-defined `issuer`. `None` only for
    /// `directory_resolve_organization_request_body`, which has no originator
    /// field: its binding object omits `issuer` and the signer identity is
    /// borne solely by `verification_method`.
    fn requester_proof_originator(&self) -> Option<&DidCoreId>;
}

impl DirectoryRequesterProofFamily for DirectoryResolveTargetRequestBody {
    fn requester_proofs(&self) -> &[DirectoryRequestProof] {
        &self.proofs
    }

    fn requester_proof_binding_bytes(
        &self,
        proof: &DirectoryRequestProof,
    ) -> Result<Vec<u8>, WireError> {
        self.proof_binding_bytes(proof)
    }

    fn requester_proof_originator(&self) -> Option<&DidCoreId> {
        self.requester_id.as_ref()
    }
}

impl DirectoryRequesterProofFamily for DirectoryResolveOrganizationRequestBody {
    fn requester_proofs(&self) -> &[DirectoryRequestProof] {
        &self.proofs
    }

    fn requester_proof_binding_bytes(
        &self,
        proof: &DirectoryRequestProof,
    ) -> Result<Vec<u8>, WireError> {
        self.proof_binding_bytes(proof)
    }

    fn requester_proof_originator(&self) -> Option<&DidCoreId> {
        None
    }
}

impl DirectoryRequesterProofFamily for DirectoryResolveHandleRequestBody {
    fn requester_proofs(&self) -> &[DirectoryRequestProof] {
        &self.proofs
    }

    fn requester_proof_binding_bytes(
        &self,
        proof: &DirectoryRequestProof,
    ) -> Result<Vec<u8>, WireError> {
        self.proof_binding_bytes(proof)
    }

    fn requester_proof_originator(&self) -> Option<&DidCoreId> {
        self.requester_id.as_ref()
    }
}

impl DirectoryRequesterProofFamily for DirectoryListHandlesForSubjectRequestBody {
    fn requester_proofs(&self) -> &[DirectoryRequestProof] {
        &self.proofs
    }

    fn requester_proof_binding_bytes(
        &self,
        proof: &DirectoryRequestProof,
    ) -> Result<Vec<u8>, WireError> {
        self.proof_binding_bytes(proof)
    }

    fn requester_proof_originator(&self) -> Option<&DidCoreId> {
        self.requester_id.as_ref()
    }
}

/// Verify every §9.0.1 requester_id proof the request carries.
///
/// A request with no `proofs[]` is accepted unchanged — the proof is an
/// authorization *input*, and whether the resolution needs one is decided by
/// the per-resource disclosure policy, not here.
///
/// `expected_audience` is this directory's `did_core_id` service identity, the
/// same value `ak.find.directory.read.describe.v1` publishes as `service_id`.
pub fn verify_requester_proofs<T: DirectoryRequesterProofFamily + ?Sized>(
    request: &T,
    expected_audience: &str,
    bindings: &DidBindingDirectory,
    now: DateTime<Utc>,
) -> Result<(), String> {
    for proof in request.requester_proofs() {
        verify_requester_proof(request, proof, expected_audience, bindings, now)?;
    }
    Ok(())
}

fn verify_requester_proof<T: DirectoryRequesterProofFamily + ?Sized>(
    request: &T,
    proof: &DirectoryRequestProof,
    expected_audience: &str,
    bindings: &DidBindingDirectory,
    now: DateTime<Utc>,
) -> Result<(), String> {
    let skew = now
        .signed_duration_since(proof.created_at)
        .num_seconds()
        .abs();
    if skew > REQUESTER_PROOF_MAX_SKEW_SECONDS {
        return Err(format!(
            "directory requester_id proof created_at is {skew}s from receipt time, \
             outside the {REQUESTER_PROOF_MAX_SKEW_SECONDS}s window"
        ));
    }

    // §9.0.1: `audience_id` MUST be the target Directory `service_id` published
    // by `ak.find.directory.read.describe.v1`; only this directory knows
    // whether the typed did_core_id value names *it*.
    // `config().service_id` is the projected core id this directory publishes,
    // which is the same value `filter::discoverers` compares §2 claim
    // presentations against.
    if proof.audience_id.as_str() != expected_audience {
        return Err(
            "directory requester_id proof audience_id must be this directory's service_id"
                .to_owned(),
        );
    }

    // The family's own canonical transcript. Never assembled locally: a
    // hand-rolled copy would be free to drift from the registered
    // `binding_fields` and would reintroduce the cross-family replay this
    // context split exists to close.
    let binding_bytes = request
        .requester_proof_binding_bytes(proof)
        .map_err(|error| format!("directory requester_id proof binding rejected: {error}"))?;

    let verification_method = proof.verification_method.as_str();
    let Some(signer_did) = verification_method_issuer(verification_method) else {
        return Err(
            "directory requester_id proof verification_method has no controller".to_owned(),
        );
    };
    // `issuer` in the transcript is the request's originator field, so the
    // signing key MUST be controlled by that same subject_id. A DID URL's bare
    // controller is a `Did` and the originator is a `DidCoreId`; project
    // before comparing.
    if let Some(originator) = request.requester_proof_originator()
        && verification_method_controller_core_id(verification_method).as_ref() != Some(originator)
    {
        return Err(
            "directory requester_id proof verification_method is not controlled by the request \
             originator"
                .to_owned(),
        );
    }

    bindings
        .verify_detached_jws(
            &binding_bytes,
            &proof.jws,
            verification_method,
            signer_did,
            DidBindingPurpose::Principal,
            SIGNATURE_KIND_DIRECTORY_REQUESTER_PROOF,
            now,
        )
        .map_err(|failure| {
            format!(
                "directory requester_id proof JWS invalid: {}",
                failure.message()
            )
        })
}

#[cfg(test)]
mod tests {
    use arkret_sdk::{Did, RealmId};
    use arkret_signatures::jws::sign_jws_ed25519;
    use arkret_wire::{DidUrl, Hash};
    use chrono::Duration;
    use ed25519_dalek::SigningKey;
    use serde_json::Value as JsonValue;

    use super::*;

    const SIGNING_SEED: [u8; 32] = [41u8; 32];
    const OTHER_SIGNING_SEED: [u8; 32] = [42u8; 32];
    const DIRECTORY_AUDIENCE: &str = "ak:did_core:web:directory.example";

    fn bindings() -> DidBindingDirectory {
        DidBindingDirectory::new(
            &["did:key".to_owned()],
            DIRECTORY_AUDIENCE,
            crate::observability::Metrics::default(),
        )
        .expect("binding directory builds")
    }

    struct Requester {
        signing_key: SigningKey,
        core_id: DidCoreId,
        verification_method: DidUrl,
    }

    fn test_requester(seed: [u8; 32]) -> Requester {
        let signing_key = SigningKey::from_bytes(&seed);
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signing_key.verifying_key().as_bytes(),
        );
        let did = Did::new(format!("did:key:{multibase}")).unwrap();
        let verification_method = DidUrl::new(format!("{}#{multibase}", did.as_str())).unwrap();
        let core_id = arkret_sdk::project_did_to_core_id(&did).unwrap();
        Requester {
            signing_key,
            core_id,
            verification_method,
        }
    }

    /// A proof leaf carrying everything §9.0.1 binds. `jws` holds a placeholder
    /// until the transcript has been signed: the signature is not part of the
    /// binding object, so overwriting it afterwards leaves the transcript
    /// unchanged, and the SDK helper rejects an empty `jws` outright.
    fn unsigned_proof(
        requester_id: &Requester,
        payload_digest: Hash,
        created_at: DateTime<Utc>,
    ) -> DirectoryRequestProof {
        DirectoryRequestProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: requester_id.verification_method.clone(),
            payload_digest,
            created_at,
            audience_id: DidCoreId::new(DIRECTORY_AUDIENCE).unwrap(),
            jws: "pending".to_owned(),
        }
    }

    fn resolve_handle_body(requester_id: &Requester) -> DirectoryResolveHandleRequestBody {
        DirectoryResolveHandleRequestBody {
            handle: "alice:example.com".to_owned(),
            expected_principal_id: None,
            proof_challenge: Some("challenge-1".to_owned()),
            claim_presentations: Vec::new(),
            intent: None,
            requester_id: Some(requester_id.core_id.clone()),
            audience: None,
            realm_id: None,
            proofs: Vec::new(),
        }
    }

    fn list_handles_body(requester_id: &Requester) -> DirectoryListHandlesForSubjectRequestBody {
        DirectoryListHandlesForSubjectRequestBody {
            account_id: arkret_sdk::AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
                DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
            ),
            realm_id: Some(
                RealmId::new("ak:realm:AY0Z0alJlPB4P2wAIOCSTs_yNX_lm1mM5r3mhhQuKIFb".to_owned())
                    .unwrap(),
            ),
            intent: None,
            requester_id: Some(requester_id.core_id.clone()),
            proof_challenge: Some("challenge-1".to_owned()),
            proofs: Vec::new(),
            as_of: None,
            cursor: None,
            limit: None,
        }
    }

    /// Sign the family's own transcript and return the request with the
    /// finished proof attached.
    fn signed_resolve_handle(
        requester_id: &Requester,
        created_at: DateTime<Utc>,
    ) -> DirectoryResolveHandleRequestBody {
        let mut body = resolve_handle_body(requester_id);
        let mut proof = unsigned_proof(requester_id, body.payload_digest().unwrap(), created_at);
        let transcript = body.proof_binding_bytes(&proof).unwrap();
        proof.jws = sign_jws_ed25519(&transcript, &requester_id.signing_key).unwrap();
        body.proofs = vec![proof];
        body
    }

    fn signed_list_handles(
        requester_id: &Requester,
        created_at: DateTime<Utc>,
    ) -> DirectoryListHandlesForSubjectRequestBody {
        let mut body = list_handles_body(requester_id);
        let mut proof = unsigned_proof(requester_id, body.payload_digest().unwrap(), created_at);
        let transcript = body.proof_binding_bytes(&proof).unwrap();
        proof.jws = sign_jws_ed25519(&transcript, &requester_id.signing_key).unwrap();
        body.proofs = vec![proof];
        body
    }

    #[test]
    fn family_proof_verifies_against_its_own_context() {
        let requester_id = test_requester(SIGNING_SEED);
        let now = Utc::now();
        verify_requester_proofs(
            &signed_resolve_handle(&requester_id, now),
            DIRECTORY_AUDIENCE,
            &bindings(),
            now,
        )
        .expect("a proof signed for this family must verify");
        verify_requester_proofs(
            &signed_list_handles(&requester_id, now),
            DIRECTORY_AUDIENCE,
            &bindings(),
            now,
        )
        .expect("a proof signed for this family must verify");
    }

    /// Domain separation, layer 1 — the transcripts themselves.
    ///
    /// Each family stamps its OWN registered context and operation id into the
    /// signed bytes, and the registered `binding_fields` sets differ per family
    /// (`resolve_handle` binds `handle`, `list_handles_for_subject` binds
    /// `subject_id`, `resolve_organization` binds neither and omits `issuer`).
    /// This is what the removed fragmentless `ak.directory_operation_proof.v1`
    /// row could not express.
    #[test]
    fn each_family_stamps_its_own_registered_context_and_binding_fields() {
        let requester_id = test_requester(SIGNING_SEED);
        let now = Utc::now();

        let handle_body = resolve_handle_body(&requester_id);
        let handle_transcript: JsonValue = serde_json::from_slice(
            &handle_body
                .proof_binding_bytes(&unsigned_proof(
                    &requester_id,
                    handle_body.payload_digest().unwrap(),
                    now,
                ))
                .unwrap(),
        )
        .unwrap();

        let list_body = list_handles_body(&requester_id);
        let list_transcript: JsonValue = serde_json::from_slice(
            &list_body
                .proof_binding_bytes(&unsigned_proof(
                    &requester_id,
                    list_body.payload_digest().unwrap(),
                    now,
                ))
                .unwrap(),
        )
        .unwrap();

        let org_body = DirectoryResolveOrganizationRequestBody {
            organization_id: Some(
                DidCoreId::new("ak:did_core:web:acme.example".to_owned()).unwrap(),
            ),
            handle: None,
            proofs: Vec::new(),
        };
        let org_transcript: JsonValue = serde_json::from_slice(
            &org_body
                .proof_binding_bytes(&unsigned_proof(
                    &requester_id,
                    org_body.payload_digest().unwrap(),
                    now,
                ))
                .unwrap(),
        )
        .unwrap();

        assert_eq!(
            handle_transcript["context"],
            JsonValue::from(arkret_wire::ProofContextId::DIRECTORY_RESOLVE_HANDLE_REQUEST_PROOF_V1)
        );
        assert_eq!(
            list_transcript["context"],
            JsonValue::from(
                arkret_wire::ProofContextId::DIRECTORY_LIST_HANDLES_FOR_SUBJECT_REQUEST_PROOF_V1
            )
        );
        assert_eq!(
            org_transcript["context"],
            JsonValue::from(
                arkret_wire::ProofContextId::DIRECTORY_RESOLVE_ORGANIZATION_REQUEST_PROOF_V1
            )
        );
        assert_ne!(
            handle_transcript["operation_id"],
            list_transcript["operation_id"]
        );

        // Registered `binding_fields`, verbatim from proof-context-registry.json.
        let keys = |value: &JsonValue| {
            let mut keys: Vec<String> = value
                .as_object()
                .unwrap()
                .keys()
                .map(ToOwned::to_owned)
                .collect();
            keys.sort();
            keys
        };
        let mut expected_handle = vec![
            "payload_digest",
            "issuer",
            "operation_id",
            "handle",
            "verification_method",
            "created_at",
            "audience_id",
            "context",
        ];
        expected_handle.sort_unstable();
        assert_eq!(keys(&handle_transcript), expected_handle);

        let mut expected_list = vec![
            "payload_digest",
            "issuer",
            "operation_id",
            "account_id",
            "verification_method",
            "created_at",
            "audience_id",
            "context",
        ];
        expected_list.sort_unstable();
        assert_eq!(keys(&list_transcript), expected_list);
        assert_eq!(
            list_transcript["account_id"],
            serde_json::to_value(&list_body.account_id).unwrap()
        );

        // `resolve_organization` has no originator wire field: no `issuer`.
        let mut expected_org = vec![
            "payload_digest",
            "operation_id",
            "verification_method",
            "created_at",
            "audience_id",
            "context",
        ];
        expected_org.sort_unstable();
        assert_eq!(keys(&org_transcript), expected_org);
    }

    /// Domain separation, layer 2 — cross-family signature transplant.
    ///
    /// The proof leaf submitted to `list_handles_for_subject` is correct in
    /// EVERY field the verifier can check independently: production kind, no
    /// generic `domain` / `proof_purpose`, typed `audience_id` naming this directory,
    /// fresh `created_at`, `payload_digest` byte-equal to
    /// `SHA-256(JCS(list_body_without_proofs))`, and a `verification_method`
    /// controlled by the request's own `requester_id`. The ONLY defect is that its
    /// JWS was produced over the `resolve_handle` family's transcript. It MUST
    /// still be rejected — that is the whole point of splitting the over-broad
    /// context into five per-family rows.
    #[test]
    fn proof_signed_under_another_family_context_is_rejected() {
        let requester_id = test_requester(SIGNING_SEED);
        let now = Utc::now();

        let handle_body = signed_resolve_handle(&requester_id, now);
        let mut list_body = signed_list_handles(&requester_id, now);

        let transplanted = handle_body.proofs[0].jws.clone();
        assert_ne!(
            transplanted, list_body.proofs[0].jws,
            "the two families must not produce the same signature"
        );
        list_body.proofs[0].jws = transplanted;

        let error = verify_requester_proofs(&list_body, DIRECTORY_AUDIENCE, &bindings(), now)
            .expect_err("a resolve_handle-context signature must not verify as list_handles");
        assert!(error.contains("JWS invalid"), "unexpected reason: {error}");
    }

    /// The same attack in its naive form: replay the whole `resolve_handle`
    /// proof leaf onto a `list_handles_for_subject` request. Rejected before
    /// the signature layer because the leaf's `payload_digest` cannot describe
    /// the other family's body either.
    #[test]
    fn whole_proof_replayed_across_families_is_rejected() {
        let requester_id = test_requester(SIGNING_SEED);
        let now = Utc::now();

        let handle_body = signed_resolve_handle(&requester_id, now);
        let mut list_body = list_handles_body(&requester_id);
        list_body.proofs = handle_body.proofs.clone();

        verify_requester_proofs(&list_body, DIRECTORY_AUDIENCE, &bindings(), now)
            .expect_err("a whole-leaf cross-family replay must be rejected");
    }

    #[test]
    fn proof_outside_the_300_second_window_is_rejected() {
        let requester_id = test_requester(SIGNING_SEED);
        let now = Utc::now();
        let stale = now - Duration::seconds(REQUESTER_PROOF_MAX_SKEW_SECONDS + 1);
        let body = signed_resolve_handle(&requester_id, stale);
        let error = verify_requester_proofs(&body, DIRECTORY_AUDIENCE, &bindings(), now)
            .expect_err("a stale proof must be rejected");
        assert!(error.contains("outside the 300s window"), "reason: {error}");

        // The window is symmetric: a future-dated proof is equally rejected.
        let future = now + Duration::seconds(REQUESTER_PROOF_MAX_SKEW_SECONDS + 1);
        let body = signed_resolve_handle(&requester_id, future);
        verify_requester_proofs(&body, DIRECTORY_AUDIENCE, &bindings(), now)
            .expect_err("a future-dated proof must be rejected");

        // Inside the window it still verifies.
        let edge = now - Duration::seconds(REQUESTER_PROOF_MAX_SKEW_SECONDS);
        let body = signed_resolve_handle(&requester_id, edge);
        verify_requester_proofs(&body, DIRECTORY_AUDIENCE, &bindings(), now)
            .expect("a proof at the window edge must verify");
    }

    #[test]
    fn proof_for_another_directory_audience_is_rejected() {
        let requester_id = test_requester(SIGNING_SEED);
        let now = Utc::now();
        let body = signed_resolve_handle(&requester_id, now);
        let error = verify_requester_proofs(
            &body,
            "ak:did_core:web:other-directory.example",
            &bindings(),
            now,
        )
        .expect_err("a proof bound to another directory must be rejected");
        assert!(error.contains("audience"), "reason: {error}");
    }

    #[test]
    fn legacy_generic_proof_members_are_rejected_by_the_closed_leaf() {
        let requester_id = test_requester(SIGNING_SEED);
        let now = Utc::now();
        let body = signed_resolve_handle(&requester_id, now);
        let canonical = serde_json::to_value(&body.proofs[0]).unwrap();
        for (field, value) in [
            ("domain", serde_json::json!("example.com")),
            ("proof_purpose", serde_json::json!("issuer_attestation")),
            (
                "audience",
                serde_json::json!([DIRECTORY_AUDIENCE, "ak:did_core:web:other.example"]),
            ),
        ] {
            let mut legacy = canonical.clone();
            legacy
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), value);
            serde_json::from_value::<DirectoryRequestProof>(legacy)
                .expect_err("generic proof member must not be a compatibility alias");
        }
    }

    /// `issuer` in the transcript is the request's `requester_id`, so a proof
    /// signed by a different principal's key cannot stand in for it.
    #[test]
    fn proof_signed_by_a_key_the_requester_does_not_control_is_rejected() {
        let requester_id = test_requester(SIGNING_SEED);
        let impostor = test_requester(OTHER_SIGNING_SEED);
        let now = Utc::now();

        let mut body = resolve_handle_body(&requester_id);
        let mut proof = unsigned_proof(&impostor, body.payload_digest().unwrap(), now);
        let transcript = body.proof_binding_bytes(&proof).unwrap();
        proof.jws = sign_jws_ed25519(&transcript, &impostor.signing_key).unwrap();
        body.proofs = vec![proof];

        let error = verify_requester_proofs(&body, DIRECTORY_AUDIENCE, &bindings(), now)
            .expect_err("a foreign signer must be rejected");
        assert!(
            error.contains("not controlled by the request originator"),
            "reason: {error}"
        );
    }

    /// A request that carries `proofs[]` but omits the family's originator
    /// field fails closed inside the SDK binding helper.
    #[test]
    fn proofs_without_the_family_originator_field_are_rejected() {
        let requester_id = test_requester(SIGNING_SEED);
        let now = Utc::now();
        let mut body = signed_resolve_handle(&requester_id, now);
        body.requester_id = None;
        verify_requester_proofs(&body, DIRECTORY_AUDIENCE, &bindings(), now)
            .expect_err("`proofs` without the originator field MUST fail closed");
    }

    /// A tampered request body no longer matches the signed `payload_digest`.
    #[test]
    fn mutated_request_body_breaks_the_payload_digest_binding() {
        let requester_id = test_requester(SIGNING_SEED);
        let now = Utc::now();
        let mut body = signed_resolve_handle(&requester_id, now);
        body.handle = "mallory:example.com".to_owned();
        verify_requester_proofs(&body, DIRECTORY_AUDIENCE, &bindings(), now)
            .expect_err("payload_digest MUST bind the whole request body");
    }

    #[test]
    fn request_without_proofs_is_accepted() {
        let requester_id = test_requester(SIGNING_SEED);
        verify_requester_proofs(
            &resolve_handle_body(&requester_id),
            DIRECTORY_AUDIENCE,
            &bindings(),
            Utc::now(),
        )
        .expect("an unproven request is not a proof failure");
    }
}
