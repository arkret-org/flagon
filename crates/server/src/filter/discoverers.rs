//! Single source of truth for `allowed_discoverers` restricted-visibility
//! matching (spec discovery-directory §3).
//!
//! `restricted` resources are only surfaced to a requester_id whose identity or
//! signed claim presentations satisfy the resource's `allowed_discoverers`
//! list. This decision gates whether a restricted Realm / Handle /
//! Organization is visible at all, so the matching logic MUST be identical
//! across every `resolve_*` / `search_*` handler.

use arkret_identity::binding::DidBindingPurpose;
use arkret_sdk::{
    DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND, DidCoreId, DirectoryPresentedClaim,
    DirectoryRestrictedClaimPresentation, canonical,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value as JsonValue;

use crate::did_binding::DidBindingDirectory;
use crate::did_resolver::{verification_method_controller_core_id, verification_method_issuer};
use crate::observability::SIGNATURE_KIND_RESTRICTED_CLAIM;

#[derive(Debug, Serialize)]
struct RestrictedClaimPresentationPayload<'a> {
    kind: &'a str,
    iss: &'a DidCoreId,
    verification_method: &'a str,
    audience: &'a DidCoreId,
    nonce: &'a str,
    claim: &'a DirectoryPresentedClaim,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct VerifiedRestrictedClaims {
    claims: Vec<DirectoryPresentedClaim>,
}

impl VerifiedRestrictedClaims {
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    #[cfg(test)]
    pub fn for_test(claims: Vec<DirectoryPresentedClaim>) -> Self {
        Self { claims }
    }
}

#[cfg(test)]
pub(crate) fn organization_membership_claim(
    claim_id: &str,
    subject_id: DidCoreId,
    issuer_id: DidCoreId,
    organization: DidCoreId,
    roles: Vec<String>,
) -> DirectoryPresentedClaim {
    DirectoryPresentedClaim {
        claim_id: claim_id.to_owned(),
        subject_id,
        issuer_id,
        claim_kind: "organization_membership".to_owned(),
        value: serde_json::from_value(serde_json::json!({
            "organization_id": organization,
            "roles": roles,
        }))
        .expect("membership claim value is an object"),
        issued_at: Utc::now(),
        refreshed_at: None,
        expires_at: None,
        revoked_at: None,
        disclosed_fields: Default::default(),
    }
}

/// Resolve the `allowed_discoverers` array from a public projection, accepting
/// either the top-level field or the `/payload/allowed_discoverers` nested
/// form produced by some ingest projections.
pub fn allowed_discoverers(projection: &JsonValue) -> Option<&Vec<JsonValue>> {
    projection
        .get("allowed_discoverers")
        .or_else(|| projection.pointer("/payload/allowed_discoverers"))
        .and_then(JsonValue::as_array)
}

/// True when the projection declares a non-empty `allowed_discoverers` list.
pub fn has_allowed_discoverers(projection: &JsonValue) -> bool {
    allowed_discoverers(projection).is_some_and(|arr| !arr.is_empty())
}

/// Decide whether `requester_id` / `proofs` satisfy the projection's
/// `allowed_discoverers` list. Returns `false` when the list is absent or
/// empty (fail-closed: a restricted resource with no discoverers is invisible).
pub fn matches_allowed_discoverers(
    projection: &JsonValue,
    requester_id: Option<&str>,
    verified_claims: &VerifiedRestrictedClaims,
) -> bool {
    let Some(discoverers) = allowed_discoverers(projection) else {
        return false;
    };
    discoverers.iter().any(|entry| match entry {
        JsonValue::Object(obj) => claim_selector_matches(obj, requester_id, verified_claims),
        _ => false,
    })
}

/// Verify every presented restricted claim.
///
/// `expected_audience` MUST be this directory's `did_core_id` — the same value
/// `ak.find.directory.read.describe.v1` publishes as `service_id`.
/// `directory-operations.schema.json#/$defs/directory_restricted_claim_presentation`
/// types `audience` as `did_core_id`, so a `did:` form can never compare
/// equal and every presentation would be rejected.
///
/// # DID-P0-C03 — this path never resolves
///
/// `bindings` is a [`DidBindingDirectory`], which owns no DID resolver. A
/// presentation therefore verifies against an **already accepted**
/// [`DidBindingPurpose::DirectoryIssuer`] binding (established when that issuer_id
/// announced itself to this directory), or — for `did:key`, which is
/// self-describing key material — against a locally decoded document. An issuer_id
/// this directory has never accepted produces `Err`, which every caller already
/// turns into the blinded `not_found` / "no verified claims" outcome, so the
/// anti-enumeration behaviour is unchanged.
pub fn verify_restricted_claim_presentations(
    presentations: &[DirectoryRestrictedClaimPresentation],
    requester_id: Option<&str>,
    proof_challenge: Option<&str>,
    expected_audience: &str,
    bindings: &DidBindingDirectory,
) -> Result<VerifiedRestrictedClaims, String> {
    if presentations.is_empty() {
        return Ok(VerifiedRestrictedClaims::default());
    }
    let requester_id = requester_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "restricted claim presentation requires requester_id".to_owned())?;
    let challenge = proof_challenge
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "restricted claim presentation requires proof_challenge".to_owned())?;

    let mut claims = Vec::with_capacity(presentations.len());
    for presentation in presentations {
        verify_presentation_envelope(
            presentation,
            requester_id,
            challenge,
            expected_audience,
            bindings,
        )?;
        claims.push(presentation.claim.clone());
    }
    Ok(VerifiedRestrictedClaims { claims })
}

fn verify_presentation_envelope(
    presentation: &DirectoryRestrictedClaimPresentation,
    requester_id: &str,
    challenge: &str,
    expected_audience: &str,
    bindings: &DidBindingDirectory,
) -> Result<(), String> {
    if presentation.kind != DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND {
        return Err("unsupported restricted claim presentation kind".to_owned());
    }
    if presentation.audience.as_str() != expected_audience {
        return Err("restricted claim presentation audience mismatch".to_owned());
    }
    if presentation.nonce != challenge {
        return Err("restricted claim presentation nonce mismatch".to_owned());
    }
    if presentation.claim.subject_id.as_str() != requester_id {
        return Err("restricted claim subject_id mismatch".to_owned());
    }
    if presentation.claim.issuer_id != presentation.iss {
        return Err("restricted claim issuer_id mismatch".to_owned());
    }
    // `verification_method` names a key on a resolvable DID; `iss` is the
    // stable identity core. Project the controller before comparing — the two
    // value categories are never byte-equal. The controller is also the only
    // resolvable identity in the envelope, so it (not `iss`) is what the JWS
    // key lookup below is given.
    let Some(signer_did) = verification_method_issuer(&presentation.verification_method) else {
        return Err("restricted claim verification method has no controller".to_owned());
    };
    if verification_method_controller_core_id(presentation.verification_method.as_str()).as_ref()
        != Some(&presentation.iss)
    {
        return Err("restricted claim verification method issuer_id mismatch".to_owned());
    }
    let signer_did = signer_did.to_owned();
    let now = Utc::now();
    if presentation
        .expires_at
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Err("restricted claim presentation expired".to_owned());
    }

    let payload = RestrictedClaimPresentationPayload {
        kind: &presentation.kind,
        iss: &presentation.iss,
        verification_method: &presentation.verification_method,
        audience: &presentation.audience,
        nonce: &presentation.nonce,
        claim: &presentation.claim,
        expires_at: presentation.expires_at,
        created_at: presentation.created_at,
    };
    let canonical_bytes = canonical::canonical_json_bytes(&payload)
        .map_err(|error| format!("restricted claim canonicalization failed: {error}"))?;

    verify_presentation_jws(
        &canonical_bytes,
        &presentation.jws,
        &presentation.verification_method,
        &signer_did,
        bindings,
    )
}

fn verify_presentation_jws(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer_id: &str,
    bindings: &DidBindingDirectory,
) -> Result<(), String> {
    // Kept at the call site (as well as inside the shared helper) because an
    // empty `allowed_methods` is fail-OPEN at the `ResolverPolicy` layer and
    // because this exact message is part of the restricted-claim contract.
    if bindings.accepted_did_methods().is_empty() {
        return Err("no accepted DID methods configured".to_owned());
    }
    // Accepted `directory_issuer` binding, or the zero-network `did:key`
    // decode. Never a live resolution — see the module note on
    // `verify_restricted_claim_presentations`.
    bindings
        .verify_detached_jws(
            canonical_bytes,
            jws,
            verification_method,
            issuer_id,
            DidBindingPurpose::DirectoryIssuer,
            SIGNATURE_KIND_RESTRICTED_CLAIM,
            Utc::now(),
        )
        .map_err(|error| format!("restricted claim JWS invalid: {error}"))
}

fn claim_selector_matches(
    selector: &serde_json::Map<String, JsonValue>,
    requester_id: Option<&str>,
    verified_claims: &VerifiedRestrictedClaims,
) -> bool {
    if selector.get("type").and_then(JsonValue::as_str) != Some("claim") {
        return false;
    }
    let Some(claim_kind) = selector.get("claim_kind").and_then(JsonValue::as_str) else {
        return false;
    };
    let Some(issuer_id) = selector.get("issuer_id").and_then(JsonValue::as_str) else {
        return false;
    };
    let Some(requester_id) = requester_id else {
        return false;
    };
    let Ok(subject_id) = DidCoreId::new(requester_id.to_owned()) else {
        return false;
    };
    let Ok(issuer_id) = DidCoreId::new(issuer_id.to_owned()) else {
        return false;
    };
    verified_claims
        .claims
        .iter()
        .any(|claim| claim_satisfies_selector(claim, selector, &subject_id, &issuer_id, claim_kind))
}

fn claim_satisfies_selector(
    claim: &DirectoryPresentedClaim,
    selector: &serde_json::Map<String, JsonValue>,
    subject_id: &DidCoreId,
    issuer_id: &DidCoreId,
    claim_kind: &str,
) -> bool {
    if claim
        .value_matches(selector, "organization_id")
        .is_some_and(|matches| !matches)
        || claim
            .value_matches(selector, "status")
            .is_some_and(|matches| !matches)
    {
        return false;
    }

    let now = Utc::now();
    claim.subject_id == *subject_id
        && claim.issuer_id == *issuer_id
        && claim.claim_kind == claim_kind
        && claim.revoked_at.is_none_or(|revoked_at| revoked_at > now)
        && claim.expires_at.is_none_or(|expires_at| expires_at > now)
}

trait ClaimSelectorValue {
    fn value_matches(
        &self,
        selector: &serde_json::Map<String, JsonValue>,
        key: &str,
    ) -> Option<bool>;
}

impl ClaimSelectorValue for DirectoryPresentedClaim {
    fn value_matches(
        &self,
        selector: &serde_json::Map<String, JsonValue>,
        key: &str,
    ) -> Option<bool> {
        let expected = selector.get(key).and_then(JsonValue::as_str)?;
        Some(self.value.get(key).and_then(JsonValue::as_str) == Some(expected))
    }
}

#[cfg(test)]
mod tests {
    use arkret_signatures::jws::sign_jws_ed25519;
    use chrono::Duration;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    use super::*;

    const SIGNING_SEED: [u8; 32] = [23u8; 32];

    /// Stand-in for the startup-built `AppState` binding directory. `did:key`
    /// only, so the whole test stays on the zero-network fast path — which is
    /// the only path this type has.
    fn test_bindings() -> DidBindingDirectory {
        DidBindingDirectory::new(
            &["did:key".to_owned()],
            "ak:did_core:web:directory.example",
            crate::observability::Metrics::default(),
        )
        .expect("binding directory builds")
    }

    #[tokio::test]
    async fn signed_restricted_claim_presentation_authorizes_claim_selector() {
        let signing_key = SigningKey::from_bytes(&SIGNING_SEED);
        let multibase = did_key_multibase(&signing_key);
        let issuer_did = arkret_sdk::Did::new(format!("did:key:{multibase}")).unwrap();
        let verification_method =
            arkret_wire::DidUrl::new(format!("{}#{multibase}", issuer_did.as_str())).unwrap();
        let issuer_id = arkret_sdk::project_did_to_core_id(&issuer_did).unwrap();
        let subject_id = DidCoreId::new("ak:did_core:web:bob.example".to_owned()).unwrap();
        let org = DidCoreId::new("ak:did_core:web:acme.example".to_owned()).unwrap();
        let claim = organization_membership_claim(
            "claim-1",
            subject_id.clone(),
            issuer_id.clone(),
            org.clone(),
            vec!["member".to_owned()],
        );
        let presentation = signed_presentation(
            &signing_key,
            issuer_id.clone(),
            verification_method,
            "ak:did_core:web:directory.example",
            "challenge-1",
            claim,
        );

        let bindings = test_bindings();
        let verified = verify_restricted_claim_presentations(
            std::slice::from_ref(&presentation),
            Some(subject_id.as_str()),
            Some("challenge-1"),
            "ak:did_core:web:directory.example",
            &bindings,
        )
        .expect("presentation verifies");
        let projection = json!({
            "allowed_discoverers": [{
                "type": "claim",
                "claim_kind": "organization_membership",
                "issuer_id": issuer_id.as_str(),
                "organization_id": org.as_str(),
            }]
        });
        assert!(matches_allowed_discoverers(
            &projection,
            Some(subject_id.as_str()),
            &verified,
        ));

        assert!(
            verify_restricted_claim_presentations(
                &[presentation],
                Some(subject_id.as_str()),
                Some("wrong-challenge"),
                "ak:did_core:web:directory.example",
                &bindings,
            )
            .is_err()
        );
    }

    fn signed_presentation(
        signing_key: &SigningKey,
        iss: DidCoreId,
        verification_method: arkret_wire::DidUrl,
        audience: &str,
        nonce: &str,
        claim: DirectoryPresentedClaim,
    ) -> DirectoryRestrictedClaimPresentation {
        let created_at = Utc::now();
        let expires_at = Some(created_at + Duration::minutes(5));
        let audience = DidCoreId::new(audience.to_owned()).unwrap();
        let payload = RestrictedClaimPresentationPayload {
            kind: DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND,
            iss: &iss,
            verification_method: &verification_method,
            audience: &audience,
            nonce,
            claim: &claim,
            expires_at,
            created_at,
        };
        let canonical = canonical::canonical_json_bytes(&payload).unwrap();
        let jws = sign_jws_ed25519(&canonical, signing_key).unwrap();
        DirectoryRestrictedClaimPresentation {
            kind: DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND.to_owned(),
            iss,
            verification_method,
            audience,
            nonce: nonce.to_owned(),
            claim,
            expires_at,
            created_at,
            jws,
        }
    }

    fn did_key_multibase(signing_key: &SigningKey) -> String {
        let mut bytes = vec![0xed, 0x01];
        bytes.extend_from_slice(signing_key.verifying_key().as_bytes());
        format!("z{}", bs58::encode(bytes).into_string())
    }
}
