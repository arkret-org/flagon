//! Single source of truth for `allowed_discoverers` restricted-visibility
//! matching (spec discovery-directory §3).
//!
//! `restricted` resources are only surfaced to a requester whose identity or
//! signed claim presentations satisfy the resource's `allowed_discoverers`
//! list. This decision gates whether a restricted Realm / Handle /
//! Organization is visible at all, so the matching logic MUST be identical
//! across every `resolve_*` / `search_*` handler.

use std::collections::BTreeSet;

use arkret_identity::binding::DidBindingPurpose;
use arkret_sdk::{
    ClaimDisclosurePolicy, ClaimDisclosureRequirement,
    DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND, Did, DirectoryPresentedClaim,
    DirectoryRestrictedClaimPresentation, PresentationRequestBody, PresentedClaim, canonical,
    validate_presentation,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value as JsonValue;

use crate::did_binding::DidBindingDirectory;
use crate::did_resolver::verification_method_issuer;
use crate::observability::SIGNATURE_KIND_RESTRICTED_CLAIM;

#[derive(Debug, Serialize)]
struct RestrictedClaimPresentationPayload<'a> {
    kind: &'a str,
    iss: &'a Did,
    verification_method: &'a str,
    audience: &'a Did,
    nonce: &'a str,
    claim: &'a DirectoryPresentedClaim,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct VerifiedRestrictedClaims {
    claims: Vec<PresentedClaim>,
}

impl VerifiedRestrictedClaims {
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    #[cfg(test)]
    pub fn for_test(claims: Vec<PresentedClaim>) -> Self {
        Self { claims }
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

/// Decide whether `requester` / `proofs` satisfy the projection's
/// `allowed_discoverers` list. Returns `false` when the list is absent or
/// empty (fail-closed: a restricted resource with no discoverers is invisible).
pub fn matches_allowed_discoverers(
    projection: &JsonValue,
    requester: Option<&str>,
    verified_claims: &VerifiedRestrictedClaims,
) -> bool {
    let Some(discoverers) = allowed_discoverers(projection) else {
        return false;
    };
    discoverers.iter().any(|entry| match entry {
        JsonValue::Object(obj) => claim_selector_matches(obj, requester, verified_claims),
        _ => false,
    })
}

/// Verify every presented restricted claim.
///
/// # DID-P0-C03 — this path never resolves
///
/// `bindings` is a [`DidBindingDirectory`], which owns no DID resolver. A
/// presentation therefore verifies against an **already accepted**
/// [`DidBindingPurpose::DirectoryIssuer`] binding (established when that issuer
/// announced itself to this directory), or — for `did:key`, which is
/// self-describing key material — against a locally decoded document. An issuer
/// this directory has never accepted produces `Err`, which every caller already
/// turns into the blinded `not_found` / "no verified claims" outcome, so the
/// anti-enumeration behaviour is unchanged.
pub fn verify_restricted_claim_presentations(
    presentations: &[DirectoryRestrictedClaimPresentation],
    requester: Option<&str>,
    proof_challenge: Option<&str>,
    expected_audience: &str,
    bindings: &DidBindingDirectory,
) -> Result<VerifiedRestrictedClaims, String> {
    if presentations.is_empty() {
        return Ok(VerifiedRestrictedClaims::default());
    }
    let requester = requester
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "restricted claim presentation requires requester".to_owned())?;
    let challenge = proof_challenge
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "restricted claim presentation requires proof_challenge".to_owned())?;

    let mut claims = Vec::with_capacity(presentations.len());
    for presentation in presentations {
        verify_presentation_envelope(
            presentation,
            requester,
            challenge,
            expected_audience,
            bindings,
        )?;
        claims.push(presentation.claim.clone().into());
    }
    Ok(VerifiedRestrictedClaims { claims })
}

fn verify_presentation_envelope(
    presentation: &DirectoryRestrictedClaimPresentation,
    requester: &str,
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
    if presentation.claim.subject.as_str() != requester {
        return Err("restricted claim subject mismatch".to_owned());
    }
    if presentation.claim.issuer != presentation.iss {
        return Err("restricted claim issuer mismatch".to_owned());
    }
    if verification_method_issuer(&presentation.verification_method)
        != Some(presentation.iss.as_str())
    {
        return Err("restricted claim verification method issuer mismatch".to_owned());
    }
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
        presentation.iss.as_str(),
        bindings,
    )
}

fn verify_presentation_jws(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
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
            issuer,
            DidBindingPurpose::DirectoryIssuer,
            SIGNATURE_KIND_RESTRICTED_CLAIM,
            Utc::now(),
        )
        .map_err(|error| format!("restricted claim JWS invalid: {error}"))
}

fn claim_selector_matches(
    selector: &serde_json::Map<String, JsonValue>,
    requester: Option<&str>,
    verified_claims: &VerifiedRestrictedClaims,
) -> bool {
    if selector.get("type").and_then(JsonValue::as_str) != Some("claim") {
        return false;
    }
    let Some(claim_kind) = selector.get("claim_kind").and_then(JsonValue::as_str) else {
        return false;
    };
    let Some(issuer) = selector.get("issuer").and_then(JsonValue::as_str) else {
        return false;
    };
    let Some(requester) = requester else {
        return false;
    };
    let Ok(subject) = Did::new(requester.to_owned()) else {
        return false;
    };
    let Ok(issuer_did) = Did::new(issuer.to_owned()) else {
        return false;
    };
    verified_claims
        .claims
        .iter()
        .any(|claim| claim_satisfies_selector(claim, selector, &subject, &issuer_did, claim_kind))
}

fn claim_satisfies_selector(
    claim: &PresentedClaim,
    selector: &serde_json::Map<String, JsonValue>,
    subject: &Did,
    issuer: &Did,
    claim_kind: &str,
) -> bool {
    if claim
        .value_matches(selector, "organization")
        .is_some_and(|matches| !matches)
        || claim
            .value_matches(selector, "status")
            .is_some_and(|matches| !matches)
    {
        return false;
    }

    let request = PresentationRequestBody {
        request_id: "teabay.restricted_discovery".to_owned(),
        subject: subject.clone(),
        audience: "teabay.restricted_discovery".to_owned(),
        nonce: "verified-by-teabay-jws".to_owned(),
        policy: ClaimDisclosurePolicy {
            policy_id: "teabay.restricted_discovery".to_owned(),
            requirements: vec![ClaimDisclosureRequirement {
                claim_kind: claim_kind.to_owned(),
                trusted_issuers: vec![issuer.clone()],
                reveal_fields: vec!["*".to_owned()],
                required: true,
            }],
            max_age: None,
            fail_closed: true,
        },
        created_at: Utc::now(),
        verifier_did: None,
        represented_org: None,
        verifier_authority_chain: Vec::new(),
    };
    let validation = validate_presentation(
        &request,
        std::slice::from_ref(claim),
        &BTreeSet::new(),
        Utc::now(),
    );
    validation.accepted
}

trait ClaimSelectorValue {
    fn value_matches(
        &self,
        selector: &serde_json::Map<String, JsonValue>,
        key: &str,
    ) -> Option<bool>;
}

impl ClaimSelectorValue for PresentedClaim {
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
            "did:web:directory.example",
            crate::observability::Metrics::default(),
        )
        .expect("binding directory builds")
    }

    #[tokio::test]
    async fn signed_restricted_claim_presentation_authorizes_claim_selector() {
        let signing_key = SigningKey::from_bytes(&SIGNING_SEED);
        let multibase = did_key_multibase(&signing_key);
        let issuer = Did::new(format!("did:key:{multibase}")).unwrap();
        let verification_method =
            arkret_wire::DidUrl::new(format!("{}#{multibase}", issuer.as_str())).unwrap();
        let subject = Did::new("did:web:bob.example".to_owned()).unwrap();
        let org = Did::new("did:web:acme.example".to_owned()).unwrap();
        let claim = PresentedClaim::organization_membership(
            "claim-1",
            subject.clone(),
            issuer.clone(),
            org.clone(),
            vec!["member".to_owned()],
        );
        let presentation = signed_presentation(
            &signing_key,
            issuer.clone(),
            verification_method,
            "did:web:directory.example",
            "challenge-1",
            claim,
        );

        let bindings = test_bindings();
        let verified = verify_restricted_claim_presentations(
            std::slice::from_ref(&presentation),
            Some(subject.as_str()),
            Some("challenge-1"),
            "did:web:directory.example",
            &bindings,
        )
        .expect("presentation verifies");
        let projection = json!({
            "allowed_discoverers": [{
                "type": "claim",
                "claim_kind": "organization_membership",
                "issuer": issuer.as_str(),
                "organization": org.as_str(),
            }]
        });
        assert!(matches_allowed_discoverers(
            &projection,
            Some(subject.as_str()),
            &verified,
        ));

        assert!(
            verify_restricted_claim_presentations(
                &[presentation],
                Some(subject.as_str()),
                Some("wrong-challenge"),
                "did:web:directory.example",
                &bindings,
            )
            .is_err()
        );
    }

    fn signed_presentation(
        signing_key: &SigningKey,
        iss: Did,
        verification_method: arkret_wire::DidUrl,
        audience: &str,
        nonce: &str,
        claim: PresentedClaim,
    ) -> DirectoryRestrictedClaimPresentation {
        let created_at = Utc::now();
        let expires_at = Some(created_at + Duration::minutes(5));
        let audience = Did::new(audience.to_owned()).unwrap();
        let claim: DirectoryPresentedClaim = claim.into();
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
