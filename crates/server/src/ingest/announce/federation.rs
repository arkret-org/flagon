//! Federation idempotency cache key + round-4 trust-domain triad verifier.

use arkret_sdk::{
    HEADER_DESTINATION_TRUST_DOMAIN, HEADER_REQUEST_CANONICAL_DIGEST, HEADER_SOURCE_TRUST_DOMAIN,
    federation_trust_domain_transcript_fragment,
};
use salvo::prelude::*;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use super::ingest_body::DirectoryAnnounceIngest;
use crate::error::ApiErrorCode;
use crate::ingest::header_value;

/// Round R2/R3 T14 + Round 4 (spec a77b995, commit f9bd7eb) — extended
/// federation idempotency cache key inputs gathered from request
/// headers + the verified discovery proof. All fields participate in
/// the cache key per spec; missing values fall back to the empty
/// string so the key remains stable for the non-federation announce
/// path.
///
/// Round 4 adds the `Source-Trust-Domain` triad
/// (`Source-Trust-Domain` / `Destination-Trust-Domain` /
/// `Request-Canonical-Digest`) so a sender from trust domain A cannot
/// replay the same idempotency key (with the same `origin_key_state_digest`)
/// into trust domain B. The destination + canonical-hash also feed into
/// the signing transcript via
/// [`arkret_sdk::federation_trust_domain_transcript_fragment`].
#[derive(Debug, Clone)]
pub struct FederationCacheKeyInputs {
    pub source_service_id: String,
    pub verification_method: String,
    pub service_binding_ref: String,
    pub origin_key_state_digest: Vec<u8>,
    /// Round 4 — `Source-Trust-Domain` header value (lowercased per
    /// RFC 9421 §2.2 — `ak:trust_domain:<scope>` is already lowercase).
    /// Empty when the request is not a cross-trust-domain federation
    /// hop.
    pub source_trust_domain: String,
    /// Round 4 — `Destination-Trust-Domain` header value. Used by the
    /// inbound verifier to confirm the request was scoped to this
    /// directory; included in the cache key so a misaddressed replay
    /// from another deployment cannot reuse a cache row.
    pub destination_trust_domain: String,
    /// Round 4 — `Request-Canonical-Digest` header value. Tied to the
    /// canonical hash of the request body in the signing transcript so
    /// transport-level body tampering after the signature was computed
    /// is detectable.
    pub request_canonical_digest: String,
}

impl FederationCacheKeyInputs {
    pub fn extract(req: &Request, body: &DirectoryAnnounceIngest) -> Self {
        let source_service_id = header_value(req, "source-service-did")
            .or_else(|| header_value(req, "x-source-service-did"))
            .unwrap_or_default();
        let verification_method = body
            .discovery_state
            .pointer("/proof/verification_method")
            .and_then(JsonValue::as_str)
            .unwrap_or_default()
            .to_owned();
        let service_binding_ref = header_value(req, "service-binding-ref")
            .or_else(|| header_value(req, "x-service-binding-ref"))
            .unwrap_or_default();
        let origin_key_state_digest = header_value(req, "origin-key-state-digest")
            .or_else(|| header_value(req, "x-origin-key-state-digest"))
            .or_else(|| header_value(req, "origin-key-state-hash"))
            .or_else(|| header_value(req, "x-origin-key-state-hash"))
            .map(|raw| raw.into_bytes())
            .unwrap_or_default();
        let source_trust_domain =
            header_value(req, &HEADER_SOURCE_TRUST_DOMAIN.to_ascii_lowercase()).unwrap_or_default();
        let destination_trust_domain =
            header_value(req, &HEADER_DESTINATION_TRUST_DOMAIN.to_ascii_lowercase())
                .unwrap_or_default();
        let request_canonical_digest =
            header_value(req, &HEADER_REQUEST_CANONICAL_DIGEST.to_ascii_lowercase())
                .unwrap_or_default();
        Self {
            source_service_id,
            verification_method,
            service_binding_ref,
            origin_key_state_digest,
            source_trust_domain,
            destination_trust_domain,
            request_canonical_digest,
        }
    }

    /// `true` when the request advertises the round-4 trust-domain
    /// triad (federation S2S hop). Non-federation directory announces
    /// have all three fields empty.
    pub fn is_federation_hop(&self) -> bool {
        !self.source_trust_domain.is_empty()
            || !self.destination_trust_domain.is_empty()
            || !self.request_canonical_digest.is_empty()
    }

    pub fn key(&self, request_digest: &[u8]) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(request_digest);
        h.update(b"\x1fSSD\x1e");
        h.update(self.source_service_id.as_bytes());
        h.update(b"\x1fVM\x1e");
        h.update(self.verification_method.as_bytes());
        h.update(b"\x1fSBR\x1e");
        h.update(self.service_binding_ref.as_bytes());
        h.update(b"\x1fOKSH\x1e");
        h.update(&self.origin_key_state_digest);
        // Round 4 — bind the trust-domain triad into the cache key so
        // a sender from A cannot replay into B with the same
        // idempotency key.
        h.update(b"\x1fSTD\x1e");
        h.update(self.source_trust_domain.as_bytes());
        h.update(b"\x1fDTD\x1e");
        h.update(self.destination_trust_domain.as_bytes());
        h.update(b"\x1fRCH\x1e");
        h.update(self.request_canonical_digest.as_bytes());
        h.finalize().to_vec()
    }
}

/// Round 4 — verify the inbound federation S2S trust-domain triad.
///
/// On a cross-trust-domain request, the directory MUST refuse to
/// accept a body whose:
/// - `Destination-Trust-Domain` is not this directory's configured `trust_domain`, OR
/// - `Request-Canonical-Digest` does not match the canonical SHA-256 digest of the request body, OR
/// - `Source-Trust-Domain` is malformed (not a `ak:trust_domain:` identifier).
///
/// Non-federation announces (no headers present) short-circuit OK —
/// unsigned announces continue through the downstream authorization
/// and signature checks.
///
/// Returns a writable signing-transcript fragment when the triad
/// validates, so the caller can append it to the RFC 9421 signature
/// base built by `crates/sdk/src/federation`. Returns
/// `Ok(None)` for non-federation announces.
pub(crate) fn verify_federation_trust_domain_headers(
    inputs: &FederationCacheKeyInputs,
    request_digest: &[u8],
    expected_destination_trust_domain: &str,
) -> Result<Option<String>, (ApiErrorCode, String)> {
    if !inputs.is_federation_hop() {
        return Ok(None);
    }
    // All three headers MUST be present on a federation hop.
    if inputs.source_trust_domain.is_empty()
        || inputs.destination_trust_domain.is_empty()
        || inputs.request_canonical_digest.is_empty()
    {
        return Err((
            ApiErrorCode::CrossDomainReplayRejected,
            format!(
                "federation S2S request must carry all three of {}, {}, {} headers",
                HEADER_SOURCE_TRUST_DOMAIN,
                HEADER_DESTINATION_TRUST_DOMAIN,
                HEADER_REQUEST_CANONICAL_DIGEST,
            ),
        ));
    }
    // Validate trust-domain identifiers via the SDK's typed wrapper so
    // method-name regex tightening + scope-length limits are enforced.
    let source_td = arkret_sdk::TypedTrustDomainId::new(inputs.source_trust_domain.clone())
        .map_err(|err| {
            (
                ApiErrorCode::CrossDomainReplayRejected,
                format!("{HEADER_SOURCE_TRUST_DOMAIN} is not a valid ak:trust_domain: {err}"),
            )
        })?;
    let destination_td = arkret_sdk::TypedTrustDomainId::new(
        inputs.destination_trust_domain.clone(),
    )
    .map_err(|err| {
        (
            ApiErrorCode::CrossDomainReplayRejected,
            format!("{HEADER_DESTINATION_TRUST_DOMAIN} is not a valid ak:trust_domain: {err}"),
        )
    })?;
    if destination_td.as_str() != expected_destination_trust_domain {
        return Err((
            ApiErrorCode::CrossDomainReplayRejected,
            format!(
                "{HEADER_DESTINATION_TRUST_DOMAIN}={} does not match this directory's trust domain {}",
                destination_td.as_str(),
                expected_destination_trust_domain,
            ),
        ));
    }
    // Verify the request-canonical-digest matches the request digest the
    // handler computed over the parsed body. `digest_request` is the
    // SHA-256 of the Arkret canonical JSON announce body, matching the
    // SDK federation transport's `Request-Canonical-Digest` domain.
    let computed_hash = format!("sha256:{}", hex_lower_sha256(request_digest));
    if !inputs
        .request_canonical_digest
        .eq_ignore_ascii_case(&computed_hash)
    {
        return Err((
            ApiErrorCode::CrossDomainReplayRejected,
            format!(
                "{HEADER_REQUEST_CANONICAL_DIGEST}={} does not match canonical body digest {computed_hash}",
                inputs.request_canonical_digest
            ),
        ));
    }
    // Build the signing-transcript fragment per RFC 9421 §2.2 so the
    // caller can append it to the canonical signature base. The
    // request-canonical-digest MUST be re-parsed by the SDK as a `Hash`,
    // but teabay's announce path does not yet sign the response with
    // an RFC 9421 envelope — the transcript fragment is emitted so the
    // federation outbound path (when wired) reuses the same value.
    let canonical_hash =
        arkret_sdk::Hash::new(inputs.request_canonical_digest.clone()).map_err(|err| {
            (
                ApiErrorCode::CrossDomainReplayRejected,
                format!("{HEADER_REQUEST_CANONICAL_DIGEST} is not a valid Hash: {err}"),
            )
        })?;
    Ok(Some(federation_trust_domain_transcript_fragment(
        &source_td,
        &destination_td,
        &canonical_hash,
    )))
}

pub(crate) fn hex_lower_sha256(bytes: &[u8]) -> String {
    // teabay's announce-request digest is already a SHA-256; we just
    // hex-encode it here so it can be compared to the wire
    // Request-Canonical-Digest header.
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Round R2/R3 T14 — extra federation cache fields persisted alongside
/// the `ingest_announces` row. Push-mode pulls them from request headers
/// and discovery proof; pull-mode pulls them from the upstream
/// `ak.self.events.query.scan` response headers/envelope plus the same proof.
#[derive(Debug, Clone, Default)]
pub struct FederationCachePersist {
    pub source_service_id: String,
    pub verification_method: String,
    pub service_binding_ref: String,
    pub origin_key_state_digest: Vec<u8>,
    pub historical_only: bool,
}
