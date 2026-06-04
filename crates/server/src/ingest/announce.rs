//! `ck.directory.announce` handler — push-mode ingest.
//!
//! Spec: discovery-directory.md §8.3 (request shape), §8.5 (verify chain),
//! §8.6 (TTL), §8.10 (anti-abuse / replay).

use std::time::Duration;

use chrono::{DateTime, Utc};
use cokret_sdk::{
    HEADER_DESTINATION_TRUST_DOMAIN, HEADER_REQUEST_CANONICAL_DIGEST, HEADER_SOURCE_TRUST_DOMAIN,
    canonical, federation_trust_domain_transcript_fragment,
};
use diesel::prelude::*;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, RunQueryDsl};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};

use crate::audit::{self, AuditEventKind};
use crate::db::Db;
use crate::error::ApiErrorCode;
use crate::filter::circle_isolation::{self, CircleRejection};
use crate::filter::enumeration::{bucket_member_count, is_valid_member_count_bucket};
use crate::ids::{IdClass, new_id};
use crate::ingest::rate_limit::enforce_ingest_rate_limit;
use crate::ingest::subscribe::{AcceptedIngestEvent, fanout_accepted_ingest};
use crate::ingest::verify::VerifyContext;
use crate::ingest::{IngestModeWire, ResourceKindWire};
use crate::state::{AppState, CachedAnnounceResponse};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnounceRequest {
    pub resource_kind: ResourceKindWire,
    pub resource_id: String,
    pub principal_server_did: String,
    pub discovery_state: JsonValue,
    pub source_refs: Vec<String>,
    pub as_of: DateTime<Utc>,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
    #[serde(default)]
    pub supersedes_announce_id: Option<String>,
    #[serde(default)]
    pub trust_root_attestation: Option<JsonValue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnnounceResponse {
    pub announce_id: String,
    pub indexed_at: DateTime<Utc>,
    pub effective_ttl_seconds: i64,
    pub next_revalidation_after: DateTime<Utc>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Round R2/R3 T14 — set when the response was served from the
    /// federation idempotency cache *and* the current capability check
    /// would have failed (e.g. the source service key has been
    /// revoked). The caller MUST treat the body as advisory only and
    /// MUST NOT trigger any new side effects.
    #[serde(default, skip_serializing_if = "is_false")]
    pub historical_only: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

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
/// [`cokret_sdk::federation_trust_domain_transcript_fragment`].
#[derive(Debug, Clone)]
pub struct FederationCacheKeyInputs {
    pub source_service_did: String,
    pub verification_method: String,
    pub service_binding_ref: String,
    pub origin_key_state_digest: Vec<u8>,
    /// Round 4 — `Source-Trust-Domain` header value (lowercased per
    /// RFC 9421 §2.2 — `ck:trust_domain:<scope>` is already lowercase).
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
    pub fn extract(req: &Request, body: &AnnounceRequest) -> Self {
        let source_service_did = header_value(req, "source-service-did")
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
            source_service_did,
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
        h.update(self.source_service_did.as_bytes());
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
/// - `Source-Trust-Domain` is malformed (not a `ck:trust_domain:` identifier).
///
/// Non-federation announces (no headers present) short-circuit OK —
/// the legacy `directory_not_authorized` / `signature_invalid` chain
/// downstream handles the unsigned path.
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
    let source_td = cokret_sdk::TypedTrustDomainId::new(inputs.source_trust_domain.clone())
        .map_err(|err| {
            (
                ApiErrorCode::CrossDomainReplayRejected,
                format!("{HEADER_SOURCE_TRUST_DOMAIN} is not a valid ck:trust_domain: {err}"),
            )
        })?;
    let destination_td = cokret_sdk::TypedTrustDomainId::new(
        inputs.destination_trust_domain.clone(),
    )
    .map_err(|err| {
        (
            ApiErrorCode::CrossDomainReplayRejected,
            format!("{HEADER_DESTINATION_TRUST_DOMAIN} is not a valid ck:trust_domain: {err}"),
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
    // SHA-256 of the Cokret canonical JSON announce body, matching the
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
        cokret_sdk::Hash::new(inputs.request_canonical_digest.clone()).map_err(|err| {
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

fn hex_lower_sha256(bytes: &[u8]) -> String {
    // teabay's announce-request digest is already a SHA-256; we just
    // hex-encode it here so it can be compared to the wire
    // Request-Canonical-Digest header.
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn header_value(req: &Request, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[handler]
pub async fn announce(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let mut ingest_metric = state.metrics().ingest_guard("announce");

    let body: AnnounceRequest = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ingest_metric.set_outcome("bad_json");
            ApiErrorCode::BadJson.render(res, format!("malformed announce body: {e}"));
            return;
        }
    };

    // CKP-0007 / P2E.2 — hard reject any Circle-scoped metadata BEFORE
    // anything else looks at the body. Circle is an intra-Realm
    // sub-boundary; the directory's anti-enumeration guarantees rely
    // on Circle membership/existence NEVER reaching teabay's index.
    // The wire message is deliberately low-information so an attacker
    // can't probe directory state by injecting a `ck:circle:` id.
    if let Err(rejection) = circle_isolation::reject_circle_payload(&body.discovery_state) {
        ingest_metric.set_outcome("circle_isolation_violation");
        let _ = audit::record(
            state.db(),
            AuditEventKind::IngestRejected,
            Some(body.resource_kind),
            Some(&body.resource_id),
            Some(&body.principal_server_did),
            json!({
                "code": ApiErrorCode::SchemaViolation.wire_code(),
                "reason": "circle_isolation_violation",
                "violation": rejection.audit_label(),
            }),
        )
        .await;
        ApiErrorCode::SchemaViolation.render(res, rejection.safe_message());
        return;
    }
    // Defence in depth: a few top-level announce fields are free-form
    // strings (`resource_id`, `principal_server_did`,
    // `supersedes_announce_id`) and could carry a smuggled
    // `ck:circle:` id if a caller is misbehaving. Re-run the typed-id
    // sentinel over the whole request envelope.
    if let Ok(envelope) = serde_json::to_value(&body)
        && let Err(rejection) = circle_isolation::reject_circle_payload(&envelope)
        && !matches!(rejection, CircleRejection::ForbiddenLegacyWireField(_))
    {
        ingest_metric.set_outcome("circle_isolation_violation");
        let _ = audit::record(
            state.db(),
            AuditEventKind::IngestRejected,
            Some(body.resource_kind),
            Some(&body.resource_id),
            Some(&body.principal_server_did),
            json!({
                "code": ApiErrorCode::SchemaViolation.wire_code(),
                "reason": "circle_isolation_violation",
                "violation": rejection.audit_label(),
            }),
        )
        .await;
        ApiErrorCode::SchemaViolation.render(res, rejection.safe_message());
        return;
    }

    // CKP R3 spec-sync 2026-05-27 (commit b47ff6e), identity-handles
    // §17 — wire-level handle homograph guard. When a handle resource
    // is announced, the localpart of `resource_id` MUST pass the SDK's
    // `normalize_handle_localpart` rule (NFC + UTS#39 confusable
    // skeleton + script-mixed reject) before the row is indexed.
    // Otherwise an attacker could push a Cyrillic / mixed-script
    // homograph row that later collides with the canonical-form
    // localpart at resolve time.
    if matches!(body.resource_kind, ResourceKindWire::Handle) {
        let localpart =
            crate::query::handle::extract_localpart_public(&body.resource_id).to_owned();
        if cokret_sdk::normalize_handle_localpart(&localpart).is_err() {
            ingest_metric.set_outcome("handle_homograph_forbidden");
            let _ = audit::record(
                state.db(),
                AuditEventKind::IngestRejected,
                Some(body.resource_kind),
                Some(&body.resource_id),
                Some(&body.principal_server_did),
                json!({
                    "code": ApiErrorCode::HandleHomographForbidden.wire_code(),
                    "reason": "handle_homograph_forbidden",
                }),
            )
            .await;
            ApiErrorCode::HandleHomographForbidden.render(
                res,
                "handle localpart violates homograph / script-mixed policy",
            );
            return;
        }
    }

    if let Err((code, msg)) = validate_request_shape(&body, state.config().max_ttl) {
        ingest_metric.set_outcome("schema_rejected");
        code.render(res, msg);
        return;
    }
    if !enforce_ingest_rate_limit(req, res, &state, &body.resource_id) {
        ingest_metric.set_outcome("rate_limited");
        return;
    }

    let request_digest = digest_request(&body);
    // Round R2/R3 T14 — federation idempotency cache key is the
    // SHA-256 over (request_digest || Source-Service-DID ||
    // verification_method || service_binding_ref ||
    // origin_key_state_digest || Source-Trust-Domain ||
    // Destination-Trust-Domain || Request-Canonical-Digest). On hit we
    // still re-do the capability check; if it now fails (e.g. revoked
    // service key), we serve the cached body with
    // `historical_only=true` and trigger no new side effects.
    let cache_inputs = FederationCacheKeyInputs::extract(req, &body);

    // Round 4 (commit f9bd7eb) — federation S2S requests MUST carry
    // the trust-domain triad and we verify it BEFORE looking at the
    // idempotency cache. A misaddressed replay from another trust
    // domain is rejected with `cross_domain_replay_rejected`; the
    // signing-transcript fragment (when the request validates) is
    // logged for downstream verifier chains.
    let _trust_domain_transcript = match verify_federation_trust_domain_headers(
        &cache_inputs,
        &request_digest,
        &state.config().trust_domain,
    ) {
        Ok(fragment) => fragment,
        Err((code, msg)) => {
            ingest_metric.set_outcome("digest_mismatch");
            let _ = audit::record(
                state.db(),
                AuditEventKind::IngestRejected,
                Some(body.resource_kind),
                Some(&body.resource_id),
                Some(&body.principal_server_did),
                json!({
                    "code": code.wire_code(),
                    "message": msg,
                    "source_trust_domain": cache_inputs.source_trust_domain,
                    "destination_trust_domain": cache_inputs.destination_trust_domain,
                }),
            )
            .await;
            code.render(res, msg);
            return;
        }
    };

    let cache_key = cache_inputs.key(&request_digest);

    // INVARIANT: the federation trust-domain triple has already been verified
    // for THIS request above (we only reach here on `Ok(..)`), and the
    // `Request-Canonical-Digest` is folded into `cache_key` — so a cache hit
    // can never serve a response whose trust-domain headers were not validated
    // against the current body. The hit path below therefore does NOT need to
    // (and must not be changed to) re-run the triple check; it re-runs only the
    // §8.5 capability verify to decide `historical_only`.
    if let Some(cached) = state.cached_federation_replay(&cache_key) {
        let ctx = VerifyContext::new(state.config(), state.db());
        let capability = ctx.verify(&body).await;
        let historical_only = capability.is_err();
        if historical_only {
            let _ = audit::record(
                state.db(),
                AuditEventKind::IngestHistoricalOnly,
                Some(body.resource_kind),
                Some(&body.resource_id),
                Some(&body.principal_server_did),
                json!({
                    "announce_id": cached.announce_id,
                    "reason": capability.as_ref().err().map(|(c, m)| json!({
                        "code": c.wire_code(),
                        "message": m,
                    })),
                    "source_service_did": cache_inputs.source_service_did,
                    "verification_method": cache_inputs.verification_method,
                    "service_binding_ref": cache_inputs.service_binding_ref,
                }),
            )
            .await;
        }
        let warning = if historical_only {
            ingest_metric.set_outcome("historical_only");
            "federation_cache_historical_only"
        } else {
            ingest_metric.set_outcome("replay");
            "digest_replay_cache"
        };
        res.render(Json(AnnounceResponse {
            announce_id: cached.announce_id,
            indexed_at: cached.indexed_at,
            effective_ttl_seconds: cached.effective_ttl_seconds,
            next_revalidation_after: cached.next_revalidation_after,
            warnings: vec![warning.into()],
            historical_only,
        }));
        return;
    }

    let ctx = VerifyContext::new(state.config(), state.db());
    let verified = match ctx.verify(&body).await {
        Ok(v) => v,
        Err((code, msg)) => {
            ingest_metric.set_outcome("verify_rejected");
            // Rejection audit (§7.4 — every rejection is logged).
            let _ = audit::record(
                state.db(),
                AuditEventKind::IngestRejected,
                Some(body.resource_kind),
                Some(&body.resource_id),
                Some(&body.principal_server_did),
                json!({ "code": code.wire_code(), "message": msg }),
            )
            .await;
            code.render(res, msg);
            return;
        }
    };

    // Idempotency on (resource_id, as_of) per §8.6.
    if let Some(existing) = find_announce_by_natural_key(
        state.db(),
        body.resource_kind,
        &body.resource_id,
        body.as_of,
    )
    .await
    .ok()
    .flatten()
    {
        let response = AnnounceResponse {
            announce_id: existing.announce_id,
            indexed_at: existing.indexed_at,
            effective_ttl_seconds: existing.effective_ttl_seconds as i64,
            next_revalidation_after: existing.indexed_at
                + chrono::Duration::seconds(existing.effective_ttl_seconds as i64),
            warnings: vec!["idempotent_replay".into()],
            historical_only: false,
        };
        state.remember_federation_replay(
            cache_key.clone(),
            CachedAnnounceResponse {
                announce_id: response.announce_id.clone(),
                indexed_at: response.indexed_at,
                effective_ttl_seconds: response.effective_ttl_seconds,
                next_revalidation_after: response.next_revalidation_after,
            },
        );
        ingest_metric.set_outcome("replay");
        res.render(Json(response));
        return;
    }

    // Reject as_of older than the most recent indexed entry (§8.10 rollback).
    if let Some(latest) = latest_as_of_for(state.db(), body.resource_kind, &body.resource_id)
        .await
        .ok()
        .flatten()
        && body.as_of < latest
    {
        ingest_metric.set_outcome("rollback_rejected");
        ApiErrorCode::PolicyRevisionRollback.render(
            res,
            format!(
                "incoming as_of {} is older than indexed {latest}",
                body.as_of
            ),
        );
        return;
    }

    let effective_ttl = effective_ttl_seconds(body.ttl_seconds, state.config());
    let announce_id = new_id(IdClass::Announce);
    let indexed_at = Utc::now();
    let next_revalidation = indexed_at + chrono::Duration::seconds(effective_ttl);
    let public_projection = match derive_public_projection(&body.discovery_state) {
        Ok(projection) => projection,
        Err((code, msg)) => {
            ingest_metric.set_outcome("projection_rejected");
            // HC-TBY-1/2 — projection rejections include the R3.2 handle-claim
            // scope rejections (`claim_type_unsupported`,
            // `handle_claim_subject_not_principal_did`). Write the audit row so
            // the operator console surfaces the reason.
            let _ = audit::record(
                state.db(),
                AuditEventKind::IngestRejected,
                Some(body.resource_kind),
                Some(&body.resource_id),
                Some(&body.principal_server_did),
                json!({ "code": code.wire_code(), "message": msg, "reason": "projection_rejected" }),
            )
            .await;
            code.render(res, msg);
            return;
        }
    };

    // Round R2/R3 T07 — discovery_state can carry a `terminal_state`
    // marker after `ck.realm.destroy` anchors. Surface it as a row-level
    // tombstone so the resolve / search projections collapse to a
    // placeholder. See `derive_realm_terminal_state`.
    let realm_terminal = derive_realm_terminal_state(body.resource_kind, &body.discovery_state);

    let insert_outcome = upsert_resource_and_audit(
        state.db(),
        &body,
        &verified,
        IngestModeWire::Push,
        &announce_id,
        indexed_at,
        effective_ttl,
        next_revalidation,
        request_digest.clone(),
        public_projection.clone(),
        FederationCachePersist {
            source_service_did: cache_inputs.source_service_did.clone(),
            verification_method: cache_inputs.verification_method.clone(),
            service_binding_ref: cache_inputs.service_binding_ref.clone(),
            origin_key_state_digest: cache_inputs.origin_key_state_digest.clone(),
            historical_only: false,
        },
        realm_terminal,
    )
    .await;

    if let Err(e) = insert_outcome {
        ingest_metric.set_outcome("persist_error");
        ApiErrorCode::InternalError.render(res, format!("persist announce: {e}"));
        return;
    }

    let _ = audit::record(
        state.db(),
        AuditEventKind::IngestAccepted,
        Some(body.resource_kind),
        Some(&body.resource_id),
        Some(&body.principal_server_did),
        json!({
            "announce_id": announce_id,
            "ingest_mode": "push",
            "discoverability": verified.discoverability.as_pg(),
            "policy_revision": verified.policy_revision,
            "realm_destroyed": realm_terminal.is_some(),
        }),
    )
    .await;

    if let Some(destroyed_at) = realm_terminal {
        let _ = audit::record(
            state.db(),
            AuditEventKind::RealmDestroyed,
            Some(body.resource_kind),
            Some(&body.resource_id),
            Some(&body.principal_server_did),
            json!({
                "announce_id": announce_id,
                "as_of": body.as_of,
            }),
        )
        .await;
        // Round R2/R3 T07 — tombstone fanout to in-flight subscribers.
        let tombstone = crate::query::admin::ReachabilityTombstone {
            kind: crate::query::admin::TombstoneKind::RealmDestroyed,
            resource_kind: body.resource_kind,
            resource_id: body.resource_id.clone(),
            principal_server_did: body.principal_server_did.clone(),
            reason: "ck.realm.destroy".into(),
            revoked_at: destroyed_at,
        };
        let _ =
            crate::ingest::subscribe::fanout_reachability_tombstone(state.clone(), &[tombstone])
                .await;
    }

    fanout_accepted_ingest(
        state.clone(),
        AcceptedIngestEvent {
            announce_id: announce_id.clone(),
            ingest_mode: IngestModeWire::Push,
            resource_kind: body.resource_kind,
            resource_id: body.resource_id.clone(),
            principal_server_did: body.principal_server_did.clone(),
            indexed_at,
            as_of: body.as_of,
            source_refs: body.source_refs.clone(),
            policy_revision: verified.policy_revision.clone(),
            public_projection,
        },
    )
    .await;

    state.remember_federation_replay(
        cache_key,
        CachedAnnounceResponse {
            announce_id: announce_id.clone(),
            indexed_at,
            effective_ttl_seconds: effective_ttl,
            next_revalidation_after: next_revalidation,
        },
    );

    ingest_metric.set_outcome("verify_ok");
    res.render(Json(AnnounceResponse {
        announce_id,
        indexed_at,
        effective_ttl_seconds: effective_ttl,
        next_revalidation_after: next_revalidation,
        warnings: vec![],
        historical_only: false,
    }));
}

/// Round R2/R3 T07 — detect a realm terminal state from the verified
/// discovery_state. The directory accepts the destroy anchor either as
/// `terminal_state: "destroyed"` (preferred, anchored via the `ck.realm.
/// destroy` event kind) or as a `realm_destroyed: true` shorthand. The
/// returned timestamp is `as_of_destroyed` if present, else `as_of`.
pub(crate) fn derive_realm_terminal_state(
    resource_kind: ResourceKindWire,
    discovery_state: &JsonValue,
) -> Option<DateTime<Utc>> {
    if !matches!(resource_kind, ResourceKindWire::Realm) {
        return None;
    }
    let destroyed_marker = discovery_state
        .pointer("/terminal_state")
        .and_then(JsonValue::as_str)
        .is_some_and(|state| state.eq_ignore_ascii_case("destroyed"))
        || discovery_state
            .pointer("/realm_destroyed")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false);
    if !destroyed_marker {
        return None;
    }
    let destroyed_at = discovery_state
        .pointer("/realm_destroyed_at")
        .or_else(|| discovery_state.pointer("/as_of_destroyed"))
        .and_then(JsonValue::as_str)
        .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);
    Some(destroyed_at)
}

fn validate_request_shape(
    req: &AnnounceRequest,
    max_ttl: Duration,
) -> Result<(), (ApiErrorCode, String)> {
    if req.resource_id.is_empty() {
        return Err((ApiErrorCode::MissingParam, "resource_id is required".into()));
    }
    if req.principal_server_did.is_empty() {
        return Err((
            ApiErrorCode::MissingParam,
            "principal_server_did is required".into(),
        ));
    }
    if !req.discovery_state.is_object() {
        return Err((
            ApiErrorCode::SchemaViolation,
            "discovery_state must be an object".into(),
        ));
    }
    if let Some(ttl) = req.ttl_seconds
        && (ttl <= 0 || ttl > max_ttl.as_secs() as i64)
    {
        return Err((
            ApiErrorCode::TtlOutOfRange,
            format!("ttl_seconds {ttl} not in (0, {}]", max_ttl.as_secs()),
        ));
    }
    Ok(())
}

pub(crate) fn effective_ttl_seconds(
    requested: Option<i64>,
    config: &crate::config::AppConfig,
) -> i64 {
    let requested = requested
        .map(|t| t.max(1))
        .unwrap_or_else(|| config.default_ttl.as_secs() as i64);
    let cap = config.max_ttl.as_secs() as i64;
    requested.min(cap)
}

pub(crate) fn derive_public_projection(
    discovery_state: &JsonValue,
) -> Result<JsonValue, (ApiErrorCode, String)> {
    // Strict subset suitable for indexing — drop the proof envelope and
    // anything else that could leak governance internals.
    //
    // Real projection logic (per resource kind) belongs in `crate::query::*`
    // and is deferred to M3.

    // HC-TBY-1/2 (R3.2, cokret-spec @ b56cab1) — handle-claim wire-level
    // scope validation. This runs in `derive_public_projection` so it
    // applies uniformly to BOTH the push-mode announce path and the
    // federation pull-worker / well-known resolver path (both funnel through
    // this function), satisfying HC-TBY-2's "all reject paths also act on
    // pulled-back claims" requirement.
    validate_handle_claim_ingest(discovery_state)?;

    let mut clone = discovery_state.clone();
    if let Some(obj) = clone.as_object_mut() {
        obj.remove("proof");
        obj.remove("directory_services");
        // `official_organizations` is a forbidden directory-projection field
        // (spec §4.5). Strip it so it never enters the index or search SQL;
        // organization scoping uses the canonical `organization_did`.
        obj.remove("official_organizations");
        normalize_member_count_projection(obj)?;
    }
    Ok(clone)
}

/// HC-TBY-1/2 — reject handle-claim ingest that violates the R3.2 wire scope:
///
/// 1. `claim_type` / `class` == `service_handle` is rejected (the draft-era value was removed in
///    R3.2). Audit reason `claim_type_unsupported`.
/// 2. A handle-claim `subject` that is a `ck:actor:` Realm actor id, a `ck:account:` server-local
///    account id, a service DID, or any non-DID resource id is rejected. Audit reason
///    `handle_claim_subject_not_principal_did`. The structural DID check is delegated to the SDK's
///    `validate_handle_claim_subject` so the directory and the rest of the stack share one rule.
///
/// Only discovery_state bodies that actually look like a handle claim (carry
/// a `subject` and/or `claim_type` / `class`) are inspected; non-handle
/// announces pass through untouched.
fn validate_handle_claim_ingest(discovery_state: &JsonValue) -> Result<(), (ApiErrorCode, String)> {
    let Some(obj) = discovery_state.as_object() else {
        return Ok(());
    };

    // (1) `claim_type` / `class` are retired field names. `service_handle`
    // is no longer a valid claim_kind value.
    if obj.get("claim_type").is_some() || obj.get("class").is_some() {
        return Err((
            ApiErrorCode::SchemaViolation,
            "claim_type_unsupported: claim_type/class are forbidden; use claim_kind".to_owned(),
        ));
    }
    if obj
        .get("claim_kind")
        .and_then(JsonValue::as_str)
        .is_some_and(|value| value == "service_handle")
    {
        return Err((
            ApiErrorCode::SchemaViolation,
            "claim_type_unsupported: service_handle is not a valid handle claim_kind".to_owned(),
        ));
    }

    // (2) handle-claim subject MUST be a holder/principal DID.
    if let Some(subject) = obj.get("subject").and_then(JsonValue::as_str) {
        match cokret_sdk::Did::new(subject.to_owned()) {
            Ok(did) => {
                if cokret_sdk::validate_handle_claim_subject(&did).is_err() {
                    return Err((
                        ApiErrorCode::SchemaViolation,
                        format!(
                            "handle_claim_subject_not_principal_did: subject {subject} is not a \
                             holder/principal DID"
                        ),
                    ));
                }
            }
            Err(_) => {
                // `ck:actor:` / `ck:account:` / generic resource ids are not
                // valid DIDs at all — same rejection family.
                if subject.starts_with("ck:actor:")
                    || subject.starts_with("ck:account:")
                    || !subject.starts_with("did:")
                {
                    return Err((
                        ApiErrorCode::SchemaViolation,
                        format!(
                            "handle_claim_subject_not_principal_did: subject {subject} is not a \
                             holder/principal DID"
                        ),
                    ));
                }
            }
        }
    }

    Ok(())
}

fn normalize_member_count_projection(
    obj: &mut serde_json::Map<String, JsonValue>,
) -> Result<(), (ApiErrorCode, String)> {
    if let Some(bucket) = obj.get("member_count_bucket").and_then(JsonValue::as_str)
        && !is_valid_member_count_bucket(bucket)
    {
        return Err((
            ApiErrorCode::InvalidResponse,
            format!("member_count_bucket {bucket} is outside the normative bucket grid"),
        ));
    }

    if let Some(exact) = obj.remove("member_count") {
        let count = exact.as_i64().ok_or_else(|| {
            (
                ApiErrorCode::InvalidResponse,
                "member_count must be an integer when present".into(),
            )
        })?;
        obj.insert(
            "member_count_bucket".into(),
            JsonValue::String(bucket_member_count(count).to_string()),
        );
    }
    Ok(())
}

pub(crate) fn digest_request(req: &AnnounceRequest) -> Vec<u8> {
    // Cokret canonical JSON body SHA-256 — used for replay detection in
    // `ingest_announces.request_digest` and for Request-Canonical-Digest.
    let mut h = Sha256::new();
    let value =
        serde_json::to_value(req).expect("AnnounceRequest is serde-serializable by construction");
    let canonical = canonical_json_bytes(&value)
        .expect("AnnounceRequest is canonical-json serializable by construction");
    h.update(&canonical);
    h.finalize().to_vec()
}

/// Cokret canonical JSON string via the SDK's `cokret_sdk::canonical`
/// implementation (UTF-16 key ordering, integer-only number profile).
///
/// Replaces a hand-written serializer that sorted object keys by byte
/// order (`sort_unstable()`) — divergent from the SDK and the rest of the
/// federation. Errors are flattened to `String` to keep the existing
/// call-site error contract.
pub(crate) fn canonical_json_string(value: &JsonValue) -> Result<String, String> {
    canonical::canonical_json_string(value).map_err(|err| err.to_string())
}

fn canonical_json_bytes(value: &JsonValue) -> Result<Vec<u8>, String> {
    canonical::canonical_json_bytes(value).map_err(|err| err.to_string())
}

#[derive(Queryable)]
struct AnnounceLookup {
    announce_id: String,
    indexed_at: DateTime<Utc>,
    effective_ttl_seconds: i32,
}

async fn find_announce_by_natural_key(
    db: &Db,
    kind: ResourceKindWire,
    resource_id: &str,
    as_of: DateTime<Utc>,
) -> anyhow::Result<Option<AnnounceLookup>> {
    use crate::schema::ingest_announces::dsl;
    let mut conn = db.get().await?;
    let row: Option<AnnounceLookup> = dsl::ingest_announces
        .filter(dsl::resource_kind.eq(kind))
        .filter(dsl::resource_id.eq(resource_id))
        .filter(dsl::as_of.eq(as_of))
        .select((
            dsl::announce_id,
            dsl::indexed_at,
            dsl::effective_ttl_seconds,
        ))
        .first(&mut *conn)
        .await
        .optional()?;
    Ok(row)
}

pub(crate) async fn latest_as_of_for(
    db: &Db,
    kind: ResourceKindWire,
    resource_id: &str,
) -> anyhow::Result<Option<DateTime<Utc>>> {
    use crate::schema::directory_resources::dsl;
    let mut conn = db.get().await?;
    let row: Option<DateTime<Utc>> = dsl::directory_resources
        .filter(dsl::resource_kind.eq(kind))
        .filter(dsl::resource_id.eq(resource_id))
        .select(dsl::as_of)
        .first(&mut *conn)
        .await
        .optional()?;
    Ok(row)
}

/// Round R2/R3 T14 — extra federation cache fields persisted alongside
/// the `ingest_announces` row. Push-mode pulls them from request headers
/// and discovery proof; pull-mode pulls them from the upstream
/// `ck.events.query` response headers/envelope plus the same proof.
#[derive(Debug, Clone, Default)]
pub struct FederationCachePersist {
    pub source_service_did: String,
    pub verification_method: String,
    pub service_binding_ref: String,
    pub origin_key_state_digest: Vec<u8>,
    pub historical_only: bool,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn upsert_resource_and_audit(
    db: &Db,
    body: &AnnounceRequest,
    verified: &super::verify::VerifyOutcome,
    ingest_mode: IngestModeWire,
    announce_id: &str,
    indexed_at: DateTime<Utc>,
    effective_ttl: i64,
    next_revalidation: DateTime<Utc>,
    request_digest: Vec<u8>,
    public_projection: JsonValue,
    federation_cache: FederationCachePersist,
    realm_terminal_state: Option<DateTime<Utc>>,
) -> anyhow::Result<()> {
    use crate::schema::directory_resources::dsl as r;
    use crate::schema::ingest_announces::dsl as a;

    let mut conn = db.get().await?;
    conn.transaction::<_, anyhow::Error, _>(|conn| {
        async move {
            let inserted = diesel::insert_into(a::ingest_announces)
                .values((
                    a::announce_id.eq(announce_id),
                    a::resource_kind.eq(body.resource_kind),
                    a::resource_id.eq(&body.resource_id),
                    a::principal_server_did.eq(&body.principal_server_did),
                    a::ingest_mode.eq(ingest_mode),
                    a::discovery_state.eq(&body.discovery_state),
                    a::source_refs.eq(&body.source_refs),
                    a::as_of.eq(body.as_of),
                    a::indexed_at.eq(indexed_at),
                    a::effective_ttl_seconds.eq(effective_ttl as i32),
                    a::supersedes_announce_id.eq(body.supersedes_announce_id.as_deref()),
                    a::request_digest.eq(&request_digest),
                    a::source_service_did.eq(&federation_cache.source_service_did),
                    a::verification_method.eq(&federation_cache.verification_method),
                    a::service_binding_ref.eq(&federation_cache.service_binding_ref),
                    a::origin_key_state_digest.eq(&federation_cache.origin_key_state_digest),
                    a::historical_only.eq(federation_cache.historical_only),
                ))
                .on_conflict((a::resource_kind, a::resource_id, a::as_of))
                .do_nothing()
                .execute(&mut *conn)
                .await?;

            let stored_announce_id = if inserted == 0 {
                let (stored_announce_id, stored_state, stored_source_refs) = a::ingest_announces
                    .filter(a::resource_kind.eq(body.resource_kind))
                    .filter(a::resource_id.eq(&body.resource_id))
                    .filter(a::as_of.eq(body.as_of))
                    .select((a::announce_id, a::discovery_state, a::source_refs))
                    .first::<(String, JsonValue, Vec<String>)>(&mut *conn)
                    .await?;
                if stored_state != body.discovery_state || stored_source_refs != body.source_refs {
                    anyhow::bail!(
                        "natural-key conflict for ({}, {}, {}) carries different signed state",
                        body.resource_kind.as_pg(),
                        body.resource_id,
                        body.as_of
                    );
                }
                stored_announce_id
            } else {
                announce_id.to_owned()
            };

            diesel::insert_into(r::directory_resources)
            .values((
                r::resource_kind.eq(body.resource_kind),
                r::resource_id.eq(&body.resource_id),
                r::principal_server_did.eq(&body.principal_server_did),
                r::discovery_state.eq(&body.discovery_state),
                r::public_projection.eq(&public_projection),
                r::discoverability.eq(verified.discoverability),
                r::as_of.eq(body.as_of),
                r::source_refs.eq(&body.source_refs),
                r::policy_revision.eq(verified.policy_revision.as_deref()),
                r::indexed_at.eq(indexed_at),
                r::effective_ttl_seconds.eq(effective_ttl as i32),
                r::next_revalidation_after.eq(next_revalidation),
                r::stale.eq(false),
                r::divergent.eq(false),
                r::via_services.eq(&verified.via_services),
                r::last_announce_id.eq(Some(stored_announce_id.as_str())),
                r::realm_destroyed_at.eq(realm_terminal_state),
                // P2E.5 — on insert the row was just refreshed at the
                // current announce; expires_at = last_refreshed_at +
                // effective_ttl_seconds.
                r::last_refreshed_at.eq(indexed_at),
                r::expires_at.eq(next_revalidation),
            ))
            .on_conflict((r::resource_kind, r::resource_id))
            .do_update()
            .set((
                r::principal_server_did.eq(&body.principal_server_did),
                r::discovery_state.eq(&body.discovery_state),
                r::public_projection.eq(&public_projection),
                r::discoverability.eq(verified.discoverability),
                r::as_of.eq(body.as_of),
                r::source_refs.eq(&body.source_refs),
                r::policy_revision.eq(verified.policy_revision.as_deref()),
                r::indexed_at.eq(indexed_at),
                r::effective_ttl_seconds.eq(effective_ttl as i32),
                r::next_revalidation_after.eq(next_revalidation),
                r::stale.eq(false),
                r::via_services.eq(&verified.via_services),
                r::last_announce_id.eq(Some(stored_announce_id.as_str())),
                // Round R2/R3 T07 — once a realm is destroyed it
                // remains destroyed; we OR in the new marker without
                // ever clearing a previously-set destroyed_at.
                r::realm_destroyed_at.eq(diesel::dsl::sql::<
                    diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>,
                >(
                    "COALESCE(directory_resources.realm_destroyed_at, EXCLUDED.realm_destroyed_at)",
                )),
                // P2E.5 — every successful announce is a refresh.
                r::last_refreshed_at.eq(indexed_at),
                r::expires_at.eq(next_revalidation),
            ))
            .execute(&mut *conn)
            .await?;

            Ok(())
        }
        .scope_boxed()
    })
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let err = super::validate_handle_claim_ingest(&state).unwrap_err();
        assert_eq!(err.0, ApiErrorCode::SchemaViolation);
        assert!(err.1.contains("claim_type_unsupported"));

        // Also reject retired discriminator fields outright.
        let state = json!({ "class": "service_handle", "subject": "did:web:alice.example" });
        assert!(super::validate_handle_claim_ingest(&state).is_err());
        let state = json!({ "claim_type": "handle_binding", "subject": "did:web:alice.example" });
        assert!(super::validate_handle_claim_ingest(&state).is_err());
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
            let err = super::validate_handle_claim_ingest(&state).unwrap_err();
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
        assert!(super::validate_handle_claim_ingest(&ok).is_ok());

        // A realm announce with no handle-claim fields is untouched.
        let realm = json!({ "kind": "ck.realm.discovery", "discoverability": "public" });
        assert!(super::validate_handle_claim_ingest(&realm).is_ok());

        // And the whole projection path accepts the principal-DID claim.
        assert!(derive_public_projection(&ok).is_ok());
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

        let first = AnnounceRequest {
            resource_kind: ResourceKindWire::Realm,
            resource_id: "ck:realm:tea".to_owned(),
            principal_server_did: "did:web:principal.test".to_owned(),
            discovery_state: JsonValue::Object(first_state),
            source_refs: vec!["evt-1".to_owned()],
            as_of,
            ttl_seconds: Some(3600),
            supersedes_announce_id: None,
            trust_root_attestation: None,
        };
        let second = AnnounceRequest {
            discovery_state: JsonValue::Object(second_state),
            ..first.clone()
        };

        assert_eq!(digest_request(&first), digest_request(&second));
    }
}
