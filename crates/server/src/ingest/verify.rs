//! 5-step verify chain for ingest (spec §8.5).
//!
//! 1. Transport layer — HTTP Message Signature for push. We surface a hook here; the actual RFC
//!    9421 HTTP signature check lives in [`crate::middleware::http_sig`] (mounted on the ingest
//!    sub-router by [`crate::routing::directory_router`] via `.hoop(HttpSigMiddleware::new(...))`)
//!    so the handler always sees an already-authenticated transport. TB-1 (this comment block)
//!    closed the prior gap where the middleware was advertised but not actually mounted.
//! 2. Discovery proof — verify the original discovery Event producer proof against the resource
//!    governance key resolved via DID document.
//! 3. Directory authorization — `discovery_state.directory_services` is a core-id list containing
//!    *this* directory's stable service id.
//! 4. Source-ref sanity — for first ingest, verifies an anchor from the resource's Station to
//!    confirm `source_refs[0]` is resolvable.
//! 5. Accept policy — local accept_policy (open / allowlist / operator_review) decision.
//!
//! Any failure MUST short-circuit; we never partially accept (§8.5 last line).

use std::net::IpAddr;
use std::time::Duration;

use arkret_identity::binding::DidBindingPurpose;
use arkret_identity::document_canonical_digest;
use arkret_sdk::identity::DidWebvhResolver;
use arkret_sdk::{
    DID_WEB_MAX_DOCUMENT_BYTES, Did, DidCoreId, DidWebResolver, DirectoryGovernanceProof,
    DirectoryWithdrawRequestBody, canonical,
};
use arkret_wire::{Hash, TrustDomainId, WireError};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;
use url::Url;

use crate::config::{AcceptPolicyKind, AppConfig};
use crate::db::Db;
use crate::did_resolver::{SharedDidResolver, did_method_allowed, did_method_prefix_for_did};
use crate::error::ApiErrorCode;
use crate::ingest::DirectoryResourceKindDb;
use crate::ingest::announce::DirectoryAnnounceIngest;
use crate::observability::SIGNATURE_KIND_INGEST_PROOF;

const MAX_VIA_SERVICES: usize = 8;
pub(crate) const EXTERNAL_JSON_MAX_BYTES: usize = 1_048_576;

#[derive(Debug)]
pub struct VerifyOutcome {
    /// Effective `discoverability` parsed from discovery_state.
    pub discoverability: super::DiscoverabilityDb,
    /// Stable service core ids explicitly supplied by the verified state, or
    /// `station_id` itself as a fallback.
    pub via_services: Vec<DidCoreId>,
    /// Effective `policy_revision` from the verified discovery state.
    pub policy_revision: String,
}

pub struct VerifyContext<'a> {
    pub config: &'a AppConfig,
    pub db: &'a Db,
    /// DID-P0-C01 — borrowed from `AppState`; never constructed here.
    pub resolver: &'a SharedDidResolver,
    pub now: DateTime<Utc>,
}

impl<'a> VerifyContext<'a> {
    pub fn new(config: &'a AppConfig, db: &'a Db, resolver: &'a SharedDidResolver) -> Self {
        Self {
            config,
            db,
            resolver,
            now: Utc::now(),
        }
    }

    /// Run all five steps. Returns `Err((code, msg))` on rejection — caller
    /// renders that via `ApiErrorCode::render`. Returns `Ok(VerifyOutcome)` on
    /// acceptance with the derived facts the announce handler needs.
    pub async fn verify(
        &self,
        req: &DirectoryAnnounceIngest,
    ) -> Result<VerifyOutcome, (ApiErrorCode, String)> {
        // --- Step 1: transport — enforced by `crate::middleware::http_sig`.
        // That middleware verifies the RFC 9421 `Signature-Input` /
        // `Signature` headers + RFC 9530 `Content-Digest` against the
        // operator-configured Ed25519 pubkey allowlist before the request
        // ever reaches this handler. See `directory_router` in
        // `crate::routing` for the `.hoop(...)` wire and `TB-1` for the
        // landing audit. ------------------------------------------------

        // --- Step 0a: DID format normalization. ----------------------------
        // Spec sync (commit 37ce729, B-D): every DID-bearing identifier in
        // the announce envelope carries a *stable identity core*, not a
        // resolvable DID: `discovery-directory.md` §8.3 types the
        // Organization / Actor / Applet `resource_id` and
        // `station_id` as `did_core_id`. We push this check
        // through the SDK `DidCoreId::new` parser so the teabay directory and
        // the rest of the Arkret stack share one normative parser.
        // Non-conforming inputs short-circuit with a structured rejection
        // BEFORE any signature / accept-policy work, which keeps audit logs
        // clean and rules out a DID smuggled into a stable-identity slot
        // at the ingest boundary. `station_id` needs no check
        // here: it is already a parsed `DidCoreId` on the ingest body.
        if matches!(
            req.resource_kind,
            DirectoryResourceKindDb::Organization
                | DirectoryResourceKindDb::Actor
                | DirectoryResourceKindDb::Applet
        ) {
            DidCoreId::new(req.resource_id.clone()).map_err(|e| {
                (
                    ApiErrorCode::SchemaViolation,
                    format!(
                        "resource_id `{}` does not conform to stable identity core syntax \
                         ^ak:did_core:[a-z0-9]+:[^\\s]+$: {e}",
                        req.resource_id
                    ),
                )
            })?;
        }

        // --- Step 0b (housekeeping): freshness window. ---------------------
        let skew = chrono::Duration::from_std(self.config.as_of_skew).map_err(|_| {
            (
                ApiErrorCode::InternalError,
                "invalid skew config".to_string(),
            )
        })?;
        let drift = (req.as_of - self.now).num_seconds().abs();
        if drift > skew.num_seconds() {
            return Err((
                ApiErrorCode::SignatureStale,
                format!(
                    "as_of skew {drift}s exceeds configured tolerance {}s",
                    skew.num_seconds()
                ),
            ));
        }

        // --- Step 2: discovery proof verification. -------------------------
        let expected_governance_controller = self.expected_governance_controller(req).await?;
        verify_discovery_event_proofs(
            &req.discovery_event,
            req.resource_kind,
            &req.resource_id,
            expected_governance_controller.as_deref(),
            self.resolver,
        )?;

        // --- Step 3: directory authorization (this DID listed). ------------
        if !directory_services_are_core_ids(&req.discovery_state) {
            return Err((
                ApiErrorCode::SchemaViolation,
                "discovery_state.directory_services must be a non-empty array of service core ids"
                    .to_owned(),
            ));
        }
        let listed =
            directory_services_lists_self(&req.discovery_state, self.config.service_id.as_str());
        if !listed {
            return Err((
                ApiErrorCode::DirectoryUnauthorized,
                format!(
                    "discovery_state.directory_services does not list this directory ({})",
                    self.config.service_id
                ),
            ));
        }

        // --- Step 4: source-ref sanity. ------------------------------------
        if req.source_refs.is_empty() {
            return Err((
                ApiErrorCode::SourceRefsUnverifiable,
                "source_refs MUST contain at least one anchor event id".into(),
            ));
        }
        if !resource_already_indexed(self.db, req.resource_kind, &req.resource_id)
            .await
            .map_err(|e| (ApiErrorCode::InternalError, format!("source-ref gate: {e}")))?
        {
            verify_first_source_ref_resolves(req, self.config, self.resolver).await?;
        }

        // --- Step 5: accept policy enforcement. ----------------------------
        self.enforce_accept_policy(req).await?;

        // --- Cross-checks: takedown-in-force --------------------------------
        if let Some(effective_at) =
            previously_withdrawn(self.db, req.resource_kind, &req.resource_id)
                .await
                .map_err(|e| {
                    (
                        ApiErrorCode::InternalError,
                        format!("withdrawal check: {e}"),
                    )
                })?
            && req.as_of <= effective_at
        {
            return Err((
                ApiErrorCode::TakedownInForce,
                format!(
                    "a withdrawal is in force as of {effective_at}; \
                     announce as_of {} is not strictly later",
                    req.as_of
                ),
            ));
        }

        // --- Derive outcome from verified state. ---------------------------
        let discoverability = read_discoverability(&req.discovery_state)?;
        let via_services = derive_via_services(&req.discovery_state, &req.station_id);
        // The request does not echo a free-form revision.  The verified source
        // frontier is the revision carrier; Realm producers include the
        // effective policy-bundle Event in this frontier.
        let policy_revision = canonical::canonical_sha256(&req.source_refs).map_err(|error| {
            (
                ApiErrorCode::SchemaViolation,
                format!("source_refs revision is not canonical: {error}"),
            )
        })?;

        Ok(VerifyOutcome {
            discoverability,
            via_services,
            policy_revision,
        })
    }

    async fn enforce_accept_policy(
        &self,
        req: &DirectoryAnnounceIngest,
    ) -> Result<(), (ApiErrorCode, String)> {
        // DID method allowlist (applies regardless of accept policy kind).
        if matches!(
            req.resource_kind,
            DirectoryResourceKindDb::Organization
                | DirectoryResourceKindDb::Actor
                | DirectoryResourceKindDb::Applet
        ) {
            let method = did_method_prefix_for_did(&req.resource_id).unwrap_or_default();
            if !self
                .config
                .accepted_did_methods
                .iter()
                .any(|m| crate::did_resolver::did_method_allowed(std::slice::from_ref(m), &method))
            {
                return Err((
                    ApiErrorCode::AcceptPolicyDenied,
                    format!(
                        "DID method {} not in TEABAY_ACCEPTED_DID_METHODS",
                        method.trim_end_matches(':')
                    ),
                ));
            }
        }

        match self.config.accept_policy_kind {
            AcceptPolicyKind::Open => Ok(()),
            AcceptPolicyKind::Allowlist => {
                if is_in_allowlist(self.db, &req.resource_id)
                    .await
                    .map_err(|e| (ApiErrorCode::InternalError, format!("allowlist read: {e}")))?
                {
                    Ok(())
                } else {
                    Err((
                        ApiErrorCode::AcceptPolicyDenied,
                        format!("{} not in operator allowlist", req.resource_id),
                    ))
                }
            }
            AcceptPolicyKind::OperatorReview => {
                // Operator-review mode requires out-of-band approval; the
                // queue lives in the audit log + operator UI. For now we
                // reject with a structured message so callers know to apply
                // through `accept_policy_ref`.
                Err((
                    ApiErrorCode::AcceptPolicyDenied,
                    self.config
                        .accept_policy_ref
                        .clone()
                        .unwrap_or_else(|| "operator review required".to_string()),
                ))
            }
        }
    }

    async fn expected_governance_controller(
        &self,
        req: &DirectoryAnnounceIngest,
    ) -> Result<Option<String>, (ApiErrorCode, String)> {
        if !matches!(
            req.resource_kind,
            DirectoryResourceKindDb::Realm | DirectoryResourceKindDb::Handle
        ) {
            return Ok(None);
        }
        let indexed = indexed_station(self.db, req.resource_kind, &req.resource_id)
            .await
            .map_err(|error| {
                (
                    ApiErrorCode::InternalError,
                    format!("governance controller lookup: {error}"),
                )
            })?;
        let expected = indexed.unwrap_or_else(|| req.station_id.as_str().to_owned());
        if expected != req.station_id.as_str() {
            return Err((
                ApiErrorCode::GovernanceKeyInvalid,
                format!(
                    "station_id `{}` does not match indexed governance controller `{expected}`",
                    req.station_id
                ),
            ));
        }
        Ok(Some(expected))
    }
}

pub(crate) fn verify_discovery_event_proofs(
    event: &arkret_wire::Event,
    resource_kind: DirectoryResourceKindDb,
    resource_id: &str,
    expected_controller_did: Option<&str>,
    resolver: &SharedDidResolver,
) -> Result<(), (ApiErrorCode, String)> {
    let derived_event_id = event
        .derive_event_id_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .map_err(|error| {
            (
                ApiErrorCode::DirectoryGovernanceProofSignatureInvalid,
                format!("discovery Event id cannot be recomputed: {error}"),
            )
        })?;
    if derived_event_id != event.event_id {
        return Err((
            ApiErrorCode::DirectoryGovernanceProofSignatureInvalid,
            "discovery Event id does not match its canonical envelope".to_owned(),
        ));
    }
    event
        .validate_proof_bindings_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .map_err(|error| {
            (
                ApiErrorCode::DirectoryGovernanceProofSignatureInvalid,
                format!("discovery Event proof binding is invalid: {error}"),
            )
        })?;
    let canonical_bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| {
            (
                ApiErrorCode::DirectoryGovernanceProofSignatureInvalid,
                format!("discovery Event proof transcript is invalid: {error}"),
            )
        })?;
    let mut producer_count = 0usize;
    for proof in event
        .proofs
        .iter()
        .filter_map(arkret_wire::EventProof::as_producer)
    {
        producer_count += 1;
        enforce_governance_method_binding(
            resource_kind,
            resource_id,
            expected_controller_did,
            proof.verification_method.as_str(),
        )?;
        let issuer_id = proof
            .verification_method
            .as_str()
            .split_once('#')
            .map_or(proof.verification_method.as_str(), |(did, _)| did);
        resolver
            .verify_detached_jws_with_authority(
                &canonical_bytes,
                &proof.jws,
                proof.verification_method.as_str(),
                issuer_id,
                DidBindingPurpose::DirectoryIngest,
                SIGNATURE_KIND_INGEST_PROOF,
                Utc::now(),
            )
            .map_err(|error| {
                (
                    ApiErrorCode::DirectoryGovernanceProofSignatureInvalid,
                    format!("discovery Event proof rejected: {error}"),
                )
            })?;
    }
    if producer_count == 0 {
        return Err((
            ApiErrorCode::DirectoryGovernanceProofSignatureInvalid,
            "discovery Event has no producer proof".to_owned(),
        ));
    }
    Ok(())
}

/// §8.7.1: a Directory MUST reject a governance proof whose `created_at`
/// deviates from receipt time by more than 300 seconds. Callers needing a
/// longer window re-issue; a deployment MUST NOT relax the constant, so it is
/// not configurable.
pub(crate) const GOVERNANCE_PROOF_MAX_SKEW_SECONDS: i64 = 300;

/// A directory write-surface request carrying a §8.7.1 `governance_proof`.
///
/// The transcript is NEVER assembled here: each body's canonical binding
/// object is built by the SDK helper that owns the registered context and
/// `binding_fields` (`arkret_sdk::DirectoryGovernanceProof::binding_bytes`),
/// which also recomputes `payload_digest` over the request without its
/// top-level `governance_proof` member and fails closed on any
/// non-conforming proof field.
pub(crate) trait DirectoryGovernanceRequest {
    fn governance_proof(&self) -> &DirectoryGovernanceProof;
    fn governance_resource_id(&self) -> &str;
    fn governance_binding_bytes(&self) -> Result<Vec<u8>, WireError>;
}

impl DirectoryGovernanceRequest for DirectoryWithdrawRequestBody {
    fn governance_proof(&self) -> &DirectoryGovernanceProof {
        &self.governance_proof
    }

    fn governance_resource_id(&self) -> &str {
        &self.resource_id
    }

    fn governance_binding_bytes(&self) -> Result<Vec<u8>, WireError> {
        self.proof_binding_bytes()
    }
}

/// Verify the §8.7.1 governance proof of a write-surface request.
///
/// Five semantic checks on top of the SDK binding helper:
///
/// 1. `context` domain separation — the SDK helper stamps the registered
///    `ak.directory_governance_request_proof.v1` context into the signed transcript, so a signature
///    produced under any other context fails the JWS check;
/// 2. `audience` MUST name *this* directory's `service_id` (the value
///    `ak.find.directory.read.describe.v1` publishes) — the typed `DidCoreId` already rejected
///    every other shape at deserialization;
/// 3. `operation_id` is stamped from the operation actually being served;
/// 4. `payload_digest` MUST be byte-identical to `SHA-256(JCS(request_without_governance_proof))`,
///    recomputed by the SDK helper from the typed body;
/// 5. `created_at` MUST sit within 300 seconds of receipt time.
///
/// Every proof-layer failure collapses to the single
/// `directory_governance_proof_signature_invalid` rejection (§9.2
/// indistinguishable rejection: one wire code, one status); the precise
/// reason string is for local logs. Signer-authority failures keep the
/// §8.7.1-named `governance_key_invalid` code.
pub(crate) fn verify_governance_proof(
    request: &impl DirectoryGovernanceRequest,
    resource_kind: DirectoryResourceKindDb,
    expected_controller_did: Option<&str>,
    directory_id: &str,
    resolver: &SharedDidResolver,
    now: DateTime<Utc>,
) -> Result<(), (ApiErrorCode, String)> {
    let proof = request.governance_proof();

    let skew = now
        .signed_duration_since(proof.created_at)
        .num_seconds()
        .abs();
    if skew > GOVERNANCE_PROOF_MAX_SKEW_SECONDS {
        return Err((
            ApiErrorCode::DirectoryGovernanceProofSignatureInvalid,
            format!(
                "governance proof created_at is {skew}s from receipt time, \
                 outside the {GOVERNANCE_PROOF_MAX_SKEW_SECONDS}s window"
            ),
        ));
    }

    if proof.audience_id.as_str() != directory_id {
        return Err((
            ApiErrorCode::DirectoryGovernanceProofSignatureInvalid,
            "governance proof audience must be this directory's service_id".to_owned(),
        ));
    }

    let binding = request.governance_binding_bytes().map_err(|error| {
        (
            ApiErrorCode::DirectoryGovernanceProofSignatureInvalid,
            format!("governance proof binding rejected: {error}"),
        )
    })?;

    enforce_governance_method_binding(
        resource_kind,
        request.governance_resource_id(),
        expected_controller_did,
        proof.verification_method.as_str(),
    )?;
    verify_jws_ed25519(
        &binding,
        &proof.jws,
        proof.verification_method.as_str(),
        resolver,
    )
    .map_err(|msg| (ApiErrorCode::DirectoryGovernanceProofSignatureInvalid, msg))
}

/// Verify an ingest governance proof.
///
/// # DID-P0-C01 / C02 — one resolver, and only on a §4 trigger
///
/// This used to build a whole new `CompositeDidResolver` (and a whole new
/// `reqwest::Client`) per proof, then resolve the signer's DID on **every**
/// announce. It now goes through the accepted-binding path:
///
/// - a repeat announce / withdraw / appeal for the same DID, verification method and policy
///   verifies against the already-accepted `directory_ingest` binding — zero network;
/// - only a new verification method, a new source service, a changed document digest, a policy
///   revision or an explicit invalidation re-enters the authority path, and that resolves exactly
///   once;
/// - `did:key` proofs still decode locally with zero network access (spec §2.4).
///
/// It also closes a **fail-open** hole that predated DID-P0-C01: this entry
/// point never checked for an empty `TEABAY_ACCEPTED_DID_METHODS`, while the
/// SDK `ResolverPolicy` treats an empty `allowed_methods` as "every method is
/// allowed". `discoverers` and `target` both had the guard; ingest — the
/// *write* path — did not. `verify_detached_jws_with_authority` now rejects an
/// empty allowlist before any cryptography, for every surface at once.
fn verify_jws_ed25519(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    resolver: &SharedDidResolver,
) -> Result<(), String> {
    let issuer_id = verification_method
        .split_once('#')
        .map(|(did, _)| did)
        .unwrap_or(verification_method);
    resolver
        .verify_detached_jws_with_authority(
            canonical_bytes,
            jws,
            verification_method,
            issuer_id,
            DidBindingPurpose::DirectoryIngest,
            SIGNATURE_KIND_INGEST_PROOF,
            Utc::now(),
        )
        .map_err(|failure| failure.message().to_owned())
}

fn enforce_governance_method_binding(
    resource_kind: DirectoryResourceKindDb,
    resource_id: &str,
    expected_controller_did: Option<&str>,
    verification_method: &str,
) -> Result<(), (ApiErrorCode, String)> {
    let did = verification_method
        .split_once('#')
        .map(|(did, _)| did)
        .unwrap_or(verification_method);
    match resource_kind {
        DirectoryResourceKindDb::Organization
        | DirectoryResourceKindDb::Actor
        | DirectoryResourceKindDb::Applet => {
            if did != resource_id {
                return Err((
                    ApiErrorCode::GovernanceKeyInvalid,
                    format!("verification_method DID `{did}` does not control `{resource_id}`"),
                ));
            }
        }
        DirectoryResourceKindDb::Realm | DirectoryResourceKindDb::Handle => {
            let Some(expected) = expected_controller_did else {
                return Err((
                    ApiErrorCode::GovernanceKeyInvalid,
                    format!("no indexed governance controller for `{resource_id}`"),
                ));
            };
            if did != expected {
                return Err((
                    ApiErrorCode::GovernanceKeyInvalid,
                    format!(
                        "verification_method DID `{did}` does not match governance controller `{expected}` for `{resource_id}`"
                    ),
                ));
            }
        }
    }
    Ok(())
}

pub(crate) async fn indexed_station(
    db: &Db,
    resource_kind: DirectoryResourceKindDb,
    resource_id: &str,
) -> anyhow::Result<Option<String>> {
    use crate::schema::directory_resources::dsl;
    let mut conn = db.get().await?;
    let row = dsl::directory_resources
        .filter(dsl::resource_kind.eq(resource_kind))
        .filter(dsl::resource_id.eq(resource_id))
        .select(dsl::station_id)
        .first::<DidCoreId>(&mut *conn)
        .await
        .optional()?;
    Ok(row.map(DidCoreId::into_string))
}

async fn resource_already_indexed(
    db: &Db,
    resource_kind: DirectoryResourceKindDb,
    resource_id: &str,
) -> anyhow::Result<bool> {
    use crate::schema::directory_resources::dsl;
    let mut conn = db.get().await?;
    let count: i64 = dsl::directory_resources
        .filter(dsl::resource_kind.eq(resource_kind))
        .filter(dsl::resource_id.eq(resource_id))
        .count()
        .get_result(&mut *conn)
        .await?;
    Ok(count > 0)
}

async fn verify_first_source_ref_resolves(
    req: &DirectoryAnnounceIngest,
    config: &AppConfig,
    resolver: &SharedDidResolver,
) -> Result<(), (ApiErrorCode, String)> {
    let source_ref = req
        .source_refs
        .as_slice()
        .first()
        .ok_or_else(|| {
            (
                ApiErrorCode::SourceRefsUnverifiable,
                "source_refs MUST contain at least one anchor event id".to_owned(),
            )
        })?
        .clone();
    // `discovery-directory.md` §8.3: `station_id` is a stable
    // `did_core_id`. The Directory MUST map it to the peer's current `did`
    // / URL through a **verified `ServiceResolutionRecord`** before pulling,
    // and MUST NOT hand the core id to a DID resolver. teabay has no peer
    // service-resolution carrier yet, so this is the single choke point where
    // that evidence has to arrive; until it does, first ingest fails closed
    // rather than guessing a resolvable DID out of a stable identity core.
    let station_did = peer_station_did(&req.station_id).map_err(|reason| {
        (
            ApiErrorCode::SourceRefsUnverifiable,
            format!(
                "cannot verify source_refs for Station `{}`: {reason}",
                req.station_id
            ),
        )
    })?;
    // DID-P0-C02: this function used to build TWO reqwest clients. The first
    // existed only to be handed to `resolve_station_endpoint`, which
    // passed it to `fetch_did_document_json`, which ignored it (the parameter
    // was literally named `_http`) and built a third client of its own. It is
    // gone. The second client further down survives and is deliberately NOT
    // shared: `strict_http_client_for_egress` pins the client to the one IP
    // that `resolve_url_for_egress` just validated for this exact target,
    // which is what closes the DNS-rebinding hole. A per-target client cannot
    // be hoisted into `AppState` without reopening that hole.
    //
    // DID-P0-C02: the endpoint is an accepted five-tuple (service DID, service
    // kind, trust domain, endpoint digest, source ref), not a cached URL, and
    // the URL below is derived from the *pinned* DID document every time.
    let accepted = resolve_station_endpoint(config, resolver, &station_did, source_ref.as_str())
        .await
        .map_err(|e| {
            (
                ApiErrorCode::SourceRefsUnverifiable,
                format!("station_id did not resolve to events endpoint: {e}"),
            )
        })?;
    tracing::debug!(
        service_did = %accepted.service_did,
        service_kind = accepted.service_kind,
        trust_domain = %accepted.trust_domain,
        endpoint_digest = %accepted.endpoint_digest,
        document_digest = %accepted.document_digest,
        acceptance_digest = %accepted.acceptance_digest,
        source_ref = %accepted.source_ref,
        "accepted Station endpoint"
    );
    let url = endpoint_child(&accepted.endpoint, &format!("events/{source_ref}")).map_err(|e| {
        (
            ApiErrorCode::SourceRefsUnverifiable,
            format!("source-ref URL: {e}"),
        )
    })?;
    let target = crate::egress::resolve_url_for_egress(
        &url,
        "source-ref fetch",
        crate::egress::local_development_enabled(config.development_mode),
    )
    .map_err(|error| (ApiErrorCode::SourceRefsUnverifiable, error))?;
    let locked_http = strict_http_client_for_egress(&target).map_err(|e| {
        (
            ApiErrorCode::InternalError,
            format!("source-ref HTTP client: {e}"),
        )
    })?;
    let response = locked_http
        .get(target.url().clone())
        .send()
        .await
        .map_err(|e| {
            (
                ApiErrorCode::SourceRefsUnverifiable,
                format!("source-ref fetch failed: {e:?}"),
            )
        })?;
    if !response.status().is_success() {
        return Err((
            ApiErrorCode::SourceRefsUnverifiable,
            format!("source-ref fetch returned {}", response.status()),
        ));
    }
    let body = response_json_limited::<JsonValue>(response, "source-ref response")
        .await
        .map_err(|e| {
            (
                ApiErrorCode::SourceRefsUnverifiable,
                format!("source-ref response was not JSON: {e}"),
            )
        })?;
    let returned_id = body
        .pointer("/event/event_id")
        .or_else(|| body.get("event_id"))
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            (
                ApiErrorCode::SourceRefsUnverifiable,
                "source-ref response did not contain event_id".to_owned(),
            )
        })?;
    if returned_id != source_ref {
        return Err((
            ApiErrorCode::SourceRefsUnverifiable,
            format!("source-ref response returned `{returned_id}`, expected `{source_ref}`"),
        ));
    }
    Ok(())
}

/// An accepted station service endpoint.
///
/// # DID-P0-C02 — an endpoint acceptance is a tuple, never a cached URL
///
/// The task requirement is explicit: an accepted endpoint MUST bind the service
/// DID, the service kind, the trust domain, the endpoint digest and the source
/// ref; caching a bare URL is not acceptable. All five live here, and none of
/// them is decorative:
///
/// | field | where it is bound |
/// | --- | --- |
/// | `service_did` | the `VerifiedDidBinding`'s `did` — part of the store key |
/// | `trust_domain` | the binding's `trust_domain` — part of the store key |
/// | `service_kind` | this struct, and folded into `acceptance_digest` |
/// | `endpoint_digest` | recomputed here from the pinned document on every request, and folded into `acceptance_digest` |
/// | `source_ref` | supplied per request and folded into `acceptance_digest` |
///
/// `service_kind` and `endpoint_digest` briefly lived in the binding's
/// `evidence_digest` as well, through a teabay-local evidence envelope.
/// `did-usage-and-verification.md` §5.2 closed the evidence receipt to
/// `{method, document_digest, method_proofs}` — evidence is a product of the
/// resolution, not something the caller contributes — so both are back here,
/// which is where a per-request value belonged anyway.
///
/// That is not a weaker binding. The endpoint set is a **projection of the
/// pinned document**, and `document_digest` is a required member of the
/// evidence receipt, so the acceptance still commits to it transitively: a host
/// that publishes a different endpoint publishes a different document, whose
/// digest differs, whose evidence digest differs, and whose binding is
/// therefore a different acceptance.
///
/// The endpoint is **always re-derived from the pinned DID document**, never
/// read out of a URL cache: on a store hit the `service` array comes from
/// `AcceptedDidBinding::document()`, whose canonical digest the binding
/// recorded. A host that later serves a different document cannot change the
/// endpoint teabay uses without the binding being invalidated first.
///
/// `source_ref` is bound per use rather than per acceptance on purpose: one
/// Station anchors many resources, so folding a single source ref into
/// the *stored* acceptance would either pin the acceptance to the first
/// announce that established it or defeat reuse entirely. What matters for the
/// security property is that a source ref can only ever be fetched from an
/// endpoint that is itself bound to a verified document — which is exactly what
/// `acceptance_digest` states.
#[derive(Debug, Clone)]
pub(crate) struct AcceptedServiceEndpoint {
    pub service_did: Did,
    pub service_kind: &'static str,
    pub trust_domain: TrustDomainId,
    pub endpoint: Url,
    pub endpoint_digest: Hash,
    pub document_digest: Hash,
    pub source_ref: String,
    /// Digest over the whole five-tuple. This is the value that would be
    /// persisted / logged; it makes "we accepted this URL" impossible to state
    /// without also stating for which service, kind, trust domain, document and
    /// source ref.
    pub acceptance_digest: Hash,
}

/// The only service kind teabay follows for source-ref anchors.
pub(crate) const ARKRET_STATION: &str = "ArkretStation";

/// Resolve `station_id` to its `ArkretStation` service
/// endpoint, fetching the DID Document **at most once per accepted binding**.
///
/// # DID-P0-C02 — the double network access, and where each check went
///
/// This function used to hit the network twice for one document: it ran the
/// resolver chain purely as a yes/no validity gate and *discarded* the
/// resolved document, then fetched the same `did.json` again over raw HTTP to
/// read `service` out of it. Besides the wasted round trip, that left a real
/// TOCTOU gap — the endpoint actually used came from the second, unvalidated
/// fetch, which a hostile host could serve differently from the first.
///
/// The merge keeps the resolver as the single fetch, because the resolver is
/// the side that carries the DID-method evidence. Nothing was dropped:
///
/// | check | before | after |
/// | --- | --- | --- |
/// | method in `TEABAY_ACCEPTED_DID_METHODS` | `principal_did_method_allowed` + the chain's `ResolverPolicy` | unchanged, both still run |
/// | document validation (content type, 64 KiB cap, `did:webvh` log chain + witness) | resolver | resolver |
/// | SSRF / egress control on the fetch | `resolve_url_for_egress` inside the raw fetch | the shared chain's client: `https_only` + the shared guarded DNS resolver, both frozen from the startup config |
/// | `document.id == station_did` | compared on the raw JSON here | still compared here, now against the resolved document |
/// | `service[].type == "ArkretStation"` | raw JSON | `DidDocument::raw_properties["service"]`, which preserves the wire document verbatim |
/// | relative `serviceEndpoint` resolution | `service_endpoint_url` | unchanged |
///
/// On top of that merge, DID-P0-C02 adds the acceptance: the resolved document
/// is filed as a `DidBindingPurpose::PrincipalServiceEndpoint` binding, so a
/// second first-ingest naming the same Station performs **zero**
/// network calls.
///
/// The development-mode loopback branch is untouched in meaning: a loopback
/// `did:web` host cannot be resolved by a chain that demands public HTTPS, so
/// that branch still deliberately bypasses the resolver and performs its one
/// raw fetch, then runs the same `id` / `service` checks on that JSON. It
/// deliberately does **not** write a binding — a development bypass must not
/// seed trust that outlives the request.
pub(crate) async fn resolve_station_endpoint(
    config: &AppConfig,
    resolver: &SharedDidResolver,
    station_did: &Did,
    source_ref: &str,
) -> anyhow::Result<AcceptedServiceEndpoint> {
    let did = station_did.clone();
    let station_did = did.as_str();
    if !principal_did_method_allowed(config, station_did) {
        anyhow::bail!("DID method is outside TEABAY_ACCEPTED_DID_METHODS");
    }

    let mut doc_url = did_document_url(&did)?;
    let bindings = resolver.bindings();
    if config.development_mode && is_loopback_url(&doc_url) {
        doc_url
            .set_scheme("http")
            .map_err(|_| anyhow::anyhow!("failed to rewrite loopback DID URL to HTTP"))?;
        let document = fetch_did_document_json(doc_url.clone(), config.development_mode).await?;
        if document.get("id").and_then(JsonValue::as_str) != Some(station_did) {
            anyhow::bail!("DID document id does not match requested DID");
        }
        let services = document
            .get("service")
            .and_then(JsonValue::as_array)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("DID document has no service array"))?;
        let endpoint = station_endpoint(&services, &doc_url, config.development_mode)?;
        let document_digest = json_digest(&document)?;
        return accepted_service_endpoint(
            bindings.trust_domain().clone(),
            did,
            endpoint,
            document_digest,
            source_ref,
        );
    }

    // Accepted `principal_service_endpoint` binding, or **exactly one** fetch.
    // The chain validates the method against the startup policy, validates the
    // document (and, for did:webvh, the whole log chain and witness set), and
    // the SDK asserts `document.id == requested DID` before the acceptance is
    // written.
    let now = Utc::now();
    let accepted = resolver
        .accepted_or_resolved(&did, DidBindingPurpose::PrincipalServiceEndpoint, None, now)
        .map_err(|e| anyhow::anyhow!("DID document did not validate: {e}"))?;
    if accepted.document().id.as_str() != station_did {
        anyhow::bail!("DID document id does not match requested DID");
    }

    let services = accepted
        .document()
        .raw_properties
        .get("service")
        .and_then(JsonValue::as_array)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("DID document has no service array"))?;
    let endpoint = station_endpoint(&services, &doc_url, config.development_mode)?;
    let document_digest = document_canonical_digest(accepted.document())
        .map_err(|e| anyhow::anyhow!("pinned document digest failed: {e}"))?;
    accepted_service_endpoint(
        accepted.binding().trust_domain().clone(),
        did,
        endpoint,
        document_digest,
        source_ref,
    )
}

/// Pick the `ArkretStation` endpoint out of a wire `service` array.
///
/// DID Document order is the owner-controlled priority order for multiple
/// Station services; teabay keeps that deterministic convention.
fn station_endpoint(
    services: &[JsonValue],
    doc_url: &Url,
    development_mode: bool,
) -> anyhow::Result<Url> {
    let service = services
        .iter()
        .find(|service| service_kind_matches(service, ARKRET_STATION))
        .ok_or_else(|| anyhow::anyhow!("DID document has no ArkretStation service"))?;
    let endpoint = service
        .get("serviceEndpoint")
        .and_then(JsonValue::as_str)
        .filter(|endpoint| !endpoint.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("ArkretStation serviceEndpoint is missing"))?;
    service_endpoint_url(doc_url, endpoint, development_mode)
}

fn json_digest(value: &JsonValue) -> anyhow::Result<Hash> {
    Hash::new(
        canonical::canonical_sha256(value)
            .map_err(|e| anyhow::anyhow!("canonical digest failed: {e}"))?,
    )
    .map_err(|e| anyhow::anyhow!("canonical digest invalid: {e}"))
}

/// Assemble (and digest) the accepted five-tuple.
fn accepted_service_endpoint(
    trust_domain: TrustDomainId,
    service_did: Did,
    endpoint: Url,
    document_digest: Hash,
    source_ref: &str,
) -> anyhow::Result<AcceptedServiceEndpoint> {
    let endpoint_digest = json_digest(&serde_json::json!({
        "kind": "teabay.accepted_service_endpoint.v1",
        "service_did": service_did.as_str(),
        "service_kind": ARKRET_STATION,
        "trust_domain": trust_domain.as_str(),
        "endpoint": endpoint.as_str(),
    }))?;
    let acceptance_digest = json_digest(&serde_json::json!({
        "kind": "teabay.accepted_service_endpoint_use.v1",
        "endpoint_digest": endpoint_digest.as_str(),
        "document_digest": document_digest.as_str(),
        "source_ref": source_ref,
    }))?;
    Ok(AcceptedServiceEndpoint {
        service_did,
        service_kind: ARKRET_STATION,
        trust_domain,
        endpoint,
        endpoint_digest,
        document_digest,
        source_ref: source_ref.to_owned(),
        acceptance_digest,
    })
}

pub(crate) fn endpoint_child(base: &Url, child: &str) -> anyhow::Result<Url> {
    let mut url = base.clone();
    let base_path = url.path().trim_end_matches('/');
    url.set_path(&format!("{base_path}/{}", child.trim_start_matches('/')));
    Ok(url)
}

/// Build an outbound client pinned to one already-SSRF-validated target.
///
/// DID-P0-C01 note: this is the one outbound client shape teabay still builds
/// per request, and it MUST stay that way. `LockedEgressUrl` carries the
/// single IP that `crate::egress::resolve_url_for_egress` resolved and
/// validated for this exact URL, and `apply_to_client_builder` pins the client
/// to it. That pinning is the DNS-rebinding defence; a client shared across
/// targets would either lose the pin or send the request to another target's
/// address. The target-independent counterpart, `strict_http_client()`, was
/// removed rather than shared: after the DID-P0-C02 merge its only caller had
/// no fetch left to perform.
pub(crate) fn strict_http_client_for_egress(
    target: &crate::egress::LockedEgressUrl,
) -> anyhow::Result<Client> {
    target
        .apply_to_client_builder(strict_http_client_builder())
        .build()
        .map_err(|e| anyhow::anyhow!("build locked reqwest client: {e}"))
}

fn strict_http_client_builder() -> reqwest::ClientBuilder {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
}

fn principal_did_method_allowed(config: &AppConfig, did: &str) -> bool {
    did_method_prefix_for_did(did)
        .as_deref()
        .is_some_and(|method| did_method_allowed(&config.accepted_did_methods, method))
}

fn did_document_url(did: &Did) -> anyhow::Result<Url> {
    let url = match did.method() {
        "web" => DidWebResolver::document_url(did)?,
        "webvh" => DidWebvhResolver::document_url(did)?,
        other => anyhow::bail!("unsupported Station DID method did:{other}"),
    };
    Url::parse(&url).map_err(|e| anyhow::anyhow!("invalid DID document URL `{url}`: {e}"))
}

/// Raw DID Document fetch. Used **only** by the development-mode loopback
/// branch of [`resolve_station_endpoint`]; the production branch goes
/// through the shared resolver chain instead.
///
/// The dead `_http: &Client` parameter is gone. It was never read: the body
/// always built its own egress-pinned client below, because that client has to
/// be bound to the validated target address and a caller-supplied one is not.
async fn fetch_did_document_json(url: Url, development_mode: bool) -> anyhow::Result<JsonValue> {
    if url.scheme() != "https"
        && !(development_mode && url.scheme() == "http" && is_loopback_url(&url))
    {
        anyhow::bail!("DID document URL must be HTTPS");
    }
    let target = crate::egress::resolve_url_for_egress(
        &url,
        "principal DID document fetch",
        crate::egress::local_development_enabled(development_mode),
    )
    .map_err(|error| anyhow::anyhow!(error))?;
    let http = strict_http_client_for_egress(&target)?;
    let response = http.get(target.url().clone()).send().await?;
    if !response.status().is_success() {
        anyhow::bail!("DID document fetch returned {}", response.status());
    }
    let bytes = response.bytes().await?;
    if bytes.len() > DID_WEB_MAX_DOCUMENT_BYTES {
        anyhow::bail!("DID document exceeds maximum size");
    }
    serde_json::from_slice(&bytes).map_err(|e| anyhow::anyhow!("DID document JSON parse: {e}"))
}

pub(crate) async fn response_json_limited<T>(
    response: reqwest::Response,
    context: &str,
) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    let bytes = response.bytes().await?;
    if bytes.len() > EXTERNAL_JSON_MAX_BYTES {
        anyhow::bail!("{context} exceeds maximum size");
    }
    serde_json::from_slice(&bytes).map_err(|e| anyhow::anyhow!("{context} JSON parse: {e}"))
}

/// Whether a wire `service` entry declares `expected` as one of its types.
///
/// `pub(crate)` because `crate::did_binding` reuses it to digest the published
/// endpoint set into a binding's evidence envelope; a second copy of the
/// string-or-array `type` handling would be a place for the two to disagree.
pub(crate) fn service_kind_matches(service: &JsonValue, expected: &str) -> bool {
    match service.get("type") {
        Some(JsonValue::String(value)) => value == expected,
        Some(JsonValue::Array(values)) => values
            .iter()
            .filter_map(JsonValue::as_str)
            .any(|value| value == expected),
        _ => false,
    }
}

fn service_endpoint_url(
    doc_url: &Url,
    endpoint: &str,
    development_mode: bool,
) -> anyhow::Result<Url> {
    let parsed = if endpoint.starts_with('/') {
        let mut url = doc_url.clone();
        url.set_path(endpoint);
        url.set_query(None);
        url.set_fragment(None);
        url
    } else {
        Url::parse(endpoint).map_err(|e| anyhow::anyhow!("invalid serviceEndpoint URL: {e}"))?
    };
    if parsed.scheme() != "https"
        && !(development_mode && parsed.scheme() == "http" && is_loopback_url(&parsed))
    {
        anyhow::bail!("serviceEndpoint must be HTTPS");
    }
    crate::egress::validate_url_for_egress(
        &parsed,
        "principal serviceEndpoint",
        crate::egress::local_development_enabled(development_mode),
    )
    .map_err(|error| anyhow::anyhow!(error))?;
    Ok(parsed)
}

fn is_loopback_url(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
        None => false,
    }
}

fn directory_services_lists_self(discovery_state: &JsonValue, self_service_id: &str) -> bool {
    discovery_state
        .get("directory_services")
        .and_then(JsonValue::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(JsonValue::as_str)
                .any(|id| id == self_service_id)
        })
        .unwrap_or(false)
}

fn directory_services_are_core_ids(discovery_state: &JsonValue) -> bool {
    discovery_state
        .get("directory_services")
        .and_then(JsonValue::as_array)
        .is_some_and(|services| {
            !services.is_empty()
                && services.iter().all(|value| {
                    value
                        .as_str()
                        .is_some_and(|service_id| DidCoreId::new(service_id.to_owned()).is_ok())
                })
        })
}

fn read_discoverability(
    discovery_state: &JsonValue,
) -> Result<super::DiscoverabilityDb, (ApiErrorCode, String)> {
    let s = discovery_state
        .get("discoverability")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            (
                ApiErrorCode::SchemaViolation,
                "discovery_state.discoverability missing".into(),
            )
        })?;
    super::DiscoverabilityDb::from_pg(s).map_err(|e| (ApiErrorCode::SchemaViolation, e.to_string()))
}

fn derive_via_services(discovery_state: &JsonValue, station_id: &DidCoreId) -> Vec<DidCoreId> {
    if let Some(arr) = discovery_state
        .get("via_services")
        .and_then(JsonValue::as_array)
    {
        let mut services = Vec::new();
        for value in arr.iter().filter_map(JsonValue::as_str) {
            let Ok(service_id) = DidCoreId::new(value.trim().to_owned()) else {
                continue;
            };
            if services.contains(&service_id) {
                continue;
            }
            services.push(service_id);
            if services.len() == MAX_VIA_SERVICES {
                break;
            }
        }
        if !services.is_empty() {
            return services;
        }
    }
    // The announce already carries the Station as a stable service
    // core id, so the fallback is the value itself — no projection, and
    // certainly no reconstruction of a resolvable DID.
    vec![station_id.clone()]
}

/// Map a peer Station's stable service core id to the resolvable
/// `Did` the source-ref anchor fetch needs.
///
/// `discovery-directory.md` §8.3 permits exactly one route: a **verified
/// `ServiceResolutionRecord`** that publishes the peer's current `did`.
/// The core id itself must never be handed to a DID resolver, and a
/// `DidCoreId` can never be widened back into a `Did` by string
/// manipulation — `project_did_to_core_id` is deliberately one-way.
///
/// teabay has no peer service-resolution store yet — the same gap that made
/// cross-directory divergence detection unimplementable — so this fails
/// closed. Wiring a verified carrier here is the single change that
/// re-enables first-ingest source-ref verification.
fn peer_station_did(station_id: &DidCoreId) -> Result<Did, String> {
    let _ = station_id;
    Err(
        "peer Station core ids have no configured verified service-resolution          carrier, so the current DID cannot be established;          `discovery-directory.md` §8.3 forbids resolving the core id directly"
            .to_owned(),
    )
}

async fn is_in_allowlist(db: &Db, resource_did: &str) -> anyhow::Result<bool> {
    use crate::schema::accept_allowlist::dsl;
    let mut conn = db.get().await?;
    let n: i64 = dsl::accept_allowlist
        .filter(dsl::resource_did.eq(resource_did))
        .count()
        .get_result(&mut *conn)
        .await?;
    Ok(n > 0)
}

async fn previously_withdrawn(
    db: &Db,
    resource_kind: DirectoryResourceKindDb,
    resource_id: &str,
) -> anyhow::Result<Option<DateTime<Utc>>> {
    use crate::schema::withdrawals::dsl;
    let mut conn = db.get().await?;
    let row: Option<DateTime<Utc>> = dsl::withdrawals
        .filter(dsl::resource_kind.eq(resource_kind))
        .filter(dsl::resource_id.eq(resource_id))
        .filter(dsl::overturned_at.is_null())
        .order(dsl::effective_at.desc())
        .select(dsl::effective_at)
        .first(&mut *conn)
        .await
        .optional()?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use arkret_sdk::{DidUrl, DirectoryGovernanceProofPurpose, Hash};
    use arkret_signatures::jws::sign_jws_ed25519;
    use chrono::Duration;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    use super::*;

    #[test]
    fn directory_authority_list_accepts_only_service_core_ids() {
        assert!(directory_services_are_core_ids(&json!({
            "directory_services": ["ak:did_core:web:directory.example"]
        })));
        for forbidden in [
            json!({"directory_services": ["did:web:directory.example"]}),
            json!({"directory_services": ["https://directory.example"]}),
            json!({"directory_services": []}),
        ] {
            assert!(!directory_services_are_core_ids(&forbidden));
        }
    }

    #[test]
    fn derive_via_services_dedupes_valid_service_core_ids_and_caps_count() {
        let discovery_state = json!({
            "via_services": [
                " ak:did_core:web:primary.example ",
                "not-a-service-id",
                "ak:did_core:web:primary.example",
                "ak:did_core:web:mirror1.example",
                "ak:did_core:web:mirror2.example",
                "ak:did_core:web:mirror3.example",
                "ak:did_core:web:mirror4.example",
                "ak:did_core:web:mirror5.example",
                "ak:did_core:web:mirror6.example",
                "ak:did_core:web:mirror7.example",
                "ak:did_core:web:mirror8.example"
            ]
        });

        let derived = derive_via_services(&discovery_state, &fallback_service_id());

        assert_eq!(derived.len(), MAX_VIA_SERVICES);
        assert_eq!(derived[0].as_str(), "ak:did_core:web:primary.example");
        assert!(!derived.iter().any(|id| id.as_str() == "not-a-service-id"));
        assert_eq!(
            derived
                .iter()
                .filter(|id| id.as_str() == "ak:did_core:web:primary.example")
                .count(),
            1
        );
    }

    fn fallback_service_id() -> DidCoreId {
        DidCoreId::new("ak:did_core:web:fallback.example").expect("fixture core id")
    }

    #[test]
    fn derive_via_services_falls_back_to_the_announced_principal_service_id() {
        let discovery_state = json!({
            "via_services": ["", "not-a-service-id", "did:web:must-not-be-treated-as-core", 7]
        });

        assert_eq!(
            derive_via_services(&discovery_state, &fallback_service_id()),
            vec![fallback_service_id()]
        );
    }

    #[test]
    fn realm_governance_binding_requires_expected_controller() {
        assert!(
            enforce_governance_method_binding(
                DirectoryResourceKindDb::Realm,
                "ak:realm:tea",
                None,
                "did:web:principal.example#key-1",
            )
            .is_err()
        );

        assert!(
            enforce_governance_method_binding(
                DirectoryResourceKindDb::Realm,
                "ak:realm:tea",
                Some("did:web:principal.example"),
                "did:web:attacker.example#key-1",
            )
            .is_err()
        );

        assert!(
            enforce_governance_method_binding(
                DirectoryResourceKindDb::Realm,
                "ak:realm:tea",
                Some("did:web:principal.example"),
                "did:web:principal.example#key-1",
            )
            .is_ok()
        );
    }

    const SIGNING_SEED: [u8; 32] = [51u8; 32];
    const DIRECTORY_SERVICE_ID: &str = "ak:did_core:web:directory.test";
    const OTHER_DIRECTORY_SERVICE_ID: &str = "ak:did_core:web:other-directory.test";
    const REALM_ID: &str = "ak:realm:AY0Z0alJlPB4P2wAIOCSTs_yNX_lm1mM5r3mhhQuKIFb";

    struct GovernanceSigner {
        signing_key: SigningKey,
        issuer_did: String,
        verification_method: DidUrl,
    }

    fn test_signer() -> GovernanceSigner {
        let signing_key = SigningKey::from_bytes(&SIGNING_SEED);
        let mut bytes = vec![0xed, 0x01];
        bytes.extend_from_slice(signing_key.verifying_key().as_bytes());
        let multibase = format!("z{}", bs58::encode(bytes).into_string());
        let issuer_did = format!("did:key:{multibase}");
        let verification_method =
            DidUrl::new(format!("{issuer_did}#{multibase}")).expect("verification method");
        GovernanceSigner {
            signing_key,
            issuer_did,
            verification_method,
        }
    }

    fn resolver() -> SharedDidResolver {
        SharedDidResolver::new(&["did:key".to_owned()], false).expect("resolver builds")
    }

    fn placeholder_proof(
        signer: &GovernanceSigner,
        created_at: DateTime<Utc>,
        audience: &str,
    ) -> DirectoryGovernanceProof {
        DirectoryGovernanceProof {
            kind: "detached_jws".to_owned(),
            verification_method: signer.verification_method.clone(),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).expect("digest"),
            created_at,
            proof_purpose: DirectoryGovernanceProofPurpose::GovernanceAuthorization,
            audience_id: DidCoreId::new(audience).expect("directory service id"),
            jws: "pending".to_owned(),
        }
    }

    /// A withdraw request whose proof is signed over the §8.7.1 transcript,
    /// exactly as a conforming resource would produce it.
    fn signed_withdraw(
        signer: &GovernanceSigner,
        created_at: DateTime<Utc>,
        audience: &str,
    ) -> DirectoryWithdrawRequestBody {
        let mut body = DirectoryWithdrawRequestBody {
            resource_id: REALM_ID.to_owned(),
            governance_proof: placeholder_proof(signer, created_at, audience),
            reason: Some(arkret_wire::AuditReasonText::new("governance proof test").unwrap()),
            effective_at: None,
        };
        let digest = body.payload_digest().expect("payload digest");
        body.governance_proof.payload_digest = digest;
        let transcript = body.proof_binding_bytes().expect("binding bytes");
        body.governance_proof.jws =
            sign_jws_ed25519(&transcript, &signer.signing_key).expect("sign");
        body
    }

    fn verify_withdraw(
        body: &DirectoryWithdrawRequestBody,
        signer: &GovernanceSigner,
        service_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), (ApiErrorCode, String)> {
        verify_governance_proof(
            body,
            DirectoryResourceKindDb::Realm,
            Some(signer.issuer_did.as_str()),
            service_id,
            &resolver(),
            now,
        )
    }

    #[tokio::test]
    async fn valid_withdraw_governance_proof_verifies() {
        let signer = test_signer();
        let now = Utc::now();
        let body = signed_withdraw(&signer, now, DIRECTORY_SERVICE_ID);
        verify_withdraw(&body, &signer, DIRECTORY_SERVICE_ID, now)
            .expect("a conforming proof must verify");
    }

    /// Negative 1 — cross-Directory replay: a proof bound to another
    /// directory's `service_id` MUST be rejected here (§8.7.1 audience).
    #[tokio::test]
    async fn cross_directory_replay_is_rejected() {
        let signer = test_signer();
        let now = Utc::now();
        let body = signed_withdraw(&signer, now, OTHER_DIRECTORY_SERVICE_ID);
        let (code, _) = verify_withdraw(&body, &signer, DIRECTORY_SERVICE_ID, now)
            .expect_err("a proof for another directory MUST be rejected");
        assert_eq!(code, ApiErrorCode::DirectoryGovernanceProofSignatureInvalid);

        // The mirror image: a proof for this directory presented to a
        // directory with a different service_id is equally rejected.
        let body = signed_withdraw(&signer, now, DIRECTORY_SERVICE_ID);
        verify_withdraw(&body, &signer, OTHER_DIRECTORY_SERVICE_ID, now)
            .expect_err("audience MUST name the receiving directory");
    }

    /// Negative 2 — expired proof: `created_at` outside the 300-second window
    /// MUST be rejected in both directions (§8.7.1 freshness).
    #[tokio::test]
    async fn stale_governance_proof_is_rejected() {
        let signer = test_signer();
        let now = Utc::now();
        let stale = now - Duration::seconds(GOVERNANCE_PROOF_MAX_SKEW_SECONDS + 1);
        let body = signed_withdraw(&signer, stale, DIRECTORY_SERVICE_ID);
        let (code, _) = verify_withdraw(&body, &signer, DIRECTORY_SERVICE_ID, now)
            .expect_err("a stale proof MUST be rejected");
        assert_eq!(code, ApiErrorCode::DirectoryGovernanceProofSignatureInvalid);

        let future = now + Duration::seconds(GOVERNANCE_PROOF_MAX_SKEW_SECONDS + 1);
        let body = signed_withdraw(&signer, future, DIRECTORY_SERVICE_ID);
        verify_withdraw(&body, &signer, DIRECTORY_SERVICE_ID, now)
            .expect_err("a future-dated proof MUST be rejected");

        let edge = now - Duration::seconds(GOVERNANCE_PROOF_MAX_SKEW_SECONDS);
        let body = signed_withdraw(&signer, edge, DIRECTORY_SERVICE_ID);
        verify_withdraw(&body, &signer, DIRECTORY_SERVICE_ID, now)
            .expect("a proof at the window edge must verify");
    }

    /// Check 1 — context domain separation: a signature over an otherwise
    /// identical binding object stamped with another family's context MUST be
    /// rejected.
    #[tokio::test]
    async fn signature_under_another_context_is_rejected() {
        let signer = test_signer();
        let now = Utc::now();
        let mut body = signed_withdraw(&signer, now, DIRECTORY_SERVICE_ID);
        let mut foreign: JsonValue =
            serde_json::from_slice(&body.proof_binding_bytes().expect("binding bytes"))
                .expect("binding object");
        foreign["context"] = JsonValue::String(
            arkret_wire::ProofContextId::DIRECTORY_RESOLVE_HANDLE_REQUEST_PROOF_V1.to_owned(),
        );
        let foreign_bytes = canonical::canonical_json_bytes(&foreign).expect("canonical bytes");
        body.governance_proof.jws =
            sign_jws_ed25519(&foreign_bytes, &signer.signing_key).expect("sign");
        let (code, _) = verify_withdraw(&body, &signer, DIRECTORY_SERVICE_ID, now)
            .expect_err("a signature under another context MUST be rejected");
        assert_eq!(code, ApiErrorCode::DirectoryGovernanceProofSignatureInvalid);
    }

    /// Check 4 — `payload_digest` binds the whole unsigned request: mutating
    /// any signed field after issuance MUST be rejected.
    #[tokio::test]
    async fn tampered_request_body_breaks_the_payload_digest_binding() {
        let signer = test_signer();
        let now = Utc::now();
        let mut body = signed_withdraw(&signer, now, DIRECTORY_SERVICE_ID);
        body.reason = Some(arkret_wire::AuditReasonText::new("rewritten after signing").unwrap());
        let (code, _) = verify_withdraw(&body, &signer, DIRECTORY_SERVICE_ID, now)
            .expect_err("a mutated body MUST be rejected");
        assert_eq!(code, ApiErrorCode::DirectoryGovernanceProofSignatureInvalid);
    }

    /// A signer that is not the resource's governance controller is rejected
    /// with the §8.7.1-named `governance_key_invalid`, distinct from the
    /// indistinguishable proof-layer rejection.
    #[tokio::test]
    async fn signer_must_be_the_governance_controller() {
        let signer = test_signer();
        let now = Utc::now();
        let body = signed_withdraw(&signer, now, DIRECTORY_SERVICE_ID);
        let (code, _) = verify_governance_proof(
            &body,
            DirectoryResourceKindDb::Realm,
            Some("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
            DIRECTORY_SERVICE_ID,
            &resolver(),
            now,
        )
        .expect_err("a foreign controller MUST be rejected");
        assert_eq!(code, ApiErrorCode::GovernanceKeyInvalid);
    }
}
