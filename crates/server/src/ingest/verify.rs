//! 5-step verify chain for ingest (spec §8.5).
//!
//! 1. Transport layer — HTTP Message Signature for push. We surface a hook here; the actual RFC
//!    9421 HTTP signature check lives in [`crate::middleware::http_sig`] (mounted on the ingest
//!    sub-router by [`crate::routing::directory_router`] via
//!    `.hoop(HttpSigMiddleware::new_with_postgres_replay_store(...))`) so the handler always sees
//!    an already-authenticated transport. TB-1 (this comment block) closed the prior gap where the
//!    middleware was advertised but not actually mounted.
//! 2. Discovery proof — verify the original discovery Event producer proof against the resource
//!    governance key resolved via DID document.
//! 3. Directory authorization — `discovery_state.directory_ids` is a core-id list containing *this*
//!    directory's stable service id.
//! 4. Source-ref authority — for first ingest, resolves every closed committed Event ref from the
//!    resource's governance Station and verifies its RealmCommit signature plus authority chain.
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
use arkret_signatures::http_signature::{
    ContentDigest, ContentDigestAlgorithm, SignedRequestParts, canonical_message,
    parse_signature_input, sign_message,
};
use arkret_wire::{Hash, TrustDomainId, WireError};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use reqwest::Client;
use salvo::async_trait;
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;
use url::Url;

use crate::config::{AcceptPolicyKind, AppConfig};
use crate::db::Db;
use crate::did_resolver::{
    SharedDidResolver, did_method_allowed, did_method_prefix_for_did,
    verification_method_controller_core_id,
};
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

/// The authenticated source Station, in both spellings a verifier needs.
///
/// They are not derivable from one another. `project_did_to_core_id` is
/// one-way — a `did:webvh` core id keeps only the SCID — so the resolvable DID
/// has to travel with the stable business id rather than be reconstructed from
/// it. Both members here have already been bound to each other and to the
/// announce: `source_service_did` projects the verified access proof's
/// verification-method DID and rejects it unless it equals
/// `source_ref_access.source_id`, which `verify_directory_source_ref_access`
/// in turn requires to equal `req.station_id`.
#[derive(Clone, Copy, Debug)]
pub struct SourceStation<'a> {
    /// Stable business identity, as carried by the announce (`station_id`).
    pub service_id: &'a DidCoreId,
    /// The same Station as a resolvable DID.
    pub did: &'a Did,
}

/// Verifies that a resolved `RealmCommit` was signed by the governance
/// authority active at that generation and that its authority chain is valid.
///
/// Structural equality is deliberately handled by the caller first. An
/// implementation of this trait must additionally verify the commit signature,
/// the genesis-to-generation authority chain, and the signing Station binding;
/// accepting solely because [`arkret_wire::CommittedEventRef::matches`] returned
/// true is forbidden.
///
/// The production implementation is
/// [`crate::ingest::authority_chain::RealmAuthorityChainVerifier`]. The trait
/// stays as a seam only so that a test can drive the announce path without a
/// live Station — not so that a deployment can choose a weaker rule.
#[async_trait]
pub trait CommittedEventAuthorityVerifier: Send + Sync + 'static {
    async fn verify(
        &self,
        station: SourceStation<'_>,
        reference: &arkret_wire::CommittedEventRef,
        item: &arkret_wire::StreamRow,
    ) -> Result<(), String>;
}

pub struct VerifyContext<'a> {
    pub config: &'a AppConfig,
    pub db: &'a Db,
    /// DID-P0-C01 — borrowed from `AppState`; never constructed here.
    pub resolver: &'a SharedDidResolver,
    pub commit_authority_verifier: &'a dyn CommittedEventAuthorityVerifier,
    pub now: DateTime<Utc>,
}

impl<'a> VerifyContext<'a> {
    pub fn new(
        config: &'a AppConfig,
        db: &'a Db,
        resolver: &'a SharedDidResolver,
        commit_authority_verifier: &'a dyn CommittedEventAuthorityVerifier,
    ) -> Self {
        Self {
            config,
            db,
            resolver,
            commit_authority_verifier,
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
        if !directory_ids_are_core_ids(&req.discovery_state) {
            return Err((
                ApiErrorCode::SchemaViolation,
                "discovery_state.directory_ids must be a non-empty array of service core ids"
                    .to_owned(),
            ));
        }
        let listed =
            directory_ids_lists_self(&req.discovery_state, self.config.service_id.as_str());
        if !listed {
            return Err((
                ApiErrorCode::DirectoryUnauthorized,
                format!(
                    "discovery_state.directory_ids does not list this directory ({})",
                    self.config.service_id
                ),
            ));
        }

        // --- Step 4: source-ref sanity. ------------------------------------
        if req.source_refs.is_empty() {
            return Err((
                ApiErrorCode::SourceRefsUnverifiable,
                "source_refs MUST contain at least one committed Event ref".into(),
            ));
        }
        verify_directory_source_ref_access(req, self.config, self.resolver, self.now)?;
        if !resource_already_indexed(self.db, req.resource_kind, &req.resource_id)
            .await
            .map_err(|e| (ApiErrorCode::InternalError, format!("source-ref gate: {e}")))?
        {
            verify_first_source_ref_resolves(
                req,
                self.config,
                self.resolver,
                self.commit_authority_verifier,
            )
            .await?;
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
        // The request does not echo a free-form revision. The bounded set of
        // authority-committed source Events is the revision carrier; Realm
        // producers include the effective policy-bundle Event in this set.
        let policy_revision = canonical::canonical_sha256(&req.source_ref_access.source_refs)
            .map_err(|error| {
                (
                    ApiErrorCode::SchemaViolation,
                    format!("committed source refs revision is not canonical: {error}"),
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
    let proof = event.producer_proof.as_ref().ok_or_else(|| {
        (
            ApiErrorCode::DirectoryGovernanceProofSignatureInvalid,
            "discovery Event has no producer proof".to_owned(),
        )
    })?;
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
    // Event identity/digest bindings were checked above. The signature
    // covers the producer proof binding object, including the complete
    // ActorId and proof metadata, never the raw Event bytes alone.
    let binding_bytes = proof
        .canonical_binding_bytes(&event.actor_id)
        .map_err(|error| {
            (
                ApiErrorCode::DirectoryGovernanceProofSignatureInvalid,
                format!("discovery Event proof transcript is invalid: {error}"),
            )
        })?;
    resolver
        .verify_detached_jws_with_authority(
            &binding_bytes,
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
        self.resource_id.as_str()
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
    expected_controller_core_id: Option<&str>,
    verification_method: &str,
) -> Result<(), (ApiErrorCode, String)> {
    let did = verification_method
        .split_once('#')
        .map(|(did, _)| did)
        .unwrap_or(verification_method);
    let controller =
        verification_method_controller_core_id(verification_method).ok_or_else(|| {
            (
                ApiErrorCode::GovernanceKeyInvalid,
                "verification_method has no valid registered DID controller".to_owned(),
            )
        })?;
    match resource_kind {
        DirectoryResourceKindDb::Organization
        | DirectoryResourceKindDb::Actor
        | DirectoryResourceKindDb::Applet => {
            if controller.as_str() != resource_id {
                return Err((
                    ApiErrorCode::GovernanceKeyInvalid,
                    format!("verification_method DID `{did}` does not control `{resource_id}`"),
                ));
            }
        }
        DirectoryResourceKindDb::Realm | DirectoryResourceKindDb::Handle => {
            let Some(expected) = expected_controller_core_id else {
                return Err((
                    ApiErrorCode::GovernanceKeyInvalid,
                    format!("no indexed governance controller for `{resource_id}`"),
                ));
            };
            if controller.as_str() != expected {
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
    commit_authority_verifier: &dyn CommittedEventAuthorityVerifier,
) -> Result<(), (ApiErrorCode, String)> {
    let source_refs = req.source_ref_access.source_refs.clone();
    if source_refs.is_empty() {
        return Err((
            ApiErrorCode::SourceRefsUnverifiable,
            "source_refs MUST contain at least one committed Event ref".to_owned(),
        ));
    }
    let resolve_request = arkret_wire::CommittedEventResolveRequest {
        realm_id: req.source_ref_access.realm_id.clone(),
        refs: source_refs.clone(),
        source_ref_access: req.source_ref_access.clone(),
    };
    resolve_request.validate().map_err(|error| {
        (
            ApiErrorCode::SourceRefsUnverifiable,
            format!("invalid committed source refs: {error}"),
        )
    })?;

    // `station_id` is a stable `did_core_id`, never a resolvable DID. The
    // source-signed access proof was verified immediately before this call;
    // its verification-method controller is the authenticated route carrier.
    // Project that supplied DID back to the declared source core and reject a
    // mismatch before authority resolution.
    let station_did = source_service_did(&req.source_ref_access).map_err(|reason| {
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
    let accepted = resolve_station_endpoint(
        config,
        resolver,
        &station_did,
        req.source_ref_access.discovery_event_id.as_str(),
    )
    .await
    .map_err(|e| {
        (
            ApiErrorCode::SourceRefsUnverifiable,
            format!("station_id did not resolve to committed-event endpoint: {e}"),
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
    let url = endpoint_child(&accepted.endpoint, "streams/resolve").map_err(|e| {
        (
            ApiErrorCode::SourceRefsUnverifiable,
            format!("committed source-ref URL: {e}"),
        )
    })?;
    let target = crate::egress::resolve_url_for_egress(
        &url,
        "committed source-ref fetch",
        crate::egress::local_development_enabled(config.development_mode),
    )
    .map_err(|error| (ApiErrorCode::SourceRefsUnverifiable, error))?;
    let locked_http = strict_http_client_for_egress(&target).map_err(|e| {
        (
            ApiErrorCode::InternalError,
            format!("committed source-ref HTTP client: {e}"),
        )
    })?;
    let body_bytes = canonical::canonical_json_bytes(&resolve_request)
        .map_err(|error| (ApiErrorCode::SourceRefsUnverifiable, error.to_string()))?;
    let signing_key = config.receipt_signing_key.as_ref().ok_or_else(|| {
        (
            ApiErrorCode::SourceRefsUnverifiable,
            "Directory service signing key is required for exact committed-event resolve"
                .to_owned(),
        )
    })?;
    let target_uri = target.url().as_str().to_owned();
    let host = target.url().host_str().ok_or_else(|| {
        (
            ApiErrorCode::SourceRefsUnverifiable,
            "committed source-ref endpoint has no authority".to_owned(),
        )
    })?;
    let authority = match target.url().port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    let digest = ContentDigest::compute(&body_bytes, ContentDigestAlgorithm::Sha256);
    let created = Utc::now().timestamp();
    let signature_input = format!(
        "sig1=(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \"source-service-id\" \"destination-service-id\" \"source-trust-domain\" \"destination-trust-domain\");created={created};expires={};keyid=\"{}\";alg=\"ed25519\"",
        created + 300,
        signing_key.key_id()
    );
    let parsed_input = parse_signature_input(&signature_input).map_err(|error| {
        (
            ApiErrorCode::InternalError,
            format!("peer signature input: {error}"),
        )
    })?;
    let headers = vec![
        ("content-digest".to_owned(), digest.wire_value.clone()),
        (
            "source-service-id".to_owned(),
            config.service_id.to_string(),
        ),
        (
            "destination-service-id".to_owned(),
            req.station_id.to_string(),
        ),
        (
            "source-trust-domain".to_owned(),
            config.trust_domain.to_string(),
        ),
        (
            "destination-trust-domain".to_owned(),
            accepted.trust_domain.to_string(),
        ),
    ];
    let signing_parts = SignedRequestParts {
        method: "POST".to_owned(),
        target_uri: target_uri.clone(),
        authority,
        path: target.url().path().to_owned(),
        headers: headers.clone(),
        body_digest: None,
    };
    let signing_message = canonical_message(&signing_parts, &parsed_input).map_err(|error| {
        (
            ApiErrorCode::InternalError,
            format!("peer signature base: {error}"),
        )
    })?;
    let signature = format!(
        "sig1=:{}:",
        sign_message(&signing_message, signing_key.signing_key())
    );
    let mut outbound = locked_http.post(target.url().clone());
    for (name, value) in headers {
        outbound = outbound.header(name, value);
    }
    let response = outbound
        .header("signature-input", signature_input)
        .header("signature", signature)
        .header(
            "arkret-operation",
            arkret_wire::ServiceOperationId::PEER_EVENTS_READ_RESOLVE_COMMITTED_V1,
        )
        .header("content-type", "application/json")
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| {
            (
                ApiErrorCode::SourceRefsUnverifiable,
                format!("committed source-ref fetch failed: {e:?}"),
            )
        })?;
    if !response.status().is_success() {
        return Err((
            ApiErrorCode::SourceRefsUnverifiable,
            format!("committed source-ref fetch returned {}", response.status()),
        ));
    }
    let body = response_json_limited::<arkret_wire::CommittedEventResolveOutcome>(
        response,
        "committed source-ref response",
    )
    .await
    .map_err(|e| {
        (
            ApiErrorCode::SourceRefsUnverifiable,
            format!("committed source-ref response was not JSON: {e}"),
        )
    })?;
    if body.items.len() != source_refs.len() {
        return Err((
            ApiErrorCode::SourceRefsUnverifiable,
            "peer exact committed-event resolve omitted or added a source ref".to_owned(),
        ));
    }
    for (reference, item) in source_refs.iter().zip(&body.items) {
        item.commit.validate_shape().map_err(|error| {
            (
                ApiErrorCode::SourceRefsUnverifiable,
                format!("resolved RealmCommit shape is invalid: {error}"),
            )
        })?;
        if !reference.matches(item) {
            return Err((
                ApiErrorCode::SourceRefsUnverifiable,
                "resolved RealmCommit/Event does not match the exact committed ref".to_owned(),
            ));
        }
        commit_authority_verifier
            .verify(
                SourceStation {
                    service_id: &req.station_id,
                    did: &station_did,
                },
                reference,
                item,
            )
            .await
            .map_err(|reason| {
                (
                    ApiErrorCode::SourceRefsUnverifiable,
                    format!("RealmCommit authority verification failed: {reason}"),
                )
            })?;
    }
    Ok(())
}

fn verify_directory_source_ref_access(
    req: &DirectoryAnnounceIngest,
    config: &AppConfig,
    resolver: &SharedDidResolver,
    now: DateTime<Utc>,
) -> Result<(), (ApiErrorCode, String)> {
    let access = &req.source_ref_access;
    if access.directory_id.as_str() != config.service_id.as_str()
        || access.source_id != req.station_id
        || access.expires_at <= now
    {
        return Err((
            ApiErrorCode::SourceRefsUnverifiable,
            "directory source-ref access binding is unavailable".to_owned(),
        ));
    }
    let controller = verification_method_controller_core_id(&access.proof.verification_method);
    if controller.as_ref() != Some(&access.source_id) {
        return Err((
            ApiErrorCode::SourceRefsUnverifiable,
            "directory source-ref signer does not control the source service".to_owned(),
        ));
    }
    let key = resolver
        .http_signature_public_key(access.proof.verification_method.as_str())
        .ok_or_else(|| {
            (
                ApiErrorCode::SourceRefsUnverifiable,
                "directory source-ref signer key is unavailable".to_owned(),
            )
        })?;
    let binding = access
        .proof_binding_bytes()
        .map_err(|error| (ApiErrorCode::SourceRefsUnverifiable, error.to_string()))?;
    arkret_signatures::verify_ed25519_detached_jws_payload_proof(
        &access.proof,
        &binding,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.to_bytes().to_vec(),
        },
    )
    .map_err(|error| (ApiErrorCode::SourceRefsUnverifiable, error.to_string()))
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

pub(crate) fn did_document_url(did: &Did) -> anyhow::Result<Url> {
    let url = match did.method() {
        "web" => DidWebResolver::document_url(did)?,
        "webvh" => DidWebvhResolver::document_url(did)?,
        other => anyhow::bail!("unsupported Station DID method did:{other}"),
    };
    Url::parse(&url).map_err(|e| anyhow::anyhow!("invalid DID document URL `{url}`: {e}"))
}

/// Raw DID Document fetch. Used **only** on development-mode loopback
/// paths — the [`resolve_station_endpoint`] branch below and
/// `crate::did_resolver::LoopbackDidWebResolver`, which is the same concession
/// made once for every other DID consumer in the process. Every production
/// path goes through the shared resolver chain instead.
///
/// It refuses anything that is not HTTPS or a development-mode loopback HTTP
/// URL, so the two callers cannot widen it by passing a different URL.
///
/// The dead `_http: &Client` parameter is gone. It was never read: the body
/// always built its own egress-pinned client below, because that client has to
/// be bound to the validated target address and a caller-supplied one is not.
pub(crate) async fn fetch_did_document_json(
    url: Url,
    development_mode: bool,
) -> anyhow::Result<JsonValue> {
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

pub(crate) fn is_loopback_url(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
        None => false,
    }
}

fn directory_ids_lists_self(discovery_state: &JsonValue, self_service_id: &str) -> bool {
    discovery_state
        .get("directory_ids")
        .and_then(JsonValue::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(JsonValue::as_str)
                .any(|id| id == self_service_id)
        })
        .unwrap_or(false)
}

fn directory_ids_are_core_ids(discovery_state: &JsonValue) -> bool {
    discovery_state
        .get("directory_ids")
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

/// Recover the authenticated source service DID from the already verified
/// source-ref proof. This never widens a stable core id into a DID: the DID is
/// supplied by the signed verification method and accepted only when its
/// adapter projection is exactly the carrier's `source_id`.
fn source_service_did(access: &arkret_wire::DirectorySourceRefAccess) -> Result<Did, String> {
    let (controller, fragment) = access
        .proof
        .verification_method
        .as_str()
        .split_once('#')
        .ok_or_else(|| "source-ref verification method requires a fragment".to_owned())?;
    if fragment.is_empty() {
        return Err("source-ref verification method fragment is empty".to_owned());
    }
    let did = Did::new(controller.to_owned())
        .map_err(|error| format!("source-ref verification method DID is invalid: {error}"))?;
    let projected = arkret_sdk::project_did_to_core_id(&did).map_err(|error| {
        format!("source-ref verification method DID cannot be projected: {error}")
    })?;
    if projected != access.source_id {
        return Err("source-ref verification method does not control source_id".to_owned());
    }
    Ok(did)
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
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;

    use arkret_sdk::identity::{DidDocument, DidResolver, ResolvedDid, Result as IdentityResult};
    use arkret_sdk::{DidUrl, DirectoryGovernanceProofPurpose, Hash};
    use arkret_signatures::jws::sign_jws_ed25519;
    use chrono::Duration;
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::config::{
        AcceptPolicyKind, AppConfig, DbPoolConfig, IngestModeAdvert, ReceiptSigningKey,
    };
    use crate::observability::Metrics;

    #[test]
    fn directory_authority_list_accepts_only_service_core_ids() {
        assert!(directory_ids_are_core_ids(&json!({
            "directory_ids": ["ak:did_core:web:directory.example"]
        })));
        for forbidden in [
            json!({"directory_ids": ["did:web:directory.example"]}),
            json!({"directory_ids": ["https://directory.example"]}),
            json!({"directory_ids": []}),
        ] {
            assert!(!directory_ids_are_core_ids(&forbidden));
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
                Some("ak:did_core:web:principal.example"),
                "did:web:attacker.example#key-1",
            )
            .is_err()
        );

        assert!(
            enforce_governance_method_binding(
                DirectoryResourceKindDb::Realm,
                "ak:realm:tea",
                Some("ak:did_core:web:principal.example"),
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
        issuer_core_id: DidCoreId,
        verification_method: DidUrl,
    }

    fn test_signer() -> GovernanceSigner {
        let signing_key = SigningKey::from_bytes(&SIGNING_SEED);
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signing_key.verifying_key().as_bytes(),
        );
        let issuer_did = format!("did:key:{multibase}");
        let verification_method =
            DidUrl::new(format!("{issuer_did}#{multibase}")).expect("verification method");
        GovernanceSigner {
            signing_key,
            issuer_core_id: arkret_sdk::project_did_to_core_id(&Did::new(issuer_did).unwrap())
                .unwrap(),
            verification_method,
        }
    }

    #[tokio::test]
    async fn discovery_event_verifies_producer_binding_and_rejects_metadata_or_station_tampering() {
        let signer = test_signer();
        let mut event = arkret_wire::test_support::raw_event(
            "ak.actor.discovery",
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_wire::RealmId::new(REALM_ID).unwrap(),
            },
            signer.issuer_core_id.clone(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            json!({"resource_id": signer.issuer_core_id, "value": {"discoverability": "public"}}),
        )
        .unwrap();
        event
            .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let mut proof = arkret_wire::ProducerEventProof {
            kind: "detached_jws".to_owned(),
            verification_method: signer.verification_method.clone(),
            event_digest: Hash::new(
                event
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .unwrap(),
            )
            .unwrap(),
            created_at: event.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: String::new(),
        };
        proof.jws = sign_jws_ed25519(
            &proof.canonical_binding_bytes(&event.actor_id).unwrap(),
            &signer.signing_key,
        )
        .unwrap();
        event.producer_proof = Some(proof.clone());
        let resolver = resolver();
        let verify = |candidate: &arkret_wire::Event| {
            verify_discovery_event_proofs(
                candidate,
                DirectoryResourceKindDb::Actor,
                signer.issuer_core_id.as_str(),
                None,
                &resolver,
            )
        };
        verify(&event).expect("the actual discovery verifier accepts SDK producer bindings");

        let mut changed_metadata = event.clone();
        let mut changed_proof = proof.clone();
        changed_proof.created_at += Duration::seconds(1);
        changed_metadata.producer_proof = Some(changed_proof);
        assert!(
            verify(&changed_metadata).is_err(),
            "proof metadata is cryptographically bound"
        );

        let mut changed_station = event.clone();
        changed_station.actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            signer.issuer_core_id.clone(),
            DidCoreId::new("ak:did_core:web:foreign.example").unwrap(),
        ));
        changed_station
            .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let mut changed_proof = proof.clone();
        changed_proof.event_digest = Hash::new(
            changed_station
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        changed_station.producer_proof = Some(changed_proof);
        assert!(
            verify(&changed_station).is_err(),
            "same principal on another Station needs a new signature"
        );
    }

    fn resolver() -> SharedDidResolver {
        SharedDidResolver::new(&["did:key".to_owned()], false).expect("resolver builds")
    }

    struct SourceDocumentResolver {
        document: DidDocument,
    }

    impl DidResolver for SourceDocumentResolver {
        fn supports(&self, did: &Did) -> bool {
            did == &self.document.id
        }

        fn resolve_did(&self, did: &Did) -> IdentityResult<ResolvedDid> {
            if self.supports(did) {
                Ok(ResolvedDid::proofless(self.document.clone()))
            } else {
                Err(arkret_sdk::identity::IdentityError::Protocol(format!(
                    "unknown source DID {did}"
                )))
            }
        }
    }

    fn source_ref_test_config() -> AppConfig {
        AppConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            metrics_bind: "127.0.0.1:0".parse().unwrap(),
            public_base_url: "http://directory.test".to_owned(),
            service_id: DidCoreId::new(DIRECTORY_SERVICE_ID).unwrap(),
            service_did: Did::new("did:web:directory.test").unwrap(),
            service_resolution: arkret_sdk::ResolutionCommitment {
                did: Did::new("did:web:directory.test").unwrap(),
                method_history_head: "directory-test-history".to_owned(),
                version_id: "directory-test-version".to_owned(),
            },
            trust_domain: "ak:trust_domain:directory.test".to_owned(),
            database_url: "postgres://unused/teabay".to_owned(),
            cors_allow_origin: None,
            admin_csrf_token: None,
            admin_token: None,
            admin_token_rotation_window: std::time::Duration::from_secs(1_800),
            development_mode: true,
            accept_policy_kind: AcceptPolicyKind::Open,
            accept_policy_ref: None,
            takedown_contact: None,
            accepted_resource_kinds: arkret_sdk::DirectoryResourceKind::ALL.to_vec(),
            accepted_did_methods: vec!["did:web".to_owned()],
            default_ttl: std::time::Duration::from_secs(3_600),
            max_ttl: std::time::Duration::from_secs(86_400),
            revalidation_grace: std::time::Duration::from_secs(300),
            as_of_skew: std::time::Duration::from_secs(300),
            ingest_modes: vec![IngestModeAdvert::Push],
            rate_limit_per_resource_per_min: 60,
            query_max_queries_per_ip_per_min: 0,
            query_max_resolves_per_resource_per_min: 0,
            query_latency_floor: std::time::Duration::ZERO,
            query_latency_jitter: std::time::Duration::ZERO,
            require_http_sig: false,
            http_sig_pubkeys: HashMap::new(),
            receipt_signing_key: Some(ReceiptSigningKey::from_raw(
                "did:web:directory.test#directory-key".to_owned(),
                [91; 32],
            )),
            db_pool: DbPoolConfig::default(),
            expiry_interval: None,
            takedown_notifier_interval: None,
            trusted_proxy: None,
            private_contact_discovery: None,
        }
    }

    fn source_ref_test_event(
        realm_id: arkret_wire::RealmId,
        source_id: DidCoreId,
    ) -> arkret_wire::Event {
        let mut event = arkret_wire::test_support::raw_event(
            "ak.realm.discovery",
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            source_id.clone(),
            source_id,
            json!({
                "value": {
                    "resource_kind": "realm",
                    "discoverability": "public",
                    "directory_ids": [DIRECTORY_SERVICE_ID]
                }
            }),
        )
        .unwrap();
        event
            .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        event
    }

    fn signed_source_ref_access(
        event: &arkret_wire::Event,
        committed_ref: arkret_wire::CommittedEventRef,
        source_id: DidCoreId,
        verification_method: DidUrl,
        signing_key: &SigningKey,
    ) -> arkret_wire::DirectorySourceRefAccess {
        let as_of = Utc::now();
        let mut access = arkret_wire::DirectorySourceRefAccess {
            kind: arkret_wire::DirectorySourceRefAccessKind::DirectoryAnnounce,
            source_id,
            directory_id: DidCoreId::new(DIRECTORY_SERVICE_ID).unwrap(),
            realm_id: event.realm_id.clone(),
            discovery_event_id: event.event_id.clone(),
            source_refs: vec![committed_ref],
            as_of,
            expires_at: as_of + Duration::minutes(5),
            proof: arkret_wire::PayloadProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method,
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: as_of,
                domain: Some("arkret-event-v1".to_owned()),
                audience: Some(arkret_wire::Audience::Single(
                    DIRECTORY_SERVICE_ID.to_owned(),
                )),
                proof_purpose: None,
                jws: "e30..c2ln".to_owned(),
            },
        };
        access.proof.payload_digest = access.payload_digest().unwrap();
        let binding = access.proof_binding_bytes().unwrap();
        access.proof.jws = sign_jws_ed25519(&binding, signing_key).unwrap();
        access
    }

    /// A `DetachedObjectSignature` shaped correctly and signed by nobody.
    ///
    /// Every use of it is immediately overwritten by a real signature; it
    /// exists because the unsigned projection a signature is computed over is
    /// the object *minus* its `signature` member, so the member has to be
    /// present before it can be dropped.
    fn unsealed_signature(
        context: arkret_wire::DetachedSignatureContext,
        verification_method: DidUrl,
    ) -> arkret_wire::DetachedObjectSignature {
        arkret_wire::DetachedObjectSignature {
            context,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method,
            signed_digest: Hash::new(arkret_canonical::sha256_digest(b"unsealed")).unwrap(),
            created_at: Utc::now(),
            sig: arkret_wire::Base64UrlString::new("AA").unwrap(),
        }
    }

    /// Seal a `RealmCommit` the way the verifier reconstructs it: the signed
    /// body is the canonical object minus its own `signature` member.
    fn seal_realm_commit(
        mut commit: arkret_wire::RealmCommit,
        verification_method: &DidUrl,
        signing_key: &SigningKey,
    ) -> arkret_wire::RealmCommit {
        let unsigned =
            arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
        commit.signature = arkret_signatures::detached_object::sign_detached_object(
            &unsigned,
            arkret_wire::DetachedSignatureContext::RealmCommit,
            verification_method.clone(),
            Utc::now(),
            signing_key,
        )
        .unwrap();
        commit
    }

    fn realm_commit_id_for(event_id: &arkret_wire::EventId) -> arkret_wire::RealmCommitId {
        arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            event_id.as_str().as_bytes(),
        ))
    }

    /// The Realm's genesis Event: position 0 of the Realm stream, and the
    /// record that installs generation 0 of its governance authority.
    ///
    /// `ak.realm.create` carries the `realm_genesis` scope and omits
    /// `realm_id` on the wire — `models/realm-and-space.md` §2.5.0 has
    /// receivers derive it from the Event's own id — so the Realm this whole
    /// fixture is about is *defined by* this Event rather than chosen next to
    /// it. Using a fixed constant here produced a bundle that verified in
    /// memory and broke the moment it round-tripped through JSON, which is the
    /// only form the production verifier ever sees.
    fn genesis_realm_event(source_id: DidCoreId) -> arkret_wire::Event {
        arkret_wire::test_support::raw_event(
            "ak.realm.create",
            arkret_wire::ScopeRef::RealmGenesis,
            source_id.clone(),
            source_id,
            json!({"value": {"name": "authority fixture realm"}}),
        )
        .unwrap()
    }

    /// The announce's discovery Event as the source Station committed it:
    /// position 1, under generation 0, naming the genesis Event as the record
    /// that installed the authority behind it.
    ///
    /// `signed_by` is a parameter because the negative case needs a commit
    /// that is structurally perfect and really signed — just not by the
    /// Station the verified chain says holds authority.
    fn committed_source_item(
        event: arkret_wire::Event,
        genesis: &arkret_wire::RealmCommit,
        signed_by: (&DidUrl, &SigningKey),
    ) -> (arkret_wire::CommittedEventRef, arkret_wire::StreamRow) {
        let stream_ref = arkret_wire::CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        };
        let commit_id = realm_commit_id_for(&event.event_id);
        let (verification_method, signing_key) = signed_by;
        let commit = seal_realm_commit(
            arkret_wire::RealmCommit {
                commit_id: commit_id.clone(),
                realm_id: event.realm_id.clone(),
                stream_ref: stream_ref.clone(),
                stream_position: 1,
                previous_commit_ref: Some(genesis.commit_id.clone()),
                event_ref: event.event_id.clone(),
                authority_generation: 0,
                authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    genesis.event_ref.clone(),
                ),
                committed_at: Utc::now(),
                signature: unsealed_signature(
                    arkret_wire::DetachedSignatureContext::RealmCommit,
                    verification_method.clone(),
                ),
            },
            verification_method,
            signing_key,
        );
        let reference = arkret_wire::CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id,
            stream_ref,
            stream_position: 1,
        };
        (reference, arkret_wire::StreamRow { commit, event })
    }

    /// The governance material the fixture Station serves from its open face.
    ///
    /// A genesis-only chain: generation 0, held by the same Station that
    /// carries the announce. Every signature in it is a real Ed25519
    /// signature over the canonical unsigned body, because the point of these
    /// tests is that the **production** verifier is what admits the announce.
    #[derive(Clone)]
    struct AuthorityFixture {
        genesis_event: arkret_wire::Event,
        genesis_commit: arkret_wire::RealmCommit,
        realm_stream_head: arkret_wire::CommitStreamHead,
        current_service_id: DidCoreId,
        verification_method: DidUrl,
        signing_key: SigningKey,
        route_record: JsonValue,
    }

    impl AuthorityFixture {
        fn new(
            source_did: &Did,
            source_id: DidCoreId,
            verification_method: DidUrl,
            signing_key: SigningKey,
            genesis_event: arkret_wire::Event,
            genesis_commit: arkret_wire::RealmCommit,
            realm_stream_head: arkret_wire::CommitStreamHead,
        ) -> Self {
            let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                signing_key.verifying_key().as_bytes(),
            );
            let document: DidDocument = serde_json::from_value(json!({
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": source_did.as_str(),
                "verificationMethod": [{
                    "id": verification_method.as_str(),
                    "controller": source_did.as_str(),
                    "type": "Multikey",
                    "publicKeyMultibase": multibase,
                }],
                "authentication": [verification_method.as_str()],
                "assertionMethod": [verification_method.as_str()],
                "service": [{
                    "id": format!("{}#station", source_did.as_str()),
                    "type": "ArkretService",
                    "serviceEndpoint": "https://source.example/",
                    "serviceKind": "station",
                }],
            }))
            .unwrap();
            let resolution = arkret_identity::build_authenticated_did_web_service_resolution(
                source_id.clone(),
                "station".to_owned(),
                document,
                Utc::now(),
            )
            .unwrap();
            Self {
                genesis_event,
                genesis_commit,
                realm_stream_head,
                current_service_id: source_id,
                verification_method,
                signing_key,
                route_record: serde_json::to_value(&resolution).unwrap(),
            }
        }

        /// Answer exactly one nonce.
        ///
        /// The current assertion is signed here, at request time, so the
        /// fixture cannot serve a pre-baked assertion for a nonce it was never
        /// asked about — which is the very replay the freshness check exists
        /// to catch.
        fn bundle(&self, nonce: arkret_wire::Base64UrlString) -> arkret_wire::RealmAuthorityBundle {
            let issued_at = Utc::now() - Duration::seconds(1);
            let mut assertion = arkret_wire::RealmAuthorityCurrentAssertion {
                realm_id: self.genesis_event.realm_id.clone(),
                current_generation: 0,
                current_service_id: self.current_service_id.clone(),
                last_handoff_ref: None,
                realm_stream_head: self.realm_stream_head.clone(),
                nonce,
                expires_at: issued_at + Duration::minutes(5),
                signature: unsealed_signature(
                    arkret_wire::DetachedSignatureContext::RealmAuthorityCurrentAssertion,
                    self.verification_method.clone(),
                ),
            };
            let unsigned =
                arkret_canonical::canonical::unsigned_value(&assertion, &["signature"]).unwrap();
            assertion.signature = arkret_signatures::detached_object::sign_detached_object(
                &unsigned,
                arkret_wire::DetachedSignatureContext::RealmAuthorityCurrentAssertion,
                self.verification_method.clone(),
                issued_at,
                &self.signing_key,
            )
            .unwrap();
            arkret_wire::RealmAuthorityBundle {
                realm_id: self.genesis_event.realm_id.clone(),
                genesis_event: self.genesis_event.clone(),
                genesis_commit: self.genesis_commit.clone(),
                authority_transitions: Vec::new(),
                current_generation: 0,
                current_service_id: self.current_service_id.clone(),
                current_route_record: self.route_record.clone(),
                realm_stream_head: self.realm_stream_head.clone(),
                bundle_issued_at: issued_at,
                current_assertion: assertion,
            }
        }
    }

    /// The fixture source Station, answering on its two real faces.
    ///
    /// Announce admission talks to a Station twice: once on the peer face for
    /// the exact committed-event resolve, and once on the open face for the
    /// nonce-bound authority bundle that decides whether the resolve's answer
    /// means anything. Serving both from one listener is what lets these
    /// tests drive the production verifier instead of a stand-in.
    ///
    /// The returned string is the peer-face request, so the existing
    /// assertions about the outbound resolve body keep working.
    async fn source_peer(
        resolve_status: u16,
        item: arkret_wire::StreamRow,
        authority: AuthorityFixture,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut captured = String::new();
            // A denied resolve ends admission before the authority bundle is
            // ever requested, so only one connection is expected then.
            let expected_requests = if resolve_status == 200 { 2 } else { 1 };
            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut received = Vec::new();
                let header_end = loop {
                    let mut chunk = [0_u8; 4096];
                    let count = stream.read(&mut chunk).await.unwrap();
                    assert!(count > 0, "source peer request ended before headers");
                    received.extend_from_slice(&chunk[..count]);
                    if let Some(position) =
                        received.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        break position + 4;
                    }
                };
                let headers = String::from_utf8(received[..header_end].to_vec()).unwrap();
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                while received.len() < header_end + content_length {
                    let mut chunk = [0_u8; 4096];
                    let count = stream.read(&mut chunk).await.unwrap();
                    assert!(count > 0, "source peer request body was truncated");
                    received.extend_from_slice(&chunk[..count]);
                }
                let body =
                    String::from_utf8(received[header_end..header_end + content_length].to_vec())
                        .unwrap();
                let request_line = headers.lines().next().unwrap_or_default().to_owned();
                let (status, response_body) = if request_line.contains("/realm-authority/bundle") {
                    assert!(
                        request_line.starts_with("POST /_arkret/open/realm-authority/bundle "),
                        "authority bundle must be fetched from the open face: {request_line}"
                    );
                    let request: arkret_wire::AuthorityBundleRequest =
                        serde_json::from_str(&body).unwrap();
                    request.validate().unwrap();
                    let bundle = authority.bundle(request.nonce);
                    (200_u16, serde_json::to_string(&bundle).unwrap())
                } else {
                    captured = format!("{headers}{body}");
                    if resolve_status == 200 {
                        (
                            resolve_status,
                            serde_json::to_string(&json!({"items": [&item]})).unwrap(),
                        )
                    } else {
                        (resolve_status, "{}".to_owned())
                    }
                };
                let reason = if status == 200 { "OK" } else { "Forbidden" };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
                    response_body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            captured
        });
        (format!("http://{address}/_arkret/peer"), task)
    }

    fn source_ref_test_resolver(
        endpoint: String,
        source_did: Did,
        verification_method: DidUrl,
        signing_key: &SigningKey,
    ) -> SharedDidResolver {
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signing_key.verifying_key().as_bytes(),
        );
        let document = DidDocument {
            id: source_did,
            verification_methods: BTreeMap::from([(verification_method.to_string(), multibase)]),
            also_known_as: Vec::new(),
            updated_at: None,
            raw_properties: BTreeMap::from([(
                "service".to_owned(),
                json!([{
                    "id": "#station",
                    "type": "ArkretStation",
                    "serviceEndpoint": endpoint
                }]),
            )]),
        };
        SharedDidResolver::with_chain_for_test(
            &["did:web".to_owned()],
            Arc::new(SourceDocumentResolver { document }),
            Metrics::default(),
        )
        .unwrap()
    }

    /// Drive one first-ingest admission against the fixture Station.
    ///
    /// There is no stand-in verifier here. `verify_first_source_ref_resolves`
    /// runs against [`crate::ingest::authority_chain::RealmAuthorityChainVerifier`],
    /// which fetches the nonce-bound bundle from the fixture Station and hands
    /// it to `arkret_identity::verify_realm_authority_bundle`. A test that
    /// passed by asserting `CommittedEventRef::matches` would prove nothing
    /// about admission, which is exactly what the trait doc forbids.
    ///
    /// `commit_authority` selects who signed the resolved commit:
    /// `CommitAuthority::Genuine` is the Station the verified chain names,
    /// `CommitAuthority::Impostor` is a different Station whose signature is
    /// just as real and whose coordinates still satisfy `matches`.
    #[derive(Clone, Copy)]
    enum CommitAuthority {
        Genuine,
        Impostor,
    }

    async fn run_source_ref_fetch(
        status: u16,
        commit_authority: CommitAuthority,
    ) -> Result<String, (ApiErrorCode, String)> {
        let signing_key = SigningKey::from_bytes(&[77; 32]);
        let source_did = Did::new("did:web:source.example").unwrap();
        let source_id = arkret_sdk::project_did_to_core_id(&source_did).unwrap();
        let verification_method = DidUrl::new("did:web:source.example#source-key").unwrap();

        // Generation 0: the genesis Event, the Realm it defines, and the
        // commit that seals it.
        let genesis_event = genesis_realm_event(source_id.clone());
        let realm_id = genesis_event.realm_id.clone();
        let genesis_commit = seal_realm_commit(
            arkret_wire::RealmCommit {
                commit_id: realm_commit_id_for(&genesis_event.event_id),
                realm_id: genesis_event.realm_id.clone(),
                stream_ref: arkret_wire::CommitStreamRef::Realm {
                    realm_id: genesis_event.realm_id.clone(),
                },
                stream_position: 0,
                previous_commit_ref: None,
                event_ref: genesis_event.event_id.clone(),
                authority_generation: 0,
                authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    genesis_event.event_id.clone(),
                ),
                committed_at: Utc::now(),
                signature: unsealed_signature(
                    arkret_wire::DetachedSignatureContext::RealmCommit,
                    verification_method.clone(),
                ),
            },
            &verification_method,
            &signing_key,
        );

        let impostor_key = SigningKey::from_bytes(&[78; 32]);
        let impostor_method = DidUrl::new("did:web:impostor.example#source-key").unwrap();
        let event = source_ref_test_event(realm_id.clone(), source_id.clone());
        let (committed_ref, item) = committed_source_item(
            event.clone(),
            &genesis_commit,
            match commit_authority {
                CommitAuthority::Genuine => (&verification_method, &signing_key),
                CommitAuthority::Impostor => (&impostor_method, &impostor_key),
            },
        );
        let access = signed_source_ref_access(
            &event,
            committed_ref.clone(),
            source_id.clone(),
            verification_method.clone(),
            &signing_key,
        );
        let authority = AuthorityFixture::new(
            &source_did,
            source_id.clone(),
            verification_method.clone(),
            signing_key.clone(),
            genesis_event,
            genesis_commit,
            arkret_wire::CommitStreamHead {
                stream_ref: committed_ref.stream_ref.clone(),
                stream_position: committed_ref.stream_position,
                commit_id: committed_ref.commit_id.clone(),
            },
        );
        let (endpoint, peer) = source_peer(status, item, authority).await;
        let resolver = Arc::new(source_ref_test_resolver(
            endpoint,
            source_did,
            verification_method,
            &signing_key,
        ));
        let request = DirectoryAnnounceIngest {
            discovery_event: event,
            resource_kind: DirectoryResourceKindDb::Realm,
            resource_id: realm_id.to_string(),
            station_id: source_id,
            discovery_state: teabay_contracts::DirectoryDiscoveryState::from_json(json!({
                "resource_kind": "realm",
                "discoverability": "public",
                "directory_ids": [DIRECTORY_SERVICE_ID]
            })),
            source_refs: access.source_refs.clone(),
            as_of: access.as_of,
            source_ref_access: access,
            ttl_seconds: None,
            supersedes_announce_id: None,
        };
        let config = source_ref_test_config();
        verify_directory_source_ref_access(&request, &config, &resolver, Utc::now())?;
        let verifier = crate::ingest::authority_chain::RealmAuthorityChainVerifier::new(
            config.clone(),
            Arc::clone(&resolver),
        );
        let outcome =
            verify_first_source_ref_resolves(&request, &config, &resolver, &verifier).await;
        let captured = peer.await.unwrap();
        outcome.map(|()| captured)
    }

    #[tokio::test]
    async fn first_ingest_fetches_one_bounded_ref_from_the_authenticated_source_service() {
        let captured = run_source_ref_fetch(200, CommitAuthority::Genuine)
            .await
            .expect("the source Station returned the selected current ref");
        assert!(captured.starts_with("POST /_arkret/peer/streams/resolve HTTP/1.1"));
        assert!(
            captured
                .to_ascii_lowercase()
                .contains(&format!("source-service-id: {}", DIRECTORY_SERVICE_ID))
        );
        let (_, body) = captured.split_once("\r\n\r\n").unwrap();
        let body: JsonValue = serde_json::from_str(body).unwrap();
        assert_eq!(body["refs"].as_array().unwrap().len(), 1);
        assert_eq!(body["refs"][0]["stream_ref"]["realm_id"], body["realm_id"]);
        assert!(body["refs"][0]["event_id"].as_str().is_some());
        assert!(body["refs"][0].get("commit_id").is_some());
        // Position 1: the genesis commit holds position 0, and the discovery
        // Event is committed after it under the same generation.
        assert_eq!(body["refs"][0]["stream_position"], 1);
        assert_eq!(
            body["source_ref_access"]["discovery_event_id"],
            body["refs"][0]["event_id"]
        );
    }

    /// The resolved commit here is perfect in every way a structural check can
    /// see: its four coordinates satisfy `CommittedEventRef::matches`, its
    /// shape validates, and its signature is a real Ed25519 signature that
    /// really verifies against the key its verification method names. The only
    /// thing wrong with it is that the signer is not the Station the verified
    /// authority chain says held generation 0 — which is precisely the thing
    /// no amount of DTO equality can notice.
    #[tokio::test]
    async fn first_ingest_rejects_matching_commit_without_verified_authority_chain() {
        let (code, message) = run_source_ref_fetch(200, CommitAuthority::Impostor)
            .await
            .expect_err("exact DTO equality must not replace authority verification");
        assert_eq!(code, ApiErrorCode::SourceRefsUnverifiable);
        assert!(
            message.contains("authority verification failed"),
            "{message}"
        );
        assert!(
            message.contains("governance Station"),
            "the rejection must name the Station binding that failed, not just fail: {message}"
        );
    }

    #[tokio::test]
    async fn first_ingest_rejects_source_ref_after_withdraw_supersession_or_other_announce() {
        for lifecycle in ["withdrawn", "superseded", "other_announce_carrier"] {
            let (code, message) = run_source_ref_fetch(403, CommitAuthority::Genuine)
                .await
                .expect_err("a source Station lifecycle denial must fail first ingest");
            assert_eq!(code, ApiErrorCode::SourceRefsUnverifiable, "{lifecycle}");
            assert!(message.contains("403 Forbidden"), "{lifecycle}: {message}");
        }
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
            jws: "e30..c2ln".to_owned(),
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
            resource_id: arkret_sdk::DirectoryWithdrawResourceId::Realm(
                arkret_sdk::RealmId::new(REALM_ID).unwrap(),
            ),
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
            Some(signer.issuer_core_id.as_str()),
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
            arkret_wire::DomainSeparationId::DIRECTORY_RESOLVE_HANDLE_REQUEST_PROOF_V1.to_owned(),
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
            Some("ak:did_core:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
            DIRECTORY_SERVICE_ID,
            &resolver(),
            now,
        )
        .expect_err("a foreign controller MUST be rejected");
        assert_eq!(code, ApiErrorCode::GovernanceKeyInvalid);
    }
}
