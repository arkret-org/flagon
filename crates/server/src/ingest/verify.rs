//! 5-step verify chain for ingest (spec §8.5).
//!
//! 1. Transport layer — HTTP Message Signature for push. We surface a hook here; the actual RFC
//!    9421 HTTP signature check lives in [`crate::middleware::http_sig`] (mounted on the ingest
//!    sub-router by [`crate::routing::directory_router`] via `.hoop(HttpSigMiddleware::new(...))`)
//!    so the handler always sees an already-authenticated transport. TB-1 (this comment block)
//!    closed the prior gap where the middleware was advertised but not actually mounted.
//! 2. Discovery proof — verify `discovery_state.proof.detached_jws` against the resource governance
//!    key resolved via DID document.
//! 3. Directory authorization — `discovery_state.directory_services` contains *this* directory's
//!    service DID.
//! 4. Source-ref sanity — for first ingest, verifies an anchor from the resource's Principal Server
//!    to confirm `source_refs[0]` is resolvable.
//! 5. Accept policy — local accept_policy (open / allowlist / operator_review) decision.
//!
//! Any failure MUST short-circuit; we never partially accept (§8.5 last line).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use arkret_identity::binding::DidBindingPurpose;
use arkret_identity::document_canonical_digest;
use arkret_sdk::identity::DidWebvhResolver;
use arkret_sdk::{DID_WEB_MAX_DOCUMENT_BYTES, Did, DidWebResolver, canonical};
use arkret_wire::{Hash, TypedTrustDomainId};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;
use url::Url;

use crate::config::{AcceptPolicyKind, AppConfig};
use crate::db::Db;
use crate::did_binding::BindingEvidence;
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
    /// `via_services` to populate from DID document (or fallback to
    /// `principal_server_did`).
    pub via_services: Vec<String>,
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
        // the announce envelope MUST conform to `^did:[a-z0-9]+:[^\s]+$`
        // (lowercase ASCII method, non-empty whitespace-free method-specific
        // id). We push this check through the SDK `Did::new` parser so the
        // teabay directory and the rest of the Arkret stack share one
        // normative parser. Non-conforming inputs short-circuit with a
        // structured rejection BEFORE any signature / accept-policy work,
        // which keeps audit logs clean and rules out removed actor_id /
        // controller DID shapes at the ingest boundary.
        if matches!(
            req.resource_kind,
            DirectoryResourceKindDb::Organization
                | DirectoryResourceKindDb::Actor
                | DirectoryResourceKindDb::Applet
        ) {
            Did::new(req.resource_id.clone()).map_err(|e| {
                (
                    ApiErrorCode::SchemaViolation,
                    format!(
                        "resource_id `{}` does not conform to did syntax \
                         ^did:[a-z0-9]+:[^\\s]+$: {e}",
                        req.resource_id
                    ),
                )
            })?;
        }
        Did::new(req.principal_server_did.clone()).map_err(|e| {
            (
                ApiErrorCode::SchemaViolation,
                format!(
                    "principal_server_did `{}` does not conform to did syntax \
                     ^did:[a-z0-9]+:[^\\s]+$: {e}",
                    req.principal_server_did
                ),
            )
        })?;

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
        verify_discovery_proof(
            &req.discovery_state,
            req.resource_kind,
            &req.resource_id,
            expected_governance_controller.as_deref(),
            self.resolver,
        )?;

        // --- Step 3: directory authorization (this DID listed). ------------
        let listed = directory_services_lists_self(&req.discovery_state, &self.config.service_id);
        if !listed {
            return Err((
                ApiErrorCode::DirectoryNotAuthorized,
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
        let via_services = derive_via_services(&req.discovery_state, &req.principal_server_did);
        let policy_revision = req.policy_revision.clone();

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
        let indexed = indexed_principal_server(self.db, req.resource_kind, &req.resource_id)
            .await
            .map_err(|error| {
                (
                    ApiErrorCode::InternalError,
                    format!("governance controller lookup: {error}"),
                )
            })?;
        let expected = indexed.unwrap_or_else(|| req.principal_server_did.clone());
        if expected != req.principal_server_did {
            return Err((
                ApiErrorCode::GovernanceKeyInvalid,
                format!(
                    "principal_server_did `{}` does not match indexed governance controller `{expected}`",
                    req.principal_server_did
                ),
            ));
        }
        Ok(Some(expected))
    }
}

pub(crate) fn verify_discovery_proof(
    discovery_state: &JsonValue,
    resource_kind: DirectoryResourceKindDb,
    resource_id: &str,
    expected_controller_did: Option<&str>,
    resolver: &SharedDidResolver,
) -> Result<(), (ApiErrorCode, String)> {
    let proof = discovery_state.get("proof").ok_or_else(|| {
        (
            ApiErrorCode::SignatureInvalid,
            "discovery_state.proof is missing".into(),
        )
    })?;
    let canonical = canonical_payload_without_jws(discovery_state, "proof")?;
    verify_detached_jws_payload(
        &canonical,
        proof,
        resource_kind,
        resource_id,
        expected_controller_did,
        resolver,
    )
}

pub(crate) fn verify_governance_proof_payload(
    canonical_payload_without_jws: &JsonValue,
    proof: &BTreeMap<String, JsonValue>,
    resource_kind: DirectoryResourceKindDb,
    resource_id: &str,
    expected_controller_did: Option<&str>,
    resolver: &SharedDidResolver,
) -> Result<(), (ApiErrorCode, String)> {
    let canonical = canonical_json_bytes(canonical_payload_without_jws)
        .map_err(|msg| (ApiErrorCode::SignatureInvalid, msg))?;
    let proof = JsonValue::Object(proof.clone().into_iter().collect());
    verify_detached_jws_payload(
        &canonical,
        &proof,
        resource_kind,
        resource_id,
        expected_controller_did,
        resolver,
    )
}

fn verify_detached_jws_payload(
    canonical_bytes: &[u8],
    proof: &JsonValue,
    resource_kind: DirectoryResourceKindDb,
    resource_id: &str,
    expected_controller_did: Option<&str>,
    resolver: &SharedDidResolver,
) -> Result<(), (ApiErrorCode, String)> {
    let DetachedProof {
        verification_method,
        jws,
    } = detached_proof(proof)?;
    enforce_governance_method_binding(
        resource_kind,
        resource_id,
        expected_controller_did,
        &verification_method,
    )?;
    verify_jws_ed25519(canonical_bytes, &jws, &verification_method, resolver)
        .map_err(|msg| (ApiErrorCode::SignatureInvalid, msg))
}

struct DetachedProof {
    verification_method: String,
    jws: String,
}

fn detached_proof(proof: &JsonValue) -> Result<DetachedProof, (ApiErrorCode, String)> {
    let kind = proof
        .get("kind")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| (ApiErrorCode::SignatureInvalid, "proof.kind missing".into()))?;
    if kind != "detached_jws" {
        return Err((
            ApiErrorCode::SignatureInvalid,
            format!("unsupported proof.kind {kind}; expected detached_jws"),
        ));
    }
    let verification_method = proof
        .get("verification_method")
        .and_then(JsonValue::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            (
                ApiErrorCode::SignatureInvalid,
                "proof.verification_method missing".into(),
            )
        })?
        .to_owned();
    let jws = proof
        .get("jws")
        .and_then(JsonValue::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| (ApiErrorCode::SignatureInvalid, "proof.jws missing".into()))?
        .to_owned();
    Ok(DetachedProof {
        verification_method,
        jws,
    })
}

fn canonical_payload_without_jws(
    payload: &JsonValue,
    proof_key: &str,
) -> Result<Vec<u8>, (ApiErrorCode, String)> {
    let mut unsigned = payload.clone();
    let proof = unsigned
        .get_mut(proof_key)
        .and_then(JsonValue::as_object_mut)
        .ok_or_else(|| {
            (
                ApiErrorCode::SignatureInvalid,
                format!("{proof_key} proof object missing"),
            )
        })?;
    if proof.remove("jws").is_none() {
        return Err((ApiErrorCode::SignatureInvalid, "proof.jws missing".into()));
    }
    canonical_json_bytes(&unsigned).map_err(|msg| (ApiErrorCode::SignatureInvalid, msg))
}

/// Arkret canonical JSON bytes via the SDK's `arkret_sdk::canonical`
/// implementation (UTF-16 key ordering, integer-only number profile).
///
/// This replaces a previously hand-written serializer that sorted object
/// keys by byte order (`sort_unstable()`) — divergent from the SDK and
/// every other Arkret service. Errors are flattened to `String` so the
/// existing `(ApiErrorCode::SignatureInvalid, _)` call sites are unchanged.
fn canonical_json_bytes(value: &JsonValue) -> Result<Vec<u8>, String> {
    canonical::canonical_json_bytes(value).map_err(|err| err.to_string())
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
    let issuer = verification_method
        .split_once('#')
        .map(|(did, _)| did)
        .unwrap_or(verification_method);
    resolver
        .verify_detached_jws_with_authority(
            canonical_bytes,
            jws,
            verification_method,
            issuer,
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

pub(crate) async fn indexed_principal_server(
    db: &Db,
    resource_kind: DirectoryResourceKindDb,
    resource_id: &str,
) -> anyhow::Result<Option<String>> {
    use crate::schema::directory_resources::dsl;
    let mut conn = db.get().await?;
    let row = dsl::directory_resources
        .filter(dsl::resource_kind.eq(resource_kind))
        .filter(dsl::resource_id.eq(resource_id))
        .select(dsl::principal_server_did)
        .first::<String>(&mut *conn)
        .await
        .optional()?;
    Ok(row)
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
    // DID-P0-C02: this function used to build TWO reqwest clients. The first
    // existed only to be handed to `resolve_principal_server_endpoint`, which
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
    let accepted = resolve_principal_server_endpoint(
        config,
        resolver,
        &req.principal_server_did,
        source_ref.as_str(),
    )
    .await
    .map_err(|e| {
        (
            ApiErrorCode::SourceRefsUnverifiable,
            format!("principal_server_did did not resolve to events endpoint: {e}"),
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
        "accepted principal server endpoint"
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

/// An accepted principal-server service endpoint.
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
/// | `service_kind` | the binding's `evidence_digest` (`BindingEvidence::PrincipalServiceEndpoint`) |
/// | `endpoint_digest` | the binding's `evidence_digest` too — `DidBindingDirectory::service_endpoint_digest` runs inside the SDK evidence closure on the resolved document — *and* recomputed here from the pinned document every time |
/// | `source_ref` | supplied per request and folded into `acceptance_digest` |
///
/// `endpoint_digest` used to be teabay-side only: the SDK's eager
/// `BindingAcceptance` demanded a finished evidence digest *before* resolution,
/// so nothing the document published could enter the evidence. The deferred
/// `resolve_and_verify_binding_with_evidence` closes that, and the two digests
/// answer different questions on purpose — the evidence one commits to the
/// endpoint set **as published** (raw, document order), the one below to the
/// single **resolved absolute URL** this request will actually fetch from.
///
/// The endpoint is **always re-derived from the pinned DID document**, never
/// read out of a URL cache: on a store hit the `service` array comes from
/// `AcceptedDidBinding::document()`, whose canonical digest the binding
/// recorded. A host that later serves a different document cannot change the
/// endpoint teabay uses without the binding being invalidated first.
///
/// `source_ref` is bound per use rather than per acceptance on purpose: one
/// principal server anchors many resources, so folding a single source ref into
/// the *stored* acceptance would either pin the acceptance to the first
/// announce that established it or defeat reuse entirely. What matters for the
/// security property is that a source ref can only ever be fetched from an
/// endpoint that is itself bound to a verified document — which is exactly what
/// `acceptance_digest` states.
#[derive(Debug, Clone)]
pub(crate) struct AcceptedServiceEndpoint {
    pub service_did: Did,
    pub service_kind: &'static str,
    pub trust_domain: TypedTrustDomainId,
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
pub(crate) const ARKRET_PRINCIPAL_SERVER: &str = "ArkretPrincipalServer";

/// Resolve `principal_server_did` to its `ArkretPrincipalServer` service
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
/// | SSRF / egress control on the fetch | `resolve_url_for_egress` inside the raw fetch | the shared chain's client: `https_only` + `egress::ValidatingDnsResolver`, both frozen from the startup config |
/// | `document.id == principal_server_did` | compared on the raw JSON here | still compared here, now against the resolved document |
/// | `service[].type == "ArkretPrincipalServer"` | raw JSON | `DidDocument::raw_properties["service"]`, which preserves the wire document verbatim |
/// | relative `serviceEndpoint` resolution | `service_endpoint_url` | unchanged |
///
/// On top of that merge, DID-P0-C02 adds the acceptance: the resolved document
/// is filed as a `DidBindingPurpose::PrincipalServiceEndpoint` binding, so a
/// second first-ingest naming the same principal server performs **zero**
/// network calls.
///
/// The development-mode loopback branch is untouched in meaning: a loopback
/// `did:web` host cannot be resolved by a chain that demands public HTTPS, so
/// that branch still deliberately bypasses the resolver and performs its one
/// raw fetch, then runs the same `id` / `service` checks on that JSON. It
/// deliberately does **not** write a binding — a development bypass must not
/// seed trust that outlives the request.
pub(crate) async fn resolve_principal_server_endpoint(
    config: &AppConfig,
    resolver: &SharedDidResolver,
    principal_server_did: &str,
    source_ref: &str,
) -> anyhow::Result<AcceptedServiceEndpoint> {
    let did = Did::new(principal_server_did.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid DID `{principal_server_did}`: {e}"))?;
    if !principal_did_method_allowed(config, principal_server_did) {
        anyhow::bail!("DID method is outside TEABAY_ACCEPTED_DID_METHODS");
    }

    let mut doc_url = did_document_url(&did)?;
    let bindings = resolver.bindings();
    if config.development_mode && is_loopback_url(&doc_url) {
        doc_url
            .set_scheme("http")
            .map_err(|_| anyhow::anyhow!("failed to rewrite loopback DID URL to HTTP"))?;
        let document = fetch_did_document_json(doc_url.clone(), config.development_mode).await?;
        if document.get("id").and_then(JsonValue::as_str) != Some(principal_server_did) {
            anyhow::bail!("DID document id does not match requested DID");
        }
        let services = document
            .get("service")
            .and_then(JsonValue::as_array)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("DID document has no service array"))?;
        let endpoint = principal_server_endpoint(&services, &doc_url, config.development_mode)?;
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
        .accepted_or_resolved_with_evidence(
            &did,
            DidBindingPurpose::PrincipalServiceEndpoint,
            None,
            BindingEvidence::PrincipalServiceEndpoint {
                service_kind: ARKRET_PRINCIPAL_SERVER,
            },
            now,
        )
        .map_err(|e| anyhow::anyhow!("DID document did not validate: {e}"))?;
    if accepted.document().id.as_str() != principal_server_did {
        anyhow::bail!("DID document id does not match requested DID");
    }

    let services = accepted
        .document()
        .raw_properties
        .get("service")
        .and_then(JsonValue::as_array)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("DID document has no service array"))?;
    let endpoint = principal_server_endpoint(&services, &doc_url, config.development_mode)?;
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

/// Pick the `ArkretPrincipalServer` endpoint out of a wire `service` array.
///
/// DID Document order is the owner-controlled priority order for multiple
/// Principal Server services; teabay keeps that deterministic convention.
fn principal_server_endpoint(
    services: &[JsonValue],
    doc_url: &Url,
    development_mode: bool,
) -> anyhow::Result<Url> {
    let service = services
        .iter()
        .find(|service| service_kind_matches(service, ARKRET_PRINCIPAL_SERVER))
        .ok_or_else(|| anyhow::anyhow!("DID document has no ArkretPrincipalServer service"))?;
    let endpoint = service
        .get("serviceEndpoint")
        .and_then(JsonValue::as_str)
        .filter(|endpoint| !endpoint.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("ArkretPrincipalServer serviceEndpoint is missing"))?;
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
    trust_domain: TypedTrustDomainId,
    service_did: Did,
    endpoint: Url,
    document_digest: Hash,
    source_ref: &str,
) -> anyhow::Result<AcceptedServiceEndpoint> {
    let endpoint_digest = json_digest(&serde_json::json!({
        "kind": "teabay.accepted_service_endpoint.v1",
        "service_did": service_did.as_str(),
        "service_kind": ARKRET_PRINCIPAL_SERVER,
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
        service_kind: ARKRET_PRINCIPAL_SERVER,
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
        other => anyhow::bail!("unsupported Principal Server DID method did:{other}"),
    };
    Url::parse(&url).map_err(|e| anyhow::anyhow!("invalid DID document URL `{url}`: {e}"))
}

/// Raw DID Document fetch. Used **only** by the development-mode loopback
/// branch of [`resolve_principal_server_endpoint`]; the production branch goes
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

fn directory_services_lists_self(discovery_state: &JsonValue, self_did: &str) -> bool {
    discovery_state
        .get("directory_services")
        .and_then(JsonValue::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(JsonValue::as_str)
                .any(|d| d.eq_ignore_ascii_case(self_did))
        })
        .unwrap_or(false)
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

fn derive_via_services(discovery_state: &JsonValue, principal_server_did: &str) -> Vec<String> {
    if let Some(arr) = discovery_state
        .get("via_services")
        .and_then(JsonValue::as_array)
    {
        let mut services = Vec::new();
        for value in arr.iter().filter_map(JsonValue::as_str) {
            let did = value.trim();
            if did.is_empty()
                || Did::new(did.to_owned()).is_err()
                || services.iter().any(|existing| existing == did)
            {
                continue;
            }
            services.push(did.to_owned());
            if services.len() == MAX_VIA_SERVICES {
                break;
            }
        }
        if !services.is_empty() {
            return services;
        }
    }
    vec![principal_server_did.to_string()]
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
    use serde_json::json;

    use super::*;

    #[test]
    fn derive_via_services_dedupes_valid_dids_and_caps_count() {
        let discovery_state = json!({
            "via_services": [
                " did:web:primary.example ",
                "not-a-did",
                "did:web:primary.example",
                "did:web:mirror1.example",
                "did:web:mirror2.example",
                "did:web:mirror3.example",
                "did:web:mirror4.example",
                "did:web:mirror5.example",
                "did:web:mirror6.example",
                "did:web:mirror7.example",
                "did:web:mirror8.example"
            ]
        });

        let derived = derive_via_services(&discovery_state, "did:web:fallback.example");

        assert_eq!(derived.len(), MAX_VIA_SERVICES);
        assert_eq!(derived[0], "did:web:primary.example");
        assert!(!derived.iter().any(|did| did == "not-a-did"));
        assert_eq!(
            derived
                .iter()
                .filter(|did| did.as_str() == "did:web:primary.example")
                .count(),
            1
        );
    }

    #[test]
    fn derive_via_services_falls_back_when_array_has_no_valid_dids() {
        let discovery_state = json!({
            "via_services": ["", "not-a-did", 7]
        });

        assert_eq!(
            derive_via_services(&discovery_state, "did:web:fallback.example"),
            vec!["did:web:fallback.example".to_owned()]
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
}
