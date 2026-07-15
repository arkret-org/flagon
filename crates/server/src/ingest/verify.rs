//! 5-step verify chain for ingest (spec §8.5).
//!
//! 1. Transport layer — HTTP Message Signature for push, or service binding + TLS for pull. We
//!    surface a hook here; the actual RFC 9421 HTTP signature check lives in
//!    [`crate::middleware::http_sig`] (mounted on the ingest sub-router by
//!    [`crate::routing::directory_router`] via `.hoop(HttpSigMiddleware::new(...))`) so the handler
//!    always sees an already-authenticated transport. TB-1 (this comment block) closed the prior
//!    gap where the middleware was advertised but not actually mounted.
//! 2. Discovery proof — verify `discovery_state.proof.detached_jws` against the resource governance
//!    key resolved via DID document.
//! 3. Directory authorization — `discovery_state.directory_services` contains *this* directory's
//!    service DID.
//! 4. Source-ref sanity — for first ingest, MAY pull at least one anchor from the resource's
//!    Principal Server to confirm `source_refs[0]` is resolvable.
//! 5. Accept policy — local accept_policy (open / allowlist / operator_review) decision.
//!
//! Any failure MUST short-circuit; we never partially accept (§8.5 last line).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use arkret_sdk::identity::{DidResolver, DidWebvhResolver};
use arkret_sdk::jws::verify_jws_ed25519 as sdk_verify_jws_ed25519;
use arkret_sdk::{DID_WEB_MAX_DOCUMENT_BYTES, Did, DidWebResolver, canonical};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;
use url::Url;

use crate::config::{AcceptPolicyKind, AppConfig};
use crate::db::Db;
use crate::did_resolver::{did_method_allowed, did_method_prefix_for_did, did_resolver_chain};
use crate::error::ApiErrorCode;
use crate::ingest::DirectoryResourceKindDb;
use crate::ingest::announce::DirectoryAnnounceIngest;

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
    pub now: DateTime<Utc>,
}

impl<'a> VerifyContext<'a> {
    pub fn new(config: &'a AppConfig, db: &'a Db) -> Self {
        Self {
            config,
            db,
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
            self.config,
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
            verify_first_source_ref_resolves(req, self.config).await?;
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
    config: &AppConfig,
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
        config,
    )
}

pub(crate) fn verify_governance_proof_payload(
    canonical_payload_without_jws: &JsonValue,
    proof: &BTreeMap<String, JsonValue>,
    resource_kind: DirectoryResourceKindDb,
    resource_id: &str,
    expected_controller_did: Option<&str>,
    config: &AppConfig,
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
        config,
    )
}

fn verify_detached_jws_payload(
    canonical_bytes: &[u8],
    proof: &JsonValue,
    resource_kind: DirectoryResourceKindDb,
    resource_id: &str,
    expected_controller_did: Option<&str>,
    config: &AppConfig,
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
    verify_jws_ed25519(canonical_bytes, &jws, &verification_method, config)
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

fn verify_jws_ed25519(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    config: &AppConfig,
) -> Result<(), String> {
    let resolver = did_resolver_chain(
        &config.accepted_did_methods,
        crate::egress::private_networks_allowed(config.development_mode),
    )?;
    let issuer = verification_method
        .split_once('#')
        .map(|(did, _)| did)
        .unwrap_or(verification_method);
    sdk_verify_jws_ed25519(canonical_bytes, jws, verification_method, issuer, &resolver)
        .map_err(|err| err.to_string())
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
    let http = strict_http_client().map_err(|e| {
        (
            ApiErrorCode::InternalError,
            format!("source-ref HTTP client: {e}"),
        )
    })?;
    let endpoint = resolve_principal_server_endpoint(config, &req.principal_server_did, &http)
        .await
        .map_err(|e| {
            (
                ApiErrorCode::SourceRefsUnverifiable,
                format!("principal_server_did did not resolve to events endpoint: {e}"),
            )
        })?;
    let url = endpoint_child(&endpoint, &format!("events/{source_ref}")).map_err(|e| {
        (
            ApiErrorCode::SourceRefsUnverifiable,
            format!("source-ref URL: {e}"),
        )
    })?;
    let target = crate::egress::resolve_url_for_egress(
        &url,
        "source-ref fetch",
        crate::egress::private_networks_allowed(config.development_mode),
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

pub(crate) async fn resolve_principal_server_endpoint(
    config: &AppConfig,
    principal_server_did: &str,
    http: &Client,
) -> anyhow::Result<Url> {
    let did = Did::new(principal_server_did.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid DID `{principal_server_did}`: {e}"))?;
    if !principal_did_method_allowed(config, principal_server_did) {
        anyhow::bail!("DID method is outside TEABAY_ACCEPTED_DID_METHODS");
    }

    let mut doc_url = did_document_url(&did)?;
    let dev_loopback = config.development_mode && is_loopback_url(&doc_url);
    if dev_loopback {
        doc_url
            .set_scheme("http")
            .map_err(|_| anyhow::anyhow!("failed to rewrite loopback DID URL to HTTP"))?;
    } else {
        let resolver = did_resolver_chain(
            &config.accepted_did_methods,
            crate::egress::private_networks_allowed(config.development_mode),
        )
        .map_err(|e| anyhow::anyhow!(e))?;
        resolver
            .resolve_did(&did)
            .map_err(|e| anyhow::anyhow!("DID document did not validate: {e}"))?;
    }

    let document = fetch_did_document_json(http, doc_url.clone(), config.development_mode).await?;
    if document.get("id").and_then(JsonValue::as_str) != Some(principal_server_did) {
        anyhow::bail!("DID document id does not match requested DID");
    }
    let services = document
        .get("service")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| anyhow::anyhow!("DID document has no service array"))?;
    // DID Document order is the owner-controlled priority order for multiple
    // Principal Server services; teabay keeps that deterministic convention.
    let service = services
        .iter()
        .find(|service| service_type_matches(service, "ArkretPrincipalServer"))
        .ok_or_else(|| anyhow::anyhow!("DID document has no ArkretPrincipalServer service"))?;
    let endpoint = service
        .get("serviceEndpoint")
        .and_then(JsonValue::as_str)
        .filter(|endpoint| !endpoint.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("ArkretPrincipalServer serviceEndpoint is missing"))?;
    service_endpoint_url(&doc_url, endpoint, config.development_mode)
}

pub(crate) fn endpoint_child(base: &Url, child: &str) -> anyhow::Result<Url> {
    let mut url = base.clone();
    let base_path = url.path().trim_end_matches('/');
    url.set_path(&format!("{base_path}/{}", child.trim_start_matches('/')));
    Ok(url)
}

pub(crate) fn strict_http_client() -> anyhow::Result<Client> {
    strict_http_client_builder()
        .build()
        .map_err(|e| anyhow::anyhow!("build reqwest client: {e}"))
}

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

async fn fetch_did_document_json(
    _http: &Client,
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
        crate::egress::private_networks_allowed(development_mode),
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

fn service_type_matches(service: &JsonValue, expected: &str) -> bool {
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
        crate::egress::private_networks_allowed(development_mode),
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
