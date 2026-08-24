//! Handle resolution. Spec §9 (`ak.find.directory.read.resolve_handle`).
//!
//! Spec sync 0a5ab85 / governance/join-policy §5.1.3:
//! `ak.find.directory.read.resolve_handle` MUST gate `intent=member_add | invite`
//! requests on the target **Realm**'s `delivery_binding_policy`
//! (`allowed_recipient_services`, `allowed_binding_sources`) and on the
//! Realm's audience-binding list. Unauthorized requesters MUST NOT receive
//! the underlying subject / service DID — they collapse to `not_found` with
//! the same response shape and latency tier as a genuine miss (§10).
//!
//! §9.0.1: `proofs[]` carries the per-object-family requester proof bound to
//! `ak.directory_resolve_handle_request_proof.v1`. A signature minted under any
//! other directory request family's context cannot verify here. Verification
//! lives in [`crate::query::requester_proof`] and its failure collapses to the
//! same blinded `not_found` inside the latency budget.

use arkret_sdk::{
    DidCoreId, DirectoryHandleResolutionOutcome, DirectoryResolveHandleRequestBody, Handle,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};

use crate::error::ApiErrorCode;
use crate::filter::discoverers::{
    VerifiedRestrictedClaims, matches_allowed_discoverers, verify_restricted_claim_presentations,
};
use crate::filter::enumeration::{LatencyBudget, pad_to_budget_observed};
use crate::filter::result::ResultEnvelope;
use crate::ingest::{DirectoryResourceKindDb, DiscoverabilityDb};
use crate::query::rate_limit::{apply_resolve_response_jitter, enforce_resolve_rate_limit};
use crate::state::AppState;

#[derive(Debug, Clone)]
struct ResolveHandleRequestView {
    pub handle: String,
    pub expected_principal_id: Option<String>,
    pub proof_challenge: Option<String>,
    pub claim_presentations: Vec<arkret_sdk::DirectoryRestrictedClaimPresentation>,
    /// Why the handle is being resolved. Spec 0a5ab85:
    /// gates audience binding on the response claim and selects the
    /// Realm `delivery_binding_policy` (`allowed_recipient_services`)
    /// filter when `intent ∈ {member_add, invite}`.
    pub intent: Option<String>,
    /// DID or service DID of the requester. Used to scope audience-bearing
    /// claims so that the verifier can enforce `audience == self` and to
    /// authorize disclosure of Realm-restricted bindings.
    pub requester: Option<String>,
    /// Explicit audience the verifier expects on the claim (typically a
    /// target Realm DID or inviter service DID).
    pub audience: Option<String>,
    /// Target Realm DID for `intent=member_add | invite`. When present we
    /// load the Realm `delivery_binding_policy` baseline and filter
    /// candidate bindings against `allowed_recipient_services`.
    pub realm_id: Option<String>,
}

impl From<DirectoryResolveHandleRequestBody> for ResolveHandleRequestView {
    fn from(body: DirectoryResolveHandleRequestBody) -> Self {
        Self {
            handle: body.handle,
            expected_principal_id: body
                .expected_principal_id
                .map(|did| did.as_str().to_owned()),
            proof_challenge: body.proof_challenge,
            claim_presentations: body.claim_presentations,
            intent: body.intent.map(|intent| intent.to_string()),
            requester: body.requester.map(|did| did.as_str().to_owned()),
            audience: body.audience,
            realm_id: body.realm_id.map(|realm_id| realm_id.as_str().to_owned()),
        }
    }
}

/// Prepare a product-private localpart input with the shared RFC 8265-derived
/// human-identifier profile.
pub(crate) fn prepare_handle_localpart_input(handle: &str) -> Result<String, String> {
    let localpart = extract_localpart(handle);
    arkret_sdk::prepare_handle_localpart(localpart)
        .map_err(|_| "handle localpart violates the human-identifier profile".to_owned())
}

fn extract_localpart(handle: &str) -> &str {
    extract_localpart_public(handle)
}

/// Accept either a bare localpart or the canonical `<localpart>:<domain>`
/// handle form. Empty localparts fall through to the SDK helper, which rejects
/// them.
fn extract_localpart_public(handle: &str) -> &str {
    // A canonical localpart forbids `:`, so the separator is unambiguous.
    if let Some((local, _)) = handle.split_once(':') {
        return local;
    }
    handle
}

/// Product-private handle probe for teabay's resolver/index view:
///
/// ```text
/// GET /_teabay/handle/probe?localpart=<localpart>&domain=<domain>
/// ```
///
/// We resolve against the directory's indexed Handle rows and return
/// the same `ResultEnvelope` shape that the POST `resolve-handle` face
/// emits. This deliberately lives outside `/.well-known/arkret/handle`:
/// the spec reserves that well-known path for signed issuer claims, while
/// teabay is a resolver/index and cannot answer as the handle issuer.
///
/// Wire-level homograph normalization runs on the localpart before any DB
/// lookup so malformed localparts fail before any directory read rather
/// than the privacy-preserving `404 not_found` returned for genuine misses.
///
/// The Host header (or the `?domain=<domain>` override) is concatenated
/// with the localpart to form the directory's stored `resource_id` —
/// teabay indexes handles in the canonical `<localpart>:<domain>` form. The
/// domain comes from `?domain=` or the Host header.
#[handler]
pub async fn private_handle_probe(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let _query_timer = state.metrics().query_timer("handle-probe");

    let localpart = req.queries().get("localpart").cloned().unwrap_or_default();
    if localpart.is_empty() {
        ApiErrorCode::ParamMissing.render(res, "localpart query parameter is required");
        return;
    }
    let localpart = match prepare_handle_localpart_input(&localpart) {
        Ok(localpart) => localpart,
        Err(reason) => {
            ApiErrorCode::ParamInvalid.render(res, reason);
            return;
        }
    };

    // Reconstruct the canonical indexed `resource_id`. Order of preference:
    //   1. explicit `?domain=` query parameter (operator probe shape)
    //   2. Host header (cross-domain well-known fetch)
    let domain = req
        .queries()
        .get("domain")
        .cloned()
        .or_else(|| {
            req.headers()
                .get(salvo::http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(':').next().unwrap_or(v).to_owned())
        })
        .unwrap_or_default();
    if domain.is_empty() {
        ApiErrorCode::ParamMissing.render(res, "domain query parameter or Host header is required");
        return;
    }
    let handle = match Handle::prepare(&format!("{localpart}:{domain}")) {
        Ok(handle) => handle.canonical().to_owned(),
        Err(error) => {
            ApiErrorCode::ParamInvalid.render(res, format!("invalid handle domain: {error}"));
            return;
        }
    };

    if !enforce_resolve_rate_limit(req, res, &state, &handle) {
        return;
    }

    let body = ResolveHandleRequestView {
        handle: handle.clone(),
        expected_principal_id: None,
        proof_challenge: None,
        claim_presentations: Vec::new(),
        intent: None,
        requester: None,
        audience: None,
        realm_id: None,
    };

    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    let requester_ip = req.remote_addr().to_string();
    let mut ip_hasher = Sha256::new();
    ip_hasher.update(requester_ip.as_bytes());
    let requester_ip_hash = URL_SAFE_NO_PAD.encode(ip_hasher.finalize());
    let privacy_key = format!("handle_probe={handle};iph={requester_ip_hash}");

    let outcome = pad_to_budget_observed(
        budget,
        "org.arkret.teabay.handle_probe",
        &privacy_key,
        |target| state.metrics().record_anti_enum_pad("handle-probe", target),
        async {
            let row = match load_handle_row(&state, &handle).await {
                Ok(Some(row)) => row,
                _ => return ResolveOutcome::NotFound,
            };
            evaluate_handle_disclosure(row, &body, &VerifiedRestrictedClaims::default(), None)
        },
    )
    .await;

    apply_resolve_response_jitter().await;

    match outcome {
        ResolveOutcome::Found(envelope) => match handle_resolution_from_envelope(envelope) {
            Ok(outcome) => res.render(Json(outcome)),
            Err(message) => ApiErrorCode::InternalError.render(res, message),
        },
        ResolveOutcome::NotFound => ApiErrorCode::NotFound.render(res, "not found"),
    }
}

#[handler]
pub async fn resolve_handle(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let _query_timer = state.metrics().query_timer("resolve-handle");
    let sdk_body: DirectoryResolveHandleRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::JsonInvalid.render(res, format!("malformed body: {error}"));
            return;
        }
    };
    // §9.0.1 requester proof. The proof binds the whole unsigned request body,
    // so it is verified against the SDK wire type before the internal view
    // drops anything.
    let proof_count = sdk_body.proofs.len();
    let requester_proof = crate::query::requester_proof::verify_requester_proofs(
        &sdk_body,
        state.config().service_id.as_str(),
        state.did_bindings(),
        Utc::now(),
    );
    let body = ResolveHandleRequestView::from(sdk_body);
    if body.handle.is_empty() {
        ApiErrorCode::ParamMissing.render(res, "handle is required");
        return;
    }
    if let Err(error) = Handle::parse(&body.handle) {
        ApiErrorCode::ParamInvalid.render(res, format!("handle is not canonical: {error}"));
        return;
    }
    if !enforce_resolve_rate_limit(req, res, &state, &body.handle) {
        return;
    }
    // Defence in depth: a bare `ak:circle:` typed id smuggled into the
    // `handle` field is also collapsed to `not_found` rather than
    // routed into the DB lookup.
    if crate::filter::selector::looks_like_circle_id(&body.handle) {
        apply_resolve_response_jitter().await;
        ApiErrorCode::NotFound.render(res, "not found");
        return;
    }
    let verified_claims = verified_restricted_claims_for_handle_query(&state, &body);

    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    // Privacy key bundles every input that affects the not_found / found /
    // unauthorized branch so the deterministic latency tier is stable
    // per-request but does not leak the branch back to the caller. C.10.9
    // — hash the requester IP into the privacy key so the same handle
    // + intent + requester from two different IPs lands on independent
    // latency tiers (an attacker can no longer share probes across
    // hosts to disambiguate a slow miss from a slow hit).
    let requester_ip = req.remote_addr().to_string();
    let mut ip_hasher = Sha256::new();
    ip_hasher.update(requester_ip.as_bytes());
    let requester_ip_hash = URL_SAFE_NO_PAD.encode(ip_hasher.finalize());
    let privacy_key = format!(
        "handle={};expected={};intent={};realm={};req={};aud={};claims={};proofs={};iph={}",
        body.handle,
        body.expected_principal_id.as_deref().unwrap_or_default(),
        body.intent.as_deref().unwrap_or_default(),
        body.realm_id.as_deref().unwrap_or_default(),
        body.requester.as_deref().unwrap_or_default(),
        body.audience.as_deref().unwrap_or_default(),
        body.claim_presentations.len(),
        proof_count,
        requester_ip_hash,
    );

    let outcome = pad_to_budget_observed(
        budget,
        arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_HANDLE,
        &privacy_key,
        |target| {
            state
                .metrics()
                .record_anti_enum_pad("resolve-handle", target)
        },
        async {
            // Collapsed inside the latency budget so a §9.0.1 proof failure is
            // timing-equivalent to a genuine miss (§9.2) and never reveals a
            // proof-layer reason.
            if let Err(reason) = &requester_proof {
                tracing::debug!(%reason, "resolve_handle requester proof rejected");
                return ResolveOutcome::NotFound;
            }
            let row = match load_handle_row(&state, &body.handle).await {
                Ok(row) => row,
                Err(_) => return ResolveOutcome::NotFound,
            };
            let row = match row {
                Some(row) => row,
                None => return ResolveOutcome::NotFound,
            };

            let policy = match member_add_policy_for(&state, &body).await {
                Ok(policy) => policy,
                Err(_) => return ResolveOutcome::NotFound,
            };

            evaluate_handle_disclosure(row, &body, &verified_claims, policy.as_ref())
        },
    )
    .await;

    // P5 — stochastic anti-enumeration jitter on resolve responses.
    apply_resolve_response_jitter().await;

    match outcome {
        ResolveOutcome::Found(envelope) => {
            // METRICS-TBY-1 — directory query outcome counter.
            state.metrics().record_query_outcome("resolve-handle", "ok");
            match handle_resolution_from_envelope(envelope) {
                Ok(outcome) => res.render(Json(outcome)),
                Err(message) => ApiErrorCode::InternalError.render(res, message),
            }
        }
        // `not_found` covers genuine miss, unauthorized requester, and "all
        // candidates filtered out" — these MUST be indistinguishable on the
        // wire so the directory does not leak the existence of the handle
        // or the recipient service identity.
        ResolveOutcome::NotFound => {
            state
                .metrics()
                .record_query_outcome("resolve-handle", "not_found");
            ApiErrorCode::NotFound.render(res, "not found")
        }
    }
}

fn verified_restricted_claims_for_handle_query(
    state: &AppState,
    body: &ResolveHandleRequestView,
) -> VerifiedRestrictedClaims {
    verify_restricted_claim_presentations(
        &body.claim_presentations,
        body.requester.as_deref(),
        body.proof_challenge.as_deref(),
        state.config().service_id.as_str(),
        state.did_bindings(),
    )
    .unwrap_or_default()
}

/// Result of running the policy filter against a stored handle row.
#[derive(Debug)]
enum ResolveOutcome {
    Found(ResultEnvelope),
    NotFound,
}

// SAFETY: alsoKnownAs is holder-side reverse endorsement only — not used here for routing.
// Spec sync 37ce729 (B-E) — identity-handles §4.1/§6.0: a Directory MUST NOT
// treat `alsoKnownAs` as a mention index, primary key, or delivery routing
// field. `HandleRow.resource_id` is the canonical handle DID; lookups go
// through `resource_id` only, never through any `alsoKnownAs` claim cached
// in `public_projection`.
#[derive(Debug, Queryable, Clone)]
struct HandleRow {
    resource_id: String,
    public_projection: JsonValue,
    discoverability: DiscoverabilityDb,
    as_of: DateTime<Utc>,
    source_refs: Vec<String>,
    policy_revision: String,
    stale: bool,
    divergent: bool,
    via_services: Vec<String>,
    expires_at: DateTime<Utc>,
}

async fn load_handle_row(state: &AppState, handle: &str) -> anyhow::Result<Option<HandleRow>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get().await?;
    let row: Option<HandleRow> = r::directory_resources
        .filter(r::resource_kind.eq(DirectoryResourceKindDb::Handle))
        .filter(r::resource_id.eq(handle))
        // Freshness worker flips `stale=true` once `expires_at` plus the
        // configured revalidation grace has elapsed; stale rows MUST NOT
        // surface through the resolve face.
        .filter(r::stale.eq(false))
        .select((
            r::resource_id,
            r::public_projection,
            r::discoverability,
            r::as_of,
            r::source_refs,
            r::policy_revision,
            r::stale,
            r::divergent,
            r::via_services,
            r::expires_at,
        ))
        .first(&mut *conn)
        .await
        .optional()?;
    match row {
        Some(row) if row.discoverability.is_directory_visible() => Ok(Some(row)),
        _ => Ok(None),
    }
}

// ---- Realm delivery-binding policy --------------------------------------

/// Baseline projection of a Realm's `delivery_binding_policy` as cached in
/// the directory's `public_projection`. Mirrors the schema in
/// governance/join-policy.md §5.1.3.
#[derive(Debug, Clone, Default)]
pub(crate) struct RealmDeliveryBindingPolicy {
    /// `allowed_recipient_services`: closed set of recipient principal-server
    /// DIDs that may appear in a Realm-bound delivery_binding. Empty rejects
    /// every recipient service; the exact singleton `["*"]` explicitly
    /// removes only this allow-list restriction.
    pub allowed_recipient_services: Vec<String>,
    /// `allowed_binding_sources`: optional sub-filter on the binding_source
    /// enum. Empty = caller does not enforce a binding_source filter here.
    pub allowed_binding_sources: Vec<String>,
    /// Trusted audience DIDs (Realm + delegated service DIDs) authorized to
    /// invoke `intent=member_add | invite`. Empty = treat the Realm's
    /// `allowed_discoverers` list as the audience-binding source (§9
    /// fallback so existing fixtures keep working).
    pub trusted_audiences: Vec<String>,
    /// Raw `public_projection` so we can fall back on `allowed_discoverers`
    /// without a second DB round-trip.
    pub raw_projection: JsonValue,
}

async fn member_add_policy_for(
    state: &AppState,
    body: &ResolveHandleRequestView,
) -> anyhow::Result<Option<RealmDeliveryBindingPolicy>> {
    if !is_member_add_intent(body.intent.as_deref()) {
        return Ok(None);
    }
    let Some(realm_id) = body.realm_id.as_deref().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    load_realm_policy(state, realm_id).await.map(Some)
}

fn is_member_add_intent(intent: Option<&str>) -> bool {
    matches!(intent, Some("member_add") | Some("invite"))
}

async fn load_realm_policy(
    state: &AppState,
    realm_id: &str,
) -> anyhow::Result<RealmDeliveryBindingPolicy> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get().await?;
    let projection: Option<(JsonValue, DiscoverabilityDb)> = r::directory_resources
        .filter(r::resource_kind.eq(DirectoryResourceKindDb::Realm))
        .filter(r::resource_id.eq(realm_id))
        .select((r::public_projection, r::discoverability))
        .first(&mut *conn)
        .await
        .optional()?;
    let Some((projection, discoverability)) = projection else {
        return Ok(RealmDeliveryBindingPolicy::default());
    };
    if !discoverability.is_directory_visible() {
        // Hidden / withdrawn Realm — collapse to default-deny policy.
        return Ok(RealmDeliveryBindingPolicy::default());
    }
    Ok(RealmDeliveryBindingPolicy::from_projection(projection))
}

impl RealmDeliveryBindingPolicy {
    /// Extract the `delivery_binding_policy` baseline from a Realm's
    /// `public_projection`.
    pub(crate) fn from_projection(projection: JsonValue) -> Self {
        let nested = projection
            .get("delivery_binding_policy")
            .or_else(|| projection.pointer("/payload/delivery_binding_policy"));
        let allowed_recipient_services =
            string_array_at(nested.and_then(|v| v.get("allowed_recipient_services")));
        let allowed_binding_sources =
            string_array_at(nested.and_then(|v| v.get("allowed_binding_sources")));
        let trusted_audiences = string_array_at(nested.and_then(|v| v.get("trusted_audiences")));
        Self {
            allowed_recipient_services,
            allowed_binding_sources,
            trusted_audiences,
            raw_projection: projection,
        }
    }

    /// True iff the requester is in the audience-binding allow-list, either
    /// via `trusted_audiences` (preferred) or `allowed_discoverers`
    /// fallback shared with `resolve_realm`.
    fn audience_authorized(
        &self,
        requester: Option<&str>,
        verified_claims: &VerifiedRestrictedClaims,
    ) -> bool {
        if self.trusted_audiences.is_empty()
            && !crate::filter::discoverers::has_allowed_discoverers(&self.raw_projection)
        {
            // No audience constraint declared — fall through to the default
            // discoverability gate the row itself carries.
            return true;
        }
        if let Some(requester) = requester
            && self.trusted_audiences.iter().any(|aud| aud == requester)
        {
            return true;
        }
        // Reuse the `allowed_discoverers` shape when the Realm does not
        // declare explicit trusted audiences.
        crate::filter::discoverers::matches_allowed_discoverers(
            &self.raw_projection,
            requester,
            verified_claims,
        )
    }
}

fn string_array_at(value: Option<&JsonValue>) -> Vec<String> {
    value
        .and_then(JsonValue::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(JsonValue::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

// ---- Disclosure decision -------------------------------------------------

/// Pure decision over `(row, request, policy)`. Extracted so unit tests can
/// exercise the policy without a Postgres dependency.
fn evaluate_handle_disclosure(
    row: HandleRow,
    body: &ResolveHandleRequestView,
    verified_claims: &VerifiedRestrictedClaims,
    policy: Option<&RealmDeliveryBindingPolicy>,
) -> ResolveOutcome {
    if body
        .expected_principal_id
        .as_deref()
        .is_some_and(|expected| {
            row.public_projection.get("did").and_then(JsonValue::as_str) != Some(expected)
        })
    {
        return ResolveOutcome::NotFound;
    }

    let audience = body
        .audience
        .clone()
        .or_else(|| body.requester.clone())
        .or_else(|| body.realm_id.clone());

    // Member-add path: audience-bind on the Realm, filter candidate bindings.
    if let Some(policy) = policy {
        if !policy.audience_authorized(body.requester.as_deref(), verified_claims) {
            // Unauthorized requester: collapse to not_found so the
            // directory does not disclose subject_id / member_delivery_binding.
            return ResolveOutcome::NotFound;
        }
        let filtered = filter_projection_against_policy(row.public_projection.clone(), policy);
        let Some(projection) = filtered else {
            // The member_delivery_binding was pruned — same not_found
            // shape so the requester cannot enumerate the Realm's policy.
            return ResolveOutcome::NotFound;
        };
        let envelope = envelope_from_projection(
            projection,
            row.resource_id,
            row.discoverability,
            row.as_of,
            row.source_refs,
            row.policy_revision,
            row.stale,
            row.divergent,
            row.via_services,
            row.expires_at,
            audience,
        );
        return ResolveOutcome::Found(envelope);
    }

    if matches!(row.discoverability, DiscoverabilityDb::Restricted)
        && !matches_allowed_discoverers(
            &row.public_projection,
            body.requester.as_deref(),
            verified_claims,
        )
    {
        return ResolveOutcome::NotFound;
    }
    if matches!(
        row.discoverability,
        DiscoverabilityDb::InviteOnly | DiscoverabilityDb::Secret
    ) {
        return ResolveOutcome::NotFound;
    }

    // Non-member-add path.
    let envelope = envelope_from_projection(
        row.public_projection,
        row.resource_id,
        row.discoverability,
        row.as_of,
        row.source_refs,
        row.policy_revision,
        row.stale,
        row.divergent,
        row.via_services,
        row.expires_at,
        audience,
    );
    ResolveOutcome::Found(envelope)
}

/// Apply Realm `allowed_recipient_services` (and, when declared,
/// `allowed_binding_sources`) to the handle's public projection. Returns
/// `None` when the member_delivery_binding was pruned — signaling the resolver
/// should emit `not_found` rather than disclose the bare subject_id.
fn filter_projection_against_policy(
    mut projection: JsonValue,
    policy: &RealmDeliveryBindingPolicy,
) -> Option<JsonValue> {
    let allow_recipient = &policy.allowed_recipient_services;
    let allow_sources = &policy.allowed_binding_sources;
    let unrestricted_recipient = matches!(allow_recipient.as_slice(), [value] if value == "*");
    let unrestricted_source = allow_sources.is_empty();

    // Track whether the projection ever declared a binding-candidate field
    // BEFORE any pruning. If it did and we drop them all, the resolver MUST
    // emit `not_found` rather than a stripped envelope so the requester
    // cannot tell whether the handle exists.
    let had_member_binding = projection.get("member_delivery_binding").is_some();
    let had_any_candidate_field = had_member_binding;

    let mut kept_any_candidate = false;

    // `member_delivery_binding` (member-delivery-binding-candidate §3.7).
    if had_member_binding {
        let binding_ok = projection
            .get("member_delivery_binding")
            .and_then(JsonValue::as_object)
            .map(|hint| binding_passes(hint, policy, unrestricted_recipient, unrestricted_source))
            .unwrap_or(false);
        if binding_ok {
            kept_any_candidate = true;
        } else if let Some(obj) = projection.as_object_mut() {
            obj.remove("member_delivery_binding");
        }
    }

    if had_any_candidate_field && !kept_any_candidate {
        return None;
    }
    Some(projection)
}

fn binding_passes(
    obj: &serde_json::Map<String, JsonValue>,
    policy: &RealmDeliveryBindingPolicy,
    unrestricted_recipient: bool,
    unrestricted_source: bool,
) -> bool {
    let recipient_ok = match obj.get("recipient_service_id").and_then(JsonValue::as_str) {
        // Recipient routing policy binds the stable service core identity.
        // A full DID or URL in this business field is dropped as if absent.
        Some(service_id) => {
            is_service_core_id(service_id) && {
                unrestricted_recipient
                    || policy
                        .allowed_recipient_services
                        .iter()
                        .any(|allowed| allowed == service_id)
            }
        }
        None => false,
    };
    let source_ok = match obj.get("binding_source").and_then(JsonValue::as_str) {
        Some(src) => unrestricted_source || policy.allowed_binding_sources.iter().any(|a| a == src),
        None => unrestricted_source, /* No binding_source declared — only allowed when policy is
                                      * open. */
    };
    recipient_ok && source_ok
}

fn is_service_core_id(service_id: &str) -> bool {
    arkret_sdk::DidCoreId::new(service_id.to_owned()).is_ok()
}

#[allow(clippy::too_many_arguments)]
fn envelope_from_projection(
    public_projection: JsonValue,
    resource_id: String,
    discoverability: DiscoverabilityDb,
    as_of: DateTime<Utc>,
    source_refs: Vec<String>,
    policy_revision: String,
    stale: bool,
    divergent: bool,
    via_services: Vec<String>,
    expires_at: DateTime<Utc>,
    audience: Option<String>,
) -> ResultEnvelope {
    let did = public_projection
        .get("did")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_string();
    let claims = public_projection
        .get("claims")
        .cloned()
        .unwrap_or(JsonValue::Null);
    let mut payload = json!({
        "did": did,
        "subject": did,
        "handle": resource_id,
        "verified": public_projection.get("verified").and_then(JsonValue::as_bool).unwrap_or(false),
        "claims": claims,
        "discoverability": discoverability.as_pg(),
        "expires_at": expires_at,
    });
    // Carry the post-filter binding fields forward so downstream builders
    // see exactly the Realm-policy-approved subset.
    for key in ["member_delivery_binding"] {
        if let Some(value) = public_projection.get(key) {
            payload[key] = value.clone();
        }
    }
    // Spec 0a5ab85: when the resolver knows the audience, MUST emit an
    // `audience`-bound payload alongside the claim so verifiers can enforce
    // `audience == self` before accepting it for delivery_binding builds.
    if let Some(audience) = audience {
        payload["audience"] = JsonValue::String(audience);
    }
    ResultEnvelope::from_row(
        payload,
        as_of,
        source_refs,
        policy_revision,
        stale,
        divergent,
        via_services,
    )
}

fn handle_resolution_from_envelope(
    envelope: ResultEnvelope,
) -> Result<DirectoryHandleResolutionOutcome, String> {
    let payload = envelope
        .payload
        .as_object()
        .ok_or_else(|| "handle projection is not an object".to_owned())?;
    let did_raw = payload
        .get("did")
        .and_then(JsonValue::as_str)
        .filter(|did| arkret_sdk::DidCoreId::new((*did).to_owned()).is_ok())
        .ok_or_else(|| "handle projection did is missing or invalid".to_owned())?
        .to_owned();
    let did = DidCoreId::new(did_raw.clone())
        .map_err(|error| format!("handle projection did is invalid: {error}"))?;
    let subject = payload
        .get("subject")
        .and_then(JsonValue::as_str)
        .unwrap_or(&did_raw);
    if subject != did_raw {
        return Err("handle projection subject must match did".to_owned());
    }
    let handle = payload
        .get("handle")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| "handle projection handle is missing".to_owned())?
        .to_owned();
    let verified = payload
        .get("verified")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false);
    let claims: Option<Vec<arkret_sdk::HandleClaim>> = payload
        .get("claims")
        .filter(|value| !value.is_null())
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| format!("handle projection claims are invalid: {error}"))?;
    let audience = payload
        .get("audience")
        .and_then(JsonValue::as_str)
        .map(str::to_owned);
    let member_delivery_binding = payload
        .get("member_delivery_binding")
        .filter(|value| !value.is_null())
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| {
            format!("handle projection member_delivery_binding is invalid: {error}")
        })?;
    let handle_claim = payload
        .get("handle_claim")
        .filter(|value| !value.is_null())
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| format!("handle projection handle_claim is invalid: {error}"))?;
    Ok(DirectoryHandleResolutionOutcome {
        principal_id: did,
        handle,
        verified,
        claims,
        audience,
        member_delivery_binding,
        handle_claim,
        as_of: Some(envelope.as_of),
        source_refs: envelope.source_refs,
        policy_revision: Some(envelope.policy_revision),
        stale: envelope.stale,
        divergent: envelope.divergent,
        via_services: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use chrono::TimeZone;

    use super::*;

    fn dummy_row(public_projection: JsonValue) -> HandleRow {
        HandleRow {
            resource_id: "alice:example.com".to_string(),
            public_projection,
            discoverability: DiscoverabilityDb::Public,
            as_of: Utc.timestamp_opt(0, 0).unwrap(),
            source_refs: vec!["evt-handle-alice".to_string()],
            policy_revision: "rev-handle-1".to_string(),
            stale: false,
            divergent: false,
            via_services: vec!["ak:did_core:web:principal.test".to_string()],
            expires_at: Utc.timestamp_opt(3_600, 0).unwrap(),
        }
    }

    fn member_add_request(realm_id: &str, requester: &str) -> ResolveHandleRequestView {
        ResolveHandleRequestView {
            handle: "alice:example.com".to_string(),
            expected_principal_id: None,
            proof_challenge: None,
            claim_presentations: Vec::new(),
            intent: Some("member_add".to_string()),
            requester: Some(requester.to_string()),
            audience: None,
            realm_id: Some(realm_id.to_string()),
        }
    }

    fn realm_policy(
        allowed_recipient_services: &[&str],
        trusted_audiences: &[&str],
    ) -> RealmDeliveryBindingPolicy {
        let projection = json!({
            "delivery_binding_policy": {
                "allowed_recipient_services": allowed_recipient_services,
                "trusted_audiences": trusted_audiences,
            },
        });
        RealmDeliveryBindingPolicy::from_projection(projection)
    }

    #[test]
    fn handle_input_profile_prepares_internationalized_localpart() {
        assert_eq!(
            prepare_handle_localpart_input("小明:example.com").unwrap(),
            "小明"
        );
        assert_eq!(
            prepare_handle_localpart_input("ＡＬＩＣＥ:example.com").unwrap(),
            "alice"
        );
    }

    #[test]
    fn handle_profile_accepts_pure_ascii() {
        assert_eq!(prepare_handle_localpart_input("alice").unwrap(), "alice");
    }

    #[test]
    fn handle_profile_rejects_structural_separator() {
        let err = prepare_handle_localpart_input("alice/ops:example.com");
        assert!(err.is_err());
    }

    #[test]
    fn extract_localpart_accepts_canonical_and_bare_forms() {
        // R3.1 canonical wire form `<localpart>:<domain>` (arkret-spec
        // @ 7157ee8). The retired `arkret://` URI form is no longer
        // parsed — feeding it now treats the whole string as a bare
        // localpart (which the SDK normalizer will then reject).
        assert_eq!(extract_localpart_public("alice:example.com"), "alice");
        assert_eq!(extract_localpart_public("小明:example.com"), "小明");
        assert_eq!(extract_localpart_public("alice.profile"), "alice.profile");
    }

    #[test]
    fn intent_member_add_is_recognized() {
        assert!(is_member_add_intent(Some("member_add")));
        assert!(is_member_add_intent(Some("invite")));
        assert!(!is_member_add_intent(Some("dm")));
        assert!(!is_member_add_intent(None));
    }

    #[test]
    fn policy_from_projection_reads_nested_shape() {
        let policy = RealmDeliveryBindingPolicy::from_projection(json!({
            "delivery_binding_policy": {
                "allowed_recipient_services": ["ak:did_core:web:principal.tea"],
                "allowed_binding_sources": ["join_policy"],
                "trusted_audiences": ["did:web:tea-org.example"],
            },
        }));
        assert_eq!(
            policy.allowed_recipient_services,
            vec!["ak:did_core:web:principal.tea".to_string()]
        );
        assert_eq!(
            policy.allowed_binding_sources,
            vec!["join_policy".to_string()]
        );
        assert_eq!(
            policy.trusted_audiences,
            vec!["did:web:tea-org.example".to_string()]
        );
    }

    /// `resolve_handle_filters_recipient_service`: handle exists but the
    /// only recipient service is outside the Realm's allow-list ⇒ resolver
    /// MUST emit `not_found`, not a stripped envelope.
    #[test]
    fn resolve_handle_filters_recipient_service() {
        let row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
            "member_delivery_binding": {
                "recipient_service_id": "ak:did_core:web:principal.other",
                "binding_source": "join_policy",
            },
        }));
        let body = member_add_request("ak:realm:tea", "did:web:tea-org.example");
        let policy = realm_policy(
            &["ak:did_core:web:principal.tea"],
            &["did:web:tea-org.example"],
        );

        let outcome = evaluate_handle_disclosure(
            row,
            &body,
            &VerifiedRestrictedClaims::default(),
            Some(&policy),
        );
        assert!(matches!(outcome, ResolveOutcome::NotFound));
    }

    #[test]
    fn expected_principal_id_must_match_resolved_principal() {
        let row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
        }));
        let mut body = member_add_request("ak:realm:tea", "did:web:tea-org.example");
        body.expected_principal_id = Some("did:web:bob.example".to_owned());

        let outcome =
            evaluate_handle_disclosure(row, &body, &VerifiedRestrictedClaims::default(), None);
        assert!(matches!(outcome, ResolveOutcome::NotFound));
    }

    /// When a member_delivery_binding passes policy the resolver MUST surface
    /// that single-source binding.
    #[test]
    fn resolve_handle_keeps_allowed_member_delivery_binding() {
        let row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
            "member_delivery_binding": {
                "recipient_service_id": "ak:did_core:web:principal.tea",
                "binding_source": "join_policy"
            }
        }));
        let body = member_add_request("ak:realm:tea", "did:web:tea-org.example");
        let policy = realm_policy(
            &["ak:did_core:web:principal.tea"],
            &["did:web:tea-org.example"],
        );

        let outcome = evaluate_handle_disclosure(
            row,
            &body,
            &VerifiedRestrictedClaims::default(),
            Some(&policy),
        );
        let envelope = match outcome {
            ResolveOutcome::Found(envelope) => envelope,
            ResolveOutcome::NotFound => panic!("expected Found, got NotFound"),
        };
        let binding = envelope
            .payload
            .get("member_delivery_binding")
            .and_then(JsonValue::as_object)
            .expect("member_delivery_binding surface");
        assert_eq!(
            binding
                .get("recipient_service_id")
                .and_then(JsonValue::as_str),
            Some("ak:did_core:web:principal.tea")
        );
    }

    /// `resolve_handle_unauthorized_requester_returns_not_found`: requester
    /// not in `trusted_audiences` MUST see the same not_found shape as a
    /// genuine miss so the directory does not enumerate audience members.
    #[test]
    fn resolve_handle_unauthorized_requester_returns_not_found() {
        let row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
            "member_delivery_binding": {
                "recipient_service_id": "ak:did_core:web:principal.tea",
                "binding_source": "join_policy",
            },
        }));
        let body = member_add_request("ak:realm:tea", "did:web:eve.example");
        let policy = realm_policy(
            &["ak:did_core:web:principal.tea"],
            &["did:web:tea-org.example"],
        );

        let outcome = evaluate_handle_disclosure(
            row,
            &body,
            &VerifiedRestrictedClaims::default(),
            Some(&policy),
        );
        assert!(matches!(outcome, ResolveOutcome::NotFound));
    }

    /// Empty `allowed_recipient_services` rejects every recipient service.
    #[test]
    fn empty_allowed_recipient_services_fails_closed() {
        let row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
            "member_delivery_binding": {
                "recipient_service_id": "ak:did_core:web:principal.anywhere",
                "binding_source": "join_policy",
            },
        }));
        let body = member_add_request("ak:realm:tea", "did:web:tea-org.example");
        let policy = realm_policy(&[], &["did:web:tea-org.example"]);

        let outcome = evaluate_handle_disclosure(
            row,
            &body,
            &VerifiedRestrictedClaims::default(),
            Some(&policy),
        );
        assert!(matches!(outcome, ResolveOutcome::NotFound));
    }

    /// The exact singleton `["*"]` explicitly removes the recipient-service
    /// allow-list restriction while leaving all other policy checks active.
    #[test]
    fn wildcard_allowed_recipient_services_is_unrestricted() {
        let row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
            "member_delivery_binding": {
                "recipient_service_id": "ak:did_core:web:principal.anywhere",
                "binding_source": "join_policy",
            },
        }));
        let body = member_add_request("ak:realm:tea", "did:web:tea-org.example");
        let policy = realm_policy(&["*"], &["did:web:tea-org.example"]);

        let outcome = evaluate_handle_disclosure(
            row,
            &body,
            &VerifiedRestrictedClaims::default(),
            Some(&policy),
        );
        let envelope = match outcome {
            ResolveOutcome::Found(envelope) => envelope,
            ResolveOutcome::NotFound => panic!("expected Found, got NotFound"),
        };
        assert_eq!(
            envelope
                .payload
                .get("member_delivery_binding")
                .and_then(JsonValue::as_object)
                .and_then(|binding| binding.get("recipient_service_id"))
                .and_then(JsonValue::as_str),
            Some("ak:did_core:web:principal.anywhere")
        );
    }

    /// `timing_consistency_smoke`: the three policy-decision branches MUST
    /// share a comparable wall-clock cost. We measure the synchronous
    /// `evaluate_handle_disclosure` core (the async caller adds a separate
    /// constant latency floor on top) and assert spread is small.
    #[test]
    fn timing_consistency_smoke() {
        let policy = realm_policy(
            &["ak:did_core:web:principal.tea"],
            &["did:web:tea-org.example"],
        );
        let allowed_row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
            "member_delivery_binding": {
                "recipient_service_id": "ak:did_core:web:principal.tea",
                "binding_source": "join_policy",
            },
        }));
        let filtered_row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
            "member_delivery_binding": {
                "recipient_service_id": "ak:did_core:web:principal.other",
                "binding_source": "join_policy",
            },
        }));

        let warmup = 256;
        let iters = 4096;

        let found_body = member_add_request("ak:realm:tea", "did:web:tea-org.example");
        let unauthorized_body = member_add_request("ak:realm:tea", "did:web:eve.example");
        let filtered_body = member_add_request("ak:realm:tea", "did:web:tea-org.example");

        // Warm caches / branch predictor.
        for _ in 0..warmup {
            let _ = evaluate_handle_disclosure(
                allowed_row.clone(),
                &found_body,
                &VerifiedRestrictedClaims::default(),
                Some(&policy),
            );
            let _ = evaluate_handle_disclosure(
                allowed_row.clone(),
                &unauthorized_body,
                &VerifiedRestrictedClaims::default(),
                Some(&policy),
            );
            let _ = evaluate_handle_disclosure(
                filtered_row.clone(),
                &filtered_body,
                &VerifiedRestrictedClaims::default(),
                Some(&policy),
            );
        }

        let measure = |body: &ResolveHandleRequestView, row: &HandleRow| -> Duration {
            let start = Instant::now();
            for _ in 0..iters {
                let _ = evaluate_handle_disclosure(
                    row.clone(),
                    body,
                    &VerifiedRestrictedClaims::default(),
                    Some(&policy),
                );
            }
            start.elapsed()
        };

        let found_elapsed = measure(&found_body, &allowed_row);
        let not_found_elapsed = measure(&unauthorized_body, &allowed_row);
        let filtered_elapsed = measure(&filtered_body, &filtered_row);

        let min = found_elapsed.min(not_found_elapsed).min(filtered_elapsed);
        let max = found_elapsed.max(not_found_elapsed).max(filtered_elapsed);
        // The pure decision is dominated by JSON cloning. We only assert
        // the spread is within an order of magnitude — anything larger
        // would indicate a data-dependent fast-path leaking the branch.
        // The async `pad_to_budget` floor + jitter then absorbs the
        // residual nanosecond-scale jitter on the wire.
        assert!(
            max <= min * 10 + Duration::from_millis(2),
            "timing skew too large: found={found_elapsed:?} not_found={not_found_elapsed:?} filtered={filtered_elapsed:?}"
        );
    }

    #[test]
    fn audience_authorization_accepts_trusted_audiences() {
        let policy = realm_policy(&[], &["did:web:tea-org.example"]);
        assert!(policy.audience_authorized(
            Some("did:web:tea-org.example"),
            &VerifiedRestrictedClaims::default()
        ));
        assert!(!policy.audience_authorized(
            Some("did:web:eve.example"),
            &VerifiedRestrictedClaims::default()
        ));
    }

    #[test]
    fn audience_authorization_falls_back_to_allowed_discoverers() {
        let issuer =
            arkret_sdk::DidCoreId::new("ak:did_core:web:issuer.example".to_owned()).unwrap();
        let org = arkret_sdk::DidCoreId::new("ak:did_core:web:acme.example".to_owned()).unwrap();
        let requester =
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap();
        let claim = crate::filter::discoverers::organization_membership_claim(
            "claim-1",
            requester.clone(),
            issuer.clone(),
            org.clone(),
            vec!["member".to_owned()],
        );
        let verified_claims = VerifiedRestrictedClaims::for_test(vec![claim]);
        let policy = RealmDeliveryBindingPolicy::from_projection(json!({
            "allowed_discoverers": [{
                "type": "claim",
                "claim_kind": "organization_membership",
                "issuer": issuer.as_str(),
                "organization_id": org.as_str(),
            }],
        }));
        assert!(policy.audience_authorized(Some(requester.as_str()), &verified_claims));
        assert!(!policy.audience_authorized(
            Some("did:web:bob.example"),
            &VerifiedRestrictedClaims::default()
        ));
    }

    #[test]
    fn restricted_handle_accepts_verified_claim_presentation() {
        let issuer =
            arkret_sdk::DidCoreId::new("ak:did_core:web:issuer.example".to_owned()).unwrap();
        let org = arkret_sdk::DidCoreId::new("ak:did_core:web:acme.example".to_owned()).unwrap();
        let requester =
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap();
        let claim = crate::filter::discoverers::organization_membership_claim(
            "claim-1",
            requester.clone(),
            issuer.clone(),
            org.clone(),
            vec!["member".to_owned()],
        );
        let verified_claims = VerifiedRestrictedClaims::for_test(vec![claim]);
        let mut row = dummy_row(json!({
            "did": requester.as_str(),
            "verified": true,
            "allowed_discoverers": [{
                "type": "claim",
                "claim_kind": "organization_membership",
                "issuer": issuer.as_str(),
                "organization_id": org.as_str(),
            }],
        }));
        row.discoverability = DiscoverabilityDb::Restricted;
        let body = ResolveHandleRequestView {
            handle: "alice:example.com".to_owned(),
            expected_principal_id: None,
            proof_challenge: None,
            claim_presentations: Vec::new(),
            intent: Some("lookup".to_owned()),
            requester: Some(requester.as_str().to_owned()),
            audience: None,
            realm_id: None,
        };

        let outcome = evaluate_handle_disclosure(row, &body, &verified_claims, None);
        assert!(matches!(outcome, ResolveOutcome::Found(_)));
    }

    #[test]
    fn policy_with_no_audience_constraint_lets_everyone_through() {
        // No `trusted_audiences`, no `allowed_discoverers` ⇒ resolver
        // SHOULD treat the Realm as unrestricted (per §9 default for
        // Public/Listed Realms).
        let policy = RealmDeliveryBindingPolicy::from_projection(json!({
            "delivery_binding_policy": {
                "allowed_recipient_services": ["ak:did_core:web:principal.tea"],
            },
        }));
        assert!(policy.audience_authorized(
            Some("did:web:anybody.example"),
            &VerifiedRestrictedClaims::default()
        ));
    }

    #[test]
    fn binding_source_filter_prunes_disallowed_source() {
        let row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
            "member_delivery_binding": {
                "recipient_service_id": "ak:did_core:web:principal.tea",
                "binding_source": "explicit",
            }
        }));
        let policy = RealmDeliveryBindingPolicy::from_projection(json!({
            "delivery_binding_policy": {
                "allowed_recipient_services": ["ak:did_core:web:principal.tea"],
                "allowed_binding_sources": ["join_policy"],
                "trusted_audiences": ["did:web:tea-org.example"],
            },
        }));
        let body = member_add_request("ak:realm:tea", "did:web:tea-org.example");

        let outcome = evaluate_handle_disclosure(
            row,
            &body,
            &VerifiedRestrictedClaims::default(),
            Some(&policy),
        );
        assert!(matches!(outcome, ResolveOutcome::NotFound));
    }
}
