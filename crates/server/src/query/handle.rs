//! Handle resolution. Spec §9 (`ck.find.directory.query.resolve_handle`).
//!
//! Spec sync 0a5ab85 / governance/join-policy §5.1.3:
//! `ck.find.directory.query.resolve_handle` MUST gate `intent=member_add | invite`
//! requests on the target **Realm**'s `delivery_binding_policy`
//! (`allowed_recipient_services`, `allow_binding_sources`) and on the
//! Realm's audience-binding list. Unauthorized requesters MUST NOT receive
//! the underlying subject / service DID — they collapse to `not_found` with
//! the same response shape and latency tier as a genuine miss (§10).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use cokret_sdk::{
    DirectoryHandleResolutionOutcome,
    DirectoryResolveHandleRequestBody as SdkDirectoryResolveHandleRequestBody,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};

use crate::error::ApiErrorCode;
use crate::filter::discoverers::{
    RestrictedClaimPresentation, VerifiedRestrictedClaims, verify_restricted_claim_presentations,
};
use crate::filter::enumeration::{LatencyBudget, pad_to_budget_observed};
use crate::filter::result::ResultEnvelope;
use crate::ingest::{DirectoryResourceKindDb, DiscoverabilityDb};
use crate::query::rate_limit::{apply_resolve_response_jitter, enforce_resolve_rate_limit};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct TeabayResolveHandleRequest {
    pub handle: String,
    #[serde(default)]
    pub expected_did: Option<String>,
    #[serde(default)]
    pub proof_challenge: Option<String>,
    /// Why the handle is being resolved. Spec 0a5ab85:
    /// gates audience binding on the response claim and selects the
    /// Realm `delivery_binding_policy` (`allowed_recipient_services`)
    /// filter when `intent ∈ {member_add, invite}`.
    #[serde(default)]
    pub intent: Option<String>,
    /// DID or service DID of the requester. Used to scope audience-bearing
    /// claims so that the verifier can enforce `audience == self` and to
    /// authorize disclosure of Realm-restricted bindings.
    #[serde(default)]
    pub requester: Option<String>,
    /// Explicit audience the verifier expects on the claim (typically a
    /// target Realm DID or inviter service DID).
    #[serde(default)]
    pub audience: Option<String>,
    /// Target Realm DID for `intent=member_add | invite`. When present we
    /// load the Realm `delivery_binding_policy` baseline and filter
    /// candidate bindings against `allowed_recipient_services`.
    #[serde(default)]
    pub realm_id: Option<String>,
    /// Optional proofs / claim ids the requester presents to be admitted as
    /// a Realm audience. Mirrors `resolve_realm` semantics.
    #[serde(default)]
    pub proofs: Vec<RestrictedClaimPresentation>,
    /// CKP R3 spec-sync 2026-05-27 (commit b47ff6e) — directory query
    /// filters now accept the unified `resource-selector` shape. We
    /// recognise the `circle` kind (CKP-0007) and immediately collapse
    /// the response to `not_found`: the directory MUST NEVER index a
    /// Circle resource, so any circle-keyed lookup is by definition a
    /// miss. The selector is accepted (not rejected) on the query face
    /// so SDK callers running a unified selector evaluator do not have
    /// to special-case the directory transport. See
    /// `filter::selector::is_circle_selector` for the parser.
    #[serde(default)]
    pub selector: Option<serde_json::Value>,
}

/// CKP R3 — extract the localpart from a handle value and run it through
/// `cokret_sdk::normalize_handle_localpart` (Unicode NFC + UTS#39
/// confusable skeleton + script-mixed reject).
///
/// Accepts the canonical R3.1 wire form `<localpart>:<domain>(:<port>)?`
/// (cokret-spec @ 7157ee8 — 2026-05-27).
/// The directory's own dot-separated index key `<localpart>.<domain>`
/// is still accepted because it remains the row's `resource_id` shape
/// in storage.
///
/// Returns the rejection reason string for the wire response when the
/// localpart fails any rule; the message intentionally does NOT echo
/// back which rule was violated (length / zero-width / script-mixed /
/// confusable) to avoid leaking the registrar's lookup table.
pub(crate) fn check_handle_homograph(handle: &str) -> Result<(), String> {
    let localpart = extract_localpart(handle);
    // TODO(R3.1): when the SDK gains a domain-side homograph check (full
    // UTS#46 IDNA normalization), also run that against the domain
    // suffix. For R3 the wire-level guard is localpart-only because the
    // domain reaches us already lowercased and ASCII-restricted by the
    // ingest path.
    match cokret_sdk::normalize_handle_localpart(localpart) {
        Ok(_) => Ok(()),
        Err(_) => Err("handle violates homograph / script-mixed policy".to_owned()),
    }
}

fn extract_localpart(handle: &str) -> &str {
    extract_localpart_public(handle)
}

/// Exposed for the ingest path so `announce.rs` can run the same
/// localpart-extraction rule before the SDK homograph normalizer. Kept
/// in this module so the two faces stay in lock-step.
///
/// R3.1 wire form (cokret-spec @ 7157ee8): `<localpart>:<domain>(:<port>)?`
/// — the colon separator is taken first because it is the canonical
/// shape the SDK `Handle::parse` emits. The directory's internal index
/// shape `<localpart>.<domain>` is still accepted for back-compat with
/// stored rows. Empty localpart falls through to the SDK helper which
/// fails on length-out-of-range.
pub fn extract_localpart_public(handle: &str) -> &str {
    // Prefer the canonical R3.1 colon-separated form. The localpart is
    // ASCII (lowercased) so a `:` in the input unambiguously means the
    // R3.1 separator and not part of the localpart.
    if let Some((local, _)) = handle.split_once(':') {
        return local;
    }
    // teabay's stored `resource_id` uses `<localpart>.<domain>`.
    handle.split('.').next().unwrap_or(handle)
}

/// CKP R3 spec-sync 2026-05-27 (commit b47ff6e), identity-handles §17 —
/// well-known handle endpoint. The spec migrated the well-known shape
/// from a path-style identifier to a query-string-keyed form:
///
/// ```text
/// GET https://<domain>/.well-known/cokret/handle?localpart=<localpart>
/// ```
///
/// We resolve against the directory's indexed Handle rows and return
/// the same `ResultEnvelope` shape that the POST `resolve-handle` face
/// emits. Wire-level homograph normalization runs on the localpart
/// before any DB lookup so a malformed query is `403
/// handle_homograph_forbidden` rather than the privacy-preserving
/// `404 not_found` returned for genuine misses.
///
/// The Host header (or the `?domain=<domain>` override) is concatenated
/// with the localpart to form the directory's stored `resource_id` —
/// teabay indexes handles as `<localpart>.<domain>` (see
/// `query::handle::load_handle_row`). When the Host header is missing
/// or no `?domain=` is supplied we still service the request against
/// the bare localpart so an operator-issued curl probe works.
#[handler]
pub async fn well_known_resolve_handle(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let _query_timer = state.metrics().query_timer("well-known-handle");

    let localpart = req.queries().get("localpart").cloned().unwrap_or_default();
    if localpart.is_empty() {
        ApiErrorCode::MissingParam.render(res, "localpart query parameter is required");
        return;
    }
    // Apply the same wire-level homograph + script-mixed guard as the
    // POST face. Reject BEFORE rate-limit / DB lookup so timing cannot
    // disambiguate a homograph from a miss.
    if let Err(reason) = check_handle_homograph(&localpart) {
        ApiErrorCode::HandleHomographForbidden.render(res, reason);
        return;
    }

    // Reconstruct the indexed `resource_id`. Order of preference:
    //   1. explicit `?domain=` query parameter (operator probe shape)
    //   2. Host header (cross-domain well-known fetch)
    //   3. bare localpart (single-tenant deployment / local conformance)
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
    let handle = if domain.is_empty() {
        localpart.clone()
    } else {
        format!("{localpart}.{domain}")
    };

    if !enforce_resolve_rate_limit(req, res, &state, &handle) {
        return;
    }

    let body = TeabayResolveHandleRequest {
        handle: handle.clone(),
        expected_did: None,
        proof_challenge: None,
        intent: None,
        requester: None,
        audience: None,
        realm_id: None,
        proofs: Vec::new(),
        selector: None,
    };

    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    let requester_ip = req.remote_addr().to_string();
    let mut ip_hasher = Sha256::new();
    ip_hasher.update(requester_ip.as_bytes());
    let requester_ip_hash = URL_SAFE_NO_PAD.encode(ip_hasher.finalize());
    let privacy_key = format!("well_known_handle={handle};iph={requester_ip_hash}");

    let outcome = pad_to_budget_observed(
        budget,
        "ck.find.directory.query.resolve_handle",
        &privacy_key,
        |target| {
            state
                .metrics()
                .record_anti_enum_pad("well-known-handle", target)
        },
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
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let _query_timer = state.metrics().query_timer("resolve-handle");
    let raw_body: JsonValue = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::BadJson.render(res, format!("malformed body: {error}"));
            return;
        }
    };
    if let Err(error) =
        serde_json::from_value::<SdkDirectoryResolveHandleRequestBody>(raw_body.clone())
    {
        ApiErrorCode::BadJson.render(res, format!("malformed SDK body: {error}"));
        return;
    }
    let body: TeabayResolveHandleRequest = match serde_json::from_value(raw_body) {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::BadJson.render(res, format!("malformed body: {error}"));
            return;
        }
    };
    if body.handle.is_empty() {
        ApiErrorCode::MissingParam.render(res, "handle is required");
        return;
    }
    // CKP R3 spec-sync 2026-05-27 (commit b47ff6e), identity-handles
    // §17 — wire-level canonical compare MUST apply Unicode NFC +
    // UTS#39 confusable skeleton + script-mixed reject before any
    // database lookup. The SDK helper centralises the rule set so the
    // ingest face (announce) and the query face (resolve_handle) stay
    // byte-identical. We reject with `handle_homograph_forbidden`
    // before timing-budget padding starts so the attacker's wall-clock
    // signal cannot disambiguate a homograph reject from a normal
    // not_found — a homograph submit deserves a 403, not the
    // privacy-preserving 404 that legitimate misses receive.
    if let Err(reason) = check_handle_homograph(&body.handle) {
        ApiErrorCode::HandleHomographForbidden.render(res, reason);
        return;
    }
    if !enforce_resolve_rate_limit(req, res, &state, &body.handle) {
        return;
    }
    // CKP R3 spec-sync 2026-05-27 — accept `circle` selector kind on
    // the query filter. Circle is an intra-Realm sub-boundary; the
    // directory never indexes Circle resources, so a circle-keyed
    // lookup collapses to the standard privacy-preserving `not_found`.
    // We do this AFTER rate-limit gating so the wire response shape is
    // identical to a genuine miss (same status, same body, same
    // jitter), but BEFORE the latency-budget padding so we don't waste
    // a query timer slot on a request that has no DB-bound work.
    if let Some(selector) = body.selector.as_ref()
        && crate::filter::selector::is_circle_selector(selector)
    {
        apply_resolve_response_jitter().await;
        ApiErrorCode::NotFound.render(res, "not found");
        return;
    }
    // Defence in depth: a bare `ck:circle:` typed id smuggled into the
    // `handle` field is also collapsed to `not_found` rather than
    // routed into the DB lookup.
    if crate::filter::selector::looks_like_circle_id(&body.handle) {
        apply_resolve_response_jitter().await;
        ApiErrorCode::NotFound.render(res, "not found");
        return;
    }
    let verified_claims = verify_restricted_claim_presentations(
        &body.proofs,
        body.requester.as_deref(),
        body.proof_challenge.as_deref(),
        &state.config().service_did,
        &state.config().accepted_did_methods,
        crate::egress::private_networks_allowed(state.config().development_mode),
    )
    .unwrap_or_default();

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
        "handle={};intent={};realm={};req={};aud={};iph={}",
        body.handle,
        body.intent.as_deref().unwrap_or_default(),
        body.realm_id.as_deref().unwrap_or_default(),
        body.requester.as_deref().unwrap_or_default(),
        body.audience.as_deref().unwrap_or_default(),
        requester_ip_hash,
    );

    let outcome = pad_to_budget_observed(
        budget,
        "ck.find.directory.query.resolve_handle",
        &privacy_key,
        |target| {
            state
                .metrics()
                .record_anti_enum_pad("resolve-handle", target)
        },
        async {
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
    policy_revision: Option<String>,
    stale: bool,
    divergent: bool,
    via_services: Vec<String>,
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
    /// DIDs that may appear in a Realm-bound delivery_binding. Empty = no
    /// restriction (per spec §5.1.3 default).
    pub allowed_recipient_services: Vec<String>,
    /// `allow_binding_sources`: optional sub-filter on the binding_source
    /// enum. Empty = caller does not enforce a binding_source filter here.
    pub allow_binding_sources: Vec<String>,
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
    body: &TeabayResolveHandleRequest,
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
        let allow_binding_sources =
            string_array_at(nested.and_then(|v| v.get("allow_binding_sources")));
        let trusted_audiences = string_array_at(nested.and_then(|v| v.get("trusted_audiences")));
        Self {
            allowed_recipient_services,
            allow_binding_sources,
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
    body: &TeabayResolveHandleRequest,
    verified_claims: &VerifiedRestrictedClaims,
    policy: Option<&RealmDeliveryBindingPolicy>,
) -> ResolveOutcome {
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
            audience,
        );
        return ResolveOutcome::Found(envelope);
    }

    // Non-member-add path: existing §9 behavior.
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
        audience,
    );
    ResolveOutcome::Found(envelope)
}

/// Apply Realm `allowed_recipient_services` (and, when declared,
/// `allow_binding_sources`) to the handle's public projection. Returns
/// `None` when the member_delivery_binding was pruned — signaling the resolver
/// should emit `not_found` rather than disclose the bare subject_id.
fn filter_projection_against_policy(
    mut projection: JsonValue,
    policy: &RealmDeliveryBindingPolicy,
) -> Option<JsonValue> {
    let allow_recipient = &policy.allowed_recipient_services;
    let allow_sources = &policy.allow_binding_sources;
    let unrestricted_recipient = allow_recipient.is_empty();
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
    let recipient_ok = match obj.get("recipient_service_did").and_then(JsonValue::as_str) {
        // Round 4 (spec a77b995, commit f9bd7eb) — the DID regex was
        // tightened to `^did:[a-z0-9]+:[^\s]+$`. The SDK `Did::new`
        // newtype enforces it; projections whose
        // `recipient_service_did` uses dot/dash/underscore/colon in
        // the method segment MUST be dropped as if absent, not allowed
        // through unconditionally.
        Some(did) => {
            is_round4_tight_did(did) && {
                unrestricted_recipient || policy.allowed_recipient_services.iter().any(|a| a == did)
            }
        }
        None => false,
    };
    let source_ok = match obj.get("binding_source").and_then(JsonValue::as_str) {
        Some(src) => unrestricted_source || policy.allow_binding_sources.iter().any(|a| a == src),
        None => unrestricted_source, /* No binding_source declared — only allowed when policy is
                                      * open. */
    };
    recipient_ok && source_ok
}

/// Round 4 — drop candidates whose `recipient_service_did` fails the
/// tightened SDK `Did` regex (`^did:[a-z0-9]+:[^\s]+$`).
fn is_round4_tight_did(did: &str) -> bool {
    cokret_sdk::Did::new(did.to_owned()).is_ok()
}

#[allow(clippy::too_many_arguments)]
fn envelope_from_projection(
    public_projection: JsonValue,
    resource_id: String,
    discoverability: DiscoverabilityDb,
    as_of: DateTime<Utc>,
    source_refs: Vec<String>,
    policy_revision: Option<String>,
    stale: bool,
    divergent: bool,
    via_services: Vec<String>,
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
        "handle": resource_id,
        "verified": public_projection.get("verified").and_then(JsonValue::as_bool).unwrap_or(false),
        "claims": claims,
        "discoverability": discoverability.as_pg(),
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
    let value = serde_json::to_value(envelope)
        .map_err(|error| format!("handle envelope serialization failed: {error}"))?;
    serde_json::from_value(value)
        .map_err(|error| format!("handle outcome is not SDK-compatible: {error}"))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use chrono::TimeZone;

    use super::*;

    fn dummy_row(public_projection: JsonValue) -> HandleRow {
        HandleRow {
            resource_id: "alice.example".to_string(),
            public_projection,
            discoverability: DiscoverabilityDb::Public,
            as_of: Utc.timestamp_opt(0, 0).unwrap(),
            source_refs: vec!["evt-handle-alice".to_string()],
            policy_revision: Some("rev-handle-1".to_string()),
            stale: false,
            divergent: false,
            via_services: vec!["did:web:principal.test".to_string()],
        }
    }

    fn member_add_request(realm_id: &str, requester: &str) -> TeabayResolveHandleRequest {
        TeabayResolveHandleRequest {
            handle: "alice.example".to_string(),
            expected_did: None,
            proof_challenge: None,
            intent: Some("member_add".to_string()),
            requester: Some(requester.to_string()),
            audience: None,
            realm_id: Some(realm_id.to_string()),
            proofs: vec![],
            selector: None,
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

    /// CKP R3 — the homograph guard MUST reject Cyrillic look-alikes
    /// before any DB lookup. We test the helper directly so the
    /// assertion does not depend on a live AppState.
    #[test]
    fn handle_homograph_check_rejects_cyrillic_lookalike() {
        // "alicе.example" with Cyrillic 'е' (U+0435).
        let err = check_handle_homograph("alic\u{0435}.example");
        assert!(err.is_err());
    }

    #[test]
    fn handle_homograph_check_accepts_pure_ascii() {
        assert!(check_handle_homograph("alice.example").is_ok());
    }

    #[test]
    fn handle_homograph_check_rejects_script_mixed() {
        // Latin + Greek alpha.
        let err = check_handle_homograph("aliceα.example");
        assert!(err.is_err());
    }

    #[test]
    fn extract_localpart_accepts_canonical_and_index_forms() {
        // R3.1 canonical wire form `<localpart>:<domain>` (cokret-spec
        // @ 7157ee8). The retired `cokret://` URI form is no longer
        // parsed — feeding it now treats the whole string as a bare
        // localpart (which the SDK normalizer will then reject).
        assert_eq!(extract_localpart_public("alice:example.com"), "alice");
        assert_eq!(extract_localpart_public("alice:example.com:8443"), "alice");
        // Directory storage index form remains accepted for back-compat
        // with existing rows.
        assert_eq!(extract_localpart_public("alice.example"), "alice");
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
                "allowed_recipient_services": ["did:web:principal.tea"],
                "allow_binding_sources": ["join_policy"],
                "trusted_audiences": ["did:web:tea-org.example"],
            },
        }));
        assert_eq!(
            policy.allowed_recipient_services,
            vec!["did:web:principal.tea".to_string()]
        );
        assert_eq!(
            policy.allow_binding_sources,
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
                "recipient_service_did": "did:web:principal.other",
                "binding_source": "join_policy",
            },
        }));
        let body = member_add_request("ck:realm:tea", "did:web:tea-org.example");
        let policy = realm_policy(&["did:web:principal.tea"], &["did:web:tea-org.example"]);

        let outcome = evaluate_handle_disclosure(
            row,
            &body,
            &VerifiedRestrictedClaims::default(),
            Some(&policy),
        );
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
                "recipient_service_did": "did:web:principal.tea",
                "binding_source": "join_policy"
            }
        }));
        let body = member_add_request("ck:realm:tea", "did:web:tea-org.example");
        let policy = realm_policy(&["did:web:principal.tea"], &["did:web:tea-org.example"]);

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
                .get("recipient_service_did")
                .and_then(JsonValue::as_str),
            Some("did:web:principal.tea")
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
                "recipient_service_did": "did:web:principal.tea",
                "binding_source": "join_policy",
            },
        }));
        let body = member_add_request("ck:realm:tea", "did:web:eve.example");
        let policy = realm_policy(&["did:web:principal.tea"], &["did:web:tea-org.example"]);

        let outcome = evaluate_handle_disclosure(
            row,
            &body,
            &VerifiedRestrictedClaims::default(),
            Some(&policy),
        );
        assert!(matches!(outcome, ResolveOutcome::NotFound));
    }

    /// Empty `allowed_recipient_services` is "no restriction" (spec
    /// §5.1.3). The resolver MUST still authorize disclosure but not prune.
    #[test]
    fn empty_allowed_recipient_services_means_unrestricted() {
        let row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
            "member_delivery_binding": {
                "recipient_service_did": "did:web:principal.anywhere",
                "binding_source": "join_policy",
            },
        }));
        let body = member_add_request("ck:realm:tea", "did:web:tea-org.example");
        let policy = realm_policy(&[], &["did:web:tea-org.example"]);

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
                .and_then(|binding| binding.get("recipient_service_did"))
                .and_then(JsonValue::as_str),
            Some("did:web:principal.anywhere")
        );
    }

    /// `timing_consistency_smoke`: the three policy-decision branches MUST
    /// share a comparable wall-clock cost. We measure the synchronous
    /// `evaluate_handle_disclosure` core (the async caller adds a separate
    /// constant latency floor on top) and assert spread is small.
    #[test]
    fn timing_consistency_smoke() {
        let policy = realm_policy(&["did:web:principal.tea"], &["did:web:tea-org.example"]);
        let allowed_row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
            "member_delivery_binding": {
                "recipient_service_did": "did:web:principal.tea",
                "binding_source": "join_policy",
            },
        }));
        let filtered_row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
            "member_delivery_binding": {
                "recipient_service_did": "did:web:principal.other",
                "binding_source": "join_policy",
            },
        }));

        let warmup = 256;
        let iters = 4096;

        let found_body = member_add_request("ck:realm:tea", "did:web:tea-org.example");
        let unauthorized_body = member_add_request("ck:realm:tea", "did:web:eve.example");
        let filtered_body = member_add_request("ck:realm:tea", "did:web:tea-org.example");

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

        let measure = |body: &TeabayResolveHandleRequest, row: &HandleRow| -> Duration {
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
        let policy = RealmDeliveryBindingPolicy::from_projection(json!({
            "allowed_discoverers": [{ "requester": "did:web:alice.example" }],
        }));
        assert!(policy.audience_authorized(
            Some("did:web:alice.example"),
            &VerifiedRestrictedClaims::default()
        ));
        assert!(!policy.audience_authorized(
            Some("did:web:bob.example"),
            &VerifiedRestrictedClaims::default()
        ));
    }

    #[test]
    fn policy_with_no_audience_constraint_lets_everyone_through() {
        // No `trusted_audiences`, no `allowed_discoverers` ⇒ resolver
        // SHOULD treat the Realm as unrestricted (per §9 default for
        // Public/Listed Realms).
        let policy = RealmDeliveryBindingPolicy::from_projection(json!({
            "delivery_binding_policy": {
                "allowed_recipient_services": ["did:web:principal.tea"],
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
                "recipient_service_did": "did:web:principal.tea",
                "binding_source": "explicit",
            }
        }));
        let policy = RealmDeliveryBindingPolicy::from_projection(json!({
            "delivery_binding_policy": {
                "allowed_recipient_services": ["did:web:principal.tea"],
                "allow_binding_sources": ["join_policy"],
                "trusted_audiences": ["did:web:tea-org.example"],
            },
        }));
        let body = member_add_request("ck:realm:tea", "did:web:tea-org.example");

        let outcome = evaluate_handle_disclosure(
            row,
            &body,
            &VerifiedRestrictedClaims::default(),
            Some(&policy),
        );
        assert!(matches!(outcome, ResolveOutcome::NotFound));
    }
}
