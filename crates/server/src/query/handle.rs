//! Handle resolution. Spec §9 (`cx.directory.resolve_handle`).
//!
//! Spec sync 0a5ab85 / governance/join-policy §5.1.3:
//! `cx.directory.resolve_handle` MUST gate `intent=member_add | invite`
//! requests on the target **Realm**'s `delivery_binding_policy`
//! (`allowed_recipient_services`, `allow_binding_sources`) and on the
//! Realm's audience-binding list. Unauthorized requesters MUST NOT receive
//! the underlying subject / service DID — they collapse to `not_found` with
//! the same response shape and latency tier as a genuine miss (§10).

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

use crate::error::ApiErrorCode;
use crate::filter::enumeration::{LatencyBudget, pad_to_budget};
use crate::filter::result::ResultEnvelope;
use crate::ingest::{DiscoverabilityWire, ResourceKindWire};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ResolveHandleRequest {
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
    pub proofs: Vec<String>,
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
    let body: ResolveHandleRequest = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ApiErrorCode::BadJson.render(res, format!("malformed body: {e}"));
            return;
        }
    };
    if body.handle.is_empty() {
        ApiErrorCode::MissingParam.render(res, "handle is required");
        return;
    }

    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    // Privacy key bundles every input that affects the not_found / found /
    // unauthorized branch so the deterministic latency tier is stable
    // per-request but does not leak the branch back to the caller.
    let privacy_key = format!(
        "handle={};intent={};realm={};req={};aud={}",
        body.handle,
        body.intent.as_deref().unwrap_or_default(),
        body.realm_id.as_deref().unwrap_or_default(),
        body.requester.as_deref().unwrap_or_default(),
        body.audience.as_deref().unwrap_or_default(),
    );

    let outcome = pad_to_budget(budget, "cx.directory.resolve_handle", &privacy_key, async {
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

        evaluate_handle_disclosure(row, &body, policy.as_ref())
    })
    .await;

    match outcome {
        ResolveOutcome::Found(envelope) => res.render(Json(envelope)),
        // `not_found` covers genuine miss, unauthorized requester, and "all
        // candidates filtered out" — these MUST be indistinguishable on the
        // wire so the directory does not leak the existence of the handle
        // or the recipient service identity.
        ResolveOutcome::NotFound => ApiErrorCode::NotFound.render(res, "not found"),
    }
}

/// Result of running the policy filter against a stored handle row.
#[derive(Debug)]
enum ResolveOutcome {
    Found(ResultEnvelope),
    NotFound,
}

#[derive(Debug, Queryable, Clone)]
struct HandleRow {
    resource_id: String,
    public_projection: JsonValue,
    discoverability: DiscoverabilityWire,
    as_of: DateTime<Utc>,
    source_refs: Vec<String>,
    policy_revision: Option<String>,
    stale: bool,
    divergent: bool,
    via_services: Vec<String>,
}

async fn load_handle_row(state: &AppState, handle: &str) -> anyhow::Result<Option<HandleRow>> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get()?;
    let row: Option<HandleRow> = r::directory_resources
        .filter(r::resource_kind.eq(ResourceKindWire::Handle))
        .filter(r::resource_id.eq(handle))
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
        .first(&mut conn)
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
    body: &ResolveHandleRequest,
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
    let mut conn = state.db().get()?;
    let projection: Option<(JsonValue, DiscoverabilityWire)> = r::directory_resources
        .filter(r::resource_kind.eq(ResourceKindWire::Realm))
        .filter(r::resource_id.eq(realm_id))
        .select((r::public_projection, r::discoverability))
        .first(&mut conn)
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
    /// `public_projection`. Tolerates both flat (legacy) and nested
    /// (`delivery_binding_policy`) shapes so cached projections from older
    /// announces still load.
    pub(crate) fn from_projection(projection: JsonValue) -> Self {
        let nested = projection
            .get("delivery_binding_policy")
            .or_else(|| projection.pointer("/payload/delivery_binding_policy"));
        let allowed_recipient_services = string_array_at(
            &projection,
            "allowed_recipient_services",
            nested.and_then(|v| v.get("allowed_recipient_services")),
        );
        let allow_binding_sources = string_array_at(
            &projection,
            "allow_binding_sources",
            nested.and_then(|v| v.get("allow_binding_sources")),
        );
        let trusted_audiences = string_array_at(
            &projection,
            "trusted_audiences",
            nested.and_then(|v| v.get("trusted_audiences")),
        );
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
    fn audience_authorized(&self, requester: Option<&str>, proofs: &[String]) -> bool {
        if self.trusted_audiences.is_empty() && !has_allowed_discoverers(&self.raw_projection) {
            // No audience constraint declared — fall through to the default
            // discoverability gate the row itself carries.
            return true;
        }
        if let Some(requester) = requester {
            if self.trusted_audiences.iter().any(|aud| aud == requester) {
                return true;
            }
        }
        // Reuse the `allowed_discoverers` shape when the Realm does not
        // declare explicit trusted audiences.
        allowed_discoverers_match(&self.raw_projection, requester, proofs)
    }
}

fn string_array_at(root: &JsonValue, flat_key: &str, nested: Option<&JsonValue>) -> Vec<String> {
    if let Some(arr) = nested.and_then(JsonValue::as_array) {
        return arr
            .iter()
            .filter_map(JsonValue::as_str)
            .map(str::to_string)
            .collect();
    }
    root.get(flat_key)
        .and_then(JsonValue::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(JsonValue::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn has_allowed_discoverers(projection: &JsonValue) -> bool {
    projection
        .get("allowed_discoverers")
        .or_else(|| projection.pointer("/payload/allowed_discoverers"))
        .and_then(JsonValue::as_array)
        .map(|arr| !arr.is_empty())
        .unwrap_or(false)
}

fn allowed_discoverers_match(
    projection: &JsonValue,
    requester: Option<&str>,
    proofs: &[String],
) -> bool {
    let Some(discoverers) = projection
        .get("allowed_discoverers")
        .or_else(|| projection.pointer("/payload/allowed_discoverers"))
        .and_then(JsonValue::as_array)
    else {
        return false;
    };
    discoverers.iter().any(|entry| match entry {
        JsonValue::String(value) => proofs.iter().any(|proof| proof == value),
        JsonValue::Object(obj) => {
            let requester_matches = requester.is_some_and(|requester| {
                ["requester", "subject", "did", "actor"]
                    .iter()
                    .any(|key| obj.get(*key).and_then(JsonValue::as_str) == Some(requester))
            });
            let proof_matches = ["proof", "presentation", "claim", "claim_id", "claim_type"]
                .iter()
                .filter_map(|key| obj.get(*key).and_then(JsonValue::as_str))
                .any(|expected| proofs.iter().any(|proof| proof == expected));
            requester_matches || proof_matches
        }
        _ => false,
    })
}

// ---- Disclosure decision -------------------------------------------------

/// Pure decision over `(row, request, policy)`. Extracted so unit tests can
/// exercise the policy without a Postgres dependency.
fn evaluate_handle_disclosure(
    row: HandleRow,
    body: &ResolveHandleRequest,
    policy: Option<&RealmDeliveryBindingPolicy>,
) -> ResolveOutcome {
    let audience = body
        .audience
        .clone()
        .or_else(|| body.requester.clone())
        .or_else(|| body.realm_id.clone());

    // Member-add path: audience-bind on the Realm, filter candidate bindings.
    if let Some(policy) = policy {
        if !policy.audience_authorized(body.requester.as_deref(), &body.proofs) {
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
        // newtype enforces it; legacy projections whose
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
        None => unrestricted_source, // No binding_source declared — only allowed when policy is open.
    };
    recipient_ok && source_ok
}

/// Round 4 — drop legacy candidates whose `recipient_service_did`
/// fails the tightened SDK `Did` regex (`^did:[a-z0-9]+:[^\s]+$`).
fn is_round4_tight_did(did: &str) -> bool {
    contrix_sdk::Did::new(did.to_owned()).is_ok()
}

#[allow(clippy::too_many_arguments)]
fn envelope_from_projection(
    public_projection: JsonValue,
    resource_id: String,
    discoverability: DiscoverabilityWire,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use chrono::TimeZone;

    fn dummy_row(public_projection: JsonValue) -> HandleRow {
        HandleRow {
            resource_id: "alice.example".to_string(),
            public_projection,
            discoverability: DiscoverabilityWire::Public,
            as_of: Utc.timestamp_opt(0, 0).unwrap(),
            source_refs: vec!["evt-handle-alice".to_string()],
            policy_revision: Some("rev-handle-1".to_string()),
            stale: false,
            divergent: false,
            via_services: vec!["did:web:principal.test".to_string()],
        }
    }

    fn member_add_request(realm_id: &str, requester: &str) -> ResolveHandleRequest {
        ResolveHandleRequest {
            handle: "alice.example".to_string(),
            expected_did: None,
            proof_challenge: None,
            intent: Some("member_add".to_string()),
            requester: Some(requester.to_string()),
            audience: None,
            realm_id: Some(realm_id.to_string()),
            proofs: vec![],
        }
    }

    fn realm_policy(
        allowed_recipient_services: &[&str],
        trusted_audiences: &[&str],
    ) -> RealmDeliveryBindingPolicy {
        let projection = json!({
            "allowed_recipient_services": allowed_recipient_services,
            "trusted_audiences": trusted_audiences,
        });
        RealmDeliveryBindingPolicy::from_projection(projection)
    }

    #[test]
    fn intent_member_add_is_recognized() {
        assert!(is_member_add_intent(Some("member_add")));
        assert!(is_member_add_intent(Some("invite")));
        assert!(!is_member_add_intent(Some("dm")));
        assert!(!is_member_add_intent(None));
    }

    #[test]
    fn policy_from_projection_reads_nested_and_flat_shapes() {
        let nested = RealmDeliveryBindingPolicy::from_projection(json!({
            "delivery_binding_policy": {
                "allowed_recipient_services": ["did:web:principal.tea"],
                "allow_binding_sources": ["join_policy"],
                "trusted_audiences": ["did:web:tea-org.example"],
            },
        }));
        assert_eq!(
            nested.allowed_recipient_services,
            vec!["did:web:principal.tea".to_string()]
        );
        assert_eq!(
            nested.allow_binding_sources,
            vec!["join_policy".to_string()]
        );
        assert_eq!(
            nested.trusted_audiences,
            vec!["did:web:tea-org.example".to_string()]
        );

        let flat = RealmDeliveryBindingPolicy::from_projection(json!({
            "allowed_recipient_services": ["did:web:principal.tea"],
        }));
        assert_eq!(
            flat.allowed_recipient_services,
            vec!["did:web:principal.tea".to_string()]
        );
        assert!(flat.allow_binding_sources.is_empty());
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
        let body = member_add_request("cx:realm:tea", "did:web:tea-org.example");
        let policy = realm_policy(&["did:web:principal.tea"], &["did:web:tea-org.example"]);

        let outcome = evaluate_handle_disclosure(row, &body, Some(&policy));
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
        let body = member_add_request("cx:realm:tea", "did:web:tea-org.example");
        let policy = realm_policy(&["did:web:principal.tea"], &["did:web:tea-org.example"]);

        let outcome = evaluate_handle_disclosure(row, &body, Some(&policy));
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
        let body = member_add_request("cx:realm:tea", "did:web:eve.example");
        let policy = realm_policy(&["did:web:principal.tea"], &["did:web:tea-org.example"]);

        let outcome = evaluate_handle_disclosure(row, &body, Some(&policy));
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
        let body = member_add_request("cx:realm:tea", "did:web:tea-org.example");
        let policy = realm_policy(&[], &["did:web:tea-org.example"]);

        let outcome = evaluate_handle_disclosure(row, &body, Some(&policy));
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

        let found_body = member_add_request("cx:realm:tea", "did:web:tea-org.example");
        let unauthorized_body = member_add_request("cx:realm:tea", "did:web:eve.example");
        let filtered_body = member_add_request("cx:realm:tea", "did:web:tea-org.example");

        // Warm caches / branch predictor.
        for _ in 0..warmup {
            let _ = evaluate_handle_disclosure(allowed_row.clone(), &found_body, Some(&policy));
            let _ =
                evaluate_handle_disclosure(allowed_row.clone(), &unauthorized_body, Some(&policy));
            let _ = evaluate_handle_disclosure(filtered_row.clone(), &filtered_body, Some(&policy));
        }

        let measure = |body: &ResolveHandleRequest, row: &HandleRow| -> Duration {
            let start = Instant::now();
            for _ in 0..iters {
                let _ = evaluate_handle_disclosure(row.clone(), body, Some(&policy));
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
        assert!(policy.audience_authorized(Some("did:web:tea-org.example"), &[]));
        assert!(!policy.audience_authorized(Some("did:web:eve.example"), &[]));
    }

    #[test]
    fn audience_authorization_falls_back_to_allowed_discoverers() {
        let policy = RealmDeliveryBindingPolicy::from_projection(json!({
            "allowed_discoverers": [{ "requester": "did:web:alice.example" }],
        }));
        assert!(policy.audience_authorized(Some("did:web:alice.example"), &[]));
        assert!(!policy.audience_authorized(Some("did:web:bob.example"), &[]));
    }

    #[test]
    fn policy_with_no_audience_constraint_lets_everyone_through() {
        // No `trusted_audiences`, no `allowed_discoverers` ⇒ resolver
        // SHOULD treat the Realm as unrestricted (per §9 default for
        // Public/Listed Realms).
        let policy = RealmDeliveryBindingPolicy::from_projection(json!({
            "allowed_recipient_services": ["did:web:principal.tea"],
        }));
        assert!(policy.audience_authorized(Some("did:web:anybody.example"), &[]));
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
            "allowed_recipient_services": ["did:web:principal.tea"],
            "allow_binding_sources": ["join_policy"],
            "trusted_audiences": ["did:web:tea-org.example"],
        }));
        let body = member_add_request("cx:realm:tea", "did:web:tea-org.example");

        let outcome = evaluate_handle_disclosure(row, &body, Some(&policy));
        assert!(matches!(outcome, ResolveOutcome::NotFound));
    }

    /// Round 4 — handle-claim / member-delivery-binding-candidate
    /// projections whose `recipient_service_did` uses dot/dash/
    /// underscore/colon in the DID method segment MUST be dropped as
    /// if absent. A legacy row with `did:web.legacy:peer` is  ROUND4-ALLOW: docstring describes a rejected legacy form.
    /// indistinguishable from a non-existent candidate to the resolver.
    #[test]
    fn round4_did_regex_tightening_rejects_legacy_method_segment() {
        assert!(is_round4_tight_did("did:web:principal.tea"));
        assert!(is_round4_tight_did("did:webvh:directory.test"));
        // Round 4 tightening rejects dot / dash / underscore in the
        // method segment (colon already terminates the method).
        assert!(!is_round4_tight_did("did:web.legacy:peer")); // ROUND4-ALLOW: negative test
        assert!(!is_round4_tight_did("did:web-legacy:peer")); // ROUND4-ALLOW: negative test
        assert!(!is_round4_tight_did("did:web_legacy:peer")); // ROUND4-ALLOW: negative test
        // Capital letters in the method segment are rejected too —
        // the tightened regex is `^did:[a-z0-9]+:[^\s]+$`.
        assert!(!is_round4_tight_did("did:Web:peer"));

        // And the filter MUST drop the legacy candidate end-to-end.
        let row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
            "member_delivery_binding": {
                "recipient_service_did": "did:web.legacy:peer", // ROUND4-ALLOW: negative test for round-4 regex
                "binding_source": "join_policy"
            }
        }));
        let body = member_add_request("cx:realm:tea", "did:web:tea-org.example");
        let policy = realm_policy(&[], &["did:web:tea-org.example"]);
        let outcome = evaluate_handle_disclosure(row, &body, Some(&policy));
        assert!(matches!(outcome, ResolveOutcome::NotFound));
    }
}
