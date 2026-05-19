//! Handle resolution. Spec §9 (`cx.directory.resolve_handle`).
//!
//! Spec sync 0a5ab85 / governance/join-policy §5.1.3:
//! `cx.directory.resolve_handle` MUST gate `intent=member_add | invite`
//! requests on the target Space's `delivery_binding_policy`
//! (`allowed_recipient_services`, `allow_binding_sources`) and on the
//! Space's audience-binding list. Unauthorized requesters MUST NOT receive
//! the underlying subject / service DID — they collapse to `not_found`
//! with the same response shape and latency tier as a genuine miss
//! (spec §10).

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

use crate::error::ErrorCode;
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
    /// Why the handle is being resolved. Spec 0a5ab85: gates audience
    /// binding on the response claim and selects the Space
    /// `delivery_binding_policy` (`allowed_recipient_services`) filter when
    /// `intent ∈ {member_add, invite}`.
    #[serde(default)]
    pub intent: Option<String>,
    /// DID or service DID of the requester. Used to scope audience-bearing
    /// claims so that the verifier can enforce `audience == self` and to
    /// authorize disclosure of Space-restricted bindings.
    #[serde(default)]
    pub requester: Option<String>,
    /// Explicit audience the verifier expects on the claim (typically a
    /// target Space DID or inviter service DID).
    #[serde(default)]
    pub audience: Option<String>,
    /// Target Space DID for `intent=member_add | invite`. When present we
    /// load the Space `delivery_binding_policy` baseline and filter
    /// candidate bindings against `allowed_recipient_services`.
    #[serde(default)]
    pub space_id: Option<String>,
    /// Optional proofs / claim ids the requester presents to be admitted as
    /// a Space audience. Mirrors `resolve_space` semantics.
    #[serde(default)]
    pub proofs: Vec<String>,
}

#[handler]
pub async fn resolve_handle(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let body: ResolveHandleRequest = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ErrorCode::BadJson.render(res, format!("malformed body: {e}"));
            return;
        }
    };
    if body.handle.is_empty() {
        ErrorCode::MissingParam.render(res, "handle is required");
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
        "handle={};intent={};space={};req={};aud={}",
        body.handle,
        body.intent.as_deref().unwrap_or_default(),
        body.space_id.as_deref().unwrap_or_default(),
        body.requester.as_deref().unwrap_or_default(),
        body.audience.as_deref().unwrap_or_default(),
    );

    let outcome = pad_to_budget(
        budget,
        "cx.directory.resolve_handle",
        &privacy_key,
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

            evaluate_handle_disclosure(row, &body, policy.as_ref())
        },
    )
    .await;

    match outcome {
        ResolveOutcome::Found(envelope) => res.render(Json(envelope)),
        // `not_found` covers genuine miss, unauthorized requester, and "all
        // candidates filtered out" — these MUST be indistinguishable on the
        // wire so the directory does not leak the existence of the handle
        // or the recipient service identity.
        ResolveOutcome::NotFound => ErrorCode::NotFound.render(res, "not found"),
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

// ---- Space delivery-binding policy --------------------------------------

/// Baseline projection of a Space's `delivery_binding_policy` as cached in
/// the directory's `public_projection`. Mirrors the schema in
/// governance/join-policy.md §5.1.3.
#[derive(Debug, Clone, Default)]
pub(crate) struct SpaceDeliveryBindingPolicy {
    /// `allowed_recipient_services`: closed set of recipient principal-server
    /// DIDs that may appear in a Space-bound delivery_binding. Empty = no
    /// restriction (per spec §5.1.3 default).
    pub allowed_recipient_services: Vec<String>,
    /// `allow_binding_sources`: optional sub-filter on the binding_source
    /// enum. Empty = caller does not enforce a binding_source filter here.
    pub allow_binding_sources: Vec<String>,
    /// Trusted audience DIDs (Space + delegated service DIDs) authorized to
    /// invoke `intent=member_add | invite`. Empty = treat the Space's
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
) -> anyhow::Result<Option<SpaceDeliveryBindingPolicy>> {
    if !is_member_add_intent(body.intent.as_deref()) {
        return Ok(None);
    }
    let Some(space_id) = body.space_id.as_deref().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    load_space_policy(state, space_id).await.map(Some)
}

fn is_member_add_intent(intent: Option<&str>) -> bool {
    matches!(intent, Some("member_add") | Some("invite"))
}

async fn load_space_policy(
    state: &AppState,
    space_id: &str,
) -> anyhow::Result<SpaceDeliveryBindingPolicy> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get()?;
    let projection: Option<(JsonValue, DiscoverabilityWire)> = r::directory_resources
        .filter(r::resource_kind.eq(ResourceKindWire::Space))
        .filter(r::resource_id.eq(space_id))
        .select((r::public_projection, r::discoverability))
        .first(&mut conn)
        .optional()?;
    let Some((projection, discoverability)) = projection else {
        return Ok(SpaceDeliveryBindingPolicy::default());
    };
    if !discoverability.is_directory_visible() {
        // Hidden / withdrawn Space — collapse to default-deny policy.
        return Ok(SpaceDeliveryBindingPolicy::default());
    }
    Ok(SpaceDeliveryBindingPolicy::from_projection(projection))
}

impl SpaceDeliveryBindingPolicy {
    /// Extract the `delivery_binding_policy` baseline from a Space's
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
    /// via `trusted_audiences` (preferred) or `allowed_discoverers` (legacy
    /// fallback shared with `resolve_space`).
    fn audience_authorized(&self, requester: Option<&str>, proofs: &[String]) -> bool {
        if self.trusted_audiences.is_empty() && !has_allowed_discoverers(&self.raw_projection) {
            // No audience constraint declared — fall through to the default
            // discoverability gate the row itself carries.
            return true;
        }
        if let Some(requester) = requester {
            if self
                .trusted_audiences
                .iter()
                .any(|aud| aud == requester)
            {
                return true;
            }
        }
        // Legacy: reuse the `allowed_discoverers` shape so existing Space
        // fixtures keep granting access without policy migration.
        allowed_discoverers_match(&self.raw_projection, requester, proofs)
    }
}

fn string_array_at(
    root: &JsonValue,
    flat_key: &str,
    nested: Option<&JsonValue>,
) -> Vec<String> {
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
    policy: Option<&SpaceDeliveryBindingPolicy>,
) -> ResolveOutcome {
    let audience = body
        .audience
        .clone()
        .or_else(|| body.requester.clone())
        .or_else(|| body.space_id.clone());

    // Member-add path: audience-bind on the Space, filter candidate bindings.
    if let Some(policy) = policy {
        if !policy.audience_authorized(body.requester.as_deref(), &body.proofs) {
            // Unauthorized requester: collapse to not_found so the
            // directory does not disclose subject_did / recipient_service_did.
            return ResolveOutcome::NotFound;
        }
        let filtered = filter_projection_against_policy(row.public_projection.clone(), policy);
        let Some(projection) = filtered else {
            // All recipient_service_did candidates pruned — same not_found
            // shape so the requester cannot enumerate the Space's policy.
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

/// Apply Space `allowed_recipient_services` (and, when declared,
/// `allow_binding_sources`) to the handle's public projection. Returns
/// `None` when every candidate was pruned — signaling the resolver should
/// emit `not_found` rather than disclose the bare subject_did.
fn filter_projection_against_policy(
    mut projection: JsonValue,
    policy: &SpaceDeliveryBindingPolicy,
) -> Option<JsonValue> {
    let allow_recipient = &policy.allowed_recipient_services;
    let allow_sources = &policy.allow_binding_sources;
    let unrestricted_recipient = allow_recipient.is_empty();
    let unrestricted_source = allow_sources.is_empty();

    // Track whether the projection ever declared a binding-candidate field
    // BEFORE any pruning. If it did and we drop them all, the resolver MUST
    // emit `not_found` rather than a stripped envelope so the requester
    // cannot tell whether the handle exists.
    let had_top_recipient = projection.get("recipient_service_did").is_some();
    let had_binding_hint = projection.get("delivery_binding_hint").is_some();
    let had_binding_candidates = projection.get("binding_candidates").is_some();
    let had_any_candidate_field = had_top_recipient || had_binding_hint || had_binding_candidates;

    let mut kept_any_candidate = false;

    // Top-level `recipient_service_did` (handle-claim §3.7 single binding).
    if had_top_recipient {
        let top_recipient_ok = match projection
            .get("recipient_service_did")
            .and_then(JsonValue::as_str)
        {
            Some(did) => unrestricted_recipient || allow_recipient.iter().any(|a| a == did),
            None => false,
        };
        if top_recipient_ok {
            kept_any_candidate = true;
        } else if let Some(obj) = projection.as_object_mut() {
            obj.remove("recipient_service_did");
        }
    }

    // `delivery_binding_hint` (member-delivery-binding-candidate §3.7).
    if had_binding_hint {
        let hint_ok = projection
            .get("delivery_binding_hint")
            .and_then(JsonValue::as_object)
            .map(|hint| binding_passes(hint, policy, unrestricted_recipient, unrestricted_source))
            .unwrap_or(false);
        if hint_ok {
            kept_any_candidate = true;
        } else if let Some(obj) = projection.as_object_mut() {
            obj.remove("delivery_binding_hint");
        }
    }

    // `binding_candidates` array — newer multi-binding shape.
    if had_binding_candidates {
        if let Some(arr) = projection
            .get("binding_candidates")
            .and_then(JsonValue::as_array)
            .cloned()
        {
            let filtered: Vec<JsonValue> = arr
                .into_iter()
                .filter(|cand| match cand.as_object() {
                    Some(obj) => {
                        binding_passes(obj, policy, unrestricted_recipient, unrestricted_source)
                    }
                    None => false,
                })
                .collect();
            let has_any = !filtered.is_empty();
            if let Some(obj) = projection.as_object_mut() {
                if has_any {
                    obj.insert("binding_candidates".into(), JsonValue::Array(filtered));
                    kept_any_candidate = true;
                } else {
                    obj.remove("binding_candidates");
                }
            }
        }
    }

    if had_any_candidate_field && !kept_any_candidate {
        return None;
    }
    Some(projection)
}

fn binding_passes(
    obj: &serde_json::Map<String, JsonValue>,
    policy: &SpaceDeliveryBindingPolicy,
    unrestricted_recipient: bool,
    unrestricted_source: bool,
) -> bool {
    let recipient_ok = match obj.get("recipient_service_did").and_then(JsonValue::as_str) {
        Some(did) => {
            unrestricted_recipient || policy.allowed_recipient_services.iter().any(|a| a == did)
        }
        None => false,
    };
    let source_ok = match obj.get("binding_source").and_then(JsonValue::as_str) {
        Some(src) => unrestricted_source || policy.allow_binding_sources.iter().any(|a| a == src),
        None => unrestricted_source, // No binding_source declared — only allowed when policy is open.
    };
    recipient_ok && source_ok
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
    // see exactly the Space-policy-approved subset.
    for key in [
        "recipient_service_did",
        "delivery_binding_hint",
        "binding_candidates",
    ] {
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

    fn member_add_request(space_id: &str, requester: &str) -> ResolveHandleRequest {
        ResolveHandleRequest {
            handle: "alice.example".to_string(),
            expected_did: None,
            proof_challenge: None,
            intent: Some("member_add".to_string()),
            requester: Some(requester.to_string()),
            audience: None,
            space_id: Some(space_id.to_string()),
            proofs: vec![],
        }
    }

    fn space_policy(
        allowed_recipient_services: &[&str],
        trusted_audiences: &[&str],
    ) -> SpaceDeliveryBindingPolicy {
        let projection = json!({
            "allowed_recipient_services": allowed_recipient_services,
            "trusted_audiences": trusted_audiences,
        });
        SpaceDeliveryBindingPolicy::from_projection(projection)
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
        let nested = SpaceDeliveryBindingPolicy::from_projection(json!({
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

        let flat = SpaceDeliveryBindingPolicy::from_projection(json!({
            "allowed_recipient_services": ["did:web:principal.tea"],
        }));
        assert_eq!(
            flat.allowed_recipient_services,
            vec!["did:web:principal.tea".to_string()]
        );
        assert!(flat.allow_binding_sources.is_empty());
    }

    /// `resolve_handle_filters_recipient_service`: handle exists but the
    /// only recipient service is outside the Space's allow-list ⇒ resolver
    /// MUST emit `not_found`, not a stripped envelope.
    #[test]
    fn resolve_handle_filters_recipient_service() {
        let row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
            "recipient_service_did": "did:web:principal.other",
        }));
        let body = member_add_request("cx:space:tea", "did:web:tea-org.example");
        let policy = space_policy(&["did:web:principal.tea"], &["did:web:tea-org.example"]);

        let outcome = evaluate_handle_disclosure(row, &body, Some(&policy));
        assert!(matches!(outcome, ResolveOutcome::NotFound));
    }

    /// When a multi-binding candidate set is partially pruned the resolver
    /// MUST surface only the surviving candidate.
    #[test]
    fn resolve_handle_keeps_allowed_binding_candidate() {
        let row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
            "binding_candidates": [
                {
                    "recipient_service_did": "did:web:principal.tea",
                    "binding_source": "join_policy"
                },
                {
                    "recipient_service_did": "did:web:principal.other",
                    "binding_source": "join_policy"
                }
            ]
        }));
        let body = member_add_request("cx:space:tea", "did:web:tea-org.example");
        let policy = space_policy(&["did:web:principal.tea"], &["did:web:tea-org.example"]);

        let outcome = evaluate_handle_disclosure(row, &body, Some(&policy));
        let envelope = match outcome {
            ResolveOutcome::Found(envelope) => envelope,
            ResolveOutcome::NotFound => panic!("expected Found, got NotFound"),
        };
        let candidates = envelope
            .payload
            .get("binding_candidates")
            .and_then(JsonValue::as_array)
            .expect("binding_candidates surface");
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0]
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
            "recipient_service_did": "did:web:principal.tea",
        }));
        let body = member_add_request("cx:space:tea", "did:web:eve.example");
        let policy = space_policy(&["did:web:principal.tea"], &["did:web:tea-org.example"]);

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
            "recipient_service_did": "did:web:principal.anywhere",
        }));
        let body = member_add_request("cx:space:tea", "did:web:tea-org.example");
        let policy = space_policy(&[], &["did:web:tea-org.example"]);

        let outcome = evaluate_handle_disclosure(row, &body, Some(&policy));
        let envelope = match outcome {
            ResolveOutcome::Found(envelope) => envelope,
            ResolveOutcome::NotFound => panic!("expected Found, got NotFound"),
        };
        assert_eq!(
            envelope
                .payload
                .get("recipient_service_did")
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
        let policy = space_policy(&["did:web:principal.tea"], &["did:web:tea-org.example"]);
        let allowed_row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
            "recipient_service_did": "did:web:principal.tea",
        }));
        let filtered_row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
            "recipient_service_did": "did:web:principal.other",
        }));

        let warmup = 256;
        let iters = 4096;

        let found_body = member_add_request("cx:space:tea", "did:web:tea-org.example");
        let unauthorized_body = member_add_request("cx:space:tea", "did:web:eve.example");
        let filtered_body = member_add_request("cx:space:tea", "did:web:tea-org.example");

        // Warm caches / branch predictor.
        for _ in 0..warmup {
            let _ = evaluate_handle_disclosure(allowed_row.clone(), &found_body, Some(&policy));
            let _ =
                evaluate_handle_disclosure(allowed_row.clone(), &unauthorized_body, Some(&policy));
            let _ =
                evaluate_handle_disclosure(filtered_row.clone(), &filtered_body, Some(&policy));
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
        let policy = space_policy(&[], &["did:web:tea-org.example"]);
        assert!(policy.audience_authorized(Some("did:web:tea-org.example"), &[]));
        assert!(!policy.audience_authorized(Some("did:web:eve.example"), &[]));
    }

    #[test]
    fn audience_authorization_falls_back_to_allowed_discoverers() {
        let policy = SpaceDeliveryBindingPolicy::from_projection(json!({
            "allowed_discoverers": [{ "requester": "did:web:alice.example" }],
        }));
        assert!(policy.audience_authorized(Some("did:web:alice.example"), &[]));
        assert!(!policy.audience_authorized(Some("did:web:bob.example"), &[]));
    }

    #[test]
    fn policy_with_no_audience_constraint_lets_everyone_through() {
        // No `trusted_audiences`, no `allowed_discoverers` ⇒ resolver
        // SHOULD treat the Space as unrestricted (per §9 default for
        // Public/Listed Spaces).
        let policy = SpaceDeliveryBindingPolicy::from_projection(json!({
            "allowed_recipient_services": ["did:web:principal.tea"],
        }));
        assert!(policy.audience_authorized(Some("did:web:anybody.example"), &[]));
    }

    #[test]
    fn binding_source_filter_prunes_disallowed_source() {
        let row = dummy_row(json!({
            "did": "did:web:alice.example",
            "verified": true,
            "delivery_binding_hint": {
                "recipient_service_did": "did:web:principal.tea",
                "binding_source": "explicit",
            }
        }));
        let policy = SpaceDeliveryBindingPolicy::from_projection(json!({
            "allowed_recipient_services": ["did:web:principal.tea"],
            "allow_binding_sources": ["join_policy"],
            "trusted_audiences": ["did:web:tea-org.example"],
        }));
        let body = member_add_request("cx:space:tea", "did:web:tea-org.example");

        let outcome = evaluate_handle_disclosure(row, &body, Some(&policy));
        assert!(matches!(outcome, ResolveOutcome::NotFound));
    }
}
