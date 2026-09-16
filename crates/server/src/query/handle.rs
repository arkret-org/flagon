//! Handle resolution. Spec §9 (`ak.find.directory.read.resolve_handle.v1`).
//!
//! Handle resolution returns the canonical account identity. The account's
//! `station_id` is the routing authority; the directory does not synthesize or
//! disclose a separate durable delivery binding.
//!
//! §9.0.1: `proofs[]` carries the per-object-family requester_id proof bound to
//! `ak.directory_resolve_handle_request_proof.v1`. A signature minted under any
//! other directory request family's context cannot verify here. Verification
//! lives in [`crate::query::requester_proof`] and its failure collapses to the
//! same blinded `not_found` inside the latency budget.

use arkret_sdk::{
    AccountId, DidCoreId, DirectoryHandleResolutionOutcome, DirectoryResolveHandleRequestBody,
    Handle, RealmId,
};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde_json::{Value as JsonValue, json};

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
    pub expected_account_id: Option<AccountId>,
    pub proof_challenge: Option<String>,
    pub claim_presentations: Vec<arkret_sdk::DirectoryRestrictedClaimPresentation>,
    /// Why the handle is being resolved. Retained in the signed request and
    /// privacy key even though routing now comes from the resolved AccountId.
    pub intent: Option<String>,
    /// Stable Arkret identity of the requester. Used to verify signed requests
    /// and authorize restricted handle disclosure.
    pub requester_id: Option<DidCoreId>,
    /// Explicit audience the verifier expects on the claim (typically a
    /// target Realm DID or inviter service DID).
    pub audience: Option<String>,
    /// Optional target Realm carried by the request context.
    pub realm_id: Option<RealmId>,
}

impl From<DirectoryResolveHandleRequestBody> for ResolveHandleRequestView {
    fn from(body: DirectoryResolveHandleRequestBody) -> Self {
        Self {
            handle: body.handle,
            expected_account_id: body.expected_account_id,
            proof_challenge: body.proof_challenge,
            claim_presentations: body.claim_presentations,
            intent: body.intent.map(|intent| intent.to_string()),
            requester_id: body.requester_id,
            audience: body.audience,
            realm_id: body.realm_id,
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
/// the spec reserves that well-known path for signed issuer_id claims, while
/// teabay is a resolver/index and cannot answer as the handle issuer_id.
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
        expected_account_id: None,
        proof_challenge: None,
        claim_presentations: Vec::new(),
        intent: None,
        requester_id: None,
        audience: None,
        realm_id: None,
    };

    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    let requester_ip = req.remote_addr().to_string();
    let requester_ip_hash = super::requester_ip_hash(&requester_ip);
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
            evaluate_handle_disclosure(row, &body, &VerifiedRestrictedClaims::default())
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
    // §9.0.1 requester_id proof. The proof binds the whole unsigned request body,
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
    // — hash the requester_id IP into the privacy key so the same handle
    // + intent + requester_id from two different IPs lands on independent
    // latency tiers (an attacker can no longer share probes across
    // hosts to disambiguate a slow miss from a slow hit).
    let requester_ip = req.remote_addr().to_string();
    let requester_ip_hash = super::requester_ip_hash(&requester_ip);
    let privacy_key = format!(
        "handle={};expected={};intent={};realm={};req={};aud={};claims={};proofs={};iph={}",
        body.handle,
        body.expected_account_id
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        body.intent.as_deref().unwrap_or_default(),
        body.realm_id
            .as_ref()
            .map(RealmId::as_str)
            .unwrap_or_default(),
        body.requester_id
            .as_ref()
            .map(DidCoreId::as_str)
            .unwrap_or_default(),
        body.audience.as_deref().unwrap_or_default(),
        body.claim_presentations.len(),
        proof_count,
        requester_ip_hash,
    );

    let outcome = pad_to_budget_observed(
        budget,
        arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_HANDLE_V1,
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
                tracing::debug!(%reason, "resolve_handle requester_id proof rejected");
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

            evaluate_handle_disclosure(row, &body, &verified_claims)
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
        // `not_found` covers genuine misses and unauthorized requesters. These
        // MUST be indistinguishable on the wire so the directory does not leak
        // the existence of a restricted handle.
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
        body.requester_id.as_ref().map(DidCoreId::as_str),
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
    station_id: String,
    public_projection: JsonValue,
    discoverability: DiscoverabilityDb,
    as_of: DateTime<Utc>,
    source_refs: crate::source_refs::CommittedEventRefs,
    policy_revision: String,
    stale: bool,
    divergent: bool,
    via_services: Vec<DidCoreId>,
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
            r::station_id,
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

// ---- Disclosure decision -------------------------------------------------

/// Pure disclosure decision extracted so unit tests can exercise the privacy
/// policy without a Postgres dependency.
fn evaluate_handle_disclosure(
    row: HandleRow,
    body: &ResolveHandleRequestView,
    verified_claims: &VerifiedRestrictedClaims,
) -> ResolveOutcome {
    if body.expected_account_id.as_ref().is_some_and(|expected| {
        row.public_projection
            .get("subject_id")
            .and_then(JsonValue::as_str)
            != Some(expected.principal_id.as_str())
            || row.station_id != expected.station_id.as_str()
    }) {
        return ResolveOutcome::NotFound;
    }

    let audience = body
        .audience
        .clone()
        .or_else(|| {
            body.requester_id
                .as_ref()
                .map(|requester_id| requester_id.as_str().to_owned())
        })
        .or_else(|| {
            body.realm_id
                .as_ref()
                .map(|realm_id| realm_id.as_str().to_owned())
        });

    if matches!(row.discoverability, DiscoverabilityDb::Restricted)
        && !matches_allowed_discoverers(
            &row.public_projection,
            body.requester_id.as_ref().map(DidCoreId::as_str),
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

    let envelope = envelope_from_projection(
        row.public_projection,
        row.resource_id,
        row.station_id,
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

#[allow(clippy::too_many_arguments)]
fn envelope_from_projection(
    public_projection: JsonValue,
    resource_id: String,
    station_id: String,
    discoverability: DiscoverabilityDb,
    as_of: DateTime<Utc>,
    source_refs: crate::source_refs::CommittedEventRefs,
    policy_revision: String,
    stale: bool,
    divergent: bool,
    via_services: Vec<DidCoreId>,
    expires_at: DateTime<Utc>,
    audience: Option<String>,
) -> ResultEnvelope {
    let principal_id = public_projection
        .get("subject_id")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .to_string();
    let claims = public_projection
        .get("claims")
        .cloned()
        .unwrap_or(JsonValue::Null);
    let mut payload = json!({
        "principal_id": principal_id,
        "station_id": station_id,
        "handle": resource_id,
        "verified": public_projection.get("verified").and_then(JsonValue::as_bool).unwrap_or(false),
        "claims": claims,
        "discoverability": discoverability.as_pg(),
        "expires_at": expires_at,
    });
    // Preserve the signed request's audience context for internal policy
    // consumers. Account routing itself is represented by principal_id plus
    // station_id and never by a separate durable delivery binding.
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
    let principal_id_raw = payload
        .get("principal_id")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| "handle projection principal_id is missing".to_owned())?
        .to_owned();
    let principal_id = DidCoreId::new(principal_id_raw)
        .map_err(|error| format!("handle projection principal_id is invalid: {error}"))?;
    let station_id_raw = payload
        .get("station_id")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| "handle projection station_id is missing".to_owned())?
        .to_owned();
    let station_id = DidCoreId::new(station_id_raw)
        .map_err(|error| format!("handle projection station_id is invalid: {error}"))?;
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
    let expires_at = payload
        .get("expires_at")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| format!("handle projection expires_at is invalid: {error}"))?;
    Ok(DirectoryHandleResolutionOutcome {
        account_id: arkret_sdk::AccountId::new(principal_id, station_id),
        handle,
        verified,
        claims,
        source_refs: super::parse_source_refs(envelope.source_refs)?,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn dummy_row(public_projection: JsonValue) -> HandleRow {
        HandleRow {
            resource_id: "alice:example.com".to_string(),
            station_id: "ak:did_core:web:station.test".to_string(),
            public_projection,
            discoverability: DiscoverabilityDb::Public,
            as_of: Utc.timestamp_opt(0, 0).unwrap(),
            source_refs: vec![crate::source_refs::fixture_committed_event_ref()].into(),
            policy_revision: "rev-handle-1".to_string(),
            stale: false,
            divergent: false,
            via_services: vec![DidCoreId::new("ak:did_core:web:principal.test").unwrap()],
            expires_at: Utc.timestamp_opt(3_600, 0).unwrap(),
        }
    }

    fn request(requester_id: &str) -> ResolveHandleRequestView {
        ResolveHandleRequestView {
            handle: "alice:example.com".to_string(),
            expected_account_id: None,
            proof_challenge: None,
            claim_presentations: Vec::new(),
            intent: Some("member_add".to_string()),
            requester_id: Some(DidCoreId::new(requester_id).unwrap()),
            audience: None,
            realm_id: Some(
                RealmId::new("ak:realm:ASrEhTMQSRXph9wD98UfShBx6MNM7ISQiBIDT0Ayiozq").unwrap(),
            ),
        }
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
    fn expected_account_id_must_match_resolved_account() {
        let row = dummy_row(json!({
            "subject_id": "ak:did_core:web:alice.example",
            "verified": true,
        }));
        let mut body = request("ak:did_core:web:tea-org.example");
        body.expected_account_id = Some(AccountId::new(
            DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.test").unwrap(),
        ));

        let outcome = evaluate_handle_disclosure(row, &body, &VerifiedRestrictedClaims::default());
        assert!(matches!(outcome, ResolveOutcome::NotFound));
    }

    #[test]
    fn matching_expected_account_id_preserves_resolution() {
        let row = dummy_row(json!({
            "subject_id": "ak:did_core:web:alice.example",
            "verified": true,
        }));
        let mut body = request("ak:did_core:web:tea-org.example");
        body.expected_account_id = Some(AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.test").unwrap(),
        ));

        let outcome = evaluate_handle_disclosure(row, &body, &VerifiedRestrictedClaims::default());
        assert!(matches!(outcome, ResolveOutcome::Found(_)));
    }

    #[test]
    fn resolution_returns_principal_and_station_as_account_id() {
        let row = dummy_row(json!({
            "subject_id": "ak:did_core:web:alice.example",
            "verified": true,
        }));
        let body = request("ak:did_core:web:tea-org.example");

        let envelope =
            match evaluate_handle_disclosure(row, &body, &VerifiedRestrictedClaims::default()) {
                ResolveOutcome::Found(envelope) => envelope,
                ResolveOutcome::NotFound => panic!("expected public handle resolution"),
            };
        let outcome = handle_resolution_from_envelope(envelope).unwrap();
        assert_eq!(
            outcome.account_id.principal_id.as_str(),
            "ak:did_core:web:alice.example"
        );
        assert_eq!(
            outcome.account_id.station_id.as_str(),
            "ak:did_core:web:station.test"
        );
    }

    #[test]
    fn restricted_handle_accepts_verified_claim_presentation() {
        let issuer_id =
            arkret_sdk::DidCoreId::new("ak:did_core:web:issuer_id.example".to_owned()).unwrap();
        let org = arkret_sdk::DidCoreId::new("ak:did_core:web:acme.example".to_owned()).unwrap();
        let requester_id =
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap();
        let claim = crate::filter::discoverers::organization_membership_claim(
            "claim-1",
            requester_id.clone(),
            issuer_id.clone(),
            org.clone(),
            vec!["member".to_owned()],
        );
        let verified_claims = VerifiedRestrictedClaims::for_test(vec![claim]);
        let mut row = dummy_row(json!({
            "subject_id": requester_id.as_str(),
            "verified": true,
            "allowed_discoverers": [{
                "type": "claim",
                "claim_kind": "organization_membership",
                "issuer_id": issuer_id.as_str(),
                "organization_id": org.as_str(),
            }],
        }));
        row.discoverability = DiscoverabilityDb::Restricted;
        let body = ResolveHandleRequestView {
            handle: "alice:example.com".to_owned(),
            expected_account_id: None,
            proof_challenge: None,
            claim_presentations: Vec::new(),
            intent: Some("lookup".to_owned()),
            requester_id: Some(requester_id.clone()),
            audience: None,
            realm_id: None,
        };

        let outcome = evaluate_handle_disclosure(row, &body, &verified_claims);
        assert!(matches!(outcome, ResolveOutcome::Found(_)));
    }

    #[test]
    fn restricted_handle_rejects_unverified_requester() {
        let mut row = dummy_row(json!({
            "subject_id": "ak:did_core:web:alice.example",
            "verified": true,
            "allowed_discoverers": [{
                "type": "did",
                "did": "ak:did_core:web:trusted.example",
            }],
        }));
        row.discoverability = DiscoverabilityDb::Restricted;
        let body = request("ak:did_core:web:eve.example");

        let outcome = evaluate_handle_disclosure(row, &body, &VerifiedRestrictedClaims::default());
        assert!(matches!(outcome, ResolveOutcome::NotFound));
    }

    #[test]
    fn invite_only_and_secret_handles_remain_hidden() {
        for discoverability in [DiscoverabilityDb::InviteOnly, DiscoverabilityDb::Secret] {
            let mut row = dummy_row(json!({
                "subject_id": "ak:did_core:web:alice.example",
                "verified": true,
            }));
            row.discoverability = discoverability;
            let body = request("ak:did_core:web:trusted.example");

            let outcome =
                evaluate_handle_disclosure(row, &body, &VerifiedRestrictedClaims::default());
            assert!(matches!(outcome, ResolveOutcome::NotFound));
        }
    }
}
