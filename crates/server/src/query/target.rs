//! Object-address resolve — R3.3 (AKP-0011, arkret-spec @ cced4b8),
//! `ak.find.directory.query.resolve_target`.
//!
//! This is the object-level generalization of
//! [`crate::query::realm::resolve_realm`]. A single client-agnostic shareable
//! address (`web+arkret:` URI form OR HTTPS-landing fragment form) points at a
//! Realm, a Strand inside a Realm, or a Message inside a Strand; this endpoint
//! parses the address, resolves the target, and returns a `target_kind` +
//! (`realm_preview` | `object_preview`) + `join_rule` + the §9.1 common fields.
//!
//! ## Delegation invariant (normative)
//!
//! Realm resolution MUST NOT be reinvented here. The realm branch DELEGATES to
//! [`crate::query::realm::resolve_realm_visible`] so the canonical `realm_id`,
//! the `realm_preview` payload, `join_candidates`, and the hidden/withdrawn/unknown
//! → blinded `not_found` collapse stay byte-for-byte identical to
//! `resolve_realm`.
//!
//! ## Token target binding (security-critical)
//!
//! When the address carries `lt=invite&tok=<token>` (or the request body
//! supplies `token`), the token's own signed payload carries an authoritative
//! [`TargetDescriptor`](arkret_sdk::models::TargetDescriptor). We:
//!   1. parse the address → [`ParsedAddress`](arkret_sdk::models::ParsedAddress),
//!   2. build a `TargetDescriptor` from the address; for an ALIAS realm we normalize via the realm
//!      resolution to obtain the canonical `realm_id` and `set_realm_id`,
//!   3. verify the token's detached Ed25519 JWS over the canonical token payload and extract its
//!      embedded `target_descriptor`,
//!   4. call [`verify_token_target`](arkret_sdk::models::verify_token_target), which recomputes &
//!      compares the `sha256:` digest. `via` / `action` / `tok` / `lt` are NOT in the digest, so a
//!      token minted for object A can never be replayed onto a different object B (scope-confusion
//!      defence).
//!
//! On ANY mismatch — bad token JSON, invalid signature, expired token,
//! missing/empty audience, digest mismatch, alias-vs-token `realm_id` mismatch,
//! or an alias that cannot be resolved to a canonical id — we collapse to the
//! SAME blinded `not_found` as an invite/restricted/secret resource for an
//! unauthorized requester. The unauthorized and the nonexistent cases are byte-
//! AND timing-indistinguishable (shared latency floor + jitter + stochastic
//! resolve jitter).
use arkret_sdk::identity::DidKeyResolver;
use arkret_sdk::jws::verify_jws_ed25519 as sdk_verify_jws_ed25519;
use arkret_sdk::models::{
    LinkType, ParsedAddress, RealmRef, TargetDescriptor, parse_address, target_digest,
    verify_token_target,
};
use arkret_sdk::{
    DirectoryResolveTargetRequestBody as SdkDirectoryResolveTargetRequestBody,
    DirectoryTargetResolutionOutcome, EventId, MessageId, NonEmptyString, ObjectPreview,
    ObjectPreviewId, RealmPreview, StrandId, TargetKind, canonical,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeZone, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};

use crate::did_resolver::{did_method_allowed, did_resolver_chain};
use crate::error::ApiErrorCode;
use crate::filter::discoverers::{
    VerifiedRestrictedClaims, matches_allowed_discoverers, verify_restricted_claim_presentations,
};
use crate::filter::enumeration::{LatencyBudget, pad_to_budget_observed};
use crate::query::rate_limit::{apply_resolve_response_jitter, enforce_resolve_rate_limit};
use crate::query::realm::resolve_realm_visible;
use crate::state::AppState;

/// Dashed metric op label for this surface.
const OP: &str = "resolve-target";

#[handler]
pub async fn resolve_target(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let _query_timer = state.metrics().query_timer(OP);

    let body: SdkDirectoryResolveTargetRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(e) => {
            state.metrics().record_query_outcome(OP, "bad_json");
            ApiErrorCode::BadJson.render(res, format!("malformed resolve-target body: {e}"));
            return;
        }
    };

    if body.address.trim().is_empty() {
        state.metrics().record_query_outcome(OP, "bad_json");
        ApiErrorCode::MissingParam.render(res, "address required");
        return;
    }

    // Rate-limit keyed on the raw address (mirrors resolve_realm keying on the
    // resolve key) so a single address cannot be probed at unbounded speed.
    if !enforce_resolve_rate_limit(req, res, &state, body.address.as_str()) {
        state.metrics().record_query_outcome(OP, "rate_limited");
        return;
    }

    let requester = body.requester.as_ref().map(|d| d.as_str().to_owned());
    let verified_claims = verified_restricted_claims_for_target_query(
        &state,
        requester.as_deref(),
        body.proof_challenge.as_deref(),
        &body.claim_presentations,
    );
    // The address carries the token via `tok=`; the request body MAY also carry
    // it explicitly. The body wins when both are present.
    let token = body.token.clone();

    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    // The privacy key steers the deterministic per-request latency tier; bundle
    // every input that changes the visible outcome so repeated probes from one
    // origin land on a stable tier without leaking hit/miss.
    let privacy_key = format!(
        "addr={};req={};tok={};claims={}",
        body.address,
        requester.as_deref().unwrap_or_default(),
        token.as_deref().map(|_| "1").unwrap_or("0"),
        body.claim_presentations.len(),
    );

    let outcome = pad_to_budget_observed(
        budget,
        "ak.find.directory.query.resolve_target",
        &privacy_key,
        |target| state.metrics().record_anti_enum_pad(OP, target),
        resolve(
            &state,
            &body.address,
            requester.as_deref(),
            &verified_claims,
            token.as_deref(),
        ),
    )
    .await;

    // P5 — stochastic anti-enumeration jitter, identical to resolve_realm /
    // resolve_handle, so the unauthorized vs nonexistent timing channel is shut.
    apply_resolve_response_jitter().await;

    match outcome {
        ResolveOutcome::Ok(response) => {
            state.metrics().record_query_outcome(OP, "ok");
            res.render(Json(response));
        }
        // Token bound to a different object / expired / malformed / alias
        // mismatch → token-reject, surfaced to the SAME blinded not_found.
        ResolveOutcome::TokenReject => {
            state.metrics().record_query_outcome(OP, "token_reject");
            ApiErrorCode::NotFound.render(res, "not found");
        }
        // Hidden / withdrawn / unknown / unparseable address — blinded miss.
        ResolveOutcome::NotFound => {
            state.metrics().record_query_outcome(OP, "not_found");
            ApiErrorCode::NotFound.render(res, "not found");
        }
        ResolveOutcome::Error(message) => {
            state.metrics().record_query_outcome(OP, "internal_error");
            ApiErrorCode::InternalError.render(res, message);
        }
    }
}

fn verified_restricted_claims_for_target_query(
    state: &AppState,
    requester: Option<&str>,
    proof_challenge: Option<&str>,
    presentations: &[arkret_sdk::DirectoryRestrictedClaimPresentation],
) -> VerifiedRestrictedClaims {
    verify_restricted_claim_presentations(
        presentations,
        requester,
        proof_challenge,
        &state.config().service_id,
        &state.config().accepted_did_methods,
        crate::egress::local_development_enabled(state.config().development_mode),
    )
    .unwrap_or_default()
}

/// The internal resolve outcome. `TokenReject` and `NotFound` BOTH render the
/// same blinded `not_found` wire response — the split exists ONLY so the
/// `/metrics` surface can distinguish a scope-confusion / token failure from a
/// genuine miss for operator dashboards. The wire bytes are identical.
enum ResolveOutcome {
    Ok(Box<DirectoryTargetResolutionOutcome>),
    TokenReject,
    NotFound,
    Error(String),
}

async fn resolve(
    state: &AppState,
    address: &str,
    requester: Option<&str>,
    verified_claims: &VerifiedRestrictedClaims,
    token: Option<&str>,
) -> ResolveOutcome {
    // 1. Parse the address. A fail-closed parse (unknown keyword, wrong order, missing intermediate
    //    level, non-uuid segment, strand/message missing `via`) collapses to a blinded not_found —
    //    indistinguishable from a nonexistent resource.
    let parsed = match parse_address(address) {
        Ok(p) => p,
        Err(_) => return ResolveOutcome::NotFound,
    };

    // 2. Resolve the realm (canonical id + preview + join_candidates). This is the delegation
    //    point: the realm branch and the alias→canonical normalization both go through
    //    resolve_realm's logic.
    let realm_key = match &parsed.realm {
        RealmRef::RealmId(uuid) => format!("ak:realm:{uuid}"),
        RealmRef::Alias(alias) => alias.clone(),
    };
    // 3. Token target binding (security-critical). Applies whenever a token is present OR the
    //    address declares an invite link — an invite link MUST carry a token; a token that fails to
    //    bind → blinded not_found.
    let effective_link_type = parsed.link_type;
    let token = token.or(parsed.token.as_deref());
    let realm_resolution = if effective_link_type == LinkType::Preview {
        crate::query::realm::resolve_realm_for_preview_link(state, &realm_key).await
    } else {
        resolve_realm_visible(state, &realm_key, requester, verified_claims).await
    };
    let resolved = match realm_resolution {
        Ok(Some(r)) => r,
        // Hidden / withdrawn / unknown realm, OR an alias that resolves to
        // nothing → blinded not_found (same as resolve_realm).
        Ok(None) => return ResolveOutcome::NotFound,
        Err(e) => return ResolveOutcome::Error(format!("resolve_target realm load: {e}")),
    };
    let canonical_realm_id = resolved.realm_id.clone();

    let mut verified_preview = None;
    if effective_link_type == LinkType::Preview {
        let preview_policy = match load_preview_policy(state, &canonical_realm_id).await {
            Ok(Some(policy)) => policy,
            Ok(None) => return ResolveOutcome::TokenReject,
            Err(error) => {
                return ResolveOutcome::Error(format!(
                    "resolve_target preview policy load: {error}"
                ));
            }
        };
        match verify_preview_token_details_with_methods(
            &parsed,
            token,
            &canonical_realm_id,
            &preview_policy.value,
            &preview_policy.digest,
            requester,
            Utc::now(),
            &state.config().accepted_did_methods,
            crate::egress::local_development_enabled(state.config().development_mode),
        ) {
            Ok(_) => verified_preview = Some(preview_policy),
            Err(TokenCheck::Reject) => return ResolveOutcome::TokenReject,
            Err(TokenCheck::Pass) => unreachable!("detail verifier never returns Pass as error"),
        }
    }

    let mut verified_invite_token = None;
    if effective_link_type != LinkType::Preview
        && (effective_link_type == LinkType::Invite || token.is_some())
    {
        match verify_address_token_details_with_methods(
            &parsed,
            token,
            &canonical_realm_id,
            effective_link_type,
            &state.config().accepted_did_methods,
            crate::egress::local_development_enabled(state.config().development_mode),
        ) {
            Ok(verified) => match invite_token_revoked(state, &verified).await {
                Ok(false) => verified_invite_token = Some(verified),
                Ok(true) => return ResolveOutcome::TokenReject,
                Err(error) => {
                    return ResolveOutcome::Error(format!(
                        "resolve_target invite revocation lookup: {error}"
                    ));
                }
            },
            Err(TokenCheck::Reject) => return ResolveOutcome::TokenReject,
            Err(TokenCheck::Pass) => unreachable!("detail verifier never returns Pass as error"),
        }
    }

    // 4. Classify the target and build the response.
    if parsed.is_realm() {
        let response = match verified_preview.as_ref() {
            Some(preview) => build_preview_response(
                resolved,
                &parsed,
                TargetKind::Realm,
                &preview.value,
                &preview.digest,
            ),
            None => build_realm_response(resolved),
        };
        return match response {
            Ok(r) => ResolveOutcome::Ok(Box::new(r)),
            Err(e) => ResolveOutcome::Error(e),
        };
    }

    let target_kind = if parsed.is_message() {
        TargetKind::Message
    } else {
        TargetKind::Strand
    };
    if let Some(preview) = verified_preview.as_ref() {
        let response = build_preview_response(
            resolved,
            &parsed,
            target_kind,
            &preview.value,
            &preview.digest,
        );
        return match response {
            Ok(r) => ResolveOutcome::Ok(Box::new(r)),
            Err(e) => ResolveOutcome::Error(e),
        };
    }
    let invite_authorized =
        effective_link_type == LinkType::Invite && verified_invite_token.is_some();
    match build_object_response(
        state,
        target_kind,
        &canonical_realm_id,
        &parsed,
        requester,
        verified_claims,
        invite_authorized,
    )
    .await
    {
        Ok(Some(response)) => ResolveOutcome::Ok(Box::new(response)),
        Ok(None) => ResolveOutcome::NotFound,
        Err(error) => ResolveOutcome::Error(format!("resolve_target object access: {error}")),
    }
}

/// Result of the token-binding check. Split out so the conformance suite can
/// assert the scope-confusion / alias-mismatch behaviour with a pure function.
#[derive(Debug, PartialEq, Eq)]
pub enum TokenCheck {
    Pass,
    Reject,
}

#[derive(Debug, Clone)]
pub struct VerifiedInviteToken {
    pub descriptor: TargetDescriptor,
    pub token_payload_digest: Vec<u8>,
    pub target_digest: String,
}

#[derive(Debug, Clone)]
struct PreviewPolicy {
    value: JsonValue,
    digest: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedPreviewToken {
    pub target_digest: String,
    pub preview_policy_digest: String,
}

async fn load_preview_policy(
    state: &AppState,
    realm_id: &str,
) -> anyhow::Result<Option<PreviewPolicy>> {
    use crate::schema::directory_resources::dsl as r;

    let mut conn = state.db().get().await?;
    let discovery_state: Option<JsonValue> = r::directory_resources
        .filter(r::resource_kind.eq(crate::ingest::DirectoryResourceKindDb::Realm))
        .filter(r::resource_id.eq(realm_id))
        .select(r::discovery_state)
        .first(&mut *conn)
        .await
        .optional()?;
    let Some(discovery_state) = discovery_state else {
        return Ok(None);
    };
    let Some(value) = preview_policy_from_discovery_state(&discovery_state) else {
        return Ok(None);
    };
    let Some(digest) = canonical::canonical_sha256(&value).ok() else {
        return Ok(None);
    };
    Ok(Some(PreviewPolicy { value, digest }))
}

fn preview_policy_from_discovery_state(discovery_state: &JsonValue) -> Option<JsonValue> {
    for candidate in [
        discovery_state.get("preview_policy"),
        discovery_state.pointer("/object/preview_policy"),
        discovery_state.pointer("/payload/object/preview_policy"),
        discovery_state.pointer("/payload/preview_policy"),
        Some(discovery_state),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(policy) = normalize_preview_policy_value(candidate) {
            return Some(policy);
        }
    }
    None
}

fn normalize_preview_policy_value(candidate: &JsonValue) -> Option<JsonValue> {
    let value = candidate
        .get("value")
        .filter(|value| preview_policy_has_required_shape(value))
        .unwrap_or(candidate);
    preview_policy_has_required_shape(value).then(|| value.clone())
}

fn preview_policy_has_required_shape(value: &JsonValue) -> bool {
    value.get("mode").and_then(JsonValue::as_str).is_some()
        && value
            .get("audiences")
            .and_then(JsonValue::as_array)
            .is_some()
        && value.get("fields").and_then(JsonValue::as_array).is_some()
}

#[allow(clippy::too_many_arguments)]
pub fn verify_preview_token_with_methods(
    parsed: &ParsedAddress,
    token: Option<&str>,
    canonical_realm_id: &str,
    preview_policy: &JsonValue,
    current_policy_digest: &str,
    requester: Option<&str>,
    now: DateTime<Utc>,
    accepted_did_methods: &[String],
    allow_private_networks: bool,
) -> TokenCheck {
    match verify_preview_token_details_with_methods(
        parsed,
        token,
        canonical_realm_id,
        preview_policy,
        current_policy_digest,
        requester,
        now,
        accepted_did_methods,
        allow_private_networks,
    ) {
        Ok(_) => TokenCheck::Pass,
        Err(reject) => reject,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_preview_token_details_with_methods(
    parsed: &ParsedAddress,
    token: Option<&str>,
    canonical_realm_id: &str,
    preview_policy: &JsonValue,
    current_policy_digest: &str,
    requester: Option<&str>,
    now: DateTime<Utc>,
    accepted_did_methods: &[String],
    allow_private_networks: bool,
) -> Result<VerifiedPreviewToken, TokenCheck> {
    if !preview_policy_accepts_link_token_holder(preview_policy) {
        return Err(TokenCheck::Reject);
    }
    let Some(token) = token else {
        return Err(TokenCheck::Reject);
    };
    let Some(mut value) = decode_token_json(token) else {
        return Err(TokenCheck::Reject);
    };
    if !preview_token_kind_allowed(&value) {
        return Err(TokenCheck::Reject);
    }
    if value.get("link_type").and_then(JsonValue::as_str) != Some("preview") {
        return Err(TokenCheck::Reject);
    }

    let verification_method = token_verification_method(&value)
        .map(str::to_owned)
        .ok_or(TokenCheck::Reject)?;
    let issuer = value
        .get("iss")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|issuer| !issuer.is_empty())
        .map(str::to_owned)
        .ok_or(TokenCheck::Reject)?;
    if verification_method_issuer(&verification_method) != Some(issuer.as_str()) {
        return Err(TokenCheck::Reject);
    }
    let jws = detach_jws(&mut value).ok_or(TokenCheck::Reject)?;
    let canonical_bytes =
        canonical::canonical_json_bytes(&value).map_err(|_| TokenCheck::Reject)?;
    verify_invite_token_jws(
        &canonical_bytes,
        &jws,
        &verification_method,
        &issuer,
        accepted_did_methods,
        allow_private_networks,
    )
    .ok_or(TokenCheck::Reject)?;

    if value
        .get("nonce")
        .and_then(JsonValue::as_str)
        .is_none_or(|nonce| nonce.trim().is_empty())
    {
        return Err(TokenCheck::Reject);
    }
    let Some(expires_at) = parse_preview_token_expiry(value.get("exp")) else {
        return Err(TokenCheck::Reject);
    };
    if expires_at <= now {
        return Err(TokenCheck::Reject);
    }
    if !preview_audience_matches(value.get("aud"), requester) {
        return Err(TokenCheck::Reject);
    }

    let Some(claimed_policy_digest) = value
        .get("preview_policy_digest")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|digest| !digest.is_empty())
    else {
        return Err(TokenCheck::Reject);
    };
    if !preview_policy_digest_allowed(
        preview_policy,
        current_policy_digest,
        claimed_policy_digest,
        now,
    ) {
        return Err(TokenCheck::Reject);
    }

    let expected_target_digest =
        expected_preview_target_digest(parsed, canonical_realm_id).ok_or(TokenCheck::Reject)?;
    let Some(claimed_target_digest) = value
        .get("target_digest")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|digest| !digest.is_empty())
    else {
        return Err(TokenCheck::Reject);
    };
    if claimed_target_digest != expected_target_digest {
        return Err(TokenCheck::Reject);
    }

    Ok(VerifiedPreviewToken {
        target_digest: expected_target_digest,
        preview_policy_digest: claimed_policy_digest.to_owned(),
    })
}

fn decode_token_json(token: &str) -> Option<JsonValue> {
    let encoded = token
        .trim()
        .strip_prefix("ak:preview-token:")
        .unwrap_or_else(|| token.trim());
    if encoded.starts_with('{') {
        return serde_json::from_str(encoded).ok();
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn preview_token_kind_allowed(value: &JsonValue) -> bool {
    matches!(
        value.get("kind").and_then(JsonValue::as_str),
        None | Some("preview_token" | "ak.directory.preview_token" | "ak.realm.preview_token")
    )
}

fn preview_policy_accepts_link_token_holder(policy: &JsonValue) -> bool {
    policy.get("mode").and_then(JsonValue::as_str) != Some("none")
        && policy_array_contains(policy, "audiences", "link_token_holder")
}

fn policy_array_contains(policy: &JsonValue, field: &str, expected: &str) -> bool {
    policy
        .get(field)
        .and_then(JsonValue::as_array)
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(expected)))
}

fn parse_preview_token_expiry(value: Option<&JsonValue>) -> Option<DateTime<Utc>> {
    match value? {
        JsonValue::String(value) => DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|datetime| datetime.with_timezone(&Utc)),
        JsonValue::Number(value) => {
            let raw = value.as_i64()?;
            if raw > 10_000_000_000 {
                Utc.timestamp_millis_opt(raw).single()
            } else {
                Utc.timestamp_opt(raw, 0).single()
            }
        }
        _ => None,
    }
}

fn preview_audience_matches(value: Option<&JsonValue>, requester: Option<&str>) -> bool {
    let matches_audience = |aud: &str| match aud.trim() {
        "" => false,
        "anonymous" | "link_token_holder" => true,
        "authenticated" => requester.is_some(),
        expected => requester.is_some_and(|requester| requester == expected),
    };
    match value {
        Some(JsonValue::String(aud)) => matches_audience(aud),
        Some(JsonValue::Array(audiences)) => audiences
            .iter()
            .filter_map(JsonValue::as_str)
            .any(matches_audience),
        _ => false,
    }
}

fn preview_policy_digest_allowed(
    policy: &JsonValue,
    current_policy_digest: &str,
    claimed_policy_digest: &str,
    now: DateTime<Utc>,
) -> bool {
    if claimed_policy_digest == current_policy_digest {
        return true;
    }
    policy
        .get("accepted_previous_policy_digests")
        .and_then(JsonValue::as_array)
        .is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry
                    .get("preview_policy_digest")
                    .and_then(JsonValue::as_str)
                    .map(str::trim)
                    == Some(claimed_policy_digest)
                    && entry
                        .get("expires_at")
                        .and_then(|expires_at| parse_preview_token_expiry(Some(expires_at)))
                        .is_some_and(|expires_at| now < expires_at)
            })
        })
}

fn expected_preview_target_digest(
    parsed: &ParsedAddress,
    canonical_realm_id: &str,
) -> Option<String> {
    let mut descriptor = TargetDescriptor::from_parsed(parsed);
    descriptor.set_realm_id(canonical_realm_id);
    descriptor.link_type = LinkType::Preview;
    target_digest(&descriptor).ok()
}

/// Verify an invite token against the parsed address under the canonical
/// (server-resolved) realm id.
///
/// Steps:
///   1. an invite link MUST carry a token (no token → reject);
///   2. verify the token's detached Ed25519 JWS over the canonical token payload, then parse its
///      embedded `target_descriptor` and its `exp`/`aud` claims;
///   3. inject the canonical realm id into the address-derived descriptor (so an alias address can
///      be compared) and call `verify_token_target`, which recomputes & compares the digest. Any
///      mismatch → reject.
///
/// `canonical_realm_id` is the `ak:realm:<uuid>` the realm resolution produced
/// (NOT the raw alias) — this is what closes the alias-vs-token realm_id
/// mismatch hole.
pub fn verify_address_token_with_methods(
    parsed: &ParsedAddress,
    token: Option<&str>,
    canonical_realm_id: &str,
    effective_link_type: LinkType,
    accepted_did_methods: &[String],
    allow_private_networks: bool,
) -> TokenCheck {
    match verify_address_token_details_with_methods(
        parsed,
        token,
        canonical_realm_id,
        effective_link_type,
        accepted_did_methods,
        allow_private_networks,
    ) {
        Ok(_) => TokenCheck::Pass,
        Err(reject) => reject,
    }
}

pub fn verify_address_token_details_with_methods(
    parsed: &ParsedAddress,
    token: Option<&str>,
    canonical_realm_id: &str,
    effective_link_type: LinkType,
    accepted_did_methods: &[String],
    allow_private_networks: bool,
) -> Result<VerifiedInviteToken, TokenCheck> {
    // An invite link with no token cannot be honoured.
    let Some(token) = token else {
        return Err(TokenCheck::Reject);
    };

    let Some(mut verified_token) =
        parse_token_descriptor(token, accepted_did_methods, allow_private_networks)
    else {
        return Err(TokenCheck::Reject);
    };

    // Build the address-derived descriptor and inject the canonical realm id so
    // an alias address can be compared honestly (the digest is meaningless over
    // an alias string). For a uuid realm this is idempotent.
    let mut address_descriptor = TargetDescriptor::from_parsed(parsed);
    address_descriptor.set_realm_id(canonical_realm_id);

    // The token binds its own authoritative realm id. If the token was minted
    // for a DIFFERENT realm than the address resolved to, that is a scope
    // confusion / alias-mismatch — reject. (verify_token_target would also
    // catch this via the digest, but checking explicitly keeps the
    // realm-mismatch path obvious and metrics-attributable.)
    if normalize_realm(&verified_token.descriptor.realm_id) != normalize_realm(canonical_realm_id) {
        return Err(TokenCheck::Reject);
    }

    // Digest comparison over the canonicalized address descriptor. We feed the
    // descriptor back through a ParsedAddress whose realm is the canonical uuid
    // so verify_token_target's own from_parsed + set effective_link_type path
    // reproduces the exact bytes.
    let canonical_parsed = with_canonical_realm(parsed, canonical_realm_id);
    if verify_token_target(
        &verified_token.descriptor,
        &canonical_parsed,
        effective_link_type,
    ) {
        verified_token.target_digest =
            target_digest(&verified_token.descriptor).map_err(|_| TokenCheck::Reject)?;
        Ok(verified_token)
    } else {
        Err(TokenCheck::Reject)
    }
}

/// Rebuild a [`ParsedAddress`] whose realm segment is the canonical
/// `ak:realm:<uuid>` (sigil-stripped to the bare uuid the grammar expects) so
/// the SDK's `verify_token_target` recomputes the digest over a uuid realm
/// rather than the original alias.
fn with_canonical_realm(parsed: &ParsedAddress, canonical_realm_id: &str) -> ParsedAddress {
    let bare_uuid = canonical_realm_id
        .strip_prefix("ak:realm:")
        .unwrap_or(canonical_realm_id)
        .to_owned();
    ParsedAddress {
        realm: RealmRef::RealmId(bare_uuid),
        strand: parsed.strand.clone(),
        message: parsed.message.clone(),
        action: parsed.action,
        link_type: parsed.link_type,
        token: parsed.token.clone(),
    }
}

/// Normalize a realm id to its bare-uuid form for equality comparison so a
/// `ak:realm:<uuid>` and the same bare `<uuid>` compare equal.
fn normalize_realm(realm_id: &str) -> &str {
    realm_id.strip_prefix("ak:realm:").unwrap_or(realm_id)
}

/// Verify the signed invite token and return its embedded [`TargetDescriptor`].
///
/// Wire format is a canonical JSON object with:
///   - `kind: "invite_token"`;
///   - `iss` and `verification_method` bound to the same DID;
///   - future `exp` and non-empty `aud`;
///   - `target_descriptor`;
///   - detached JWS in top-level `jws` (or `proof.jws`).
///
/// The JWS signs the same object after removing only the detached `jws` value.
/// Unsigned JSON is rejected even when it carries a matching descriptor.
fn parse_token_descriptor(
    token: &str,
    accepted_did_methods: &[String],
    allow_private_networks: bool,
) -> Option<VerifiedInviteToken> {
    let mut value: JsonValue = serde_json::from_str(token).ok()?;
    if !matches!(
        value.get("kind").and_then(JsonValue::as_str),
        Some("invite_token" | "ak.directory.invite_token")
    ) {
        return None;
    }

    let verification_method = token_verification_method(&value).map(str::to_owned)?;
    let issuer = value
        .get("iss")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|issuer| !issuer.is_empty())
        .map(str::to_owned);
    let issuer = issuer?;
    if verification_method_issuer(&verification_method)? != issuer {
        return None;
    }

    // Expiry / audience checks are part of the signed payload. `exp` is
    // required so a captured token has a bounded validity window; `aud` is
    // required and must be non-empty so minting systems cannot accidentally
    // issue an unscoped bearer.
    let exp = value.get("exp").and_then(JsonValue::as_i64)?;
    if exp <= Utc::now().timestamp() {
        return None;
    }
    if !audience_present(value.get("aud")) {
        return None;
    }

    let jws = detach_jws(&mut value)?;
    let canonical_bytes = canonical::canonical_json_bytes(&value).ok()?;
    let token_payload_digest = Sha256::digest(&canonical_bytes).to_vec();
    verify_invite_token_jws(
        &canonical_bytes,
        &jws,
        &verification_method,
        &issuer,
        accepted_did_methods,
        allow_private_networks,
    )?;

    let descriptor = value.get("target_descriptor")?;
    let descriptor: TargetDescriptor = serde_json::from_value(descriptor.clone()).ok()?;
    let target_digest = target_digest(&descriptor).ok()?;
    Some(VerifiedInviteToken {
        descriptor,
        token_payload_digest,
        target_digest,
    })
}

fn verify_invite_token_jws(
    canonical_bytes: &[u8],
    jws: &str,
    verification_method: &str,
    issuer: &str,
    accepted_did_methods: &[String],
    allow_private_networks: bool,
) -> Option<()> {
    if accepted_did_methods.is_empty() {
        return None;
    }
    if issuer.starts_with("did:key:") && did_method_allowed(accepted_did_methods, "did:key") {
        let resolver = DidKeyResolver::new();
        return sdk_verify_jws_ed25519(
            canonical_bytes,
            jws,
            verification_method,
            issuer,
            &resolver,
        )
        .ok();
    }

    let resolver = did_resolver_chain(accepted_did_methods, allow_private_networks).ok()?;
    sdk_verify_jws_ed25519(canonical_bytes, jws, verification_method, issuer, &resolver).ok()
}

fn token_verification_method(value: &JsonValue) -> Option<&str> {
    value
        .get("verification_method")
        .and_then(JsonValue::as_str)
        .or_else(|| {
            value
                .get("proof")
                .and_then(|proof| proof.get("verification_method"))
                .and_then(JsonValue::as_str)
        })
        .map(str::trim)
        .filter(|method| !method.is_empty())
}

fn verification_method_issuer(verification_method: &str) -> Option<&str> {
    let issuer = verification_method
        .split_once('#')
        .map(|(did, _)| did)
        .unwrap_or(verification_method)
        .trim();
    (!issuer.is_empty()).then_some(issuer)
}

fn audience_present(value: Option<&JsonValue>) -> bool {
    match value {
        Some(JsonValue::String(aud)) => !aud.trim().is_empty(),
        Some(JsonValue::Array(audiences)) => audiences.iter().any(|aud| {
            aud.as_str()
                .map(str::trim)
                .is_some_and(|aud| !aud.is_empty())
        }),
        _ => false,
    }
}

fn detach_jws(value: &mut JsonValue) -> Option<String> {
    let object = value.as_object_mut()?;
    if let Some(jws) = object
        .remove("jws")
        .and_then(|jws| jws.as_str().map(str::to_owned))
    {
        return Some(jws);
    }

    let proof = object.get_mut("proof")?.as_object_mut()?;
    if let Some(kind) = proof.get("kind").and_then(JsonValue::as_str)
        && kind != "detached_jws"
    {
        return None;
    }
    proof
        .remove("jws")
        .and_then(|jws| jws.as_str().map(str::to_owned))
}

/// Build the Realm-target response, delegating the entire preview / join_candidates
/// / §9.1 envelope to the realm resolution.
fn build_realm_response(
    resolved: crate::query::realm::ResolvedRealm,
) -> Result<DirectoryTargetResolutionOutcome, String> {
    let realm_preview =
        crate::query::realm::realm_preview_from_envelope(&resolved.realm_id, &resolved.envelope)?;

    Ok(DirectoryTargetResolutionOutcome {
        target_kind: TargetKind::Realm,
        realm_preview: Some(realm_preview),
        object_preview: None,
        join_rule: None,
        as_of: resolved.envelope.as_of,
        source_refs: resolved.envelope.source_refs.clone(),
        join_candidates: resolved.join_candidates.clone(),
        policy_revision: NonEmptyString::new(resolved.envelope.policy_revision.clone())
            .map_err(str::to_owned)?,
    })
}

fn build_preview_response(
    resolved: crate::query::realm::ResolvedRealm,
    parsed: &ParsedAddress,
    target_kind: TargetKind,
    preview_policy: &JsonValue,
    preview_policy_digest: &str,
) -> Result<DirectoryTargetResolutionOutcome, String> {
    let mut realm_preview =
        crate::query::realm::realm_preview_from_envelope(&resolved.realm_id, &resolved.envelope)?;
    trim_realm_preview_for_policy(&mut realm_preview, preview_policy, preview_policy_digest);

    Ok(DirectoryTargetResolutionOutcome {
        target_kind,
        realm_preview: Some(realm_preview),
        object_preview: preview_object_for_address(
            parsed,
            target_kind,
            resolved.envelope.as_of,
            &resolved.envelope.source_refs,
            preview_policy_digest,
            resolved.envelope.stale,
            resolved.envelope.divergent,
        )?,
        join_rule: None,
        as_of: resolved.envelope.as_of,
        source_refs: resolved.envelope.source_refs.clone(),
        join_candidates: Vec::new(),
        policy_revision: NonEmptyString::new(preview_policy_digest).map_err(str::to_owned)?,
    })
}

fn trim_realm_preview_for_policy(
    preview: &mut RealmPreview,
    policy: &JsonValue,
    preview_policy_digest: &str,
) {
    preview.alias = None;
    if !preview_policy_field_allowed(policy, "title") {
        preview.title = None;
    }
    if !preview_policy_field_allowed(policy, "avatar_blob_ref") {
        preview.avatar_blob_ref = None;
    }
    if !preview_policy_field_allowed(policy, "owning_organizations") {
        preview.organization_did = None;
        preview.owning_organizations.clear();
    }
    if !preview_policy_field_allowed(policy, "join_rule") {
        preview.join_rule = None;
    }
    if !preview_policy_field_allowed(policy, "member_count_bucket") {
        preview.member_count_bucket = None;
    }
    if !preview_policy_field_allowed(policy, "summary") {
        preview.summary = None;
    }
    if !preview_policy_field_allowed(policy, "preview_ref") {
        preview.preview_ref = None;
    }
    if !preview_policy_field_allowed(policy, "history_visibility") {
        preview.history_visibility = None;
    }
    preview.discoverability = None;
    preview.join_candidates.clear();
    preview.policy_revision = preview_policy_digest.to_owned();
}

fn preview_policy_field_allowed(policy: &JsonValue, field: &str) -> bool {
    policy_array_contains(policy, "fields", field)
}

fn preview_object_for_address(
    parsed: &ParsedAddress,
    target_kind: TargetKind,
    as_of: DateTime<Utc>,
    source_refs: &[String],
    policy_revision: &str,
    stale: bool,
    divergent: bool,
) -> Result<Option<ObjectPreview>, String> {
    let source_refs = source_refs
        .iter()
        .cloned()
        .map(EventId::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("invalid object preview source reference: {error}"))?;
    match target_kind {
        TargetKind::Realm => Ok(None),
        TargetKind::Strand | TargetKind::Message => {
            let object_id = object_preview_id(parsed, target_kind)?;
            Ok(Some(ObjectPreview {
                object_id,
                object_kind: target_kind_name(target_kind).to_owned(),
                title: None,
                summary: None,
                as_of,
                source_refs,
                policy_revision: policy_revision.to_owned(),
                stale: opt_bool(stale),
                divergent: opt_bool(divergent),
            }))
        }
    }
}

fn object_preview_id(
    parsed: &ParsedAddress,
    target_kind: TargetKind,
) -> Result<ObjectPreviewId, String> {
    match target_kind {
        TargetKind::Realm => Err("realm target has no object preview id".to_owned()),
        TargetKind::Strand => parsed
            .strand
            .as_deref()
            .map(|strand| format!("ak:strand:{strand}"))
            .ok_or_else(|| "strand target is missing strand id".to_owned())
            .and_then(|id| StrandId::new(id).map_err(|error| error.to_string()))
            .map(ObjectPreviewId::Strand),
        TargetKind::Message => parsed
            .message
            .as_deref()
            .map(|message| format!("ak:message:{message}"))
            .ok_or_else(|| "message target is missing message id".to_owned())
            .and_then(|id| MessageId::new(id).map_err(|error| error.to_string()))
            .map(ObjectPreviewId::Message),
    }
}

fn target_kind_name(target_kind: TargetKind) -> &'static str {
    match target_kind {
        TargetKind::Realm => "realm",
        TargetKind::Strand => "strand",
        TargetKind::Message => "message",
    }
}

#[derive(Debug, Queryable)]
struct ObjectAccessRow {
    public_projection: JsonValue,
    required_claims: JsonValue,
    as_of: chrono::DateTime<Utc>,
    source_refs: Vec<String>,
    policy_revision: Option<String>,
    stale: bool,
    divergent: bool,
}

async fn build_object_response(
    state: &AppState,
    target_kind: TargetKind,
    canonical_realm_id: &str,
    parsed: &ParsedAddress,
    requester: Option<&str>,
    verified_claims: &VerifiedRestrictedClaims,
    invite_authorized: bool,
) -> anyhow::Result<Option<DirectoryTargetResolutionOutcome>> {
    let Some(strand_id) = parsed.strand.as_deref().map(|f| format!("ak:strand:{f}")) else {
        return Ok(None);
    };
    let message_id = parsed
        .message
        .as_deref()
        .map(|m| format!("ak:message:{m}"))
        .unwrap_or_default();
    let object_kind = match target_kind {
        TargetKind::Strand => "strand",
        TargetKind::Message => "message",
        TargetKind::Realm => return Ok(None),
    };

    let Some(row) = load_object_access_row(
        state,
        canonical_realm_id,
        object_kind,
        &strand_id,
        &message_id,
    )
    .await?
    else {
        return Ok(None);
    };
    if !object_access_allowed(&row, requester, verified_claims, invite_authorized) {
        return Ok(None);
    }
    let Some(policy_revision) = required_object_policy_revision(&row) else {
        return Ok(None);
    };

    let object_id = object_preview_id(parsed, target_kind).map_err(anyhow::Error::msg)?;
    let object_source_refs = row
        .source_refs
        .iter()
        .cloned()
        .map(EventId::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| anyhow::anyhow!("invalid object preview source reference: {error}"))?;
    let object_preview = ObjectPreview {
        object_id,
        object_kind: object_kind.to_owned(),
        title: row
            .public_projection
            .get("title")
            .and_then(JsonValue::as_str)
            .map(str::to_owned),
        summary: row
            .public_projection
            .get("summary")
            .and_then(JsonValue::as_str)
            .map(str::to_owned),
        as_of: row.as_of,
        source_refs: object_source_refs,
        policy_revision: policy_revision.clone(),
        stale: opt_bool(row.stale),
        divergent: opt_bool(row.divergent),
    };

    Ok(Some(DirectoryTargetResolutionOutcome {
        target_kind,
        realm_preview: None,
        object_preview: Some(object_preview),
        join_rule: None,
        as_of: row.as_of,
        source_refs: row.source_refs,
        join_candidates: Vec::new(),
        policy_revision: NonEmptyString::new(policy_revision)
            .map_err(|error| anyhow::anyhow!(error))?,
    }))
}

async fn load_object_access_row(
    state: &AppState,
    realm_id: &str,
    object_kind: &str,
    strand_id: &str,
    message_id: &str,
) -> anyhow::Result<Option<ObjectAccessRow>> {
    use crate::schema::directory_object_access::dsl as o;

    let mut conn = state.db().get().await?;
    let row = o::directory_object_access
        .filter(o::realm_id.eq(realm_id))
        .filter(o::object_kind.eq(object_kind))
        .filter(o::strand_id.eq(strand_id))
        .filter(o::message_id.eq(message_id))
        .filter(o::stale.eq(false))
        .select((
            o::public_projection,
            o::required_claims,
            o::as_of,
            o::source_refs,
            o::policy_revision,
            o::stale,
            o::divergent,
        ))
        .first(&mut *conn)
        .await
        .optional()?;
    Ok(row)
}

fn object_access_allowed(
    row: &ObjectAccessRow,
    requester: Option<&str>,
    verified_claims: &VerifiedRestrictedClaims,
    invite_authorized: bool,
) -> bool {
    if invite_authorized {
        return true;
    }
    if verified_claims.is_empty() {
        return false;
    }
    let required = json!({ "allowed_discoverers": row.required_claims.clone() });
    matches_allowed_discoverers(&required, requester, verified_claims)
}

fn required_object_policy_revision(row: &ObjectAccessRow) -> Option<String> {
    row.policy_revision
        .as_deref()
        .map(str::trim)
        .filter(|policy_revision| !policy_revision.is_empty())
        .map(str::to_owned)
}

async fn invite_token_revoked(
    state: &AppState,
    token: &VerifiedInviteToken,
) -> anyhow::Result<bool> {
    use crate::schema::directory_invite_revocations::dsl as rev;

    let mut conn = state.db().get().await?;
    let now = Utc::now();
    let count: i64 = rev::directory_invite_revocations
        .filter(rev::token_payload_digest.eq(&token.token_payload_digest))
        .filter(rev::target_digest.eq(&token.target_digest))
        .filter(rev::revoked_at.le(now))
        .filter(rev::expires_at.is_null().or(rev::expires_at.gt(now)))
        .count()
        .get_result(&mut *conn)
        .await?;
    Ok(count > 0)
}

/// Render the boolean §9.1 freshness flags only when they are `true` (so the
/// response omits `stale: false` / `divergent: false` rather than emitting a
/// noisy default).
fn opt_bool(value: bool) -> Option<bool> {
    value.then_some(true)
}

#[cfg(test)]
mod tests {
    use arkret_sdk::jws::sign_jws_ed25519;
    use arkret_sdk::models::{AddressAction, build_address};
    use chrono::DateTime;
    use ed25519_dalek::SigningKey;

    use super::*;

    const R: &str = "01904100-0000-7000-8000-0000000000aa";
    const F: &str = "01904100-0000-7000-8000-0000000000bb";
    const F2: &str = "01904100-0000-7000-8000-0000000000cc";
    const VIA: &str = "did:web:relay.example";
    const INVITE_SIGNING_SEED: [u8; 32] = [17u8; 32];

    /// Mint a signed token JSON string whose embedded `target_descriptor` is
    /// bound to `address`, with the canonical realm id injected (so the digest
    /// is over a uuid realm, not an alias).
    fn mint_token(address: &ParsedAddress, canonical_realm_id: &str) -> String {
        let mut descriptor = TargetDescriptor::from_parsed(address);
        descriptor.set_realm_id(canonical_realm_id);
        descriptor.link_type = LinkType::Invite;
        let signing_key = SigningKey::from_bytes(&INVITE_SIGNING_SEED);
        let multibase = did_key_multibase(&signing_key);
        let issuer = format!("did:key:{multibase}");
        let verification_method = format!("{issuer}#{multibase}");
        let mut payload = json!({
            "kind": "invite_token",
            "iss": issuer,
            "verification_method": verification_method,
            "exp": Utc::now().timestamp() + 3600,
            "aud": "did:web:alice.example",
            "target_descriptor": descriptor,
        });
        let canonical = canonical::canonical_json_bytes(&payload).unwrap();
        let jws = sign_jws_ed25519(&canonical, &signing_key).unwrap();
        payload
            .as_object_mut()
            .unwrap()
            .insert("jws".to_owned(), json!(jws));
        payload.to_string()
    }

    fn did_key_multibase(signing_key: &SigningKey) -> String {
        let mut bytes = vec![0xed, 0x01];
        bytes.extend_from_slice(signing_key.verifying_key().as_bytes());
        format!("z{}", bs58::encode(bytes).into_string())
    }

    fn verify_address_token(
        parsed: &ParsedAddress,
        token: Option<&str>,
        canonical_realm_id: &str,
        effective_link_type: LinkType,
    ) -> TokenCheck {
        let accepted_did_methods = vec!["did:key".to_owned()];
        verify_address_token_with_methods(
            parsed,
            token,
            canonical_realm_id,
            effective_link_type,
            &accepted_did_methods,
            false,
        )
    }

    #[test]
    fn token_binds_to_matching_object() {
        let addr = parse_address(&format!(
            "web+arkret:realm/{R}/strand/{F}?via={VIA}&lt=invite"
        ))
        .unwrap();
        let canonical = format!("ak:realm:{R}");
        let token = mint_token(&addr, &canonical);
        assert_eq!(
            verify_address_token(&addr, Some(&token), &canonical, LinkType::Invite),
            TokenCheck::Pass
        );
    }

    #[test]
    fn token_replayed_onto_other_object_is_rejected() {
        // Token minted for strand A.
        let addr_a = parse_address(&format!(
            "web+arkret:realm/{R}/strand/{F}?via={VIA}&lt=invite"
        ))
        .unwrap();
        let canonical = format!("ak:realm:{R}");
        let token = mint_token(&addr_a, &canonical);

        // Replayed onto strand B (same realm, different strand).
        let addr_b = parse_address(&format!(
            "web+arkret:realm/{R}/strand/{F2}?via={VIA}&lt=invite"
        ))
        .unwrap();
        assert_eq!(
            verify_address_token(&addr_b, Some(&token), &canonical, LinkType::Invite),
            TokenCheck::Reject
        );
    }

    #[test]
    fn invite_link_without_token_is_rejected() {
        let addr = parse_address(&format!(
            "web+arkret:realm/{R}/strand/{F}?via={VIA}&lt=invite"
        ))
        .unwrap();
        let canonical = format!("ak:realm:{R}");
        assert_eq!(
            verify_address_token(&addr, None, &canonical, LinkType::Invite),
            TokenCheck::Reject
        );
    }

    #[test]
    fn expired_token_is_rejected() {
        let addr = parse_address(&format!(
            "web+arkret:realm/{R}/strand/{F}?via={VIA}&lt=invite"
        ))
        .unwrap();
        let canonical = format!("ak:realm:{R}");
        let mut descriptor = TargetDescriptor::from_parsed(&addr);
        descriptor.set_realm_id(&canonical);
        descriptor.link_type = LinkType::Invite;
        let signing_key = SigningKey::from_bytes(&INVITE_SIGNING_SEED);
        let multibase = did_key_multibase(&signing_key);
        let issuer = format!("did:key:{multibase}");
        let verification_method = format!("{issuer}#{multibase}");
        let mut payload = json!({
            "kind": "invite_token",
            "iss": issuer,
            "verification_method": verification_method,
            "exp": Utc::now().timestamp() - 1,
            "aud": "did:web:alice.example",
            "target_descriptor": descriptor,
        });
        let canonical_payload = canonical::canonical_json_bytes(&payload).unwrap();
        let jws = sign_jws_ed25519(&canonical_payload, &signing_key).unwrap();
        payload
            .as_object_mut()
            .unwrap()
            .insert("jws".to_owned(), json!(jws));
        let token = payload.to_string();
        assert_eq!(
            verify_address_token(&addr, Some(&token), &canonical, LinkType::Invite),
            TokenCheck::Reject
        );
    }

    #[test]
    fn unsigned_token_with_matching_descriptor_is_rejected() {
        let addr = parse_address(&format!(
            "web+arkret:realm/{R}/strand/{F}?via={VIA}&lt=invite"
        ))
        .unwrap();
        let canonical = format!("ak:realm:{R}");
        let mut descriptor = TargetDescriptor::from_parsed(&addr);
        descriptor.set_realm_id(&canonical);
        descriptor.link_type = LinkType::Invite;
        let token = json!({
            "exp": Utc::now().timestamp() + 3600,
            "aud": "did:web:alice.example",
            "target_descriptor": descriptor,
        })
        .to_string();
        assert_eq!(
            verify_address_token(&addr, Some(&token), &canonical, LinkType::Invite),
            TokenCheck::Reject
        );
    }

    #[test]
    fn tampered_signed_token_payload_is_rejected() {
        let addr = parse_address(&format!(
            "web+arkret:realm/{R}/strand/{F}?via={VIA}&lt=invite"
        ))
        .unwrap();
        let canonical = format!("ak:realm:{R}");
        let token = mint_token(&addr, &canonical);
        let mut value: JsonValue = serde_json::from_str(&token).unwrap();
        value["target_descriptor"]["strand_id"] = json!(format!("ak:strand:{F2}"));
        let tampered = value.to_string();
        assert_eq!(
            verify_address_token(&addr, Some(&tampered), &canonical, LinkType::Invite),
            TokenCheck::Reject
        );
    }

    #[test]
    fn token_bound_to_alias_resolves_via_canonical_id() {
        // The address used an alias realm; the token was minted with the
        // canonical id injected. Verification must succeed because the server
        // resolved the alias to the same canonical id.
        let alias_addr = parse_address(&format!(
            "web+arkret:realm/team.example.com/strand/{F}?via={VIA}&lt=invite"
        ))
        .unwrap();
        let canonical = format!("ak:realm:{R}");
        let token = mint_token(&alias_addr, &canonical);
        assert_eq!(
            verify_address_token(&alias_addr, Some(&token), &canonical, LinkType::Invite),
            TokenCheck::Pass
        );
    }

    #[test]
    fn token_for_different_realm_is_rejected() {
        let addr = parse_address(&format!(
            "web+arkret:realm/{R}/strand/{F}?via={VIA}&lt=invite"
        ))
        .unwrap();
        let other_realm = "01904100-0000-7000-8000-0000000000ff";
        let token = mint_token(&addr, &format!("ak:realm:{other_realm}"));
        // Address resolved to realm R, token bound to a different realm.
        let canonical = format!("ak:realm:{R}");
        assert_eq!(
            verify_address_token(&addr, Some(&token), &canonical, LinkType::Invite),
            TokenCheck::Reject
        );
    }

    #[test]
    fn realm_response_carries_realm_preview() {
        let resolved = crate::query::realm::ResolvedRealm {
            realm_id: format!("ak:realm:{R}"),
            envelope: crate::filter::result::ResultEnvelope::from_row(
                json!({ "realm_id": format!("ak:realm:{R}"), "title": "Tea Time" }),
                sample_time(),
                vec!["ak:event:1".to_owned()],
                "rev-7".to_owned(),
                false,
                false,
                vec!["did:web:hps.example".to_owned()],
            ),
            join_candidates: Vec::new(),
        };
        let response = build_realm_response(resolved).expect("realm response builds");
        assert_eq!(response.target_kind, TargetKind::Realm);
        let preview = response.realm_preview.expect("realm preview present");
        assert_eq!(preview.realm_id.as_str(), format!("ak:realm:{R}"));
        assert_eq!(preview.title.as_deref(), Some("Tea Time"));
        assert_eq!(
            response.join_candidates,
            Vec::<arkret_sdk::RealmJoinCandidate>::new()
        );
        assert!(response.object_preview.is_none());
    }

    #[test]
    fn object_access_gate_requires_verified_policy_or_invite() {
        let row = ObjectAccessRow {
            public_projection: json!({ "title": "Strand" }),
            required_claims: json!([]),
            as_of: sample_time(),
            source_refs: vec!["ak:event:1".to_owned()],
            policy_revision: None,
            stale: false,
            divergent: false,
        };

        assert!(!object_access_allowed(
            &row,
            Some("did:web:alice.example"),
            &VerifiedRestrictedClaims::default(),
            false,
        ));
        assert!(!object_access_allowed(
            &row,
            Some("did:web:bob.example"),
            &VerifiedRestrictedClaims::default(),
            false,
        ));
        assert!(object_access_allowed(
            &row,
            Some("did:web:bob.example"),
            &VerifiedRestrictedClaims::default(),
            true,
        ));
    }

    #[test]
    fn object_access_accepts_matching_verified_claim_presentation() {
        let issuer = arkret_sdk::Did::new("did:web:issuer.example".to_owned()).unwrap();
        let org = arkret_sdk::Did::new("did:web:acme.example".to_owned()).unwrap();
        let requester = arkret_sdk::Did::new("did:web:alice.example".to_owned()).unwrap();
        let claim = arkret_sdk::PresentedClaim::organization_membership(
            "claim-1",
            requester.clone(),
            issuer.clone(),
            org.clone(),
            vec!["member".to_owned()],
        );
        let verified_claims = VerifiedRestrictedClaims::for_test(vec![claim]);
        let row = ObjectAccessRow {
            public_projection: json!({ "title": "Strand" }),
            required_claims: json!([{
                "type": "claim",
                "claim_type": "organization_membership",
                "issuer": issuer.as_str(),
                "organization": org.as_str(),
            }]),
            as_of: sample_time(),
            source_refs: vec!["ak:event:1".to_owned()],
            policy_revision: Some("rev-7".to_owned()),
            stale: false,
            divergent: false,
        };

        assert!(object_access_allowed(
            &row,
            Some(requester.as_str()),
            &verified_claims,
            false,
        ));
        assert!(!object_access_allowed(
            &row,
            Some("did:web:bob.example"),
            &verified_claims,
            false,
        ));
    }

    #[test]
    fn object_policy_revision_is_required() {
        let mut row = ObjectAccessRow {
            public_projection: json!({ "title": "Strand" }),
            required_claims: json!([]),
            as_of: sample_time(),
            source_refs: vec!["ak:event:1".to_owned()],
            policy_revision: None,
            stale: false,
            divergent: false,
        };

        assert!(required_object_policy_revision(&row).is_none());
        row.policy_revision = Some("   ".to_owned());
        assert!(required_object_policy_revision(&row).is_none());
        row.policy_revision = Some(" rev-7 ".to_owned());
        assert_eq!(
            required_object_policy_revision(&row).as_deref(),
            Some("rev-7")
        );
    }

    #[test]
    fn retired_via_hint_is_ignored_by_parser() {
        let parsed = parse_address(&format!(
            "web+arkret:realm/{R}/strand/{F}?via={VIA}&via=did:web:extra.example"
        ))
        .unwrap();
        assert!(parsed.is_strand());
    }

    #[test]
    fn build_address_action_smoke() {
        // Sanity: the SDK address builder is reachable from this module.
        let parsed = ParsedAddress {
            realm: RealmRef::RealmId(R.to_owned()),
            strand: None,
            message: None,
            action: AddressAction::View,
            link_type: LinkType::Reference,
            token: None,
        };
        assert!(build_address(&parsed).starts_with("web+arkret:realm/"));
    }

    fn sample_time() -> DateTime<Utc> {
        chrono::TimeZone::timestamp_opt(&Utc, 1_700_000_000, 0).unwrap()
    }
}
