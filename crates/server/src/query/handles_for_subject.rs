//! Reverse handle lookup — R3.2 (cokret-spec @ b56cab1),
//! `cx.directory.list_handles_for_subject`.
//!
//! This is the inverse of [`crate::query::handle::resolve_handle`]: given a
//! known holder/principal DID (the `subject`) plus disclosure context, return
//! the subject's currently-visible handle claims and (when present) the
//! subject's primary handle. The mention renderer in yougen / sodmin uses
//! this live-resolve path to turn a known DID into the `@handle` it should
//! display.
//!
//! ## Privacy & anti-enumeration
//!
//! The subject is supplied by the caller, so this endpoint does NOT leak the
//! existence of an unknown DID — but it CAN leak which handles a subject
//! holds, so we apply the same disclosure-policy + issuer-trust + audience +
//! intent filtering that `resolve_handle` uses, plus the same anti-enumeration
//! latency floor + deterministic jitter + 50ms stochastic resolve jitter
//! (DIR-TBY-3). An over-broad query that filters every claim collapses to an
//! empty `claims` array rather than disclosing the existence of restricted
//! claims.
//!
//! ## Output invariant
//!
//! Per `cx.schema.list_handles_for_subject_response.v1`, every
//! `claims[].subject` MUST byte-equal `response.subject`. We fail closed:
//! any claim whose derived subject does not equal the request subject is
//! DROPPED before the response is built, and the assembled response is run
//! through the SDK's [`DirectoryListHandlesForSubjectResBody::validate`] as a
//! defence-in-depth check (a validate failure collapses to `not_found`).
//!
//! ## Deferred work
//!
//! - Historical replay for `as_of` in the past is `TODO(R3.2.1)`: we accept the `as_of` field
//!   (happy path returns the current indexed view and echoes `as_of` back) but do not yet
//!   reconstruct the handle index as of an arbitrary past instant.
//! - The full disclosure-policy engine (per-claim visibility, claim_scope evaluation) is shared
//!   with `resolve_handle` and is `TODO(R3.2.1)`; for R3.2 we apply the directory-visibility gate,
//!   issuer-trust ordering, and audience scope filter the same way `resolve_handle` does.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
// NOTE: `contrix_sdk::HandleClaim` resolves to the SDK identity-layer claim
// (`identity::handles::HandleClaim`), which shadows the wire-schema claim at
// the crate root. The `cx.schema.list_handles_for_subject_response.v1` body
// is built from the wire-schema `model::HandleClaim`, so import it explicitly.
use contrix_sdk::model::HandleClaim;
use contrix_sdk::{
    DirectoryListHandlesForSubjectReqBody, DirectoryListHandlesForSubjectResBody, Handle,
    validate_handle_claim_subject,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use crate::error::ApiErrorCode;
use crate::filter::enumeration::{LatencyBudget, pad_to_budget_observed};
use crate::ingest::{DiscoverabilityWire, ResourceKindWire};
use crate::query::rate_limit::{apply_resolve_response_jitter, enforce_resolve_rate_limit};
use crate::state::AppState;

/// Default page size when the caller omits `limit`.
const DEFAULT_LIMIT: u32 = 20;
/// Hard ceiling on a single page — DIR-TBY-3 cardinality guard. A caller
/// cannot ask the directory to materialise an unbounded reverse-lookup set
/// in one round trip.
const MAX_LIMIT: u32 = 100;
/// Cardinality guard for the candidate scan: we never load more than this
/// many handle rows into memory for a single subject reverse lookup, mirroring
/// the bounded scan `search_users` performs.
const MAX_CANDIDATE_SCAN: i64 = 500;

#[handler]
pub async fn list_handles_for_subject(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let _query_timer = state.metrics().query_timer("list-handles-for-subject");

    let body: DirectoryListHandlesForSubjectReqBody = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            state
                .metrics()
                .record_query_outcome("list-handles-for-subject", "bad_json");
            ApiErrorCode::BadJson.render(res, format!("malformed body: {e}"));
            return;
        }
    };

    // Input validator (DIR-TBY-2): the subject MUST be a holder/principal
    // DID. Reject `ck:actor:` Realm actor ids, `ck:account:` server-local
    // account ids, service DIDs, and any non-DID resource id with
    // `failed_precondition` carrying the `invalid_subject_kind` reason. We
    // reuse the SDK's `validate_handle_claim_subject` so the reverse-lookup
    // key obeys exactly the same rule as the forward claim subject. This
    // runs BEFORE rate-limit / latency padding because it is a structural
    // rejection, not a privacy-preserving miss.
    if let Err(err) = validate_handle_claim_subject(&body.subject) {
        state
            .metrics()
            .record_query_outcome("list-handles-for-subject", "invalid_subject_kind");
        state.metrics().record_filter_drop("invalid_subject_kind");
        ApiErrorCode::FailedPrecondition.render(
            res,
            format!("invalid_subject_kind: subject must be a holder/principal DID ({err})"),
        );
        return;
    }

    // Anti-enumeration rate-limit keyed on the subject DID (DIR-TBY-3).
    if !enforce_resolve_rate_limit(req, res, &state, body.subject.as_str()) {
        state
            .metrics()
            .record_query_outcome("list-handles-for-subject", "rate_limited");
        return;
    }

    let requested_limit = body.limit.unwrap_or(DEFAULT_LIMIT);
    let limit = requested_limit.clamp(1, MAX_LIMIT);
    if requested_limit > MAX_LIMIT {
        // DIR-TBY-3 cardinality guard: a caller asked for more than the
        // per-page ceiling; record the clamp so operators can see when
        // clients hammer the reverse-lookup with oversized page sizes.
        state
            .metrics()
            .record_cardinality_guard("page_limit_clamped", 1);
    }
    let cursor_offset = decode_cursor(body.cursor.as_deref());

    let budget = LatencyBudget::new(
        state.config().query_latency_floor,
        state.config().query_latency_jitter,
    );
    // Privacy key bundles every input that steers the visible-claims set so
    // repeated probes from one IP land on a stable latency tier without
    // leaking the result back to the caller. The requester IP is hashed in
    // so the same subject probed from two hosts cannot be cross-correlated.
    let requester_ip = req.remote_addr().to_string();
    let mut ip_hasher = Sha256::new();
    ip_hasher.update(requester_ip.as_bytes());
    let requester_ip_hash = URL_SAFE_NO_PAD.encode(ip_hasher.finalize());
    let privacy_key = format!(
        "subject={};intent={};realm={};req={};cursor={};limit={limit};iph={requester_ip_hash}",
        body.subject.as_str(),
        body.intent.as_deref().unwrap_or_default(),
        body.realm_id
            .as_ref()
            .map(|r| r.as_str())
            .unwrap_or_default(),
        body.requester
            .as_ref()
            .map(|r| r.as_str())
            .unwrap_or_default(),
        body.cursor.as_deref().unwrap_or_default(),
    );

    let metrics = state.metrics().clone();
    let outcome = pad_to_budget_observed(
        budget,
        "cx.directory.list_handles_for_subject",
        &privacy_key,
        |target| {
            state
                .metrics()
                .record_anti_enum_pad("list-handles-for-subject", target)
        },
        async { build_response(&state, &body, cursor_offset, limit, &metrics).await },
    )
    .await;

    // P5 — stochastic resolve jitter, identical to `resolve_handle`.
    apply_resolve_response_jitter().await;

    match outcome {
        ListOutcome::Ok(response) => {
            state
                .metrics()
                .record_query_outcome("list-handles-for-subject", "ok");
            res.render(Json(response));
        }
        // A reverse lookup that finds nothing visible returns an EMPTY claim
        // set (not a 404) — the subject is caller-supplied, so existence is
        // not a secret; only the handle set is. A schema-invariant failure
        // (claims[].subject mismatch that survived filtering) fails CLOSED to
        // `not_found` so a malformed projection cannot leak a foreign subject.
        ListOutcome::FailClosed => {
            state
                .metrics()
                .record_query_outcome("list-handles-for-subject", "fail_closed");
            ApiErrorCode::NotFound.render(res, "not found");
        }
        ListOutcome::Error => {
            state
                .metrics()
                .record_query_outcome("list-handles-for-subject", "internal_error");
            ApiErrorCode::InternalError.render(res, "list_handles_for_subject failed");
        }
    }
}

enum ListOutcome {
    Ok(DirectoryListHandlesForSubjectResBody),
    FailClosed,
    Error,
}

async fn build_response(
    state: &AppState,
    body: &DirectoryListHandlesForSubjectReqBody,
    cursor_offset: usize,
    limit: u32,
    metrics: &crate::observability::Metrics,
) -> ListOutcome {
    let (rows, scan_capped) = match load_subject_handle_rows(state, body.subject.as_str()).await {
        Ok(result) => result,
        Err(_) => return ListOutcome::Error,
    };
    if scan_capped {
        // DIR-TBY-3: the bounded candidate scan hit its ceiling, so the
        // reverse-lookup set may be incomplete. Surface it for operators.
        metrics.record_cardinality_guard("candidate_scan_capped", 1);
    }
    // One subject was resolved this request.
    metrics.record_cardinality_guard("resolved_subjects", 1);

    // Issuer-trust ordering (DIR-TBY-2): when the target Realm declares an
    // `accepted_issuers` order, rows from non-accepted issuers are filtered.
    let accepted_issuers = match body.realm_id.as_ref() {
        Some(realm_id) => load_accepted_issuers(state, realm_id.as_str()).await,
        None => Vec::new(),
    };

    match assemble_response(
        body,
        rows,
        &accepted_issuers,
        cursor_offset,
        limit,
        Some(metrics),
    ) {
        Some(response) => ListOutcome::Ok(response),
        None => ListOutcome::FailClosed,
    }
}

/// Pure response assembler — extracted from [`build_response`] so the
/// conformance suite (DIR-TBY-5) can exercise the disclosure / issuer-trust /
/// audience / subject-mismatch filters, cursor pagination, and the
/// `claims[].subject == response.subject` invariant WITHOUT a live Postgres
/// dependency.
///
/// Returns `None` to signal a fail-closed (`not_found`) collapse when the
/// assembled response would violate the schema invariant; otherwise returns
/// the populated, validated response body. `metrics`, when present, receives
/// per-reason `filter_drop` increments.
pub fn assemble_response(
    body: &DirectoryListHandlesForSubjectReqBody,
    rows: Vec<SubjectHandleRow>,
    accepted_issuers: &[String],
    cursor_offset: usize,
    limit: u32,
    metrics: Option<&crate::observability::Metrics>,
) -> Option<DirectoryListHandlesForSubjectResBody> {
    let drop = |reason: &str| {
        if let Some(m) = metrics {
            m.record_filter_drop(reason);
        }
    };

    // The most-recent `as_of` across the visible rows is the response's
    // `as_of` (TODO(R3.2.1): historical replay uses the request `as_of`).
    let mut as_of = body.as_of.unwrap_or_else(Utc::now);

    let mut claims: Vec<HandleClaim> = Vec::new();
    for row in rows {
        // Disclosure gate: only directory-visible rows surface (shared with
        // resolve_handle). TODO(R3.2.1): full per-claim visibility +
        // claim_scope evaluation.
        if !row.discoverability.is_directory_visible() {
            drop("disclosure");
            continue;
        }
        // Issuer-trust filter: when the Realm declares accepted issuers, drop
        // claims whose issuer is not in the set.
        if !accepted_issuers.is_empty()
            && !issuer_in_accepted(&row.public_projection, accepted_issuers)
        {
            drop("issuer_trust");
            continue;
        }
        // Audience scope filter: when the request carries a requester/audience
        // context and the claim pins an audience, drop claims whose audience
        // is mutually exclusive with the request context.
        if !audience_compatible(&row.public_projection, body) {
            drop("audience");
            continue;
        }

        let Some(claim) = claim_from_projection(&row, body.subject.as_str()) else {
            // subject mismatch / unparseable — fail-closed DROP (DIR-TBY-2).
            drop("subject_mismatch");
            continue;
        };
        if row.as_of > as_of && body.as_of.is_none() {
            as_of = row.as_of;
        }
        claims.push(claim);
    }

    // Stable order so the opaque cursor is deterministic: by canonical handle
    // string then by issuer.
    claims.sort_by(|a, b| {
        let ah = a.handle.as_ref().map(Handle::canonical).unwrap_or_default();
        let bh = b.handle.as_ref().map(Handle::canonical).unwrap_or_default();
        ah.cmp(bh).then_with(|| a.issuer.cmp(&b.issuer))
    });

    // Primary handle: the first verified claim (sorted), else the first
    // claim's handle. The spec leaves the exact primary-selection policy to
    // the directory; we pick the lowest-sorted verified handle.
    let primary_handle = select_primary_handle(&claims);

    let total = claims.len();
    let page: Vec<HandleClaim> = claims
        .into_iter()
        .skip(cursor_offset)
        .take(limit as usize)
        .collect();
    let next_offset = cursor_offset + page.len();
    let has_more = next_offset < total;
    let next_cursor = has_more.then(|| encode_cursor(next_offset));

    let response = DirectoryListHandlesForSubjectResBody {
        subject: body.subject.clone(),
        claims: page,
        primary_handle,
        as_of,
        next_cursor,
        has_more,
    };

    // Defence in depth: the SDK validator enforces claims[].subject ==
    // response.subject byte-for-byte. We already dropped mismatches above, so
    // a failure here means a projection slipped through — fail CLOSED.
    if response.validate().is_err() {
        return None;
    }
    Some(response)
}

/// One indexed handle row that may belong to the subject.
#[derive(Debug, Queryable, Clone)]
pub struct SubjectHandleRow {
    public_projection: JsonValue,
    discoverability: DiscoverabilityWire,
    as_of: DateTime<Utc>,
}

impl SubjectHandleRow {
    /// Construct a row from its constituent parts. Exposed for the
    /// conformance suite (DIR-TBY-5) so tests can assemble fixture rows
    /// without a Postgres round trip.
    pub fn for_test(
        public_projection: JsonValue,
        discoverability: DiscoverabilityWire,
        as_of: DateTime<Utc>,
    ) -> Self {
        Self {
            public_projection,
            discoverability,
            as_of,
        }
    }
}

/// Load every directory handle row whose projection asserts the requested
/// subject DID. teabay stores the holder DID in the projection's `did` (and
/// optionally `subject`) field; we scan the handle rows (bounded by
/// [`MAX_CANDIDATE_SCAN`]) and match in memory because the subject is not the
/// row's primary key (the `resource_id` is the handle string).
/// Returns `(matching_rows, scan_capped)`. `scan_capped` is true when the
/// bounded candidate scan returned a full page ([`MAX_CANDIDATE_SCAN`] rows),
/// meaning the reverse-lookup set may be incomplete and the caller should
/// record the cardinality guard.
async fn load_subject_handle_rows(
    state: &AppState,
    subject: &str,
) -> anyhow::Result<(Vec<SubjectHandleRow>, bool)> {
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get().await?;
    let rows: Vec<SubjectHandleRow> = r::directory_resources
        .filter(r::resource_kind.eq(ResourceKindWire::Handle))
        // Stale rows (TTL+grace expired) MUST NOT surface, same as
        // resolve_handle's `load_handle_row`.
        .filter(r::stale.eq(false))
        .order(r::indexed_at.desc())
        .limit(MAX_CANDIDATE_SCAN)
        .select((r::public_projection, r::discoverability, r::as_of))
        .load(&mut *conn)
        .await?;
    let scan_capped = rows.len() as i64 >= MAX_CANDIDATE_SCAN;
    let matching = rows
        .into_iter()
        .filter(|row| projection_subject(&row.public_projection) == Some(subject))
        .collect();
    Ok((matching, scan_capped))
}

/// Extract the holder/principal DID a handle projection asserts. Order of
/// preference: explicit `subject`, then `did` (teabay's stored holder DID
/// field). Returns `None` when neither is a string.
fn projection_subject(projection: &JsonValue) -> Option<&str> {
    projection
        .get("subject")
        .and_then(JsonValue::as_str)
        .or_else(|| projection.get("did").and_then(JsonValue::as_str))
}

/// Build a typed [`HandleClaim`] from a stored handle row, binding the claim
/// `subject` to the request subject. Returns `None` (DROP) when the row's
/// asserted subject does not byte-equal the request subject — this is the
/// fail-closed path for the `claims[].subject == response.subject` invariant.
fn claim_from_projection(row: &SubjectHandleRow, subject: &str) -> Option<HandleClaim> {
    if projection_subject(&row.public_projection) != Some(subject) {
        return None;
    }
    let subject_did = contrix_sdk::Did::new(subject.to_owned()).ok()?;
    // The handle string must come from the projection's canonical
    // `handle` field. The directory index key may use a dot-form
    // resource_id, so it is intentionally not a fallback.
    let handle = row
        .public_projection
        .get("handle")
        .and_then(JsonValue::as_str)
        .and_then(|h| Handle::parse(h).ok());

    let verified = row
        .public_projection
        .get("verified")
        .and_then(JsonValue::as_bool)
        .unwrap_or(false);

    let issuer = row
        .public_projection
        .get("issuer")
        .and_then(JsonValue::as_str)
        .map(str::to_owned);

    let claim_kind = row
        .public_projection
        .get("claim_kind")
        .and_then(JsonValue::as_str)
        .and_then(parse_handle_claim_kind);

    Some(HandleClaim {
        handle,
        subject: Some(subject_did),
        issuer,
        claim_kind,
        binding_state: verified.then_some(contrix_sdk::HandleBindingState::Verified),
        ..Default::default()
    })
}

/// Parse the wire `claim_kind` string into the SDK enum. The draft-era
/// `service_handle` value was removed, so unknown / retired values yield
/// `None` (the claim still surfaces, just without a typed claim kind).
fn parse_handle_claim_kind(value: &str) -> Option<contrix_sdk::HandleClaimKind> {
    match value {
        "handle_binding" => Some(contrix_sdk::HandleClaimKind::HandleBinding),
        "organization_handle" => Some(contrix_sdk::HandleClaimKind::OrganizationHandle),
        _ => None,
    }
}

/// Pick the primary handle: lowest-sorted verified claim's handle, else the
/// lowest-sorted claim's handle. `claims` is assumed already sorted.
fn select_primary_handle(claims: &[HandleClaim]) -> Option<Handle> {
    claims
        .iter()
        .find(|c| {
            matches!(
                c.binding_state,
                Some(contrix_sdk::HandleBindingState::Verified)
            ) && c.handle.is_some()
        })
        .or_else(|| claims.iter().find(|c| c.handle.is_some()))
        .and_then(|c| c.handle.clone())
}

/// Load a Realm's `accepted_issuers` ordering from its cached projection.
/// Empty (or absent Realm) means "no issuer-trust constraint".
async fn load_accepted_issuers(state: &AppState, realm_id: &str) -> Vec<String> {
    use crate::schema::directory_resources::dsl as r;
    let Ok(mut conn) = state.db().get().await else {
        return Vec::new();
    };
    let projection: Option<(JsonValue, DiscoverabilityWire)> = r::directory_resources
        .filter(r::resource_kind.eq(ResourceKindWire::Realm))
        .filter(r::resource_id.eq(realm_id))
        .select((r::public_projection, r::discoverability))
        .first(&mut *conn)
        .await
        .optional()
        .ok()
        .flatten();
    let Some((projection, discoverability)) = projection else {
        return Vec::new();
    };
    if !discoverability.is_directory_visible() {
        // Hidden / withdrawn Realm — treat as no declared trust set.
        return Vec::new();
    }
    projection
        .get("accepted_issuers")
        .or_else(|| projection.pointer("/policy/accepted_issuers"))
        .and_then(JsonValue::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(JsonValue::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// True iff the projection's issuer is in the Realm's accepted-issuer set.
/// A projection with no declared issuer fails closed against a non-empty
/// accepted set (the caller checks `accepted_issuers.is_empty()` first).
fn issuer_in_accepted(projection: &JsonValue, accepted: &[String]) -> bool {
    match projection
        .get("issuer")
        .and_then(JsonValue::as_str)
        .or_else(|| {
            projection
                .get("issuer_service_did")
                .and_then(JsonValue::as_str)
        }) {
        Some(issuer) => accepted.iter().any(|a| a == issuer),
        None => false,
    }
}

/// Audience scope filter: when a claim pins an `audience` and the request
/// declares a requester/audience context, the claim is only compatible when
/// the audience matches the requester or the realm. A claim with no pinned
/// audience is always compatible; a request with no context never filters.
fn audience_compatible(
    projection: &JsonValue,
    body: &DirectoryListHandlesForSubjectReqBody,
) -> bool {
    let Some(claim_audience) = projection.get("audience").and_then(JsonValue::as_str) else {
        return true;
    };
    let requester = body.requester.as_ref().map(|d| d.as_str());
    let realm = body.realm_id.as_ref().map(|r| r.as_str());
    if requester.is_none() && realm.is_none() {
        // Request carries no audience context — do not filter audience-pinned
        // claims here (resolve_handle applies the stronger member_add gate).
        return true;
    }
    Some(claim_audience) == requester || Some(claim_audience) == realm
}

// ---- Opaque cursor (offset-encoded) -------------------------------------
//
// The cursor is an opaque, URL-safe base64 of the next offset. It is an
// implementation detail; clients MUST pass it back verbatim. A malformed
// cursor decodes to offset 0 (start) rather than erroring — fail-open on the
// cursor only, never on the subject.

fn encode_cursor(offset: usize) -> String {
    URL_SAFE_NO_PAD.encode(format!("o:{offset}").as_bytes())
}

fn decode_cursor(cursor: Option<&str>) -> usize {
    let Some(cursor) = cursor.filter(|c| !c.is_empty()) else {
        return 0;
    };
    URL_SAFE_NO_PAD
        .decode(cursor)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| s.strip_prefix("o:").map(str::to_owned))
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn handle_row(projection: JsonValue, discoverability: DiscoverabilityWire) -> SubjectHandleRow {
        SubjectHandleRow::for_test(
            projection,
            discoverability,
            chrono::TimeZone::timestamp_opt(&Utc, 0, 0).unwrap(),
        )
    }

    #[test]
    fn projection_subject_prefers_subject_then_did() {
        assert_eq!(
            projection_subject(&json!({"subject":"did:web:alice.example","did":"did:web:other"})),
            Some("did:web:alice.example")
        );
        assert_eq!(
            projection_subject(&json!({"did":"did:web:alice.example"})),
            Some("did:web:alice.example")
        );
        assert_eq!(projection_subject(&json!({"handle":"alice.example"})), None);
    }

    #[test]
    fn claim_from_projection_binds_request_subject() {
        let row = handle_row(
            json!({"did":"did:web:alice.example","handle":"alice:example.com","verified":true}),
            DiscoverabilityWire::Public,
        );
        let claim = claim_from_projection(&row, "did:web:alice.example").expect("claim built");
        assert_eq!(
            claim.subject.as_ref().unwrap().as_str(),
            "did:web:alice.example"
        );
        assert_eq!(
            claim.handle.as_ref().unwrap().canonical(),
            "alice:example.com"
        );
        assert!(matches!(
            claim.binding_state,
            Some(contrix_sdk::HandleBindingState::Verified)
        ));
    }

    #[test]
    fn claim_from_projection_drops_subject_mismatch() {
        // The row asserts a different subject than the request — fail-closed
        // DROP so claims[].subject == response.subject always holds.
        let row = handle_row(
            json!({"did":"did:web:eve.example","handle":"alice:example.com"}),
            DiscoverabilityWire::Public,
        );
        assert!(claim_from_projection(&row, "did:web:alice.example").is_none());
    }

    #[test]
    fn service_handle_claim_kind_is_dropped_to_none() {
        assert!(parse_handle_claim_kind("service_handle").is_none());
        assert_eq!(
            parse_handle_claim_kind("handle_binding"),
            Some(contrix_sdk::HandleClaimKind::HandleBinding)
        );
        assert_eq!(
            parse_handle_claim_kind("organization_handle"),
            Some(contrix_sdk::HandleClaimKind::OrganizationHandle)
        );
    }

    #[test]
    fn issuer_trust_filter_matches_accepted_set() {
        let accepted = vec!["did:web:issuer.tea".to_owned()];
        assert!(issuer_in_accepted(
            &json!({"issuer":"did:web:issuer.tea"}),
            &accepted
        ));
        assert!(!issuer_in_accepted(
            &json!({"issuer":"did:web:issuer.other"}),
            &accepted
        ));
        // No issuer declared ⇒ fails closed against a non-empty accepted set.
        assert!(!issuer_in_accepted(
            &json!({"handle":"alice:example.com"}),
            &accepted
        ));
    }

    #[test]
    fn audience_filter_passes_unpinned_and_matching() {
        let body = DirectoryListHandlesForSubjectReqBody {
            subject: contrix_sdk::Did::new("did:web:alice.example".to_owned()).unwrap(),
            realm_id: None,
            intent: None,
            requester: Some(contrix_sdk::Did::new("did:web:tea-org.example".to_owned()).unwrap()),
            proof_challenge: None,
            proofs: Vec::new(),
            as_of: None,
            cursor: None,
            limit: None,
        };
        // Unpinned audience always compatible.
        assert!(audience_compatible(&json!({"handle":"a:b.com"}), &body));
        // Pinned audience matching the requester is compatible.
        assert!(audience_compatible(
            &json!({"audience":"did:web:tea-org.example"}),
            &body
        ));
        // Pinned audience mutually exclusive with the requester is dropped.
        assert!(!audience_compatible(
            &json!({"audience":"did:web:someone-else.example"}),
            &body
        ));
    }

    #[test]
    fn cursor_round_trips_and_tolerates_garbage() {
        assert_eq!(decode_cursor(Some(&encode_cursor(40))), 40);
        assert_eq!(decode_cursor(None), 0);
        assert_eq!(decode_cursor(Some("")), 0);
        // Garbage cursor fails open to offset 0 (never errors the subject).
        assert_eq!(decode_cursor(Some("!!!not-base64!!!")), 0);
    }

    #[test]
    fn primary_handle_prefers_verified() {
        let verified = HandleClaim {
            handle: Some(Handle::parse("zed:example.com").unwrap()),
            subject: Some(contrix_sdk::Did::new("did:web:alice.example".to_owned()).unwrap()),
            binding_state: Some(contrix_sdk::HandleBindingState::Verified),
            ..Default::default()
        };
        let unverified = HandleClaim {
            handle: Some(Handle::parse("aaa:example.com").unwrap()),
            subject: Some(contrix_sdk::Did::new("did:web:alice.example".to_owned()).unwrap()),
            ..Default::default()
        };
        let claims = vec![unverified, verified];
        // Even though `aaa` sorts first, the verified `zed` is the primary.
        assert_eq!(
            select_primary_handle(&claims).unwrap().canonical(),
            "zed:example.com"
        );
    }
}
