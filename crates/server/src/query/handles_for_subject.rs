//! Reverse handle lookup — R3.2 (arkret-spec @ b56cab1),
//! `ak.find.directory.read.list_handles_for_subject`.
//!
//! This is the inverse of [`crate::query::handle::resolve_handle`]: given a
//! known holder/principal DID (the `subject`) plus disclosure context, return
//! the subject's currently-visible handle claims and (when present) the
//! subject's primary handle. The mention renderer in inkson / sodmin uses
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
//! Per `ak.schema.list_handles_for_subject_response.v1`, every
//! `claims[].subject` MUST byte-equal `response.subject`. We fail closed:
//! any claim whose derived subject does not equal the request subject is
//! DROPPED before the response is built, and the assembled response is run
//! through the SDK's [`DirectorySubjectHandleList::validate`] as a
//! defence-in-depth check (a validate failure collapses to `not_found`).
//!
//! ## Disclosure scope
//!
//! This endpoint applies the directory-visibility gate, issuer-trust ordering,
//! audience scope filter, and historical `as_of` replay for the indexed handle
//! projections.
//!
//! Its authorization inputs are exactly the ones the §9 operation table lists:
//! `requester` and the §9.0.1 `proofs[]`. There is no `claim_presentations[]`
//! channel here, so a `restricted` row (whose `allowed_discoverers` selectors
//! are claim-shaped) stays invisible on this surface.
//!
//! ## Requester proof (§9.0.1)
//!
//! `proofs[]` carries the per-object-family requester proof bound to
//! `ak.directory_list_handles_for_subject_request_proof.v1`. Verification lives
//! in [`crate::query::requester_proof`] and runs inside the latency budget; a
//! rejected proof collapses to the same blinded `not_found` as any other
//! failure.

// NOTE: `arkret_sdk::HandleClaim` resolves to the SDK identity-layer claim
// (`identity::handles::HandleClaim`), which shadows the wire-schema claim at
// the crate root. The `ak.schema.list_handles_for_subject_response.v1` body
// is built from the wire-schema `models::HandleClaim`, so import it explicitly.
use arkret_models_identity::HandleClaim;
use arkret_models_identity::primary_handle::{
    HandleIssuerPolicyEntry, handle_issuer_policy_entry_authorizes,
};
use arkret_sdk::{
    DirectoryListHandlesForSubjectRequestBody, DirectorySubjectHandleList, Handle,
    validate_handle_claim_subject,
};
use arkret_server::CursorBindingContext;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::RunQueryDsl;
use salvo::prelude::*;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use teabay_contracts::DirectoryDiscoveryState;

use crate::error::ApiErrorCode;
use crate::filter::enumeration::{LatencyBudget, pad_to_budget_observed};
use crate::ingest::{DirectoryResourceKindDb, DiscoverabilityDb};
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
    let state = match depot.get_typed::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let _query_timer = state.metrics().query_timer("list-handles-for-subject");

    let body: DirectoryListHandlesForSubjectRequestBody = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            state
                .metrics()
                .record_query_outcome("list-handles-for-subject", "json_invalid");
            ApiErrorCode::JsonInvalid.render(res, format!("malformed body: {e}"));
            return;
        }
    };

    // Input validator (DIR-TBY-2): the subject MUST be a holder/principal
    // DID. Reject `ak:actor:` Realm actor ids, `ak:account:` server-local
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
    let filter_digest = match arkret_server::cursor_filter_digest(&serde_json::json!({
        "operation": arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_LIST_HANDLES_FOR_SUBJECT,
        "realm_id": body.realm_id.as_ref(),
        "intent": body.intent.as_deref(),
        "requester": body.requester.as_ref(),
        "as_of": body.as_of,
    })) {
        Ok(digest) => digest,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("handle cursor filter: {error}"));
            return;
        }
    };
    let cursor_context = CursorBindingContext::new(
        body.subject.as_str(),
        None,
        state.config().service_id.clone(),
        filter_digest,
    );
    let cursor_offset = match body.cursor.as_deref() {
        Some(token) => match state
            .cursor_authority()
            .resolve_stream(token, &cursor_context)
            .and_then(|positions| {
                positions
                    .get("offset")
                    .and_then(JsonValue::as_u64)
                    .and_then(|offset| usize::try_from(offset).ok())
                    .ok_or(arkret_server::CursorAuthorityError::IntegrityInvalid)
            }) {
            Ok(offset) => offset,
            Err(error) => {
                super::render_cursor_error(res, error);
                return;
            }
        },
        None => 0,
    };

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
        arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_LIST_HANDLES_FOR_SUBJECT,
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
        ListOutcome::Ok(mut response) => {
            if response.has_more {
                let next_offset = cursor_offset.saturating_add(response.claims.len());
                response.next_cursor = match state.cursor_authority().mint_stream(
                    cursor_context,
                    serde_json::json!({ "offset": next_offset }),
                    60 * 60 * 1000,
                ) {
                    Ok(cursor) => Some(cursor),
                    Err(error) => {
                        state
                            .metrics()
                            .record_query_outcome("list-handles-for-subject", "internal_error");
                        ApiErrorCode::InternalError.render(res, format!("handle cursor: {error}"));
                        return;
                    }
                };
            }
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
    Ok(DirectorySubjectHandleList),
    FailClosed,
    Error,
}

async fn build_response(
    state: &AppState,
    body: &DirectoryListHandlesForSubjectRequestBody,
    cursor_offset: usize,
    limit: u32,
    metrics: &crate::observability::Metrics,
) -> ListOutcome {
    // §9.0.1 requester proof. Runs inside the caller's latency budget so a
    // proof-layer rejection is timing-equivalent to a genuine miss (§9.2), and
    // BEFORE any row load so an invalid proof cannot be timed against the
    // presence of the subject.
    if let Err(reason) = crate::query::requester_proof::verify_requester_proofs(
        body,
        state.config().service_id.as_str(),
        state.did_bindings(),
        Utc::now(),
    ) {
        tracing::debug!(%reason, "list_handles_for_subject requester proof rejected");
        metrics.record_filter_drop("requester_proof_invalid");
        return ListOutcome::FailClosed;
    }

    let (rows, scan_capped) =
        match load_subject_handle_rows(state, body.subject.as_str(), body.as_of).await {
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

    // Issuer trust is domain-scoped. A Realm may authorize the same issuer for
    // one handle domain without trusting it for every domain it can sign.
    let handle_issuer_policy = match body.realm_id.as_ref() {
        Some(realm_id) => load_handle_issuer_policy(state, realm_id.as_str(), body.as_of).await,
        None => None,
    };
    match assemble_response(
        body,
        rows,
        handle_issuer_policy.as_deref(),
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
    body: &DirectoryListHandlesForSubjectRequestBody,
    rows: Vec<SubjectHandleRow>,
    handle_issuer_policy: Option<&[HandleIssuerPolicyEntry]>,
    cursor_offset: usize,
    limit: u32,
    metrics: Option<&crate::observability::Metrics>,
) -> Option<DirectorySubjectHandleList> {
    let drop = |reason: &str| {
        if let Some(m) = metrics {
            m.record_filter_drop(reason);
        }
    };

    // Without a historical request, the most-recent `as_of` across visible
    // rows is the response timestamp. With `body.as_of`, historical loading has
    // already bounded the rows and the response keeps the requested timestamp.
    let mut as_of = body.as_of.unwrap_or_else(Utc::now);

    let mut claims: Vec<HandleClaim> = Vec::new();
    for row in rows {
        // Disclosure gate: only directory-visible rows surface, shared with
        // resolve_handle.
        if !handle_row_visible_to_requester(&row) {
            drop("disclosure");
            continue;
        }
        // Issuer-trust filter: a declared Realm policy authorizes both the
        // issuer identity and the canonical handle domain. Malformed or empty
        // declared policy is fail-closed (all candidates are dropped).
        if handle_issuer_policy
            .is_some_and(|policy| !issuer_authorized_for_projection(&row.public_projection, policy))
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
    let response = DirectorySubjectHandleList {
        subject: body.subject.clone(),
        claims: page,
        primary_handle,
        as_of,
        next_cursor: None,
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

/// Disclosure gate for one indexed handle row.
///
/// `ak.find.directory.read.list_handles_for_subject` has no
/// `claim_presentations[]` channel (spec §9 operation table): its only
/// authorization inputs are `requester` and the §9.0.1 `proofs[]`, and
/// `allowed_discoverers` selectors are claim-shaped (§3). A `restricted` row
/// therefore has no way to be unlocked on this surface and stays invisible —
/// fail closed, and the same blinded outcome as a row that does not exist.
///
/// `proofs[]` MUST NOT be reinterpreted as claim presentations here: §2
/// forbids parsing an Event/payload proof as a claim presentation, and the two
/// wire shapes are disjoint.
fn handle_row_visible_to_requester(row: &SubjectHandleRow) -> bool {
    match row.discoverability {
        DiscoverabilityDb::Restricted => false,
        other => other.is_directory_visible(),
    }
}

/// One indexed handle row that may belong to the subject.
#[derive(Debug, Queryable, Clone)]
pub struct SubjectHandleRow {
    public_projection: JsonValue,
    discoverability: DiscoverabilityDb,
    as_of: DateTime<Utc>,
}

impl SubjectHandleRow {
    /// Construct a row from its constituent parts. Exposed for the
    /// conformance suite (DIR-TBY-5) so tests can assemble fixture rows
    /// without a Postgres round trip.
    pub fn for_test(
        public_projection: JsonValue,
        discoverability: DiscoverabilityDb,
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
    as_of: Option<DateTime<Utc>>,
) -> anyhow::Result<(Vec<SubjectHandleRow>, bool)> {
    if let Some(as_of) = as_of {
        return load_subject_handle_rows_at(state, subject, as_of).await;
    }
    use crate::schema::directory_resources::dsl as r;
    let mut conn = state.db().get().await?;
    let rows: Vec<SubjectHandleRow> = r::directory_resources
        .filter(r::resource_kind.eq(DirectoryResourceKindDb::Handle))
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

#[derive(Debug, QueryableByName)]
struct HistoricalHandleRow {
    #[diesel(sql_type = Jsonb)]
    discovery_state: JsonValue,
    #[diesel(sql_type = Timestamptz)]
    as_of: DateTime<Utc>,
}

async fn load_subject_handle_rows_at(
    state: &AppState,
    subject: &str,
    as_of: DateTime<Utc>,
) -> anyhow::Result<(Vec<SubjectHandleRow>, bool)> {
    let mut conn = state.db().get().await?;
    let rows: Vec<HistoricalHandleRow> = diesel::sql_query(HISTORICAL_HANDLES_SQL)
        .bind::<Timestamptz, _>(as_of)
        .bind::<BigInt, _>(MAX_CANDIDATE_SCAN)
        .load(&mut *conn)
        .await?;
    let scan_capped = rows.len() as i64 >= MAX_CANDIDATE_SCAN;
    let mut matching = Vec::new();
    for row in rows {
        let discovery_state = DirectoryDiscoveryState::from_json_object(
            row.discovery_state,
            "historical handle discovery_state",
        )
        .map_err(anyhow::Error::msg)?;
        let discoverability = discoverability_from_state(&discovery_state)?;
        let public_projection =
            crate::ingest::announce::derive_public_projection(&discovery_state, discoverability)
                .map_err(|(_, message)| anyhow::anyhow!(message))?;
        if projection_subject(&public_projection) == Some(subject) {
            matching.push(SubjectHandleRow {
                public_projection,
                discoverability,
                as_of: row.as_of,
            });
        }
    }
    Ok((matching, scan_capped))
}

const HISTORICAL_HANDLES_SQL: &str = r#"
WITH latest AS (
    SELECT DISTINCT ON (a.resource_id)
        a.resource_id,
        a.discovery_state,
        a.source_refs,
        a.as_of
    FROM ingest_announces a
    WHERE a.resource_kind = 'handle'::resource_kind
      AND a.as_of <= $1
    ORDER BY a.resource_id, a.as_of DESC
)
SELECT
    l.discovery_state,
    l.as_of
FROM latest l
WHERE NOT EXISTS (
    SELECT 1
    FROM withdrawals w
    WHERE w.resource_kind = 'handle'::resource_kind
      AND w.resource_id = l.resource_id
      AND w.effective_at <= $1
      AND w.effective_at >= l.as_of
)
ORDER BY l.as_of DESC, l.resource_id ASC
LIMIT $2
"#;

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
    let subject_did = arkret_sdk::DidCoreId::new(subject.to_owned()).ok()?;
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

    // `issuer` is a stable identity core. A present-but-unparseable issuer is
    // not "no issuer": it would strip the trust anchor a caller filters on, so
    // the whole claim is dropped instead (same fail-closed path as a subject
    // mismatch above).
    let issuer = match row
        .public_projection
        .get("issuer")
        .and_then(JsonValue::as_str)
    {
        Some(raw) => Some(arkret_sdk::DidCoreId::new(raw.to_owned()).ok()?),
        None => None,
    };

    let claim_kind = row
        .public_projection
        .get("claim_kind")
        .and_then(JsonValue::as_str)
        .and_then(parse_handle_claim_kind);

    // `created_at` is schema-required for handle claims
    // (`handle-claim.schema.json` `required` list). A projection without a
    // parseable canonical `created_at` cannot yield a compliant claim, so the
    // row is dropped (same fail-closed path as the subject/issuer guards).
    let created_at = row
        .public_projection
        .get("created_at")
        .and_then(JsonValue::as_str)
        .and_then(|raw| arkret_sdk::canonical::parse_timestamp_canonical(raw).ok())?;

    Some(HandleClaim {
        schema: HandleClaim::SCHEMA.to_owned(),
        handle,
        handle_aliases: Vec::new(),
        subject: Some(subject_did),
        issuer,
        issuer_service_id: None,
        binding_state: verified.then_some(arkret_sdk::HandleBindingState::Verified),
        claim_kind,
        visibility: None,
        audience: None,
        challenge: None,
        claim_scope: Default::default(),
        member_delivery_binding: None,
        claims: Vec::new(),
        created_at,
        expires_at: None,
        verified_at: None,
        source_refs: Vec::new(),
        proofs: Vec::new(),
    })
}

/// Parse the wire `claim_kind` string into the SDK enum. The draft-era
/// `service_handle` value was removed, so unknown / retired values yield
/// `None` (the claim still surfaces, just without a typed claim kind).
fn parse_handle_claim_kind(value: &str) -> Option<arkret_sdk::HandleClaimKind> {
    match value {
        "handle_binding" => Some(arkret_sdk::HandleClaimKind::HandleBinding),
        "organization_handle" => Some(arkret_sdk::HandleClaimKind::OrganizationHandle),
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
                Some(arkret_sdk::HandleBindingState::Verified)
            ) && c.handle.is_some()
        })
        .or_else(|| claims.iter().find(|c| c.handle.is_some()))
        .and_then(|c| c.handle.clone())
}

/// Load a Realm's domain-scoped `handle_issuer_policy` from its cached
/// projection. `None` means the policy is absent; `Some([])` means it was
/// declared but malformed/empty and therefore denies every candidate.
async fn load_handle_issuer_policy(
    state: &AppState,
    realm_id: &str,
    as_of: Option<DateTime<Utc>>,
) -> Option<Vec<HandleIssuerPolicyEntry>> {
    if let Some(as_of) = as_of
        && let Ok(Some((projection, discoverability))) =
            load_historical_realm_projection(state, realm_id, as_of).await
    {
        if !discoverability.is_directory_visible() {
            return None;
        }
        return handle_issuer_policy_from_projection(&projection);
    }
    use crate::schema::directory_resources::dsl as r;
    let Ok(mut conn) = state.db().get().await else {
        return None;
    };
    let projection: Option<(JsonValue, DiscoverabilityDb)> = r::directory_resources
        .filter(r::resource_kind.eq(DirectoryResourceKindDb::Realm))
        .filter(r::resource_id.eq(realm_id))
        .select((r::public_projection, r::discoverability))
        .first(&mut *conn)
        .await
        .optional()
        .ok()
        .flatten();
    let (projection, discoverability) = projection?;
    if !discoverability.is_directory_visible() {
        // Hidden / withdrawn Realm — treat as no declared trust set.
        return None;
    }
    handle_issuer_policy_from_projection(&projection)
}

async fn load_historical_realm_projection(
    state: &AppState,
    realm_id: &str,
    as_of: DateTime<Utc>,
) -> anyhow::Result<Option<(JsonValue, DiscoverabilityDb)>> {
    let mut conn = state.db().get().await?;
    let row: Option<HistoricalRealmRow> = diesel::sql_query(HISTORICAL_REALM_SQL)
        .bind::<Text, _>(realm_id)
        .bind::<Timestamptz, _>(as_of)
        .get_result(&mut *conn)
        .await
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let discovery_state = DirectoryDiscoveryState::from_json_object(
        row.discovery_state,
        "historical realm discovery_state",
    )
    .map_err(anyhow::Error::msg)?;
    let discoverability = discoverability_from_state(&discovery_state)?;
    let projection =
        crate::ingest::announce::derive_public_projection(&discovery_state, discoverability)
            .map_err(|(_, message)| anyhow::anyhow!(message))?;
    Ok(Some((projection, discoverability)))
}

#[derive(Debug, QueryableByName)]
struct HistoricalRealmRow {
    #[diesel(sql_type = Jsonb)]
    discovery_state: JsonValue,
}

const HISTORICAL_REALM_SQL: &str = r#"
SELECT a.discovery_state
FROM ingest_announces a
WHERE a.resource_kind = 'realm'::resource_kind
  AND a.resource_id = $1
  AND a.as_of <= $2
  AND NOT EXISTS (
      SELECT 1
      FROM withdrawals w
      WHERE w.resource_kind = 'realm'::resource_kind
        AND w.resource_id = a.resource_id
        AND w.effective_at <= $2
        AND w.effective_at >= a.as_of
  )
ORDER BY a.as_of DESC
LIMIT 1
"#;

fn discoverability_from_state(
    discovery_state: &DirectoryDiscoveryState,
) -> anyhow::Result<DiscoverabilityDb> {
    let value = discovery_state
        .get("discoverability")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow::anyhow!("discovery_state.discoverability missing"))?;
    DiscoverabilityDb::from_pg(value)
}

fn handle_issuer_policy_from_projection(
    projection: &JsonValue,
) -> Option<Vec<HandleIssuerPolicyEntry>> {
    let value = projection
        .get("handle_issuer_policy")
        .or_else(|| projection.pointer("/policy_bundle/handle_issuer_policy"))?;
    Some(serde_json::from_value(value.clone()).unwrap_or_default())
}

/// True iff a policy entry authorizes both the projection issuer and the
/// canonical handle domain.
fn issuer_authorized_for_projection(
    projection: &JsonValue,
    policy: &[HandleIssuerPolicyEntry],
) -> bool {
    let issuer = projection
        .get("issuer")
        .and_then(JsonValue::as_str)
        .or_else(|| {
            projection
                .get("issuer_service_id")
                .and_then(JsonValue::as_str)
        })
        .and_then(|raw| arkret_sdk::DidCoreId::new(raw.to_owned()).ok());
    let handle = projection
        .get("handle")
        .and_then(JsonValue::as_str)
        .and_then(|raw| Handle::parse(raw).ok());
    match (issuer, handle) {
        (Some(issuer), Some(handle)) => policy
            .iter()
            .any(|entry| handle_issuer_policy_entry_authorizes(entry, &issuer, &handle)),
        _ => false,
    }
}

/// Audience scope filter: when a claim pins an `audience` and the request
/// declares a requester/audience context, the claim is only compatible when
/// the audience matches the requester or the realm. A claim with no pinned
/// audience is always compatible; a request with no context never filters.
fn audience_compatible(
    projection: &JsonValue,
    body: &DirectoryListHandlesForSubjectRequestBody,
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn handle_row(projection: JsonValue, discoverability: DiscoverabilityDb) -> SubjectHandleRow {
        SubjectHandleRow::for_test(
            projection,
            discoverability,
            chrono::TimeZone::timestamp_opt(&Utc, 0, 0).unwrap(),
        )
    }

    #[test]
    fn projection_subject_prefers_subject_then_did() {
        assert_eq!(
            projection_subject(
                &json!({"subject":"ak:did_core:web:alice.example","did":"ak:did_core:web:other"})
            ),
            Some("ak:did_core:web:alice.example")
        );
        assert_eq!(
            projection_subject(&json!({"did":"ak:did_core:web:alice.example"})),
            Some("ak:did_core:web:alice.example")
        );
        assert_eq!(
            projection_subject(&json!({"handle":"alice:example.com"})),
            None
        );
    }

    #[test]
    fn claim_from_projection_binds_request_subject() {
        let row = handle_row(
            json!({"did":"ak:did_core:web:alice.example","handle":"alice:example.com","verified":true,"created_at":"2026-05-20T00:00:00.000Z"}),
            DiscoverabilityDb::Public,
        );
        let claim =
            claim_from_projection(&row, "ak:did_core:web:alice.example").expect("claim built");
        assert_eq!(
            claim.subject.as_ref().unwrap().as_str(),
            "ak:did_core:web:alice.example"
        );
        assert_eq!(
            claim.handle.as_ref().unwrap().canonical(),
            "alice:example.com"
        );
        assert!(matches!(
            claim.binding_state,
            Some(arkret_sdk::HandleBindingState::Verified)
        ));
    }

    #[test]
    fn claim_from_projection_drops_subject_mismatch() {
        // The row asserts a different subject than the request — fail-closed
        // DROP so claims[].subject == response.subject always holds.
        let row = handle_row(
            json!({"did":"ak:did_core:web:eve.example","handle":"alice:example.com","created_at":"2026-05-20T00:00:00.000Z"}),
            DiscoverabilityDb::Public,
        );
        assert!(claim_from_projection(&row, "ak:did_core:web:alice.example").is_none());
    }

    #[test]
    fn claim_from_projection_drops_missing_created_at() {
        // `created_at` is required by `handle-claim.schema.json` and by the
        // `claims[]` items of `list-handles-for-subject-response.schema.json`.
        // A projection without a canonical `created_at` cannot produce a
        // compliant claim, so the row is dropped (fail-closed).
        let row = handle_row(
            json!({"did":"ak:did_core:web:alice.example","handle":"alice:example.com","verified":true}),
            DiscoverabilityDb::Public,
        );
        assert!(claim_from_projection(&row, "ak:did_core:web:alice.example").is_none());
        // A non-canonical spelling (no milliseconds) is rejected the same way.
        let row = handle_row(
            json!({"did":"ak:did_core:web:alice.example","handle":"alice:example.com","created_at":"2026-05-20T00:00:00Z"}),
            DiscoverabilityDb::Public,
        );
        assert!(claim_from_projection(&row, "ak:did_core:web:alice.example").is_none());
    }

    #[test]
    fn service_handle_claim_kind_is_dropped_to_none() {
        assert!(parse_handle_claim_kind("service_handle").is_none());
        assert_eq!(
            parse_handle_claim_kind("handle_binding"),
            Some(arkret_sdk::HandleClaimKind::HandleBinding)
        );
        assert_eq!(
            parse_handle_claim_kind("organization_handle"),
            Some(arkret_sdk::HandleClaimKind::OrganizationHandle)
        );
    }

    #[test]
    fn issuer_policy_matches_issuer_and_handle_domain() {
        let policy: Vec<HandleIssuerPolicyEntry> = serde_json::from_value(json!([{
            "issuer": "ak:did_core:web:issuer.tea",
            "authorized_handle_domains": ["example.com"],
            "issuer_class": "domain_authority"
        }]))
        .unwrap();
        assert!(issuer_authorized_for_projection(
            &json!({"issuer":"ak:did_core:web:issuer.tea","handle":"alice:example.com"}),
            &policy
        ));
        assert!(!issuer_authorized_for_projection(
            &json!({"issuer":"ak:did_core:web:issuer.other","handle":"alice:example.com"}),
            &policy
        ));
        assert!(!issuer_authorized_for_projection(
            &json!({"issuer":"ak:did_core:web:issuer.tea","handle":"alice:other.example"}),
            &policy
        ));
    }

    #[test]
    fn audience_filter_passes_unpinned_and_matching() {
        let body = DirectoryListHandlesForSubjectRequestBody {
            subject: arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned())
                .unwrap(),
            realm_id: None,
            intent: None,
            requester: Some(
                arkret_sdk::DidCoreId::new("ak:did_core:web:tea-org.example".to_owned()).unwrap(),
            ),
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
            &json!({"audience":"ak:did_core:web:tea-org.example"}),
            &body
        ));
        // Pinned audience mutually exclusive with the requester is dropped.
        assert!(!audience_compatible(
            &json!({"audience":"ak:did_core:web:someone-else.example"}),
            &body
        ));
    }

    #[test]
    fn primary_handle_prefers_verified() {
        let verified = HandleClaim {
            schema: HandleClaim::SCHEMA.to_owned(),
            handle: Some(Handle::parse("zed:example.com").unwrap()),
            handle_aliases: Vec::new(),
            subject: Some(
                arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            ),
            issuer: None,
            issuer_service_id: None,
            binding_state: Some(arkret_sdk::HandleBindingState::Verified),
            claim_kind: None,
            visibility: None,
            audience: None,
            challenge: None,
            claim_scope: Default::default(),
            member_delivery_binding: None,
            claims: Vec::new(),
            created_at: Utc::now(),
            expires_at: None,
            verified_at: None,
            source_refs: Vec::new(),
            proofs: Vec::new(),
        };
        let unverified = HandleClaim {
            binding_state: None,
            handle: Some(Handle::parse("aaa:example.com").unwrap()),
            ..verified.clone()
        };
        let claims = vec![unverified, verified];
        // Even though `aaa` sorts first, the verified `zed` is the primary.
        assert_eq!(
            select_primary_handle(&claims).unwrap().canonical(),
            "zed:example.com"
        );
    }
}
