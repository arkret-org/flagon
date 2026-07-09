//! Request-shape validation, TTL clamping, and public-projection derivation
//! for directory announces.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;

use super::ingest_body::DirectoryAnnounceIngest;
use crate::error::ApiErrorCode;
use crate::filter::enumeration::{bucket_member_count, is_valid_member_count_bucket};
use crate::ingest::{DirectoryResourceKindDb, DiscoverabilityDb};

/// Round R2/R3 T07 — detect a realm terminal state from the verified
/// discovery_state. The directory accepts the destroy anchor either as
/// `terminal_state: "destroyed"` (preferred, anchored via the `ck.realm.
/// destroy` event kind) or as a `realm_destroyed: true` shorthand. The
/// returned timestamp is `as_of_destroyed` if present, else `as_of`.
pub(crate) fn derive_realm_terminal_state(
    resource_kind: DirectoryResourceKindDb,
    discovery_state: &JsonValue,
) -> Option<DateTime<Utc>> {
    if !matches!(resource_kind, DirectoryResourceKindDb::Realm) {
        return None;
    }
    let destroyed_marker = discovery_state
        .pointer("/terminal_state")
        .and_then(JsonValue::as_str)
        .is_some_and(|state| state.eq_ignore_ascii_case("destroyed"))
        || discovery_state
            .pointer("/realm_destroyed")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false);
    if !destroyed_marker {
        return None;
    }
    let destroyed_at = discovery_state
        .pointer("/realm_destroyed_at")
        .or_else(|| discovery_state.pointer("/as_of_destroyed"))
        .and_then(JsonValue::as_str)
        .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);
    Some(destroyed_at)
}

pub(crate) fn validate_request_shape(
    req: &DirectoryAnnounceIngest,
    max_ttl: Duration,
) -> Result<(), (ApiErrorCode, String)> {
    if req.resource_id.is_empty() {
        return Err((ApiErrorCode::MissingParam, "resource_id is required".into()));
    }
    if req.principal_server_did.is_empty() {
        return Err((
            ApiErrorCode::MissingParam,
            "principal_server_did is required".into(),
        ));
    }
    if !req.discovery_state.is_object() {
        return Err((
            ApiErrorCode::SchemaViolation,
            "discovery_state must be an object".into(),
        ));
    }
    if req.policy_revision.trim().is_empty() {
        return Err((
            ApiErrorCode::MissingParam,
            "policy_revision is required".into(),
        ));
    }
    if let Some(discovery_policy_revision) = req
        .discovery_state
        .get("policy_revision")
        .and_then(JsonValue::as_str)
        && discovery_policy_revision != req.policy_revision
    {
        return Err((
            ApiErrorCode::PolicyRevisionRollback,
            "policy_revision does not match discovery_state.policy_revision".into(),
        ));
    }
    if let Some(ttl) = req.ttl_seconds
        && (ttl <= 0 || ttl > max_ttl.as_secs() as i64)
    {
        return Err((
            ApiErrorCode::TtlOutOfRange,
            format!("ttl_seconds {ttl} not in (0, {}]", max_ttl.as_secs()),
        ));
    }
    Ok(())
}

pub(crate) fn effective_ttl_seconds(
    requested: Option<i64>,
    config: &crate::config::AppConfig,
) -> i64 {
    let requested = requested
        .map(|t| t.max(1))
        .unwrap_or_else(|| config.default_ttl.as_secs() as i64);
    let cap = config.max_ttl.as_secs() as i64;
    requested.min(cap)
}

pub(crate) fn derive_public_projection(
    discovery_state: &JsonValue,
    discoverability: DiscoverabilityDb,
) -> Result<JsonValue, (ApiErrorCode, String)> {
    // Ingest-projection / validation critical path (NOT a placeholder — the
    // "deferred to M3" note that used to live here was stale). Everything this
    // function does is normative and load-bearing:
    //   * `validate_handle_claim_ingest` enforces the HC-TBY-1/2 wire scope (retired
    //     `claim_type`/`class`, non-principal handle-claim subjects).
    //   * the `proof` / `directory_services` / `official_organizations` fields are stripped so
    //     governance internals and the forbidden §4.5 `official_organizations` field never enter
    //     the index or search SQL.
    //   * `normalize_member_count_projection` enforces the §3 member-count disclosure rules
    //     (bucket-grid validity + default-`omit` for non-public discoverability).
    // Do not weaken or short-circuit any of these without re-reading §3 / §4.5
    // / the HC-TBY-* requirements.

    // HC-TBY-1/2 (R3.2, arkret-spec @ b56cab1) — handle-claim wire-level
    // scope validation. This runs in `derive_public_projection` so it
    // applies uniformly to BOTH the push-mode announce path and the
    // federation pull-worker / well-known resolver path (both funnel through
    // this function), satisfying HC-TBY-2's "all reject paths also act on
    // pulled-back claims" requirement.
    validate_handle_claim_ingest(discovery_state)?;

    // The effective `member_count_mode` is read from the *original*
    // discovery_state (before stripping); spec §3 places it at
    // `anti_enumeration.member_count_mode`.
    let declared_mode = discovery_state
        .pointer("/anti_enumeration/member_count_mode")
        .and_then(JsonValue::as_str)
        .map(str::to_owned);

    let mut clone = discovery_state.clone();
    if let Some(obj) = clone.as_object_mut() {
        obj.remove("proof");
        obj.remove("directory_services");
        // `official_organizations` is a forbidden directory-projection field
        // (spec §4.5). Strip it so it never enters the index or search SQL;
        // organization scoping uses the canonical `organization_did`.
        obj.remove("official_organizations");
        // TBY-ORG-01/02 — the `ck.realm.organization` statements are verified
        // and projected into a separate `verified_realm_organizations` index;
        // they MUST NOT leak verbatim into the public projection (which is
        // served to unauthenticated callers and indexed for search).
        obj.remove("organization_statements");
        // TBY-ORG-02 — `owning_organizations` / `organization_did` that survive
        // here are DECLARED hints only (realm.schema: "This field alone is not a
        // verified ownership/governance endorsement; directories MUST require an
        // active ck.realm.organization statement"). They are retained for
        // org-scoped *search* filtering, but a caller MUST NOT be able to inject
        // an official verified badge through the projection — the query layer
        // re-derives the verified `owning_organizations` from the verified index
        // and ignores any pre-supplied badge field here.
        obj.remove("verified_badge");
        obj.remove("official_badge");
        strip_private_search_projection_fields(obj);
        normalize_member_count_projection(obj, discoverability, declared_mode.as_deref())?;
    }
    crate::filter::circle_directory::sanitize_circle_directory_projection(&mut clone);
    Ok(clone)
}

fn strip_private_search_projection_fields(obj: &mut serde_json::Map<String, JsonValue>) {
    const PRIVATE_SEARCH_FIELDS: &[&str] = &[
        "search_policy",
        "search_index_manifest",
        "enabled_profile_refs",
        "allowed_service_dids",
        "data_classes",
        "index_retention_ms",
        "revocation_behavior",
        "encrypted_index",
        "encrypted_shard",
        "blind_tokens",
        "shard_key",
        "epoch_id",
    ];

    obj.retain(|key, value| {
        if PRIVATE_SEARCH_FIELDS.contains(&key.as_str()) {
            return false;
        }
        match value {
            JsonValue::Object(nested) => strip_private_search_projection_fields(nested),
            JsonValue::Array(values) => {
                for item in values {
                    if let JsonValue::Object(nested) = item {
                        strip_private_search_projection_fields(nested);
                    }
                }
            }
            _ => {}
        }
        true
    });
}

/// Spec §3: `restricted` / `unlisted` / `invite_only` / `secret` default to
/// `member_count_mode = omit` and only disclose a bucket when the resource
/// *explicitly* declares `bucketed`. `public` / `listed` default to disclosing
/// (the resource may still pick `omit`/`bucketed`/`exact`).
fn member_count_disclosure_omitted(
    discoverability: DiscoverabilityDb,
    declared_mode: Option<&str>,
) -> bool {
    match declared_mode {
        // An explicit mode always wins, regardless of discoverability.
        Some("omit") => true,
        Some(_) => false,
        // No explicit mode: non-public discoverability defaults to `omit`.
        None => matches!(
            discoverability,
            DiscoverabilityDb::Restricted
                | DiscoverabilityDb::Unlisted
                | DiscoverabilityDb::InviteOnly
                | DiscoverabilityDb::Secret
        ),
    }
}

/// HC-TBY-1/2 — reject handle-claim ingest that violates the R3.2 wire scope:
///
/// 1. `claim_type` / `class` == `service_handle` is rejected (the draft-era value was removed in
///    R3.2). Audit reason `claim_type_unsupported`.
/// 2. A handle-claim `subject` that is a `ck:actor:` Realm actor id, a `ck:account:` server-local
///    account id, a service DID, or any non-DID resource id is rejected. Audit reason
///    `handle_claim_subject_not_principal_did`. The structural DID check is delegated to the SDK's
///    `validate_handle_claim_subject` so the directory and the rest of the stack share one rule.
///
/// Only discovery_state bodies that actually look like a handle claim (carry
/// a `subject` and/or `claim_type` / `class`) are inspected; non-handle
/// announces pass through untouched.
pub(crate) fn validate_handle_claim_ingest(
    discovery_state: &JsonValue,
) -> Result<(), (ApiErrorCode, String)> {
    let Some(obj) = discovery_state.as_object() else {
        return Ok(());
    };

    // (1) `claim_type` / `class` are retired field names. `service_handle`
    // is no longer a valid claim_kind value.
    if obj.get("claim_type").is_some() || obj.get("class").is_some() {
        return Err((
            ApiErrorCode::SchemaViolation,
            "claim_type_unsupported: claim_type/class are forbidden; use claim_kind".to_owned(),
        ));
    }
    if obj
        .get("claim_kind")
        .and_then(JsonValue::as_str)
        .is_some_and(|value| value == "service_handle")
    {
        return Err((
            ApiErrorCode::SchemaViolation,
            "claim_type_unsupported: service_handle is not a valid handle claim_kind".to_owned(),
        ));
    }

    // (2) handle-claim subject MUST be a holder/principal DID.
    if let Some(subject) = obj.get("subject").and_then(JsonValue::as_str) {
        match cokret_sdk::Did::new(subject.to_owned()) {
            Ok(did) => {
                if cokret_sdk::validate_handle_claim_subject(&did).is_err() {
                    return Err((
                        ApiErrorCode::SchemaViolation,
                        format!(
                            "handle_claim_subject_not_principal_did: subject {subject} is not a \
                             holder/principal DID"
                        ),
                    ));
                }
            }
            Err(_) => {
                // `ck:actor:` / `ck:account:` / generic resource ids are not
                // valid DIDs at all — same rejection family.
                if subject.starts_with("ak:actor:")
                    || subject.starts_with("ak:account:")
                    || !subject.starts_with("did:")
                {
                    return Err((
                        ApiErrorCode::SchemaViolation,
                        format!(
                            "handle_claim_subject_not_principal_did: subject {subject} is not a \
                             holder/principal DID"
                        ),
                    ));
                }
            }
        }
    }

    Ok(())
}

fn normalize_member_count_projection(
    obj: &mut serde_json::Map<String, JsonValue>,
    discoverability: DiscoverabilityDb,
    declared_mode: Option<&str>,
) -> Result<(), (ApiErrorCode, String)> {
    // §3 default-`omit`: for non-public discoverability without an explicit
    // `bucketed`/`exact` declaration the directory MUST NOT disclose any
    // member-count signal — drop both the exact count and any pre-supplied
    // bucket (even if `preview.fields` listed it).
    if member_count_disclosure_omitted(discoverability, declared_mode) {
        obj.remove("member_count");
        obj.remove("member_count_bucket");
        return Ok(());
    }

    if let Some(bucket) = obj.get("member_count_bucket").and_then(JsonValue::as_str)
        && !is_valid_member_count_bucket(bucket)
    {
        return Err((
            ApiErrorCode::InvalidResponse,
            format!("member_count_bucket {bucket} is outside the normative bucket grid"),
        ));
    }

    if let Some(exact) = obj.remove("member_count") {
        let count = exact.as_i64().ok_or_else(|| {
            (
                ApiErrorCode::InvalidResponse,
                "member_count must be an integer when present".into(),
            )
        })?;
        // A zero/negative count has no valid bucket (lowest grid bucket is
        // `1-10` = "1 to 10 members"); omit rather than falsely advertise the
        // lowest non-empty bucket.
        match bucket_member_count(count) {
            Some(bucket) => {
                obj.insert(
                    "member_count_bucket".into(),
                    JsonValue::String(bucket.to_string()),
                );
            }
            None => {
                obj.remove("member_count_bucket");
            }
        }
    }
    Ok(())
}
