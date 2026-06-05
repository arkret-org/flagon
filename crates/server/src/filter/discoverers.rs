//! Single source of truth for `allowed_discoverers` restricted-visibility
//! matching (spec discovery-directory §3).
//!
//! `restricted` resources are only surfaced to a requester whose identity or
//! presented proofs satisfy the resource's `allowed_discoverers` list. This
//! decision gates whether a restricted Realm / Handle / Organization is
//! visible at all, so the matching logic MUST be identical across every
//! `resolve_*` / `search_*` handler. Previously `query::realm` and
//! `query::handle` each hand-rolled a byte-for-byte copy of this list and its
//! key sets; a future tightening of the rule could have silently drifted one
//! copy from the other and opened an authorization inconsistency. Keeping the
//! one implementation here removes that hazard.

use serde_json::Value as JsonValue;

/// Object-entry keys that identify the requesting principal.
const REQUESTER_KEYS: [&str; 4] = ["requester", "subject", "did", "actor"];
/// Object-entry keys that carry a proof / presentation reference.
const PROOF_KEYS: [&str; 5] = ["proof", "presentation", "claim", "claim_id", "claim_kind"];

/// Resolve the `allowed_discoverers` array from a public projection, accepting
/// either the top-level field or the `/payload/allowed_discoverers` nested
/// form produced by some ingest projections.
pub fn allowed_discoverers(projection: &JsonValue) -> Option<&Vec<JsonValue>> {
    projection
        .get("allowed_discoverers")
        .or_else(|| projection.pointer("/payload/allowed_discoverers"))
        .and_then(JsonValue::as_array)
}

/// True when the projection declares a non-empty `allowed_discoverers` list.
pub fn has_allowed_discoverers(projection: &JsonValue) -> bool {
    allowed_discoverers(projection).is_some_and(|arr| !arr.is_empty())
}

/// Decide whether `requester` / `proofs` satisfy the projection's
/// `allowed_discoverers` list. Returns `false` when the list is absent or
/// empty (fail-closed: a restricted resource with no discoverers is invisible).
pub fn matches_allowed_discoverers(
    projection: &JsonValue,
    requester: Option<&str>,
    proofs: &[String],
) -> bool {
    let Some(discoverers) = allowed_discoverers(projection) else {
        return false;
    };
    discoverers.iter().any(|entry| match entry {
        JsonValue::String(value) => proofs.iter().any(|proof| proof == value),
        JsonValue::Object(obj) => {
            let requester_matches = requester.is_some_and(|requester| {
                REQUESTER_KEYS
                    .iter()
                    .any(|key| obj.get(*key).and_then(JsonValue::as_str) == Some(requester))
            });
            let proof_matches = PROOF_KEYS
                .iter()
                .filter_map(|key| obj.get(*key).and_then(JsonValue::as_str))
                .any(|expected| proofs.iter().any(|proof| proof == expected));
            requester_matches || proof_matches
        }
        _ => false,
    })
}
