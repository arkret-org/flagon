//! CKP R3 spec-sync 2026-05-27 (commit b47ff6e), authz/resource-
//! selector-grammar — accept the `circle` selector kind on directory
//! query filters.
//!
//! The directory MUST NEVER index Circle as a top-level resource
//! (CKP-0007), but a Realm discovery event may carry a spec-bounded Circle
//! directory preview/stub subtree. Upstream callers — SDK clients running a
//! unified resource-selector evaluator, capability engines, governance bridges
//! — now legitimately emit selector envelopes that include `kind="circle"` and
//! a `ck:circle:<uuid>` target. The directory's job on the generic query face
//! is to **recognise** the selector (so the request validates, doesn't crash)
//! and then respond with the same privacy-preserving `not_found`/locked-stub
//! class used for every unauthorized Circle probe.
//!
//! By contrast, the announce ingest face only accepts exact Circle ids under
//! recognized Circle directory preview containers; every other Circle typed-id
//! occurrence remains a schema violation.
//!
//! Wire shape per `resource-selector.schema.json` (R3 delta):
//!
//! ```json
//! { "kind": "circle", "circle_id": "ak:circle:<uuid>" }
//! ```
//!
//! Discriminator values remain strict lowercase per the protocol registry.

use cokret_sdk::CircleId;
use serde_json::Value as JsonValue;

/// True iff the given filter JSON identifies the `circle` selector
/// kind. Used by query handlers to short-circuit to `not_found`
/// without touching the database (Circle is intra-Realm only).
///
/// Recognises any of:
///   - `{"kind": "circle", ...}`
///   - `{"resource_selector": {"kind": "circle", ...}}`
pub fn is_circle_selector(filter: &JsonValue) -> bool {
    let Some(map) = filter.as_object() else {
        return false;
    };
    if let Some(value) = map.get("kind").and_then(JsonValue::as_str)
        && value == "circle"
    {
        return true;
    }
    if let Some(nested) = map
        .get("resource_selector")
        .and_then(JsonValue::as_object)
        .and_then(|inner| inner.get("kind"))
        .and_then(JsonValue::as_str)
        && nested == "circle"
    {
        return true;
    }
    false
}

/// True iff `value` carries a `ck:circle:<uuid>` typed id. This is a
/// thinner check than [`is_circle_selector`]: it answers "does the
/// caller want to point at a Circle?" regardless of which surrounding
/// envelope field carries the id.
pub fn looks_like_circle_id(value: &str) -> bool {
    CircleId::new(value.to_owned()).is_ok()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn recognises_flat_kind_circle() {
        assert!(is_circle_selector(&json!({"kind": "circle"})));
        assert!(is_circle_selector(
            &json!({"kind": "circle", "circle_id": "ak:circle:01904100-0000-7000-8000-000000000001"})
        ));
    }

    #[test]
    fn recognises_nested_resource_selector() {
        assert!(is_circle_selector(&json!({
            "resource_selector": {"kind": "circle", "circle_id": "ak:circle:01904100-0000-7000-8000-000000000001"}
        })));
    }

    #[test]
    fn rejects_uppercase_discriminator() {
        assert!(!is_circle_selector(&json!({"kind": "CIRCLE"})));
    }

    #[test]
    fn rejects_unrelated_kinds() {
        assert!(!is_circle_selector(&json!({"kind": "space"})));
        assert!(!is_circle_selector(&json!({"kind": "actor"})));
        assert!(!is_circle_selector(&JsonValue::Null));
    }

    #[test]
    fn typed_id_prefix_detected() {
        assert!(looks_like_circle_id(
            "ak:circle:01904100-0000-7000-8000-000000000001"
        ));
        assert!(!looks_like_circle_id(
            "ak:realm:01904100-0000-7000-8000-000000000001"
        ));
    }
}
