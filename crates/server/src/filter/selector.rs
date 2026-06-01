//! CXP R3 spec-sync 2026-05-27 (commit b47ff6e), authz/resource-
//! selector-grammar — accept the `circle` selector kind on directory
//! query filters.
//!
//! The directory MUST NEVER index Circle resources (CXP-0007;
//! `circle_isolation.rs` enforces this on the ingest face). However,
//! upstream callers — SDK clients running a unified resource-selector
//! evaluator, capability engines, governance bridges — now legitimately
//! emit selector envelopes that include `selector_kind="circle"` and a
//! `cx:circle:<uuid>` target. The directory's job on the query face is
//! to **recognise** the selector (so the request validates, doesn't
//! crash) and then respond with the same privacy-preserving `not_found`
//! shape that every directory miss returns.
//!
//! By contrast the ingest face still hard-rejects Circle via
//! [`crate::filter::circle_isolation`]; that asymmetry is intentional —
//! a query asking "do you have anything for this circle?" is legitimate
//! and earns a 404; an ingest publishing Circle metadata is an
//! anti-rollback violation and earns a 422 schema-violation.
//!
//! Wire shape per `resource-selector.schema.json` (R3 delta):
//!
//! ```json
//! { "kind": "circle", "circle_id": "cx:circle:<uuid>" }
//! ```
//!
//! Legacy callers may also send `{ "selector_kind": "circle", ... }`
//! or include the typed id at top level; the parser is forgiving.

use serde_json::Value as JsonValue;

/// True iff the given filter JSON identifies the `circle` selector
/// kind. Used by query handlers to short-circuit to `not_found`
/// without touching the database (Circle is intra-Realm only).
///
/// Recognises any of:
///   - `{"kind": "circle", ...}`
///   - `{"selector_kind": "circle", ...}`
///   - `{"resource_selector": {"kind": "circle", ...}}`
///
/// Case-insensitive on the discriminator value because Contrix typed
/// kinds are stable lowercase identifiers.
pub fn is_circle_selector(filter: &JsonValue) -> bool {
    let Some(map) = filter.as_object() else {
        return false;
    };
    for key in ["kind", "selector_kind"] {
        if let Some(value) = map.get(key).and_then(JsonValue::as_str)
            && value.eq_ignore_ascii_case("circle")
        {
            return true;
        }
    }
    if let Some(nested) = map
        .get("resource_selector")
        .and_then(JsonValue::as_object)
        .and_then(|inner| inner.get("kind"))
        .and_then(JsonValue::as_str)
        && nested.eq_ignore_ascii_case("circle")
    {
        return true;
    }
    false
}

/// True iff `value` carries a `cx:circle:<uuid>` typed id. This is a
/// thinner check than [`is_circle_selector`]: it answers "does the
/// caller want to point at a Circle?" regardless of which surrounding
/// envelope field carries the id.
///
/// TODO(R3.1): once `contrix_sdk::CircleId` exposes a public
/// `wire_form()` constructor accepting bare strings, swap this for
/// the SDK typed parse so we share the validator with the engine
/// selector parser in `crates/sdk/src/authz/selectors.rs`.
pub fn looks_like_circle_id(value: &str) -> bool {
    value.starts_with("cx:circle:")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn recognises_flat_kind_circle() {
        assert!(is_circle_selector(&json!({"kind": "circle"})));
        assert!(is_circle_selector(
            &json!({"kind": "circle", "circle_id": "cx:circle:abc"})
        ));
    }

    #[test]
    fn recognises_selector_kind_alias() {
        assert!(is_circle_selector(&json!({"selector_kind": "circle"})));
    }

    #[test]
    fn recognises_nested_resource_selector() {
        assert!(is_circle_selector(&json!({
            "resource_selector": {"kind": "circle", "circle_id": "cx:circle:abc"}
        })));
    }

    #[test]
    fn case_insensitive_on_discriminator() {
        assert!(is_circle_selector(&json!({"kind": "CIRCLE"})));
    }

    #[test]
    fn rejects_unrelated_kinds() {
        assert!(!is_circle_selector(&json!({"kind": "space"})));
        assert!(!is_circle_selector(&json!({"kind": "actor"})));
        assert!(!is_circle_selector(&JsonValue::Null));
    }

    #[test]
    fn typed_id_prefix_detected() {
        assert!(looks_like_circle_id("cx:circle:01J0XYZ"));
        assert!(!looks_like_circle_id("cx:realm:01J0XYZ"));
    }
}
