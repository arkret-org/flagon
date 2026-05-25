//! Circle isolation guard for ingest/subscribe payloads.
//!
//! Circle (CXP-0007, spec b7d35be / 2b0d70d) is an **intra-Realm**
//! encrypted sub-boundary: a Circle's existence, member list, and
//! routing metadata MUST NEVER appear in the public directory. teabay's
//! anti-enumeration story is built on the directory only ever indexing
//! Realm-level discovery state; Circle metadata leaking through
//! `cx.directory.announce` or a `cx.directory.subscribe` filter would
//! immediately defeat that.
//!
//! This module is the single hard-reject point. Both ingest paths
//! (`ingest/announce.rs`, `ingest/subscribe.rs`) call
//! [`reject_circle_payload`] BEFORE the JSON body is touched by any
//! other code, so an attacker cannot smuggle Circle metadata through a
//! deeply-nested field. The reject deliberately uses
//! `ERROR_CODE_SCHEMA_VIOLATION` with the
//! `circle_isolation_violation` reason sub-code (the closest
//! spec-registered code; see SDK
//! `KNOWN_REASON_CODES_CXP_0007`). It does NOT leak which field or
//! which Circle id triggered the reject — the rejection message names
//! only that a Circle reference was found.
//!
//! The walker is intentionally pessimistic:
//!  - any object key in [`CIRCLE_FORBIDDEN_KEYS`] is a hard reject
//!  - any string value starting with `cx:circle:` is a hard reject
//!    (so a `circle_id` smuggled under a free-form `description` field
//!    is still caught)
//!  - any forbidden top-level wire field per SDK
//!    [`contrix_sdk::is_forbidden_wire_field`] (e.g. `discussion_realm_ref`)
//!    is a hard reject — this is the CXP-0007 anti-rollback floor.

use serde_json::Value as JsonValue;

/// Object keys that name a Circle scope or membership. Any of these
/// appearing at any nesting depth inside an ingest payload is an
/// immediate hard reject.
///
/// `scope_circle_id` is the canonical CXP-0007 field on Flow/Space/
/// Morph; it MUST stay strictly inside a Realm (soland) and never
/// project into the directory. `circle_id` / `circle_members` /
/// `member_circle_ids` cover legacy/short names that downstream
/// services might be tempted to emit. `cx.circle.*` event-kind echoes
/// (e.g. `event_kind: "cx.circle.member.add"`) are independently
/// rejected via the `cx:circle:` value sentinel.
pub const CIRCLE_FORBIDDEN_KEYS: &[&str] = &[
    "circle_id",
    "circle_members",
    "circle_member_ids",
    "member_circle_ids",
    "scope_circle_id",
    "default_scope_circle_id",
    // Pre-CXP-0007 names that the SDK forbidden-wire-fields list
    // already hard-rejects on Event payloads; we mirror them here so
    // they fail at the directory edge too.
    "discussion_realm_ref",
    "discussion_space_ref",
];

/// Canonical typed-id prefix for a Circle (`cx:circle:<ulid>`). Any
/// string value carrying this prefix anywhere in the payload is a
/// hard reject — this is the parser-tolerance plank from P2E.7: we
/// recognise the typed id only to refuse it.
pub const CIRCLE_TYPED_ID_PREFIX: &str = "cx:circle:";

/// Outcome of [`reject_circle_payload`]. The caller maps each variant
/// to its preferred `ApiErrorCode` — typically `SchemaViolation` for
/// Circle field/value violations and (where the SDK already names a
/// code) the matching forbidden-wire-field reject for the legacy
/// names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircleRejection {
    /// A forbidden Circle-scoped object key was found. Field name is
    /// returned so the caller can include it in the audit record; the
    /// wire response MUST NOT echo the field name back to the
    /// attacker.
    ForbiddenKey(&'static str),
    /// A string value carrying `cx:circle:<...>` was found. The
    /// caller MUST NOT echo the actual id back to the attacker; the
    /// returned tuple is `(json_pointer, prefix)` where `prefix` is
    /// always [`CIRCLE_TYPED_ID_PREFIX`].
    ForbiddenTypedId(String),
    /// A spec-registered legacy forbidden-wire-field (per SDK
    /// `is_forbidden_wire_field`) was found. We mirror the SDK
    /// hard-reject list at the directory edge.
    ForbiddenLegacyWireField(String),
}

impl CircleRejection {
    /// Stable, low-information wire message. We deliberately do NOT
    /// echo back the field name or any typed id, because the directory
    /// is anti-enumeration: an attacker probing for "is `cx:circle:X`
    /// known here?" must not be able to read that back from the
    /// error body.
    pub fn safe_message(&self) -> &'static str {
        match self {
            Self::ForbiddenKey(_) => {
                "ingest payload carries a Circle-scoped field; Circle is intra-Realm only"
            }
            Self::ForbiddenTypedId(_) => {
                "ingest payload references a Circle typed identifier; Circle is intra-Realm only"
            }
            Self::ForbiddenLegacyWireField(_) => {
                "ingest payload carries a forbidden legacy wire field (CXP-0007)"
            }
        }
    }

    /// Audit-only label — safe to log because the audit trail is
    /// operator-private. Distinct from [`safe_message`] which goes on
    /// the wire.
    pub fn audit_label(&self) -> &str {
        match self {
            Self::ForbiddenKey(key) => key,
            Self::ForbiddenTypedId(pointer) => pointer.as_str(),
            Self::ForbiddenLegacyWireField(key) => key.as_str(),
        }
    }
}

/// Walk `value` recursively and return the first Circle-related
/// rejection found. Returns `Ok(())` when the payload is clean.
///
/// The walker is intentionally cheap (no allocation beyond the
/// returned json-pointer string on a hit) so the announce/subscribe
/// hot path can call it unconditionally on every request.
pub fn reject_circle_payload(value: &JsonValue) -> Result<(), CircleRejection> {
    walk(value, &mut String::new())
}

fn walk(value: &JsonValue, pointer: &mut String) -> Result<(), CircleRejection> {
    match value {
        JsonValue::Object(map) => {
            for (key, child) in map {
                // Order matters: the SDK forbidden-wire-fields list
                // takes priority for spec-registered legacy names
                // (e.g. `discussion_realm_ref`) so the caller can
                // distinguish a CXP-0007 anti-rollback reject from a
                // generic Circle-key reject in audit. The Circle-only
                // names (`circle_id`, `scope_circle_id`, etc.) are
                // not in the SDK list and fall through to
                // `ForbiddenKey`.
                if contrix_sdk::is_forbidden_wire_field(key) {
                    return Err(CircleRejection::ForbiddenLegacyWireField(key.clone()));
                }
                if let Some(forbidden) = CIRCLE_FORBIDDEN_KEYS
                    .iter()
                    .find(|name| name.eq_ignore_ascii_case(key))
                {
                    return Err(CircleRejection::ForbiddenKey(forbidden));
                }
                let preserved_len = pointer.len();
                pointer.push('/');
                push_pointer_token(pointer, key);
                walk(child, pointer)?;
                pointer.truncate(preserved_len);
            }
            Ok(())
        }
        JsonValue::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let preserved_len = pointer.len();
                pointer.push('/');
                pointer.push_str(&index.to_string());
                walk(child, pointer)?;
                pointer.truncate(preserved_len);
            }
            Ok(())
        }
        JsonValue::String(s) => {
            // We match `cx:circle:` anywhere in the string — not just
            // as a prefix — because an attacker can embed a typed id
            // inside a free-form `summary` / `description` / `note`
            // field and the directory MUST still refuse to index it.
            // Case-insensitive because typed-id parsers are
            // case-insensitive per spec §id-format.
            let needle = CIRCLE_TYPED_ID_PREFIX; // lowercase
            if contains_ignore_ascii_case(s, needle) {
                let pointer_clone = if pointer.is_empty() {
                    "/".to_owned()
                } else {
                    pointer.clone()
                };
                return Err(CircleRejection::ForbiddenTypedId(pointer_clone));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

/// RFC 6901 json-pointer token escaping: `~` → `~0`, `/` → `~1`.
fn push_pointer_token(out: &mut String, token: &str) {
    for ch in token.chars() {
        match ch {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            other => out.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_realm_only_announce_state() {
        let value = json!({
            "kind": "cx.realm.discovery",
            "discoverability": "public",
            "directory_services": ["did:web:directory.test"],
            "member_count_bucket": "11-50",
        });
        assert!(reject_circle_payload(&value).is_ok());
    }

    #[test]
    fn rejects_top_level_circle_id() {
        let value = json!({
            "kind": "cx.realm.discovery",
            "circle_id": "cx:circle:01J0XXXXX",
        });
        let err = reject_circle_payload(&value).unwrap_err();
        assert!(matches!(err, CircleRejection::ForbiddenKey("circle_id")));
    }

    #[test]
    fn rejects_nested_circle_members_array() {
        let value = json!({
            "discoverability": "listed",
            "membership": {
                "advertised_admins": [],
                "circle_members": ["did:web:a", "did:web:b"],
            },
        });
        let err = reject_circle_payload(&value).unwrap_err();
        assert!(matches!(
            err,
            CircleRejection::ForbiddenKey("circle_members")
        ));
    }

    #[test]
    fn rejects_scope_circle_id_in_filter() {
        // `scope_circle_id` is the canonical CXP-0007 field name — it
        // MUST NEVER appear in a subscribe filter or an announce body.
        let value = json!({
            "scope_circle_id": "cx:circle:01J0XXXXX",
        });
        assert!(matches!(
            reject_circle_payload(&value).unwrap_err(),
            CircleRejection::ForbiddenKey("scope_circle_id")
        ));
    }

    #[test]
    fn rejects_typed_circle_id_embedded_in_free_text_field() {
        // An attacker can't smuggle a Circle id through a free-form
        // value either — the walker catches `cx:circle:` no matter
        // which key it lives under.
        let value = json!({
            "kind": "cx.realm.discovery",
            "summary": "see also cx:circle:01J0XXXXXX for the back-channel",
        });
        let err = reject_circle_payload(&value).unwrap_err();
        match err {
            CircleRejection::ForbiddenTypedId(_) => {}
            other => panic!("expected ForbiddenTypedId, got {other:?}"),
        }
    }

    #[test]
    fn rejects_circle_id_array_element() {
        let value = json!({
            "kind": "cx.realm.discovery",
            "related": ["cx:realm:a", "cx:circle:b"],
        });
        let err = reject_circle_payload(&value).unwrap_err();
        assert!(matches!(err, CircleRejection::ForbiddenTypedId(_)));
    }

    /// P2E.7 — the parser-tolerance plank: a `cx:circle:<ulid>`
    /// living in the `resource_id` field of an announce envelope (i.e.
    /// the attacker tries to "announce a Circle into the directory")
    /// MUST be recognised and rejected. The directory never adds an
    /// `IdClass::Circle` variant — see crate::ids docs.
    #[test]
    fn rejects_cx_circle_in_resource_id_field() {
        let envelope = json!({
            "resource_kind": "realm",
            "resource_id": "cx:circle:01J0CIRCLEULIDV4XYZ",
            "principal_server_did": "did:web:principal.test",
            "discovery_state": {"kind": "cx.realm.discovery"},
        });
        let err = reject_circle_payload(&envelope).unwrap_err();
        assert!(matches!(err, CircleRejection::ForbiddenTypedId(_)));
    }

    /// P2E.7 — uppercase / mixed-case `Cx:CIRCLE:` MUST still be
    /// caught (typed-id parsers are case-insensitive per spec
    /// §id-format).
    #[test]
    fn rejects_mixed_case_cx_circle_prefix() {
        let envelope = json!({
            "discovery_state": {"note": "Cx:CIRCLE:0123ABC"},
        });
        let err = reject_circle_payload(&envelope).unwrap_err();
        assert!(matches!(err, CircleRejection::ForbiddenTypedId(_)));
    }

    #[test]
    fn rejects_legacy_discussion_realm_ref() {
        // CXP-0007 pre-rename field; the SDK's forbidden-wire-fields
        // list already hard-rejects it on Event payloads. teabay
        // mirrors that at the directory edge.
        let value = json!({
            "discussion_realm_ref": "cx:realm:x",
        });
        let err = reject_circle_payload(&value).unwrap_err();
        assert!(matches!(
            err,
            CircleRejection::ForbiddenLegacyWireField(field) if field == "discussion_realm_ref"
        ));
    }

    #[test]
    fn safe_message_does_not_leak_field_name_or_id() {
        let key_err = CircleRejection::ForbiddenKey("circle_members");
        assert!(!key_err.safe_message().contains("circle_members"));
        let id_err = CircleRejection::ForbiddenTypedId("/summary".into());
        assert!(!id_err.safe_message().contains("summary"));
        assert!(!id_err.safe_message().contains("cx:circle:"));
    }

    /// Property-style test (small fixed seed): random injection of
    /// `circle_id` / `cx:circle:` into otherwise-clean payloads is
    /// always caught.
    #[test]
    fn property_random_circle_injection_is_always_caught() {
        let bases = [
            json!({"kind": "cx.realm.discovery"}),
            json!({"kind": "cx.realm.discovery", "directory_services": []}),
            json!({"nested": {"a": {"b": {"c": 1}}}}),
            json!({"list": [1, 2, {"deep": "ok"}]}),
        ];
        let injections: &[(&str, JsonValue)] = &[
            ("circle_id", JsonValue::String("cx:circle:abc".into())),
            ("scope_circle_id", JsonValue::String("cx:circle:abc".into())),
            (
                "circle_members",
                JsonValue::Array(vec![JsonValue::String("did:web:a".into())]),
            ),
            (
                "default_scope_circle_id",
                JsonValue::String("cx:circle:abc".into()),
            ),
        ];
        for base in bases {
            for (key, value) in injections {
                let mut victim = base.clone();
                // Inject at either top-level or one level of nesting.
                victim.as_object_mut().unwrap().insert(
                    (*key).to_owned(),
                    value.clone(),
                );
                assert!(
                    reject_circle_payload(&victim).is_err(),
                    "injection of {key} into {victim} must be rejected"
                );

                // Also inject as a string value somewhere unrelated.
                let mut victim2 = base.clone();
                victim2.as_object_mut().unwrap().insert(
                    "note".to_owned(),
                    JsonValue::String(format!("see {CIRCLE_TYPED_ID_PREFIX}01")),
                );
                assert!(
                    reject_circle_payload(&victim2).is_err(),
                    "injection of cx:circle: literal must be rejected"
                );
            }
        }
    }

    /// Sanity: the rejector must not flag any plausible non-Circle
    /// announce body. (Lightly-randomized exploration of the realm-
    /// only schema surface that teabay actually projects.)
    #[test]
    fn property_clean_realm_payloads_are_accepted() {
        let payloads = [
            json!({"kind": "cx.realm.discovery", "discoverability": "public"}),
            json!({"kind": "cx.realm.discovery", "directory_services": ["did:web:d.test"], "policy_revision": "r-42"}),
            json!({"kind": "cx.space.discovery", "as_of": "2026-05-26T00:00:00Z"}),
            json!({"kind": "cx.actor.discovery", "handle": "did:web:alice"}),
            // member_count_bucket is allowed — the bucket grid is the
            // anti-enumeration sanctioned projection.
            json!({"kind": "cx.realm.discovery", "member_count_bucket": "11-50"}),
        ];
        for payload in payloads {
            assert!(
                reject_circle_payload(&payload).is_ok(),
                "clean payload {payload} must be accepted",
            );
        }
    }
}
