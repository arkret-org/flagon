//! Circle isolation guard for ingest/subscribe payloads.
//!
//! Circle (CKP-0007, spec b7d35be / 2b0d70d) is an **intra-Realm**
//! encrypted sub-boundary: a Circle's existence, member list, and
//! routing metadata MUST NEVER appear in the public directory. teabay's
//! anti-enumeration story is built on the directory only ever indexing
//! Realm-level discovery state; Circle metadata leaking through
//! `ck.find.directory.command.announce` or a `ck.find.directory.push.command.register` filter would
//! immediately defeat that.
//!
//! This module is the single hard-reject point. Both ingest paths
//! (`ingest/announce.rs`, `ingest/subscribe.rs`) call
//! [`reject_circle_payload`] BEFORE the JSON body is touched by any
//! other code, so an attacker cannot smuggle Circle typed identifiers
//! through a deeply-nested field. The reject deliberately uses
//! `ERROR_CODE_SCHEMA_VIOLATION` with the
//! `circle_isolation_violation` reason sub-code (the closest
//! spec-registered code; see SDK
//! `KNOWN_REASON_CODES_CKP_0007`). It does NOT leak which field or
//! which Circle id triggered the reject — the rejection message names
//! only that a Circle reference was found.
//!
//! The walker is intentionally scoped to Circle leakage:
//!  - any string value containing `ck:circle:` is a hard reject (so a `circle_id` smuggled under a
//!    free-form `description` field is still caught)

use serde_json::Value as JsonValue;

/// Canonical typed-id prefix for a Circle (`ck:circle:<uuid>`). Any
/// string value carrying this prefix anywhere in the payload is a
/// hard reject — this is the parser-tolerance plank from P2E.7: we
/// recognise the typed id only to refuse it.
pub const CIRCLE_TYPED_ID_PREFIX: &str = "ck:circle:";

/// Outcome of [`reject_circle_payload`]. The caller maps each variant
/// to its preferred `ApiErrorCode`, typically `SchemaViolation` for
/// Circle typed-id violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircleRejection {
    /// A string value carrying `ck:circle:<...>` was found. The
    /// caller MUST NOT echo the actual id back to the attacker; the
    /// returned string is the JSON pointer where the value was found.
    ForbiddenTypedId(String),
}

impl CircleRejection {
    /// Stable, low-information wire message. We deliberately do NOT
    /// echo back any typed id, because the directory
    /// is anti-enumeration: an attacker probing for "is `ck:circle:X`
    /// known here?" must not be able to read that back from the
    /// error body.
    pub fn safe_message(&self) -> &'static str {
        match self {
            Self::ForbiddenTypedId(_) => {
                "ingest payload references a Circle typed identifier; Circle is intra-Realm only"
            }
        }
    }

    /// Audit-only label — safe to log because the audit trail is
    /// operator-private. Distinct from [`safe_message`] which goes on
    /// the wire.
    pub fn audit_label(&self) -> &str {
        match self {
            Self::ForbiddenTypedId(pointer) => pointer.as_str(),
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
            // We match `ck:circle:` anywhere in the string — not just
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
    use serde_json::json;

    use super::*;

    #[test]
    fn accepts_realm_only_announce_state() {
        let value = json!({
            "kind": "ck.realm.discovery",
            "discoverability": "public",
            "directory_services": ["did:web:directory.test"],
            "member_count_bucket": "11-50",
        });
        assert!(reject_circle_payload(&value).is_ok());
    }

    #[test]
    fn rejects_top_level_typed_circle_id_value() {
        let value = json!({
            "kind": "ck.realm.discovery",
            "circle_id": "ck:circle:01904100-0000-7000-8000-000000000001",
        });
        let err = reject_circle_payload(&value).unwrap_err();
        assert!(matches!(err, CircleRejection::ForbiddenTypedId(_)));
    }

    #[test]
    fn rejects_typed_circle_id_embedded_in_free_text_field() {
        // An attacker can't smuggle a Circle id through a free-form
        // value either — the walker catches `ck:circle:` no matter
        // which key it lives under.
        let value = json!({
            "kind": "ck.realm.discovery",
            "summary": "see also ck:circle:01904100-0000-7000-8000-000000000001 for the back-channel",
        });
        let err = reject_circle_payload(&value).unwrap_err();
        assert!(matches!(err, CircleRejection::ForbiddenTypedId(_)));
    }

    #[test]
    fn rejects_circle_id_array_element() {
        let value = json!({
            "kind": "ck.realm.discovery",
            "related": [
                "ck:realm:01904100-0000-7000-8000-000000000101",
                "ck:circle:01904100-0000-7000-8000-000000000001",
            ],
        });
        let err = reject_circle_payload(&value).unwrap_err();
        assert!(matches!(err, CircleRejection::ForbiddenTypedId(_)));
    }

    /// P2E.7 — the parser-tolerance plank: a `ck:circle:<uuid>`
    /// living in the `resource_id` field of an announce envelope (i.e.
    /// the attacker tries to "announce a Circle into the directory")
    /// MUST be recognised and rejected. The directory never adds an
    /// `IdClass::Circle` variant — see crate::ids docs.
    #[test]
    fn rejects_cx_circle_in_resource_id_field() {
        let envelope = json!({
            "resource_kind": "realm",
            "resource_id": "ck:circle:01904100-0000-7000-8000-000000000001",
            "principal_server_did": "did:web:principal.test",
            "discovery_state": {"kind": "ck.realm.discovery"},
        });
        let err = reject_circle_payload(&envelope).unwrap_err();
        assert!(matches!(err, CircleRejection::ForbiddenTypedId(_)));
    }

    /// P2E.7 — uppercase / mixed-case `Ck:CIRCLE:` MUST still be
    /// caught (typed-id parsers are case-insensitive per spec
    /// §id-format).
    #[test]
    fn rejects_mixed_case_ck_circle_prefix() {
        let envelope = json!({
            "discovery_state": {"note": "Ck:CIRCLE:01904100-0000-7000-8000-000000000001"},
        });
        let err = reject_circle_payload(&envelope).unwrap_err();
        assert!(matches!(err, CircleRejection::ForbiddenTypedId(_)));
    }

    #[test]
    fn safe_message_does_not_leak_field_name_or_id() {
        let id_err = CircleRejection::ForbiddenTypedId("/summary".into());
        assert!(!id_err.safe_message().contains("summary"));
        assert!(!id_err.safe_message().contains("ck:circle:"));
    }

    /// Property-style test (small fixed seed): random injection of
    /// `ck:circle:` into otherwise-clean payloads is always caught.
    #[test]
    fn property_random_circle_injection_is_always_caught() {
        let bases = [
            json!({"kind": "ck.realm.discovery"}),
            json!({"kind": "ck.realm.discovery", "directory_services": []}),
            json!({"nested": {"a": {"b": {"c": 1}}}}),
            json!({"list": [1, 2, {"deep": "ok"}]}),
        ];
        let injections: &[(&str, JsonValue)] = &[
            (
                "circle_id",
                JsonValue::String("ck:circle:01904100-0000-7000-8000-000000000001".into()),
            ),
            (
                "scope_circle_id",
                JsonValue::String("ck:circle:01904100-0000-7000-8000-000000000001".into()),
            ),
            (
                "circle_members",
                JsonValue::Array(vec![JsonValue::String(
                    "ck:circle:01904100-0000-7000-8000-000000000001".into(),
                )]),
            ),
            (
                "default_scope_circle_id",
                JsonValue::String("ck:circle:01904100-0000-7000-8000-000000000001".into()),
            ),
        ];
        for base in bases {
            for (key, value) in injections {
                let mut victim = base.clone();
                // Inject at either top-level or one level of nesting.
                victim
                    .as_object_mut()
                    .unwrap()
                    .insert((*key).to_owned(), value.clone());
                assert!(
                    reject_circle_payload(&victim).is_err(),
                    "injection of {key} into {victim} must be rejected"
                );

                // Also inject as a string value somewhere unrelated.
                let mut victim2 = base.clone();
                victim2.as_object_mut().unwrap().insert(
                    "note".to_owned(),
                    JsonValue::String(format!(
                        "see {CIRCLE_TYPED_ID_PREFIX}01904100-0000-7000-8000-000000000001"
                    )),
                );
                assert!(
                    reject_circle_payload(&victim2).is_err(),
                    "injection of ck:circle: literal must be rejected"
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
            json!({"kind": "ck.realm.discovery", "discoverability": "public"}),
            json!({"kind": "ck.realm.discovery", "directory_services": ["did:web:d.test"], "policy_revision": "r-42"}),
            json!({"kind": "ck.realm.discovery", "as_of": "2026-05-26T00:00:00Z"}),
            json!({"kind": "ck.actor.discovery", "handle": "did:web:alice"}),
            // member_count_bucket is allowed — the bucket grid is the
            // anti-enumeration sanctioned projection.
            json!({"kind": "ck.realm.discovery", "member_count_bucket": "11-50"}),
        ];
        for payload in payloads {
            assert!(
                reject_circle_payload(&payload).is_ok(),
                "clean payload {payload} must be accepted",
            );
        }
    }
}
