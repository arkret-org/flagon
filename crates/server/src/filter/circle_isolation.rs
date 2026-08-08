//! Circle isolation guard for ingest/subscribe payloads.
//!
//! Circle (AKP-0007, spec b7d35be / 2b0d70d) is an **intra-Realm**
//! encrypted sub-boundary: a Circle's existence, member list, and
//! routing metadata MUST NEVER appear in the public directory. teabay's
//! anti-enumeration story is built on the directory only indexing
//! Realm-level discovery state plus the spec-bounded Circle directory
//! preview/stub projection.
//!
//! This module is the typed-id guard point. Subscribe filters still call
//! [`reject_circle_payload`] as a full hard reject. Announce calls
//! [`reject_circle_payload_allowing_directory_preview`] so a signed Realm
//! discovery event can carry a spec-bounded Circle directory entry id, while
//! every other Circle typed-id occurrence remains rejected before indexing.
//! The reject deliberately uses
//! `arkret::ErrorCode::SCHEMA_VIOLATION` with the
//! `circle_isolation_violation` reason sub-code (the closest
//! spec-registered code; see SDK
//! `KNOWN_REASON_CODES_CKP_0007`). It does NOT leak which field or
//! which Circle id triggered the reject — the rejection message names
//! only that a Circle reference was found.
//!
//! The walker is intentionally scoped to Circle leakage:
//!  - by default, any string value containing `ak:circle:` is a hard reject;
//!  - in the announce-only preview mode, the only exception is an exact canonical Circle id under a
//!    recognized Circle directory container's `circle_id` / `id` field.

use serde_json::Value as JsonValue;

use crate::filter::circle_directory::is_circle_directory_container_key;

/// Canonical typed-id prefix for a Circle (`ak:circle:<uuid>`). Any
/// string value carrying this prefix anywhere in the payload is a
/// hard reject — this is the parser-tolerance plank from P2E.7: we
/// recognise the typed id only to refuse it.
pub const CIRCLE_TYPED_ID_PREFIX: &str = "ak:circle:";

/// Outcome of [`reject_circle_payload`]. The caller maps each variant
/// to its preferred `ApiErrorCode`, typically `SchemaViolation` for
/// Circle typed-id violations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircleRejection {
    /// A string value carrying `ak:circle:<...>` was found. The
    /// caller MUST NOT echo the actual id back to the attacker; the
    /// returned string is the JSON pointer where the value was found.
    ForbiddenTypedId(String),
}

impl CircleRejection {
    /// Stable, low-information wire message. We deliberately do NOT
    /// echo back any typed id, because the directory
    /// is anti-enumeration: an attacker probing for "is `ak:circle:X`
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
    walk(value, &mut String::new(), false)
}

/// Announce-only variant used before signature/shape validation. It permits
/// the Circle id field required by a Realm's Circle directory projection, but
/// it still rejects top-level Circle resources, scope references, embedded
/// free-text ids, member lists, and subscribe filters.
pub fn reject_circle_payload_allowing_directory_preview(
    value: &JsonValue,
) -> Result<(), CircleRejection> {
    walk(value, &mut String::new(), true)
}

fn walk(
    value: &JsonValue,
    pointer: &mut String,
    allow_directory_preview_ids: bool,
) -> Result<(), CircleRejection> {
    match value {
        JsonValue::Object(map) => {
            for (key, child) in map {
                let preserved_len = pointer.len();
                pointer.push('/');
                push_pointer_token(pointer, key);
                walk(child, pointer, allow_directory_preview_ids)?;
                pointer.truncate(preserved_len);
            }
            Ok(())
        }
        JsonValue::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let preserved_len = pointer.len();
                pointer.push('/');
                pointer.push_str(&index.to_string());
                walk(child, pointer, allow_directory_preview_ids)?;
                pointer.truncate(preserved_len);
            }
            Ok(())
        }
        JsonValue::String(s) => {
            // We match `ak:circle:` anywhere in the string — not just
            // as a prefix — because an attacker can embed a typed id
            // inside a free-form `summary` / `description` / `note`
            // field and the directory MUST still refuse to index it.
            // Case-insensitive because typed-id parsers are
            // case-insensitive per spec §id-format.
            let needle = CIRCLE_TYPED_ID_PREFIX; // lowercase
            if contains_ignore_ascii_case(s, needle) {
                if allow_directory_preview_ids && is_allowed_directory_preview_id(pointer, s) {
                    return Ok(());
                }
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

fn is_allowed_directory_preview_id(pointer: &str, value: &str) -> bool {
    if arkret_sdk::CircleId::new(value.to_owned()).is_err() {
        return false;
    }

    let mut segments: Vec<&str> = pointer
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.first() == Some(&"discovery_state") {
        segments.remove(0);
    }
    if segments.first() == Some(&"payload") {
        segments.remove(0);
    }

    for index in 0..segments.len() {
        if !is_circle_directory_container_key(segments[index]) {
            continue;
        }
        let tail = &segments[index + 1..];
        if matches_directory_id_tail(tail) {
            return true;
        }
    }
    false
}

fn matches_directory_id_tail(tail: &[&str]) -> bool {
    match tail {
        [idx, field] if is_array_index(idx) && is_circle_id_field(field) => true,
        [nested, idx, field]
            if matches!(*nested, "entries" | "circles")
                && is_array_index(idx)
                && is_circle_id_field(field) =>
        {
            true
        }
        _ => false,
    }
}

fn is_circle_id_field(field: &str) -> bool {
    matches!(field, "circle_id" | "id")
}

fn is_array_index(segment: &str) -> bool {
    !segment.is_empty() && segment.as_bytes().iter().all(u8::is_ascii_digit)
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
            "kind": "ak.realm.discovery",
            "discoverability": "public",
            "directory_services": ["did:web:directory.test"],
            "member_count_bucket": "11-50",
        });
        assert!(reject_circle_payload(&value).is_ok());
    }

    #[test]
    fn rejects_top_level_typed_circle_id_value() {
        let value = json!({
            "kind": "ak.realm.discovery",
            "circle_id": "ak:circle:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH",
        });
        let err = reject_circle_payload(&value).unwrap_err();
        assert!(matches!(err, CircleRejection::ForbiddenTypedId(_)));
    }

    #[test]
    fn announce_preview_mode_allows_exact_circle_directory_ids() {
        let value = json!({
            "kind": "ak.realm.discovery",
            "circles": [{
                "circle_id": "ak:circle:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH",
                "realm_id": "ak:realm:AfUOZyPWNBbSVKNRXHMbULldhuzzMwa7DvqrqFSUksz3",
                "directory_visibility": "realm_members",
            }],
            "circle_directory": {
                "entries": [{
                    "id": "ak:circle:Ae5vV8Lwlft2Dp8x2y6Dv4NysvsHJwrADG-6PXdUz1Sl"
                }]
            }
        });
        assert!(reject_circle_payload_allowing_directory_preview(&value).is_ok());
        assert!(reject_circle_payload(&value).is_err());
    }

    #[test]
    fn announce_preview_mode_rejects_embedded_circle_id_text() {
        let value = json!({
            "kind": "ak.realm.discovery",
            "circles": [{
                "circle_id": "ak:circle:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH extra"
            }]
        });
        let err = reject_circle_payload_allowing_directory_preview(&value).unwrap_err();
        assert!(matches!(err, CircleRejection::ForbiddenTypedId(_)));
    }

    #[test]
    fn announce_preview_mode_rejects_circle_id_in_free_text_inside_directory() {
        let value = json!({
            "kind": "ak.realm.discovery",
            "circles": [{
                "circle_id": "ak:circle:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH",
                "summary": "see ak:circle:Ae5vV8Lwlft2Dp8x2y6Dv4NysvsHJwrADG-6PXdUz1Sl",
            }]
        });
        let err = reject_circle_payload_allowing_directory_preview(&value).unwrap_err();
        assert!(matches!(err, CircleRejection::ForbiddenTypedId(_)));
    }

    #[test]
    fn announce_preview_mode_rejects_top_level_resource_id() {
        let envelope = json!({
            "resource_kind": "realm",
            "resource_id": "ak:circle:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH",
            "principal_server_did": "did:web:principal.test",
            "discovery_state": {
                "kind": "ak.realm.discovery",
                "circles": [{
                    "circle_id": "ak:circle:Ae5vV8Lwlft2Dp8x2y6Dv4NysvsHJwrADG-6PXdUz1Sl"
                }]
            },
        });
        let err = reject_circle_payload_allowing_directory_preview(&envelope).unwrap_err();
        assert!(matches!(err, CircleRejection::ForbiddenTypedId(_)));
    }

    #[test]
    fn announce_preview_mode_allows_discovery_state_path_in_full_envelope() {
        let envelope = json!({
            "resource_kind": "realm",
            "resource_id": "ak:realm:AfUOZyPWNBbSVKNRXHMbULldhuzzMwa7DvqrqFSUksz3",
            "principal_server_did": "did:web:principal.test",
            "discovery_state": {
                "kind": "ak.realm.discovery",
                "payload": {
                    "circle_directory": {
                        "entries": [{
                            "circle_id": "ak:circle:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH"
                        }]
                    }
                }
            },
        });
        assert!(reject_circle_payload_allowing_directory_preview(&envelope).is_ok());
    }

    #[test]
    fn rejects_typed_circle_id_embedded_in_free_text_field() {
        // An attacker can't smuggle a Circle id through a free-form
        // value either — the walker catches `ak:circle:` no matter
        // which key it lives under.
        let value = json!({
            "kind": "ak.realm.discovery",
            "summary": "see also ak:circle:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH for the back-channel",
        });
        let err = reject_circle_payload(&value).unwrap_err();
        assert!(matches!(err, CircleRejection::ForbiddenTypedId(_)));
    }

    #[test]
    fn rejects_circle_id_array_element() {
        let value = json!({
            "kind": "ak.realm.discovery",
            "related": [
                "ak:realm:AfUOZyPWNBbSVKNRXHMbULldhuzzMwa7DvqrqFSUksz3",
                "ak:circle:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH",
            ],
        });
        let err = reject_circle_payload(&value).unwrap_err();
        assert!(matches!(err, CircleRejection::ForbiddenTypedId(_)));
    }

    /// P2E.7 — the parser-tolerance plank: a `ak:circle:<uuid>`
    /// living in the `resource_id` field of an announce envelope (i.e.
    /// the attacker tries to "announce a Circle into the directory")
    /// MUST be recognised and rejected. The directory never adds an
    /// `IdClass::Circle` variant — see crate::ids docs.
    #[test]
    fn rejects_cx_circle_in_resource_id_field() {
        let envelope = json!({
            "resource_kind": "realm",
            "resource_id": "ak:circle:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH",
            "principal_server_did": "did:web:principal.test",
            "discovery_state": {"kind": "ak.realm.discovery"},
        });
        let err = reject_circle_payload(&envelope).unwrap_err();
        assert!(matches!(err, CircleRejection::ForbiddenTypedId(_)));
    }

    /// P2E.7 — uppercase / mixed-case `Ak:CIRCLE:` MUST still be
    /// caught (typed-id parsers are case-insensitive per spec
    /// §id-format).
    #[test]
    fn rejects_mixed_case_ak_circle_prefix() {
        let envelope = json!({
            "discovery_state": {"note": "Ak:CIRCLE:01904100-0000-7000-8000-000000000001"},
        });
        let err = reject_circle_payload(&envelope).unwrap_err();
        assert!(matches!(err, CircleRejection::ForbiddenTypedId(_)));
    }

    #[test]
    fn safe_message_does_not_leak_field_name_or_id() {
        let id_err = CircleRejection::ForbiddenTypedId("/summary".into());
        assert!(!id_err.safe_message().contains("summary"));
        assert!(!id_err.safe_message().contains("ak:circle:"));
    }

    /// Property-style test (small fixed seed): random injection of
    /// `ak:circle:` into otherwise-clean payloads is always caught.
    #[test]
    fn property_random_circle_injection_is_always_caught() {
        let bases = [
            json!({"kind": "ak.realm.discovery"}),
            json!({"kind": "ak.realm.discovery", "directory_services": []}),
            json!({"nested": {"a": {"b": {"c": 1}}}}),
            json!({"list": [1, 2, {"deep": "ok"}]}),
        ];
        let injections: &[(&str, JsonValue)] = &[
            (
                "circle_id",
                JsonValue::String("ak:circle:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH".into()),
            ),
            (
                "scope_circle_id",
                JsonValue::String("ak:circle:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH".into()),
            ),
            (
                "circle_members",
                JsonValue::Array(vec![JsonValue::String(
                    "ak:circle:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH".into(),
                )]),
            ),
            (
                "default_scope_circle_id",
                JsonValue::String("ak:circle:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH".into()),
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
                    "injection of ak:circle: literal must be rejected"
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
            json!({"kind": "ak.realm.discovery", "discoverability": "public"}),
            json!({"kind": "ak.realm.discovery", "directory_services": ["did:web:d.test"], "policy_revision": "r-42"}),
            json!({"kind": "ak.realm.discovery", "as_of": "2026-05-26T00:00:00Z"}),
            json!({"kind": "ak.actor.discovery", "handle": "did:web:alice"}),
            // member_count_bucket is allowed — the bucket grid is the
            // anti-enumeration sanctioned projection.
            json!({"kind": "ak.realm.discovery", "member_count_bucket": "11-50"}),
        ];
        for payload in payloads {
            assert!(
                reject_circle_payload(&payload).is_ok(),
                "clean payload {payload} must be accepted",
            );
        }
    }
}
