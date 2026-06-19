//! Circle directory preview and locked-stub projection.
//!
//! Cokret v1 keeps Circle membership/history scoped to the parent Realm. The
//! directory may only surface a tightly bounded directory projection:
//! non-authorized callers receive a fixed locked stub, while active parent
//! Realm members may receive the `directory_visibility=realm_members`
//! whitelist.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value as JsonValue, json};
use sha2::{Digest, Sha256};

use crate::filter::enumeration::is_valid_member_count_bucket;

pub const LOCKED_VISIBILITY: &str = "locked";
pub const REALM_MEMBERS_VISIBILITY: &str = "realm_members";
pub const MEMBERS_VISIBILITY: &str = "members";

const COMMITMENT_DOMAIN_LOCKED: &str = "ck.circle.directory.locked_stub.v1";
const COMMITMENT_DOMAIN_PREVIEW: &str = "ck.circle.directory.realm_members_preview.v1";

const DIRECTORY_CONTAINER_KEYS: &[&str] = &[
    "circle_directory",
    "circle_directory_entries",
    "circle_directory_preview",
    "circle_previews",
    "circles",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircleDirectoryAudience {
    Unauthorized,
    ParentRealmMember,
}

pub fn locked_circle_stub() -> JsonValue {
    json!({
        "visibility": LOCKED_VISIBILITY,
        "opaque_commitment": fixed_locked_commitment(),
    })
}

/// Build the caller-facing projection for one Circle directory entry.
///
/// The input may be the durable Circle object or a pre-projected Circle
/// directory row. This function never forwards raw member lists, exact member
/// counts, title, summary, creator fields, history fields, or display
/// short_name to non-Circle callers.
pub fn project_circle_entry(entry: &JsonValue, audience: CircleDirectoryAudience) -> JsonValue {
    match audience {
        CircleDirectoryAudience::Unauthorized => locked_circle_stub(),
        CircleDirectoryAudience::ParentRealmMember => {
            if directory_visibility(entry) == Some(REALM_MEMBERS_VISIBILITY) {
                realm_member_preview(entry).unwrap_or_else(locked_circle_stub)
            } else {
                locked_circle_stub()
            }
        }
    }
}

/// Collapse any Circle directory subtree inside a public projection into one
/// fixed locked envelope. This avoids leaking the number of hidden Circles via
/// array length while still preserving the spec-visible "locked" response
/// type for generic directory fanout/raw projection consumers.
pub fn sanitize_circle_directory_projection(projection: &mut JsonValue) {
    sanitize_at_value(projection);
}

pub fn is_circle_directory_container_key(key: &str) -> bool {
    DIRECTORY_CONTAINER_KEYS.contains(&key)
}

pub fn fixed_locked_commitment() -> String {
    commitment([COMMITMENT_DOMAIN_LOCKED])
}

fn realm_member_preview(entry: &JsonValue) -> Option<JsonValue> {
    let circle_id = string_field(entry, &["circle_id", "id"])?;
    let realm_id = string_field(entry, &["realm_id"])?;
    let display = realm_member_display(entry.get("display")?)?;
    let member_count_bucket = entry
        .get("member_count_bucket")
        .and_then(JsonValue::as_str)
        .filter(|bucket| is_valid_member_count_bucket(bucket))?;
    let join_rule = entry
        .get("join_rule")
        .and_then(JsonValue::as_str)
        .filter(|value| matches!(*value, "invite" | "request" | "open"))?;

    let mut out = Map::new();
    out.insert(
        "circle_id".to_owned(),
        JsonValue::String(circle_id.to_owned()),
    );
    out.insert(
        "realm_id".to_owned(),
        JsonValue::String(realm_id.to_owned()),
    );
    out.insert(
        "visibility".to_owned(),
        JsonValue::String(REALM_MEMBERS_VISIBILITY.to_owned()),
    );
    out.insert("display".to_owned(), JsonValue::Object(display));
    out.insert(
        "member_count_bucket".to_owned(),
        JsonValue::String(member_count_bucket.to_owned()),
    );
    out.insert(
        "join_rule".to_owned(),
        JsonValue::String(join_rule.to_owned()),
    );
    out.insert(
        "opaque_commitment".to_owned(),
        JsonValue::String(realm_member_commitment(realm_id, circle_id)),
    );
    Some(JsonValue::Object(out))
}

fn realm_member_display(display: &JsonValue) -> Option<Map<String, JsonValue>> {
    let obj = display.as_object()?;
    let color_token = obj
        .get("color_token")
        .and_then(JsonValue::as_str)
        .filter(|value| is_allowed_color_token(value))?;
    let symbol = realm_member_symbol(obj.get("symbol")?)?;

    let mut out = Map::new();
    out.insert(
        "color_token".to_owned(),
        JsonValue::String(color_token.to_owned()),
    );
    out.insert("symbol".to_owned(), symbol);
    Some(out)
}

fn realm_member_symbol(symbol: &JsonValue) -> Option<JsonValue> {
    let obj = symbol.as_object()?;
    if let Some(emoji) = obj.get("emoji").and_then(JsonValue::as_str)
        && !emoji.is_empty()
        && emoji.chars().count() <= 4
    {
        return Some(json!({ "emoji": emoji }));
    }
    if let Some(glyph) = obj
        .get("glyph")
        .and_then(JsonValue::as_str)
        .filter(|value| is_allowed_glyph(value))
    {
        return Some(json!({ "glyph": glyph }));
    }
    None
}

fn is_allowed_color_token(value: &str) -> bool {
    matches!(
        value,
        "slate"
            | "red"
            | "orange"
            | "amber"
            | "yellow"
            | "lime"
            | "green"
            | "emerald"
            | "teal"
            | "cyan"
            | "sky"
            | "blue"
            | "indigo"
            | "violet"
            | "fuchsia"
            | "pink"
            | "gray_high_contrast"
    )
}

fn is_allowed_glyph(value: &str) -> bool {
    matches!(
        value,
        "lock"
            | "shield"
            | "eye"
            | "eye_off"
            | "user_shield"
            | "fingerprint"
            | "key"
            | "diamond"
            | "flame"
            | "leaf"
            | "seal"
            | "compass"
            | "atom"
            | "bolt"
            | "moon"
            | "sun"
            | "star"
            | "globe"
            | "satellite"
            | "ring"
            | "chain"
            | "tag"
            | "flag"
            | "scroll"
            | "scale"
            | "hourglass"
            | "spark"
    )
}

fn directory_visibility(entry: &JsonValue) -> Option<&str> {
    entry
        .get("directory_visibility")
        .or_else(|| entry.get("visibility"))
        .and_then(JsonValue::as_str)
}

fn string_field<'a>(entry: &'a JsonValue, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| entry.get(*key).and_then(JsonValue::as_str))
        .filter(|value| !value.is_empty())
}

fn sanitize_at_value(value: &mut JsonValue) {
    match value {
        JsonValue::Object(obj) => sanitize_at_object(obj),
        JsonValue::Array(items) => {
            for item in items {
                sanitize_at_value(item);
            }
        }
        _ => {}
    }
}

fn sanitize_at_object(obj: &mut Map<String, JsonValue>) {
    let keys: Vec<String> = obj.keys().cloned().collect();
    for key in keys {
        if is_circle_directory_container_key(&key) {
            obj.insert(key, locked_circle_stub());
            continue;
        }
        if let Some(value) = obj.get_mut(&key) {
            sanitize_at_value(value);
        }
    }
}

fn realm_member_commitment(realm_id: &str, circle_id: &str) -> String {
    commitment([COMMITMENT_DOMAIN_PREVIEW, realm_id, circle_id])
}

fn commitment<const N: usize>(parts: [&str; N]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn circle_entry() -> JsonValue {
        json!({
            "circle_id": "ck:circle:01904100-0000-7000-8000-000000000001",
            "realm_id": "ck:realm:01904100-0000-7000-8000-000000000101",
            "title": "Security Council",
            "summary": "Must not leak to parent Realm non-members",
            "display": {
                "short_name": "SEC",
                "color_token": "slate",
                "symbol": { "glyph": "shield" }
            },
            "directory_visibility": "realm_members",
            "member_count": 7,
            "member_count_bucket": "1-10",
            "join_rule": "invite",
            "history_visibility": "joined",
            "members": ["did:web:alice.example"],
            "created_by": "did:web:alice.example",
            "created_at": "2026-06-19T00:00:00Z",
            "join_history": [{ "actor_id": "did:web:alice.example" }]
        })
    }

    #[test]
    fn locked_stub_has_fixed_shape_and_commitment_length() {
        let stub = locked_circle_stub();
        assert_eq!(stub["visibility"], LOCKED_VISIBILITY);
        assert_eq!(
            stub.as_object()
                .expect("object")
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            vec!["opaque_commitment".to_owned(), "visibility".to_owned()]
        );
        assert_eq!(stub["opaque_commitment"].as_str().unwrap().len(), 43);
        assert_eq!(stub, locked_circle_stub());
    }

    #[test]
    fn realm_member_preview_uses_only_spec_whitelist() {
        let preview =
            project_circle_entry(&circle_entry(), CircleDirectoryAudience::ParentRealmMember);
        let object = preview.as_object().expect("preview object");
        assert_eq!(object.get("visibility").unwrap(), REALM_MEMBERS_VISIBILITY);
        assert_eq!(
            object.get("circle_id").unwrap(),
            "ck:circle:01904100-0000-7000-8000-000000000001"
        );
        assert_eq!(
            object.get("realm_id").unwrap(),
            "ck:realm:01904100-0000-7000-8000-000000000101"
        );
        assert_eq!(object.get("member_count_bucket").unwrap(), "1-10");
        assert_eq!(object.get("join_rule").unwrap(), "invite");
        assert_eq!(
            object
                .get("opaque_commitment")
                .and_then(JsonValue::as_str)
                .unwrap()
                .len(),
            43
        );

        let display = object
            .get("display")
            .and_then(JsonValue::as_object)
            .unwrap();
        assert_eq!(display.get("color_token").unwrap(), "slate");
        assert_eq!(
            display.get("symbol").unwrap(),
            &json!({ "glyph": "shield" })
        );
        assert!(!display.contains_key("short_name"));

        for forbidden in [
            "title",
            "summary",
            "member_count",
            "members",
            "created_by",
            "created_at",
            "history_visibility",
            "join_history",
        ] {
            assert!(!object.contains_key(forbidden), "{forbidden} leaked");
        }
    }

    #[test]
    fn members_visibility_projects_to_locked_for_parent_realm_member() {
        let mut entry = circle_entry();
        entry["directory_visibility"] = JsonValue::String(MEMBERS_VISIBILITY.to_owned());
        assert_eq!(
            project_circle_entry(&entry, CircleDirectoryAudience::ParentRealmMember),
            locked_circle_stub()
        );
    }

    #[test]
    fn unauthorized_projection_is_locked_for_realm_members_circle() {
        assert_eq!(
            project_circle_entry(&circle_entry(), CircleDirectoryAudience::Unauthorized),
            locked_circle_stub()
        );
    }

    #[test]
    fn invalid_member_count_bucket_fails_closed_to_locked() {
        let mut entry = circle_entry();
        entry["member_count_bucket"] = JsonValue::String("7".to_owned());
        assert_eq!(
            project_circle_entry(&entry, CircleDirectoryAudience::ParentRealmMember),
            locked_circle_stub()
        );
    }

    #[test]
    fn display_symbol_extra_fields_are_not_forwarded() {
        let mut entry = circle_entry();
        entry["display"]["symbol"] = json!({
            "glyph": "shield",
            "title": "Security Council",
            "member_count": 7
        });
        let preview = project_circle_entry(&entry, CircleDirectoryAudience::ParentRealmMember);
        assert_eq!(preview["display"]["symbol"], json!({ "glyph": "shield" }));
        let serialized = preview.to_string();
        assert!(!serialized.contains("Security Council"));
        assert!(!serialized.contains("\"member_count\":"));
    }

    #[test]
    fn public_projection_sanitizer_collapses_circle_directory_to_one_stub() {
        let mut projection = json!({
            "name": "Tea Research",
            "circle_directory": [
                circle_entry(),
                circle_entry(),
            ],
            "nested": {
                "circle_previews": [circle_entry()]
            }
        });
        sanitize_circle_directory_projection(&mut projection);

        assert_eq!(projection["circle_directory"], locked_circle_stub());
        assert_eq!(
            projection["nested"]["circle_previews"],
            locked_circle_stub()
        );
        let serialized = projection.to_string();
        for forbidden in [
            "Security Council",
            "short_name",
            "did:web:alice.example",
            "member_count",
            "created_by",
            "join_history",
        ] {
            assert!(!serialized.contains(forbidden), "{forbidden} leaked");
        }
    }
}
