//! Circle directory locked-stub projection for the public directory index.
//!
//! Arkret v1 keeps Circle membership/history scoped to the parent Realm
//! (`circle.md` §9.3). Two projections exist, and they belong to two different
//! services:
//!
//! * the `directory_visibility=realm_members` preview whitelist, which is only servable to a caller
//!   proven to be an active parent-Realm member. That authority is the Principal Server's — soland
//!   gates it in `routing/circles.rs::circle_directory_visible_to_actor`;
//! * the fixed locked stub every other caller receives. The directory has no Realm-membership
//!   authority and serves an index built for unauthenticated callers, so this is the only Circle
//!   projection teabay may produce.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value as JsonValue, json};
use sha2::{Digest, Sha256};

pub const LOCKED_VISIBILITY: &str = "locked";

const COMMITMENT_DOMAIN_LOCKED: &str = "org.arkret.teabay.circle_directory_locked_stub.v1";

const DIRECTORY_CONTAINER_KEYS: &[&str] = &[
    "circle_directory",
    "circle_directory_entries",
    "circle_directory_preview",
    "circle_previews",
    "circles",
];

pub fn locked_circle_stub() -> JsonValue {
    json!({
        "visibility": LOCKED_VISIBILITY,
        "opaque_commitment": fixed_locked_commitment(),
    })
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
            "circle_id": "ak:circle:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH",
            "realm_id": "ak:realm:AfUOZyPWNBbSVKNRXHMbULldhuzzMwa7DvqrqFSUksz3",
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
            "history_access": "since_join",
            "members": ["ak:did_core:web:alice.example"],
            "created_by": "ak:did_core:web:alice.example",
            "created_at": "2026-06-19T00:00:00Z",
            "join_history": [{ "actor_id": "ak:did_core:web:alice.example" }]
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
            "ak:did_core:web:alice.example",
            "member_count",
            "created_by",
            "join_history",
        ] {
            assert!(!serialized.contains(forbidden), "{forbidden} leaked");
        }
    }

    #[test]
    fn realm_members_visibility_still_collapses_in_the_public_index() {
        let mut projection = json!({ "circles": [circle_entry()] });
        sanitize_circle_directory_projection(&mut projection);
        assert_eq!(projection["circles"], locked_circle_stub());
    }
}
