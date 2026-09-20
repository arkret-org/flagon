//! Authorized search / resolve handlers — spec §9.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use salvo::prelude::Response;
use sha2::{Digest, Sha256};

use crate::error::ApiErrorCode;

/// SHA-256 of the requester_id IP, base64url-encoded. Mixed into the latency
/// privacy keys so identical probes from different IPs land on independent
/// latency tiers and cannot be cross-correlated.
pub(crate) fn requester_ip_hash(requester_ip: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(requester_ip.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

pub(crate) fn parse_source_refs(
    source_refs: impl IntoIterator<Item = arkret_wire::CommittedEventRef>,
) -> Result<Vec<arkret_wire::CommittedEventRef>, String> {
    Ok(source_refs.into_iter().collect())
}

/// Read one typed member out of a stored public projection.
///
/// The stored projection is an **open** carrier: it keeps every field the
/// Directory itself needs — `allowed_discoverers` for restricted visibility,
/// declared organization hints for org-scoped search, search-only aliases —
/// while every `*_preview` DTO is `deny_unknown_fields` because its schema
/// says `additionalProperties: false`. The two are different objects and a
/// preview must therefore be **assembled field by field**.
///
/// Deserializing the whole projection into a closed DTO and deleting a few
/// known-bad keys first is the shape this helper exists to replace: the
/// blacklist is never complete, and each field it misses is a 500 on a main
/// read path rather than a rejection at ingest.
pub(crate) fn projection_field<T: serde::de::DeserializeOwned>(
    projection: &serde_json::Map<String, serde_json::Value>,
    resource: &str,
    field: &str,
) -> Result<Option<T>, String> {
    projection
        .get(field)
        .filter(|value| !value.is_null())
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| format!("invalid {resource} preview {field}: {error}"))
}

pub(crate) fn render_cursor_error(
    response: &mut Response,
    error: arkret_server::CursorAuthorityError,
) {
    match error {
        arkret_server::CursorAuthorityError::ParamInvalid(message) => {
            ApiErrorCode::ParamInvalid.render(response, message);
        }
        arkret_server::CursorAuthorityError::Expired => {
            ApiErrorCode::CursorExpired.render(response, "cursor has expired");
        }
        arkret_server::CursorAuthorityError::IntegrityInvalid => {
            ApiErrorCode::CursorIntegrityInvalid.render(response, "cursor integrity check failed");
        }
    }
}

pub mod admin;
pub mod describe;
pub mod rate_limit;
pub mod realm;
