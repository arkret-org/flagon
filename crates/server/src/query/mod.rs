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

pub mod actor;
pub mod admin;
pub mod describe;
pub mod handle;
pub mod handles_for_subject;
pub mod organization;
pub mod rate_limit;
pub mod realm;
pub mod requester_proof;
pub mod target;
