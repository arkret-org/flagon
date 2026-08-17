//! Authorized search / resolve handlers — spec §9.

use salvo::prelude::Response;

use crate::error::ApiErrorCode;

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
pub mod psi;
pub mod rate_limit;
pub mod realm;
pub mod requester_proof;
pub mod target;
