//! Authorized search / resolve handlers — spec §9.

use salvo::prelude::Response;

use crate::error::ApiErrorCode;

pub(crate) fn render_cursor_error(
    response: &mut Response,
    error: arkret_sdk::CursorAuthorityError,
) {
    match error {
        arkret_sdk::CursorAuthorityError::InvalidParam(message) => {
            ApiErrorCode::InvalidParam.render(response, message);
        }
        arkret_sdk::CursorAuthorityError::Expired => {
            ApiErrorCode::CursorExpired.render(response, "cursor has expired");
        }
        arkret_sdk::CursorAuthorityError::IntegrityInvalid => {
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
pub mod target;
