//! Authorized search / resolve handlers — spec §9.

use salvo::prelude::Response;

use crate::error::ApiErrorCode;

pub(crate) fn render_cursor_error(
    response: &mut Response,
    error: arkret_server::CursorAuthorityError,
) {
    match error {
        arkret_server::CursorAuthorityError::ParamInvalid(message) => {
            crate::error::render_problem(
                response,
                ApiErrorCode::ParamInvalid.http_status(),
                arkret_sdk::Problem::from_code(arkret_sdk::ErrorCode::PARAM_INVALID, message)
                    .with_instance(arkret_sdk::new_prefixed_uuid7("ak:request:"))
                    .with_extension(
                        "reason_code",
                        serde_json::json!(arkret_sdk::ReasonCode::INVALID_CURSOR),
                    ),
            );
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

#[cfg(test)]
mod cursor_error_tests {
    use salvo::test::ResponseExt;

    use super::*;

    #[tokio::test]
    async fn cursor_stages_render_typed_problem_codes() {
        use arkret_server::CursorAuthorityError;
        for (error, code, status) in [
            (
                CursorAuthorityError::ParamInvalid("invalid wire".into()),
                "param_invalid",
                400,
            ),
            (CursorAuthorityError::Expired, "cursor_expired", 410),
            (
                CursorAuthorityError::IntegrityInvalid,
                "cursor_integrity_invalid",
                400,
            ),
        ] {
            let mut response = Response::new();
            render_cursor_error(&mut response, error);
            assert_eq!(response.status_code.unwrap().as_u16(), status);
            let problem: arkret_sdk::Problem = response.take_json().await.unwrap();
            assert_eq!(problem.error_code(), arkret_sdk::ErrorCode::from_wire(code));
            if code == "param_invalid" {
                assert_eq!(problem.extensions["reason_code"], "invalid_cursor");
            }
        }
    }
}
