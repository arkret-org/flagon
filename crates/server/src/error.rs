//! Wire-form error codes for teabay.
//!
//! The read-only query and admin faces use canonical Arkret codes.

use salvo::http::StatusCode;
use salvo::prelude::*;

pub(crate) fn render_problem(
    res: &mut Response,
    status: StatusCode,
    envelope: arkret_sdk::Problem,
) {
    let problem = envelope.with_status(status.as_u16());
    let mut output = salvo::http::Problem::new(status)
        .kind(problem.problem_type)
        .title(problem.title)
        .detail(problem.detail)
        .with_extensions(
            problem
                .extensions
                .into_iter()
                .collect::<serde_json::Map<_, _>>(),
        );
    if let Some(instance) = problem.instance {
        output = output.instance(instance);
    }
    res.render(output);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ApiErrorCode {
    code: &'static str,
    fallback_status: StatusCode,
}

impl ApiErrorCode {
    const fn new(code: &'static str, fallback_status: StatusCode) -> Self {
        Self {
            code,
            fallback_status,
        }
    }

    // -------- canonical Arkret codes used here --------
    #[allow(non_upper_case_globals)]
    pub const JsonInvalid: Self =
        Self::new(arkret_sdk::ErrorCode::JSON_INVALID, StatusCode::BAD_REQUEST);
    #[allow(non_upper_case_globals)]
    pub const QueryInvalid: Self = Self::new(
        arkret_sdk::ErrorCode::QUERY_INVALID,
        StatusCode::BAD_REQUEST,
    );
    #[allow(non_upper_case_globals)]
    pub const SchemaViolation: Self = Self::new(
        arkret_sdk::ErrorCode::SCHEMA_VIOLATION,
        StatusCode::UNPROCESSABLE_ENTITY,
    );
    #[allow(non_upper_case_globals)]
    pub const ParamInvalid: Self = Self::new(
        arkret_sdk::ErrorCode::PARAM_INVALID,
        StatusCode::BAD_REQUEST,
    );
    #[allow(non_upper_case_globals)]
    pub const CursorExpired: Self =
        Self::new(arkret_sdk::ErrorCode::CURSOR_EXPIRED, StatusCode::GONE);
    #[allow(non_upper_case_globals)]
    pub const CursorIntegrityInvalid: Self = Self::new(
        arkret_sdk::ErrorCode::CURSOR_INTEGRITY_INVALID,
        StatusCode::BAD_REQUEST,
    );
    #[allow(non_upper_case_globals)]
    pub const Unauthenticated: Self = Self::new(
        arkret_sdk::ErrorCode::UNAUTHENTICATED,
        StatusCode::UNAUTHORIZED,
    );
    #[allow(non_upper_case_globals)]
    pub const NotFound: Self = Self::new(arkret_sdk::ErrorCode::NOT_FOUND, StatusCode::NOT_FOUND);
    #[allow(non_upper_case_globals)]
    pub const RateLimited: Self = Self::new(
        arkret_sdk::ErrorCode::RATE_LIMITED,
        StatusCode::TOO_MANY_REQUESTS,
    );
    #[allow(non_upper_case_globals)]
    pub const OperationSelectorRequired: Self = Self::new(
        arkret_sdk::ErrorCode::OPERATION_SELECTOR_REQUIRED,
        StatusCode::BAD_REQUEST,
    );
    #[allow(non_upper_case_globals)]
    pub const UnsupportedOperationVersion: Self = Self::new(
        arkret_sdk::ErrorCode::UNSUPPORTED_OPERATION_VERSION,
        StatusCode::UNPROCESSABLE_ENTITY,
    );
    #[allow(non_upper_case_globals)]
    pub const InternalError: Self = Self::new(
        arkret_sdk::ErrorCode::INTERNAL_ERROR,
        StatusCode::INTERNAL_SERVER_ERROR,
    );
    #[allow(non_upper_case_globals)]
    pub fn wire_code(self) -> &'static str {
        self.code
    }

    pub fn http_status(self) -> StatusCode {
        arkret_sdk::error_code_http_status(self.code)
            .and_then(|status| StatusCode::from_u16(status).ok())
            .unwrap_or(self.fallback_status)
    }

    /// Render the canonical Arkret error envelope and set its HTTP status.
    pub fn render(self, res: &mut Response, message: impl Into<String>) {
        render_problem(
            res,
            self.http_status(),
            arkret_sdk::Problem::from_code(self.wire_code(), message)
                .with_instance(arkret_sdk::new_prefixed_uuid7("ak:request:")),
        );
    }
}
