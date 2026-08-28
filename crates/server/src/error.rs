//! Wire-form error codes for teabay.
//!
//! The query-side uses Arkret canonical codes (`not_found`, `rate_limited`,
//! `unauthenticated`, etc.). The ingest side adds the §8 / §8.10 ingest-
//! specific codes that are normative on `/_arkret/find/directory/announce` and
//! `/_arkret/find/directory/withdraw`.

use salvo::http::StatusCode;
use salvo::prelude::*;

pub(crate) fn render_problem(
    res: &mut Response,
    status: StatusCode,
    envelope: arkret_sdk::ErrorEnvelope,
) {
    let problem = arkret_sdk::Problem::from_error_envelope(&envelope, status.as_u16());
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
    pub const ParamMissing: Self = Self::new(
        arkret_sdk::ErrorCode::PARAM_MISSING,
        StatusCode::BAD_REQUEST,
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
    pub const SignatureInvalid: Self = Self::new(
        arkret_sdk::ErrorCode::SIGNATURE_INVALID,
        StatusCode::UNAUTHORIZED,
    );
    #[allow(non_upper_case_globals)]
    pub const Unauthenticated: Self = Self::new(
        arkret_sdk::ErrorCode::UNAUTHENTICATED,
        StatusCode::UNAUTHORIZED,
    );
    #[allow(non_upper_case_globals)]
    pub const NotFound: Self = Self::new(arkret_sdk::ErrorCode::NOT_FOUND, StatusCode::NOT_FOUND);
    #[allow(non_upper_case_globals)]
    pub const Conflict: Self = Self::new(arkret_sdk::ErrorCode::CONFLICT, StatusCode::CONFLICT);
    #[allow(non_upper_case_globals)]
    pub const RateLimited: Self = Self::new(
        arkret_sdk::ErrorCode::RATE_LIMITED,
        StatusCode::TOO_MANY_REQUESTS,
    );
    #[allow(non_upper_case_globals)]
    pub const UnsupportedFeature: Self = Self::new(
        arkret_sdk::ErrorCode::UNSUPPORTED_FEATURE,
        StatusCode::NOT_IMPLEMENTED,
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
    pub const CrossDomainReplayRejected: Self =
        Self::new(arkret_sdk::ErrorCode::CONFLICT, StatusCode::CONFLICT);

    // -------- directory ingest codes --------
    #[allow(non_upper_case_globals)]
    pub const ResponseInvalid: Self = Self::new(
        arkret_sdk::ErrorCode::RESPONSE_INVALID,
        StatusCode::BAD_REQUEST,
    );
    #[allow(non_upper_case_globals)]
    pub const DirectoryUnauthorized: Self = Self::new(
        arkret_sdk::ErrorCode::DIRECTORY_UNAUTHORIZED,
        StatusCode::FORBIDDEN,
    );
    #[allow(non_upper_case_globals)]
    pub const AcceptPolicyDenied: Self = Self::new(
        arkret_sdk::ErrorCode::ACCEPT_POLICY_DENIED,
        StatusCode::FORBIDDEN,
    );
    #[allow(non_upper_case_globals)]
    pub const DirectoryGovernanceProofSignatureInvalid: Self = Self::new(
        arkret_sdk::ErrorCode::DIRECTORY_GOVERNANCE_PROOF_SIGNATURE_INVALID,
        StatusCode::BAD_REQUEST,
    );
    #[allow(non_upper_case_globals)]
    pub const SignatureStale: Self = Self::new(
        arkret_sdk::ErrorCode::SIGNATURE_STALE,
        StatusCode::BAD_REQUEST,
    );
    #[allow(non_upper_case_globals)]
    pub const SourceRefsUnverifiable: Self = Self::new(
        arkret_sdk::ErrorCode::SOURCE_REFS_UNVERIFIABLE,
        StatusCode::BAD_REQUEST,
    );
    #[allow(non_upper_case_globals)]
    pub const GovernanceKeyInvalid: Self = Self::new(
        arkret_sdk::ErrorCode::GOVERNANCE_KEY_INVALID,
        StatusCode::BAD_REQUEST,
    );
    #[allow(non_upper_case_globals)]
    pub const TtlOutOfRange: Self = Self::new(
        arkret_sdk::ErrorCode::TTL_OUT_OF_RANGE,
        StatusCode::BAD_REQUEST,
    );
    #[allow(non_upper_case_globals)]
    pub const TakedownInForce: Self = Self::new(
        arkret_sdk::ErrorCode::TAKEDOWN_IN_FORCE,
        StatusCode::CONFLICT,
    );
    #[allow(non_upper_case_globals)]
    pub const PolicyRevisionRollback: Self = Self::new(
        arkret_sdk::ErrorCode::POLICY_REVISION_ROLLBACK,
        StatusCode::CONFLICT,
    );
    // -------- R3.2 spec-sync 2026-05-28 (arkret-spec @ b56cab1) --------
    // `ak.find.directory.read.list_handles_for_subject.v1` input validation. A
    // `subject_id` that is not a holder/principal DID (a `ak:actor:` Realm
    // actor_id, a `ak:account:` server-local account id, a service DID,
    // or a non-DID resource id) is rejected with `failed_precondition`
    // carrying the `invalid_subject_kind` reason in the message — the
    // request is structurally well-formed JSON but cannot be satisfied
    // because the subject_id is the wrong kind of identifier.
    #[allow(non_upper_case_globals)]
    pub const FailedPrecondition: Self = Self::new(
        arkret_sdk::error_codes::ErrorCode::FAILED_PRECONDITION,
        StatusCode::CONFLICT,
    );

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
            arkret_sdk::ErrorEnvelope::new(self.wire_code(), message)
                .with_request_id(arkret_sdk::new_prefixed_uuid7("ak:request:")),
        );
    }
}
