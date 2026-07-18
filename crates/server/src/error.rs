//! Wire-form error codes for teabay.
//!
//! The query-side uses Arkret canonical codes (`not_found`, `rate_limited`,
//! `unauthenticated`, etc.). The ingest side adds the §8 / §8.10 ingest-
//! specific codes that are normative on `/_arkret/find/directory/announce` and
//! `/_arkret/find/directory/withdraw`.

use salvo::http::StatusCode;
use salvo::prelude::*;

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
    pub const BadJson: Self = Self::new(arkret_sdk::ErrorCode::BAD_JSON, StatusCode::BAD_REQUEST);
    #[allow(non_upper_case_globals)]
    pub const BadQuery: Self = Self::new(arkret_sdk::ErrorCode::BAD_QUERY, StatusCode::BAD_REQUEST);
    #[allow(non_upper_case_globals)]
    pub const SchemaViolation: Self = Self::new(
        arkret_sdk::ErrorCode::SCHEMA_VIOLATION,
        StatusCode::UNPROCESSABLE_ENTITY,
    );
    #[allow(non_upper_case_globals)]
    pub const MissingParam: Self = Self::new(
        arkret_sdk::ErrorCode::MISSING_PARAM,
        StatusCode::BAD_REQUEST,
    );
    #[allow(non_upper_case_globals)]
    pub const InvalidParam: Self = Self::new(
        arkret_sdk::ErrorCode::INVALID_PARAM,
        StatusCode::BAD_REQUEST,
    );
    #[allow(non_upper_case_globals)]
    pub const InvalidSignature: Self = Self::new(
        arkret_sdk::ErrorCode::INVALID_SIGNATURE,
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
    pub const UnrecognizedEndpoint: Self = Self::new(
        arkret_sdk::ErrorCode::UNRECOGNIZED_ENDPOINT,
        StatusCode::NOT_FOUND,
    );
    #[allow(non_upper_case_globals)]
    pub const MethodNotAllowed: Self = Self::new(
        arkret_sdk::ErrorCode::METHOD_NOT_ALLOWED,
        StatusCode::METHOD_NOT_ALLOWED,
    );
    #[allow(non_upper_case_globals)]
    pub const Conflict: Self = Self::new(arkret_sdk::ErrorCode::CONFLICT, StatusCode::CONFLICT);
    #[allow(non_upper_case_globals)]
    pub const PayloadTooLarge: Self = Self::new(
        arkret_sdk::ErrorCode::PAYLOAD_TOO_LARGE,
        StatusCode::PAYLOAD_TOO_LARGE,
    );
    #[allow(non_upper_case_globals)]
    pub const RateLimited: Self = Self::new(
        arkret_sdk::ErrorCode::RATE_LIMITED,
        StatusCode::TOO_MANY_REQUESTS,
    );
    #[allow(non_upper_case_globals)]
    pub const QuotaExceeded: Self =
        Self::new(arkret_sdk::ErrorCode::QUOTA_EXCEEDED, StatusCode::FORBIDDEN);
    #[allow(non_upper_case_globals)]
    pub const Timeout: Self =
        Self::new(arkret_sdk::ErrorCode::TIMEOUT, StatusCode::GATEWAY_TIMEOUT);
    #[allow(non_upper_case_globals)]
    pub const UnsupportedFeature: Self = Self::new(
        arkret_sdk::ErrorCode::UNSUPPORTED_FEATURE,
        StatusCode::NOT_IMPLEMENTED,
    );
    #[allow(non_upper_case_globals)]
    pub const InternalError: Self = Self::new(
        arkret_sdk::ErrorCode::INTERNAL_ERROR,
        StatusCode::INTERNAL_SERVER_ERROR,
    );
    #[allow(non_upper_case_globals)]
    pub const TemporarilyUnavailable: Self = Self::new(
        arkret_sdk::ErrorCode::TEMPORARILY_UNAVAILABLE,
        StatusCode::SERVICE_UNAVAILABLE,
    );
    #[allow(non_upper_case_globals)]
    pub const CrossDomainReplayRejected: Self =
        Self::new(arkret_sdk::ErrorCode::CONFLICT, StatusCode::CONFLICT);
    #[allow(non_upper_case_globals)]
    pub const HistorySharingPolicyMissing: Self = Self::new(
        arkret_sdk::ErrorCode::HISTORY_SHARING_POLICY_MISSING,
        StatusCode::UNPROCESSABLE_ENTITY,
    );
    #[allow(non_upper_case_globals)]
    pub const HistoryNotVisible: Self = Self::new(
        arkret_sdk::ErrorCode::HISTORY_NOT_VISIBLE,
        StatusCode::FORBIDDEN,
    );
    #[allow(non_upper_case_globals)]
    pub const PreviewPolicyDenied: Self = Self::new(
        arkret_sdk::ErrorCode::PREVIEW_POLICY_DENIED,
        StatusCode::FORBIDDEN,
    );

    // -------- directory ingest codes --------
    #[allow(non_upper_case_globals)]
    pub const InvalidResponse: Self = Self::new(
        arkret_sdk::ErrorCode::INVALID_RESPONSE,
        StatusCode::BAD_REQUEST,
    );
    #[allow(non_upper_case_globals)]
    pub const DirectoryNotAuthorized: Self = Self::new(
        arkret_sdk::ErrorCode::DIRECTORY_NOT_AUTHORIZED,
        StatusCode::FORBIDDEN,
    );
    #[allow(non_upper_case_globals)]
    pub const AcceptPolicyDenied: Self = Self::new(
        arkret_sdk::ErrorCode::ACCEPT_POLICY_DENIED,
        StatusCode::FORBIDDEN,
    );
    #[allow(non_upper_case_globals)]
    pub const SignatureInvalid: Self = Self::new(
        arkret_sdk::ErrorCode::SIGNATURE_INVALID,
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
    // §8.7 — an announce against a Realm that has reached the
    // `ak.realm.destroy` terminal state. Distinct from
    // `policy_revision_rollback` (which means an `as_of`/`policy_revision`
    // earlier than the indexed value, §8.10).
    #[allow(non_upper_case_globals)]
    pub const RealmTerminalState: Self =
        Self::new(arkret_sdk::ErrorCode::CONFLICT, StatusCode::CONFLICT);

    // -------- R3 spec-sync 2026-05-27 (commit b47ff6e) --------
    // AKP R3 handle homograph wire-level enforce. Emitted by
    // `ak.find.directory.query.resolve_handle` (query face) and announce ingest
    // when the handle localpart fails the NFC + UTS#39 confusable +
    // script-mixed normalization check provided by
    // `arkret_sdk::normalize_handle_localpart`.
    #[allow(non_upper_case_globals)]
    pub const HandleHomographForbidden: Self = Self::new(
        arkret_sdk::ErrorCode::INVALID_PARAM,
        StatusCode::BAD_REQUEST,
    );

    // -------- R3.2 spec-sync 2026-05-28 (arkret-spec @ b56cab1) --------
    // `ak.find.directory.query.list_handles_for_subject` input validation. A
    // `subject` that is not a holder/principal DID (a `ak:actor:` Realm
    // actor_id, a `ak:account:` server-local account id, a service DID,
    // or a non-DID resource id) is rejected with `failed_precondition`
    // carrying the `invalid_subject_kind` reason in the message — the
    // request is structurally well-formed JSON but cannot be satisfied
    // because the subject is the wrong kind of identifier.
    #[allow(non_upper_case_globals)]
    pub const FailedPrecondition: Self = Self::new(
        arkret_sdk::error::ErrorCode::FAILED_PRECONDITION,
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
        res.status_code(self.http_status());
        res.render(Json(
            arkret_sdk::ErrorEnvelope::new(self.wire_code(), message)
                .with_request_id(arkret_sdk::new_prefixed_uuid7("ak:request:")),
        ));
    }
}
