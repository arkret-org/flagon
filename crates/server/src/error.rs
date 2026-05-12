//! Wire-form error codes for teabay.
//!
//! The query-side uses Contrix canonical codes (`not_found`, `rate_limited`,
//! `unauthenticated`, etc.). The ingest side adds the §8 / §8.10 ingest-
//! specific codes that are normative on `/api/v1/directory/announce` and
//! `/api/v1/directory/withdraw`.

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::json;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    // -------- canonical Contrix codes used here --------
    BadJson,
    BadQuery,
    SchemaViolation,
    MissingParam,
    InvalidParam,
    InvalidResponse,
    InvalidSignature,
    Unauthenticated,
    NotFound,
    UnrecognizedEndpoint,
    MethodNotAllowed,
    Conflict,
    PayloadTooLarge,
    RateLimited,
    QuotaExceeded,
    Timeout,
    UnsupportedFeature,
    InternalError,
    TemporarilyUnavailable,

    // -------- §8 ingest-specific codes (normative) --------
    /// §8.1: resource signed payload does not list this Directory's DID.
    DirectoryNotAuthorized,
    /// §8.1: resource is outside the directory's accept policy.
    AcceptPolicyDenied,
    /// §8.5 / §8.10: governance signature invalid.
    SignatureInvalid,
    /// §8.10: `as_of` outside the configured skew window.
    SignatureStale,
    /// §8.10: `source_refs` could not be verified against the principal server.
    SourceRefsUnverifiable,
    /// §8.1: governance key not in resource DID document current epoch.
    GovernanceKeyInvalid,
    /// §8.6: declared `ttl_seconds` outside [1, max_ttl_seconds].
    TtlOutOfRange,
    /// §8.10: a recorded withdrawal blocks acceptance of this announce.
    TakedownInForce,
    /// §8.10: `policy_revision` / `as_of` is older than the indexed entry.
    PolicyRevisionRollback,
}

impl ErrorCode {
    pub fn wire_code(self) -> &'static str {
        match self {
            Self::BadJson => "bad_json",
            Self::BadQuery => "bad_query",
            Self::SchemaViolation => "schema_violation",
            Self::MissingParam => "missing_param",
            Self::InvalidParam => "invalid_param",
            Self::InvalidResponse => "invalid_response",
            Self::InvalidSignature => "invalid_signature",
            Self::Unauthenticated => "unauthenticated",
            Self::NotFound => "not_found",
            Self::UnrecognizedEndpoint => "unrecognized_endpoint",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::Conflict => "conflict",
            Self::PayloadTooLarge => "payload_too_large",
            Self::RateLimited => "rate_limited",
            Self::QuotaExceeded => "quota_exceeded",
            Self::Timeout => "timeout",
            Self::UnsupportedFeature => "unsupported_feature",
            Self::InternalError => "internal_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",

            Self::DirectoryNotAuthorized => "directory_not_authorized",
            Self::AcceptPolicyDenied => "accept_policy_denied",
            Self::SignatureInvalid => "signature_invalid",
            Self::SignatureStale => "signature_stale",
            Self::SourceRefsUnverifiable => "source_refs_unverifiable",
            Self::GovernanceKeyInvalid => "governance_key_invalid",
            Self::TtlOutOfRange => "ttl_out_of_range",
            Self::TakedownInForce => "takedown_in_force",
            Self::PolicyRevisionRollback => "policy_revision_rollback",
        }
    }

    pub fn http_status(self) -> StatusCode {
        match self {
            Self::BadJson | Self::BadQuery | Self::SchemaViolation => StatusCode::BAD_REQUEST,
            Self::MissingParam
            | Self::InvalidParam
            | Self::InvalidSignature
            | Self::InvalidResponse => StatusCode::BAD_REQUEST,
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::NotFound | Self::UnrecognizedEndpoint => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::Conflict => StatusCode::CONFLICT,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RateLimited | Self::QuotaExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Self::UnsupportedFeature => StatusCode::NOT_IMPLEMENTED,
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::TemporarilyUnavailable => StatusCode::SERVICE_UNAVAILABLE,

            // §8.5 / §8.10 ingest rejections — 4xx authorization-class except
            // signature problems (still 4xx) and rollback (409 conflict).
            Self::DirectoryNotAuthorized | Self::AcceptPolicyDenied => StatusCode::FORBIDDEN,
            Self::SignatureInvalid
            | Self::SignatureStale
            | Self::SourceRefsUnverifiable
            | Self::GovernanceKeyInvalid
            | Self::TtlOutOfRange => StatusCode::BAD_REQUEST,
            Self::TakedownInForce | Self::PolicyRevisionRollback => StatusCode::CONFLICT,
        }
    }

    /// Render `{ ok: false, error: { code, message } }` and set the
    /// canonical HTTP status. Same shape as soland's util::render_error.
    pub fn render(self, res: &mut Response, message: impl Into<String>) {
        res.status_code(self.http_status());
        res.render(Json(json!({
            "ok": false,
            "error": {
                "code": self.wire_code(),
                "message": message.into(),
            },
        })));
    }
}
