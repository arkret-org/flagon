//! Query-face rate limiting.
//!
//! Companion to `crate::ingest::rate_limit`: this guard runs in front
//! of every read-side endpoint (`search_realms`, `resolve_realm`,
//! `resolve_handle`, ...) and caps how often a single IP can make
//! query calls, and how often a single resource_id can be resolved.
//!
//! Both limits are configured via `TEABAY_QUERY_MAX_QUERIES_PER_IP_PER_MIN`
//! and `TEABAY_QUERY_MAX_RESOLVES_PER_RESOURCE_PER_MIN`. A value of `0`
//! disables that particular check, which is useful for the in-process
//! conformance harness.

use salvo::http::header;
use salvo::prelude::*;

use crate::error::ApiErrorCode;
use crate::state::{AppState, RateLimitOutcome};

/// Enforce the per-IP query rate limit. Returns `true` when the
/// request is allowed to continue. On limit-exceeded, renders a
/// `rate_limited` response and returns `false`.
pub fn enforce_query_rate_limit(req: &Request, res: &mut Response, state: &AppState) -> bool {
    let max = state.config().query_max_queries_per_ip_per_min;
    if max == 0 {
        return true;
    }
    let ip = req.remote_addr().to_string();
    let key = format!("query-ip:{ip}");
    check(state, res, key, max)
}

/// Per-`resource_id` resolve rate limit. Use for resolve endpoints
/// (`resolve_realm`, `resolve_handle`, `resolve_organization`) so
/// a single resource cannot be probed at unlimited speed even
/// across many distinct IPs.
pub fn enforce_resolve_rate_limit(
    req: &Request,
    res: &mut Response,
    state: &AppState,
    resource_id: &str,
) -> bool {
    if !enforce_query_rate_limit(req, res, state) {
        return false;
    }
    let max = state.config().query_max_resolves_per_resource_per_min;
    if max == 0 || resource_id.trim().is_empty() {
        return true;
    }
    let key = format!("query-resolve:{}", resource_id.trim());
    check(state, res, key, max)
}

fn check(state: &AppState, res: &mut Response, key: String, max: u32) -> bool {
    match state.check_rate_limit(key, max) {
        RateLimitOutcome::Allowed => true,
        RateLimitOutcome::Limited { retry_after } => {
            let retry_after_seconds = retry_after.as_secs().max(1);
            if let Ok(value) = retry_after_seconds.to_string().parse() {
                res.headers_mut().insert(header::RETRY_AFTER, value);
            }
            ApiErrorCode::RateLimited.render(res, "query rate limited");
            false
        }
    }
}
