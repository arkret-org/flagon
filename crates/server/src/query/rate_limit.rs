//! Query-face rate limiting.
//!
//! Runs in front of the public Realm reads and caps per-IP queries and
//! per-Realm or search-needle probes.
//!
//! Both limits are configured via `TEABAY_QUERY_MAX_QUERIES_PER_IP_PER_MIN`
//! and `TEABAY_QUERY_MAX_RESOLVES_PER_RESOURCE_PER_MIN`. A value of `0`
//! disables that particular check, which is useful for the in-process
//! conformance harness.
//!
//! P5 — IP resolution honours `TEABAY_TRUSTED_PROXY`: when the direct
//! `remote_addr()` is in the trusted-proxy allowlist we use the leading
//! `X-Forwarded-For` value; otherwise we ignore the header so a
//! spoofed value cannot poison the per-IP bucket.
use std::net::IpAddr;
use std::time::Duration;

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
    let ip = resolve_client_ip(req, state);
    let key = format!("query-ip:{ip}");
    check(state, res, key, max)
}

/// Per-Realm resolve rate limit so one identifier cannot be probed at
/// unlimited speed even across many distinct IPs.
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

/// Per-search-needle rate limit. Caps how fast a single query string can be
/// probed across the public Realm index even when requests span IPs. Reuses the
/// per-resource-resolve cap. An empty needle is not throttled (it is the
/// broad "list public" query the per-IP limit already covers). Returns `true`
/// when the request may proceed.
pub fn enforce_search_needle_rate_limit(
    res: &mut Response,
    state: &AppState,
    needle: &str,
) -> bool {
    let max = state.config().query_max_resolves_per_resource_per_min;
    let needle = needle.trim();
    if max == 0 || needle.is_empty() {
        return true;
    }
    let key = format!("query-search-needle:{needle}");
    check(state, res, key, max)
}

/// Resolve the client IP for rate-limit bucketing. Trusts the leading
/// `X-Forwarded-For` value only when the direct `remote_addr` is in the
/// `TEABAY_TRUSTED_PROXY` allowlist.
pub(crate) fn resolve_client_ip(req: &Request, state: &AppState) -> String {
    let direct_ip = req.remote_addr().ip();
    let remote = direct_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| req.remote_addr().to_string());
    let trusted = state.config().trusted_proxy.as_deref().unwrap_or(&[]);
    if trusted.is_empty() {
        return remote;
    }
    let Some(direct_ip) = direct_ip else {
        return remote;
    };
    if !trusted.contains(&direct_ip) {
        return remote;
    }
    if let Some(forwarded) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| v.trim())
        .and_then(|value| value.parse::<IpAddr>().ok())
    {
        return forwarded.to_string();
    }
    remote
}

fn check(state: &AppState, res: &mut Response, key: String, max: u32) -> bool {
    match state.check_rate_limit(key, max) {
        RateLimitOutcome::Allowed => true,
        RateLimitOutcome::Limited { retry_after } => {
            reject_rate_limited(res, retry_after, "query rate limited");
            false
        }
    }
}

/// Render a `429`-style rate-limited rejection with a `Retry-After` header.
/// Used by both public Realm reads.
pub(crate) fn reject_rate_limited(res: &mut Response, retry_after: Duration, message: &str) {
    let retry_after_seconds = retry_after.as_secs().max(1);
    if let Ok(value) = retry_after_seconds.to_string().parse() {
        res.headers_mut().insert(header::RETRY_AFTER, value);
    }
    ApiErrorCode::RateLimited.render(res, message);
}
