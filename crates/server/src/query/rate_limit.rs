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
//!
//! P5 — IP resolution honours `TEABAY_TRUSTED_PROXY`: when the direct
//! `remote_addr()` is in the trusted-proxy allowlist we use the leading
//! `X-Forwarded-For` value; otherwise we ignore the header so a
//! spoofed value cannot poison the per-IP bucket.
//!
//! P5 — resolve endpoints additionally pay a 50ms response-time
//! jitter (see [`apply_resolve_response_jitter`]) so existence-probe
//! timing leaks cannot be amplified by bursts.

use std::net::IpAddr;
use std::time::Duration;

use rand::RngExt;
use salvo::http::header;
use salvo::prelude::*;

use crate::error::ApiErrorCode;
use crate::state::{AppState, RateLimitOutcome};

/// Maximum jitter (response-time) applied to resolve endpoints. The
/// concrete delay is uniformly sampled in `[0, RESOLVE_JITTER_MAX)`.
pub const RESOLVE_JITTER_MAX: Duration = Duration::from_millis(50);

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

/// Per-search-needle rate limit. Caps how fast a single query string can be
/// probed across the search endpoints (`search_actors` / `search_users`),
/// throttling substring/prefix enumeration of the public namespace even when
/// an attacker spreads requests across many IPs. Reuses the
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

/// P5 — anti-enumeration response jitter for resolve endpoints. The
/// per-route deterministic jitter (`LatencyBudget`) handles route-level
/// timing isolation; this adds a stochastic component so an attacker
/// cannot subtract the deterministic component out by averaging.
///
/// Sleeps for a uniformly-random duration in `[0,
/// RESOLVE_JITTER_MAX)`. Caller should `.await` immediately before
/// returning the response body.
pub async fn apply_resolve_response_jitter() {
    let max = RESOLVE_JITTER_MAX.as_micros() as u64;
    if max == 0 {
        return;
    }
    let pick = rand::rng().random_range(0..max);
    tokio::time::sleep(Duration::from_micros(pick)).await;
}

/// Resolve the client IP for rate-limit bucketing. Trusts the leading
/// `X-Forwarded-For` value only when the direct `remote_addr` is in the
/// `TEABAY_TRUSTED_PROXY` allowlist. Shared with `crate::ingest::rate_limit`
/// so both faces resolve the client IP identically behind a reverse proxy.
pub(crate) fn resolve_client_ip(req: &Request, state: &AppState) -> String {
    let remote = req.remote_addr().to_string();
    let trusted = state.config().trusted_proxy.as_deref().unwrap_or(&[]);
    if trusted.is_empty() {
        return remote;
    }
    let Some(direct_ip) = direct_remote_ip(&remote) else {
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
        .filter(|v| !v.is_empty())
    {
        return forwarded.to_owned();
    }
    remote
}

fn direct_remote_ip(remote: &str) -> Option<IpAddr> {
    // `req.remote_addr()` renders as `SocketAddr` / `Unix` / `Unknown`
    // depending on the listener. Strip the trailing `:port` if present
    // and try IP parsing.
    if let Ok(ip) = remote.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Some((host, _port)) = remote.rsplit_once(':') {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    None
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
/// Shared by the ingest and query rate-limit guards so the rejection shape
/// stays consistent across both faces.
pub(crate) fn reject_rate_limited(res: &mut Response, retry_after: Duration, message: &str) {
    let retry_after_seconds = retry_after.as_secs().max(1);
    if let Ok(value) = retry_after_seconds.to_string().parse() {
        res.headers_mut().insert(header::RETRY_AFTER, value);
    }
    ApiErrorCode::RateLimited.render(res, message);
}
