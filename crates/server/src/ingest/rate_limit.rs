//! Ingest-side per-resource / per-IP rate limiting.

use salvo::prelude::*;

use crate::query::rate_limit::{reject_rate_limited, resolve_client_ip};
use crate::state::{AppState, RateLimitOutcome};

pub fn enforce_ingest_rate_limit(
    req: &Request,
    res: &mut Response,
    state: &AppState,
    resource_id: &str,
    principal_server_id: Option<&str>,
) -> bool {
    let max = state.config().rate_limit_per_resource_per_min;
    // Resolve the client IP through the shared trusted-proxy logic so the
    // per-IP bucket is keyed on the real client behind a reverse proxy rather
    // than on the proxy's address.
    let ip = resolve_client_ip(req, state);
    let mut checks = vec![format!("resource:{resource_id}"), format!("ip:{ip}")];
    if let Some(principal_server_id) = principal_server_id
        && !principal_server_id.trim().is_empty()
    {
        checks.push(format!("principal-server:{}", principal_server_id.trim()));
    }

    for key in checks {
        if let RateLimitOutcome::Limited { retry_after } = state.check_rate_limit(key, max) {
            reject_rate_limited(res, retry_after, "rate limited");
            return false;
        }
    }
    true
}
