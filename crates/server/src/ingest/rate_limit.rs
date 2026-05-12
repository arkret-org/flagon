//! Ingest-side per-resource / per-IP rate limiting.

use salvo::http::header;
use salvo::prelude::*;

use crate::error::ErrorCode;
use crate::state::{AppState, RateLimitOutcome};

pub fn enforce_ingest_rate_limit(
    req: &Request,
    res: &mut Response,
    state: &AppState,
    resource_id: &str,
) -> bool {
    let max = state.config().rate_limit_per_resource_per_min;
    let ip = req.remote_addr().to_string();
    let checks = [format!("resource:{resource_id}"), format!("ip:{ip}")];

    for key in checks {
        if let RateLimitOutcome::Limited { retry_after } = state.check_rate_limit(key, max) {
            let retry_after_seconds = retry_after.as_secs().max(1);
            if let Ok(value) = retry_after_seconds.to_string().parse() {
                res.headers_mut().insert(header::RETRY_AFTER, value);
            }
            ErrorCode::RateLimited.render(res, "rate limited");
            return false;
        }
    }
    true
}
