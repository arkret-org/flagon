//! Operator-facing admin query endpoints.

mod audit;

pub use audit::{audit_chain_verify, audit_feed};
use chrono::{DateTime, Utc};
use salvo::prelude::*;

use crate::error::ApiErrorCode;
use crate::middleware::{require_admin_csrf, verify_admin_credential};
use crate::state::AppState;

async fn require_admin(req: &Request, state: &AppState) -> Result<(), ApiErrorCode> {
    verify_admin_credential(req, state).await.map(|_| ())
}

fn parse_since(raw: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|error| format!("since must be RFC3339: {error}"))
}
