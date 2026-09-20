//! Operator-facing admin query endpoints.

mod allowlist;
mod audit;
mod consent;
mod dashboard;
mod takedown;

pub use allowlist::{allowlist_delete, allowlist_list, allowlist_upsert};
pub use audit::{audit_chain_verify, audit_feed};
use chrono::{DateTime, Utc};
pub use consent::consent_revoke_invalidate;
pub use dashboard::dashboard_stats;
use salvo::prelude::*;
pub use takedown::takedown_audit_export;

use crate::error::ApiErrorCode;
use crate::middleware::admin_auth::AdminCredential;
use crate::middleware::{require_admin_csrf, verify_admin_credential};
use crate::state::AppState;

const DEFAULT_ADMIN_LIMIT: i64 = 100;
const MAX_ADMIN_LIMIT: i64 = 500;

async fn admin_state(
    req: &Request,
    depot: &mut Depot,
    res: &mut Response,
) -> Option<(AppState, AdminCredential)> {
    let state = match depot.get_typed::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return None;
        }
    };
    let credential = match verify_admin_credential(req, &state).await {
        Ok(credential) => credential,
        Err(error) => {
            error.render(res, "admin bearer token required");
            return None;
        }
    };
    if let Err(error) = require_admin_csrf(req, &state) {
        error.render(res, "X-CSRF-Token header required");
        return None;
    }
    Some((state, credential))
}

async fn require_admin(req: &Request, state: &AppState) -> Result<(), ApiErrorCode> {
    verify_admin_credential(req, state).await.map(|_| ())
}

#[allow(clippy::too_many_arguments)]
async fn record_admin_audit(
    state: &AppState,
    credential: &AdminCredential,
    kind: crate::audit::AuditEventKind,
    resource_kind: Option<crate::ingest::DirectoryResourceKindDb>,
    resource_id: Option<&str>,
    asserted_operator_localpart: Option<&str>,
    detail: serde_json::Value,
) -> anyhow::Result<()> {
    let authenticated_credential_id = credential.authenticated_credential_id();
    crate::audit::record_with_identity(
        state.db(),
        kind,
        resource_kind,
        resource_id,
        Some(state.config().service_id.as_str()),
        detail,
        crate::audit::ActorIdentity {
            authentication_method: Some(credential.authentication_method()),
            authenticated_credential_id: Some(authenticated_credential_id.as_str()),
            asserted_operator_localpart,
        },
    )
    .await
}

fn parse_since(raw: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|error| format!("since must be RFC3339: {error}"))
}
