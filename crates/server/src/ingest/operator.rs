//! Operator-admin ingest actions.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::AsyncConnection;
use diesel_async::RunQueryDsl;
use diesel_async::scoped_futures::ScopedFutureExt;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

use crate::audit::{self, ActorIdentity, AuditEventKind};
use crate::error::ApiErrorCode;
use crate::ids::{IdClass, new_id};
use crate::ingest::rate_limit::enforce_ingest_rate_limit;
use crate::ingest::receipt::operator_takedown_proof;
use crate::ingest::{ResourceKindWire, WithdrawalKindWire};
use crate::middleware::{require_admin_csrf, verify_admin_credential};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct OperatorTakedownRequest {
    pub resource_kind: ResourceKindWire,
    pub resource_id: String,
    pub reason: String,
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub evidence: JsonValue,
    #[serde(default)]
    pub effective_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct OperatorTakedownResponse {
    pub withdraw_id: String,
    pub acked_at: DateTime<Utc>,
    pub effective_at: DateTime<Utc>,
    pub notification_status: &'static str,
}

#[handler]
pub async fn operator_takedown(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };

    let credential = match verify_admin_credential(req, &state).await {
        Ok(credential) => credential,
        Err(error) => {
            error.render(res, "admin bearer token required");
            return;
        }
    };
    if let Err(error) = require_admin_csrf(req, &state) {
        error.render(res, "X-CSRF-Token header required");
        return;
    }

    let body: OperatorTakedownRequest = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::BadJson.render(res, format!("malformed takedown body: {error}"));
            return;
        }
    };

    if !enforce_ingest_rate_limit(req, res, &state, &body.resource_id) {
        return;
    }
    if body.resource_id.trim().is_empty() {
        ApiErrorCode::MissingParam.render(res, "resource_id is required");
        return;
    }
    if body.reason.trim().is_empty() {
        ApiErrorCode::MissingParam.render(res, "reason is required");
        return;
    }

    let withdraw_id = new_id(IdClass::Withdraw);
    let acked_at = Utc::now();
    let effective_at = body.effective_at.unwrap_or(acked_at);
    let operator = body.operator.as_deref().unwrap_or("admin-console");
    let notification_status =
        initial_notification_status(state.config().takedown_contact.is_some());

    if let Err(error) = persist_operator_takedown(
        &state,
        &body,
        &withdraw_id,
        operator,
        acked_at,
        effective_at,
        notification_status,
    )
    .await
    {
        ApiErrorCode::InternalError.render(res, format!("persist operator takedown: {error}"));
        return;
    }

    let authenticated_actor = credential.authenticated_actor();
    let identity = ActorIdentity {
        authentication_method: Some(credential.authentication_method()),
        authenticated_actor: Some(&authenticated_actor),
        asserted_operator: Some(operator),
    };
    let _ = audit::record_with_identity(
        state.db(),
        AuditEventKind::OperatorTakedown,
        Some(body.resource_kind),
        Some(&body.resource_id),
        Some(operator),
        json!({
            "withdraw_id": withdraw_id,
            "reason": body.reason,
            "effective_at": effective_at,
            "notification_status": notification_status,
            "takedown_contact": state.config().takedown_contact,
            "authentication_method": credential.authentication_method(),
            "credential_key_id": credential.key_id,
        }),
        identity,
    )
    .await;

    res.render(Json(OperatorTakedownResponse {
        withdraw_id,
        acked_at,
        effective_at,
        notification_status,
    }));
}

#[allow(clippy::too_many_arguments)]
async fn persist_operator_takedown(
    state: &AppState,
    body: &OperatorTakedownRequest,
    withdraw_id: &str,
    operator: &str,
    acked_at: DateTime<Utc>,
    effective_at: DateTime<Utc>,
    notification_status: &str,
) -> anyhow::Result<()> {
    use crate::schema::directory_resources::dsl as r;
    use crate::schema::withdrawals::dsl as w;

    let proof = operator_takedown_proof(
        state.config(),
        body,
        withdraw_id,
        operator,
        acked_at,
        effective_at,
        notification_status,
    )?;

    let mut conn = state.db().get().await?;
    conn.transaction::<_, diesel::result::Error, _>(|conn| {
        async move {
            diesel::insert_into(w::withdrawals)
                .values((
                    w::withdraw_id.eq(withdraw_id),
                    w::resource_kind.eq(body.resource_kind),
                    w::resource_id.eq(&body.resource_id),
                    w::kind.eq(WithdrawalKindWire::OperatorTakedown),
                    w::reason.eq(&body.reason),
                    w::proof.eq(&proof),
                    w::effective_at.eq(effective_at),
                    w::acked_at.eq(acked_at),
                    w::operator.eq(Some(operator)),
                    w::notified_at.eq::<Option<DateTime<Utc>>>(None),
                ))
                .execute(&mut *conn)
                .await?;

            diesel::delete(r::directory_resources)
                .filter(r::resource_kind.eq(body.resource_kind))
                .filter(r::resource_id.eq(&body.resource_id))
                .execute(&mut *conn)
                .await?;

            Ok(())
        }
        .scope_boxed()
    })
    .await?;
    Ok(())
}

fn initial_notification_status(has_takedown_contact: bool) -> &'static str {
    if has_takedown_contact {
        "pending"
    } else {
        "no_takedown_contact_configured"
    }
}

#[cfg(test)]
mod tests {
    use super::initial_notification_status;

    #[test]
    fn takedown_contact_starts_notifier_visible_pending_status() {
        assert_eq!(initial_notification_status(true), "pending");
        assert_eq!(
            initial_notification_status(false),
            "no_takedown_contact_configured"
        );
    }
}
