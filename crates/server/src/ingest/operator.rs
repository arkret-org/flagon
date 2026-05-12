//! Operator-admin ingest actions.

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use salvo::http::header;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

use crate::audit::{self, AuditEventKind};
use crate::error::ErrorCode;
use crate::ids::{IdClass, new_id};
use crate::ingest::rate_limit::enforce_ingest_rate_limit;
use crate::ingest::{ResourceKindWire, WithdrawalKindWire};
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
            ErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };

    if let Err(error) = require_admin(req, &state) {
        error.render(res, "admin bearer token required");
        return;
    }

    let body: OperatorTakedownRequest = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ErrorCode::BadJson.render(res, format!("malformed takedown body: {error}"));
            return;
        }
    };

    if !enforce_ingest_rate_limit(req, res, &state, &body.resource_id) {
        return;
    }
    if body.resource_id.trim().is_empty() {
        ErrorCode::MissingParam.render(res, "resource_id is required");
        return;
    }
    if body.reason.trim().is_empty() {
        ErrorCode::MissingParam.render(res, "reason is required");
        return;
    }

    let withdraw_id = new_id(IdClass::Withdraw);
    let acked_at = Utc::now();
    let effective_at = body.effective_at.unwrap_or(acked_at);
    let operator = body.operator.as_deref().unwrap_or("admin-console");
    let notification_status = if state.config().takedown_contact.is_some() {
        "todo_notification_queued"
    } else {
        "no_takedown_contact_configured"
    };

    if let Err(error) = persist_operator_takedown(
        &state,
        &body,
        &withdraw_id,
        operator,
        acked_at,
        effective_at,
        notification_status,
    ) {
        ErrorCode::InternalError.render(res, format!("persist operator takedown: {error}"));
        return;
    }

    let _ = audit::record(
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
        }),
    );

    res.render(Json(OperatorTakedownResponse {
        withdraw_id,
        acked_at,
        effective_at,
        notification_status,
    }));
}

fn require_admin(req: &Request, state: &AppState) -> Result<(), ErrorCode> {
    let expected = state
        .config()
        .admin_token
        .as_deref()
        .ok_or(ErrorCode::Unauthenticated)?;
    let actual = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    if actual == Some(expected) {
        Ok(())
    } else {
        Err(ErrorCode::Unauthenticated)
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_operator_takedown(
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

    let proof = json!({
        "kind": "operator_takedown",
        "operator": operator,
        "evidence": body.evidence,
        "notification_status": notification_status,
        "todo": "wire email/DIDComm notification transport",
    });

    let mut conn = state.db().get()?;
    conn.transaction::<_, diesel::result::Error, _>(|conn| {
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
            .execute(conn)?;

        diesel::delete(r::directory_resources)
            .filter(r::resource_kind.eq(body.resource_kind))
            .filter(r::resource_id.eq(&body.resource_id))
            .execute(conn)?;

        Ok(())
    })?;
    Ok(())
}
