//! `cx.directory.withdraw` handler — resource-initiated path 2 from §8.7.
//!
//! On accept:
//!   * insert a `withdrawals` row with `kind=resource_withdraw`
//!   * delete the `directory_resources` row (or mark stale; we delete to
//!     avoid leaking via search ranking — §10 hidden-result rule)
//!   * write a `Withdrawal` audit row
//!   * subsequent resolves return blinded `not_found` (§8.7 last paragraph).

use chrono::Utc;
use diesel::prelude::*;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

use crate::{
    audit::{self, AuditEventKind},
    error::ErrorCode,
    ids::{IdClass, new_id},
    ingest::{ResourceKindWire, WithdrawalKindWire, rate_limit::enforce_ingest_rate_limit, verify},
    state::AppState,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct WithdrawRequest {
    pub resource_kind: ResourceKindWire,
    pub resource_id: String,
    /// Same proof envelope used in `cx.{kind}.discovery.proof` — must be
    /// signed by the resource's governance key. Verification follows §8.5
    /// step 2.
    pub governance_proof: JsonValue,
    pub reason: String,
    /// If absent the directory uses `now()`.
    #[serde(default)]
    pub effective_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct WithdrawResponse {
    pub withdraw_id: String,
    pub acked_at: chrono::DateTime<Utc>,
}

#[handler]
pub async fn withdraw(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };

    let body: WithdrawRequest = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ErrorCode::BadJson.render(res, format!("malformed withdraw body: {e}"));
            return;
        }
    };

    if body.resource_id.is_empty() {
        ErrorCode::MissingParam.render(res, "resource_id is required");
        return;
    }
    if !enforce_ingest_rate_limit(req, res, &state, &body.resource_id) {
        return;
    }
    if body.reason.trim().is_empty() {
        ErrorCode::MissingParam.render(res, "reason is required");
        return;
    }
    if !body.governance_proof.is_object() {
        ErrorCode::SchemaViolation.render(res, "governance_proof must be an object");
        return;
    }

    let canonical_payload = match withdraw_payload_without_jws(&body) {
        Ok(payload) => payload,
        Err((code, msg)) => {
            code.render(res, msg);
            return;
        }
    };
    if let Err((code, msg)) = verify::verify_governance_proof_payload(
        &canonical_payload,
        &body.governance_proof,
        body.resource_kind,
        &body.resource_id,
        state.config(),
    ) {
        code.render(res, msg);
        return;
    }

    let withdraw_id = new_id(IdClass::Withdraw);
    let acked_at = Utc::now();
    let effective_at = body.effective_at.unwrap_or(acked_at);

    if let Err(e) = persist_withdraw(&state, &body, &withdraw_id, acked_at, effective_at) {
        ErrorCode::InternalError.render(res, format!("persist withdraw: {e}"));
        return;
    }

    let _ = audit::record(
        state.db(),
        AuditEventKind::Withdrawal,
        Some(body.resource_kind),
        Some(&body.resource_id),
        None,
        json!({
            "withdraw_id": withdraw_id,
            "kind": "resource_withdraw",
            "reason": body.reason,
            "effective_at": effective_at,
        }),
    );

    res.render(Json(WithdrawResponse {
        withdraw_id,
        acked_at,
    }));
}

fn withdraw_payload_without_jws(body: &WithdrawRequest) -> Result<JsonValue, (ErrorCode, String)> {
    let mut payload = serde_json::to_value(body).map_err(|e| {
        (
            ErrorCode::InternalError,
            format!("serialize withdraw payload: {e}"),
        )
    })?;
    let proof = payload
        .get_mut("governance_proof")
        .and_then(JsonValue::as_object_mut)
        .ok_or((
            ErrorCode::SignatureInvalid,
            "governance_proof object missing".to_owned(),
        ))?;
    if proof.remove("jws").is_none() {
        return Err((
            ErrorCode::SignatureInvalid,
            "governance_proof.jws missing".to_owned(),
        ));
    }
    Ok(payload)
}

fn persist_withdraw(
    state: &AppState,
    body: &WithdrawRequest,
    withdraw_id: &str,
    acked_at: chrono::DateTime<Utc>,
    effective_at: chrono::DateTime<Utc>,
) -> anyhow::Result<()> {
    use crate::schema::{directory_resources::dsl as r, withdrawals::dsl as w};

    let mut conn = state.db().get()?;
    conn.transaction::<_, diesel::result::Error, _>(|conn| {
        diesel::insert_into(w::withdrawals)
            .values((
                w::withdraw_id.eq(withdraw_id),
                w::resource_kind.eq(body.resource_kind),
                w::resource_id.eq(&body.resource_id),
                w::kind.eq(WithdrawalKindWire::ResourceWithdraw),
                w::reason.eq(&body.reason),
                w::proof.eq(&body.governance_proof),
                w::effective_at.eq(effective_at),
                w::acked_at.eq(acked_at),
                w::operator.eq::<Option<&str>>(None),
                w::notified_at.eq::<Option<chrono::DateTime<Utc>>>(None),
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
