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
    ingest::{ResourceKindWire, WithdrawalKindWire},
    schema::{directory_resources, withdrawals},
    state::AppState,
};

#[derive(Debug, Deserialize)]
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
    if body.reason.trim().is_empty() {
        ErrorCode::MissingParam.render(res, "reason is required");
        return;
    }
    if !body.governance_proof.is_object() {
        ErrorCode::SchemaViolation.render(res, "governance_proof must be an object");
        return;
    }

    // TODO M2-T2: verify governance_proof against the resolved DID document
    // (same chain as `verify::verify_discovery_proof_shape`, then real JWS
    // verification). For now we accept structurally-valid envelopes.
    if let Err((code, msg)) = verify_governance_proof_shape(&body.governance_proof) {
        code.render(res, msg);
        return;
    }

    let withdraw_id = new_id(IdClass::Withdraw);
    let acked_at = Utc::now();
    let effective_at = body.effective_at.unwrap_or(acked_at);

    if let Err(e) = persist_withdraw(
        &state,
        &body,
        &withdraw_id,
        acked_at,
        effective_at,
    ) {
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

    res.render(Json(WithdrawResponse { withdraw_id, acked_at }));
}

fn verify_governance_proof_shape(proof: &JsonValue) -> Result<(), (ErrorCode, String)> {
    let kind = proof
        .get("kind")
        .and_then(JsonValue::as_str)
        .ok_or((ErrorCode::SignatureInvalid, "governance_proof.kind missing".into()))?;
    if kind != "detached_jws" {
        return Err((
            ErrorCode::SignatureInvalid,
            format!("unsupported governance_proof.kind {kind}"),
        ));
    }
    if proof.get("verification_method").and_then(JsonValue::as_str).is_none() {
        return Err((
            ErrorCode::SignatureInvalid,
            "governance_proof.verification_method missing".into(),
        ));
    }
    if proof.get("jws").and_then(JsonValue::as_str).is_none() {
        return Err((ErrorCode::SignatureInvalid, "governance_proof.jws missing".into()));
    }
    Ok(())
}

fn persist_withdraw(
    state: &AppState,
    body: &WithdrawRequest,
    withdraw_id: &str,
    acked_at: chrono::DateTime<Utc>,
    effective_at: chrono::DateTime<Utc>,
) -> anyhow::Result<()> {
    use crate::schema::{
        directory_resources::dsl as r,
        withdrawals::dsl as w,
    };

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
