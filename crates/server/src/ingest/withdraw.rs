//! `ck.find.directory.command.withdraw` handler — resource-initiated path 2 from §8.7.
//!
//! On accept:
//!   * insert a `withdrawals` row with `kind=resource_withdraw`
//!   * delete the `directory_resources` row (or mark stale; we delete to avoid leaking via search
//!     ranking — §10 hidden-result rule)
//!   * write a `Withdrawal` audit row
//!   * subsequent resolves return blinded `not_found` (§8.7 last paragraph).

use chrono::Utc;
use cokret_sdk::DirectoryWithdrawOutcome as SdkDirectoryWithdrawOutcome;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};

use crate::audit::{self, AuditEventKind};
use crate::error::ApiErrorCode;
use crate::ids::{IdClass, new_id};
use crate::ingest::rate_limit::enforce_ingest_rate_limit;
use crate::ingest::receipt::resource_withdrawal_proof;
use crate::ingest::{DirectoryResourceKindDb, WithdrawalKindWire, verify};
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct DirectoryWithdrawInput {
    #[serde(skip)]
    pub resource_kind: DirectoryResourceKindDb,
    pub resource_id: String,
    /// Same proof envelope used in `ck.{kind}.discovery.proof` — must be
    /// signed by the resource's governance key. Verification follows §8.5
    /// step 2.
    pub governance_proof: JsonValue,
    pub reason: String,
    /// If absent the directory uses `now()`.
    #[serde(default)]
    pub effective_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct DirectoryWithdrawWireBody {
    pub resource_id: String,
    pub governance_proof: JsonValue,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub effective_at: Option<chrono::DateTime<Utc>>,
}

#[handler]
pub async fn withdraw(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let mut ingest_metric = state.metrics().ingest_guard("withdraw");

    let wire_body: DirectoryWithdrawWireBody = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ingest_metric.set_outcome("bad_json");
            ApiErrorCode::BadJson.render(res, format!("malformed withdraw body: {e}"));
            return;
        }
    };

    if wire_body.resource_id.is_empty() {
        ingest_metric.set_outcome("schema_rejected");
        ApiErrorCode::MissingParam.render(res, "resource_id is required");
        return;
    }
    if !enforce_ingest_rate_limit(req, res, &state, &wire_body.resource_id) {
        ingest_metric.set_outcome("rate_limited");
        return;
    }
    if !wire_body.governance_proof.is_object() {
        ingest_metric.set_outcome("schema_rejected");
        ApiErrorCode::SchemaViolation.render(res, "governance_proof must be an object");
        return;
    }
    let resource_kind = match resolve_withdraw_resource_kind(&state, &wire_body.resource_id).await {
        Ok(resource_kind) => resource_kind,
        Err(message) => {
            ingest_metric.set_outcome("schema_rejected");
            ApiErrorCode::SchemaViolation.render(res, message);
            return;
        }
    };
    let body = DirectoryWithdrawInput {
        resource_kind,
        resource_id: wire_body.resource_id,
        governance_proof: wire_body.governance_proof,
        reason: wire_body.reason.unwrap_or_default(),
        effective_at: wire_body.effective_at,
    };

    let canonical_payload = match withdraw_payload_without_jws(&body) {
        Ok(payload) => payload,
        Err((code, msg)) => {
            ingest_metric.set_outcome("signature_invalid");
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
        ingest_metric.set_outcome("signature_invalid");
        code.render(res, msg);
        return;
    }

    let withdraw_id = new_id(IdClass::Withdraw);
    let acked_at = Utc::now();
    // Spec §8.10 anti-revocation-evasion: a withdrawal MUST NOT take effect
    // in the past. The requester-supplied `effective_at` is clamped up to
    // `acked_at` (now), so a backdated value can never narrow the
    // `TakedownInForce` window and let a later `as_of` announce slip back
    // in. Requesters may only push effectiveness *forward*.
    let effective_at = body
        .effective_at
        .map(|t| t.max(acked_at))
        .unwrap_or(acked_at);

    let proof = match resource_withdrawal_proof(
        state.config(),
        &body,
        &withdraw_id,
        acked_at,
        effective_at,
    ) {
        Ok(proof) => proof,
        Err(error) => {
            ingest_metric.set_outcome("persist_error");
            ApiErrorCode::InternalError.render(res, format!("build withdraw receipt: {error}"));
            return;
        }
    };

    if let Err(e) =
        persist_withdraw(&state, &body, &withdraw_id, &proof, acked_at, effective_at).await
    {
        ingest_metric.set_outcome("persist_error");
        ApiErrorCode::InternalError.render(res, format!("persist withdraw: {e}"));
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
    )
    .await;

    ingest_metric.set_outcome("verify_ok");
    res.render(Json(SdkDirectoryWithdrawOutcome {
        withdrawal_ref: withdraw_id,
        acked_at,
    }));
}

pub(crate) fn withdraw_payload_without_jws(
    body: &DirectoryWithdrawInput,
) -> Result<JsonValue, (ApiErrorCode, String)> {
    let mut payload = serde_json::to_value(body).map_err(|e| {
        (
            ApiErrorCode::InternalError,
            format!("serialize withdraw payload: {e}"),
        )
    })?;
    let proof = payload
        .get_mut("governance_proof")
        .and_then(JsonValue::as_object_mut)
        .ok_or_else(|| {
            (
                ApiErrorCode::SignatureInvalid,
                "governance_proof object missing".to_owned(),
            )
        })?;
    if proof.remove("jws").is_none() {
        return Err((
            ApiErrorCode::SignatureInvalid,
            "governance_proof.jws missing".to_owned(),
        ));
    }
    Ok(payload)
}

async fn persist_withdraw(
    state: &AppState,
    body: &DirectoryWithdrawInput,
    withdraw_id: &str,
    proof: &JsonValue,
    acked_at: chrono::DateTime<Utc>,
    effective_at: chrono::DateTime<Utc>,
) -> anyhow::Result<()> {
    use crate::schema::directory_resources::dsl as r;
    use crate::schema::withdrawals::dsl as w;

    let mut conn = state.db().get().await?;
    conn.transaction::<_, diesel::result::Error, _>(async move |conn| {
        diesel::insert_into(w::withdrawals)
            .values((
                w::withdraw_id.eq(withdraw_id),
                w::resource_kind.eq(body.resource_kind),
                w::resource_id.eq(&body.resource_id),
                w::kind.eq(WithdrawalKindWire::ResourceWithdraw),
                w::reason.eq(&body.reason),
                w::proof.eq(proof),
                w::effective_at.eq(effective_at),
                w::acked_at.eq(acked_at),
                w::operator.eq::<Option<&str>>(None),
                w::notified_at.eq::<Option<chrono::DateTime<Utc>>>(None),
            ))
            .execute(&mut *conn)
            .await?;

        diesel::delete(r::directory_resources)
            .filter(r::resource_kind.eq(body.resource_kind))
            .filter(r::resource_id.eq(&body.resource_id))
            .execute(&mut *conn)
            .await?;

        Ok(())
    })
    .await?;
    crate::psi_index::delete_resource_tokens(state.db(), body.resource_kind, &body.resource_id)
        .await?;
    Ok(())
}

/// Resolve the `resource_kind` for a `resource_id` that does not carry the
/// kind on the wire (withdraw, takedown appeal): prefer the indexed
/// directory row, fall back to ck-id prefix inference. Shared with the appeal
/// ingest handler.
pub(crate) async fn resolve_withdraw_resource_kind(
    state: &AppState,
    resource_id: &str,
) -> Result<DirectoryResourceKindDb, String> {
    use crate::schema::directory_resources::dsl as r;

    let mut conn = state
        .db()
        .get()
        .await
        .map_err(|error| format!("directory lookup failed: {error}"))?;
    let rows: Vec<DirectoryResourceKindDb> = r::directory_resources
        .filter(r::resource_id.eq(resource_id))
        .select(r::resource_kind)
        .limit(2)
        .load(&mut conn)
        .await
        .map_err(|error| format!("directory lookup failed: {error}"))?;
    match rows.as_slice() {
        [resource_kind] => Ok(*resource_kind),
        [] => infer_resource_kind(resource_id)
            .ok_or_else(|| "resource_id does not identify a known directory resource".to_owned()),
        _ => Err("resource_id is ambiguous across directory resource kinds".to_owned()),
    }
}

fn infer_resource_kind(resource_id: &str) -> Option<DirectoryResourceKindDb> {
    if resource_id.starts_with("ck:realm:") {
        Some(DirectoryResourceKindDb::Realm)
    } else if resource_id.starts_with("ck:applet:") {
        Some(DirectoryResourceKindDb::Applet)
    } else if resource_id.starts_with("ck:handle:") {
        Some(DirectoryResourceKindDb::Handle)
    } else {
        None
    }
}
