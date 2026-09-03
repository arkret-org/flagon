//! `ak.find.directory.command.withdraw.v1` handler — resource-initiated path 2 from §8.7.
//!
//! On accept:
//!   * insert a `withdrawals` row with `kind=resource_withdraw`
//!   * delete the `directory_resources` row (or mark stale; we delete to avoid leaking via search
//!     ranking — §10 hidden-result rule)
//!   * write a `Withdrawal` audit row
//!   * subsequent resolves return blinded `not_found` (§8.7 last paragraph).

use arkret_sdk::{DirectoryWithdrawOutcome, DirectoryWithdrawRequestBody};
use chrono::Utc;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl};
use salvo::prelude::*;
use serde_json::{Value as JsonValue, json};

use crate::audit::{self, AuditEventKind};
use crate::error::ApiErrorCode;
use crate::ids::{IdClass, new_id};
use crate::ingest::rate_limit::enforce_ingest_rate_limit;
use crate::ingest::receipt::resource_withdrawal_proof;
use crate::ingest::{DirectoryResourceKindDb, WithdrawalKindWire, verify};
use crate::state::AppState;

#[handler]
pub async fn withdraw(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let mut ingest_metric = state.metrics().ingest_guard("withdraw");

    let body: DirectoryWithdrawRequestBody = match req.parse_json().await {
        Ok(b) => b,
        Err(e) => {
            ingest_metric.set_outcome("json_invalid");
            ApiErrorCode::JsonInvalid.render(res, format!("malformed withdraw body: {e}"));
            return;
        }
    };

    let resource_id = body.resource_id.as_str();
    if resource_id.is_empty() {
        ingest_metric.set_outcome("schema_rejected");
        ApiErrorCode::ParamMissing.render(res, "resource_id is required");
        return;
    }
    if !enforce_ingest_rate_limit(req, res, &state, resource_id, None) {
        ingest_metric.set_outcome("rate_limited");
        return;
    }
    let resource_kind = match resolve_withdraw_resource_kind(&state, resource_id).await {
        Ok(resource_kind) => resource_kind,
        Err(message) => {
            ingest_metric.set_outcome("schema_rejected");
            ApiErrorCode::SchemaViolation.render(res, message);
            return;
        }
    };

    let expected_controller =
        match governance_controller_for_withdraw(&state, resource_kind, resource_id).await {
            Ok(controller) => controller,
            Err((code, msg)) => {
                ingest_metric.set_outcome("directory_governance_proof_signature_invalid");
                code.render(res, msg);
                return;
            }
        };
    if let Err((code, msg)) = verify::verify_governance_proof(
        &body,
        resource_kind,
        expected_controller.as_deref(),
        state.config().service_id.as_str(),
        state.did_resolver(),
        Utc::now(),
    ) {
        ingest_metric.set_outcome("directory_governance_proof_signature_invalid");
        code.render(res, msg);
        return;
    }

    let withdraw_id = new_id(IdClass::Withdraw);
    let acked_at = Utc::now();
    // Spec §8.10 anti-revocation-evasion: a withdrawal MUST NOT take effect
    // in the past. The requester_id-supplied `effective_at` is clamped up to
    // `acked_at` (now), so a backdated value can never narrow the
    // `TakedownInForce` window and let a later `as_of` announce slip back
    // in. Requesters may only push effectiveness *forward*.
    let effective_at = body
        .effective_at
        .map(|t| t.max(acked_at))
        .unwrap_or(acked_at);

    let proof = match resource_withdrawal_proof(
        state.config(),
        resource_kind,
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

    if let Err(e) = persist_withdraw(
        &state,
        resource_kind,
        &body,
        &withdraw_id,
        &proof,
        acked_at,
        effective_at,
    )
    .await
    {
        ingest_metric.set_outcome("persist_error");
        ApiErrorCode::InternalError.render(res, format!("persist withdraw: {e}"));
        return;
    }

    let _ = audit::record(
        state.db(),
        AuditEventKind::Withdrawal,
        Some(resource_kind),
        Some(resource_id),
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
    res.render(Json(DirectoryWithdrawOutcome {
        withdrawal_ref: withdraw_id,
        acked_at,
    }));
}

pub(crate) async fn governance_controller_for_withdraw(
    state: &AppState,
    resource_kind: DirectoryResourceKindDb,
    resource_id: &str,
) -> Result<Option<String>, (ApiErrorCode, String)> {
    if !matches!(
        resource_kind,
        DirectoryResourceKindDb::Realm | DirectoryResourceKindDb::Handle
    ) {
        return Ok(None);
    }
    verify::indexed_station(state.db(), resource_kind, resource_id)
        .await
        .map_err(|error| {
            (
                ApiErrorCode::InternalError,
                format!("governance controller lookup: {error}"),
            )
        })?
        .map(Some)
        .ok_or_else(|| {
            (
                ApiErrorCode::GovernanceKeyInvalid,
                format!("no indexed governance controller for `{resource_id}`"),
            )
        })
}

async fn persist_withdraw(
    state: &AppState,
    resource_kind: DirectoryResourceKindDb,
    body: &DirectoryWithdrawRequestBody,
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
                w::resource_kind.eq(resource_kind),
                w::resource_id.eq(body.resource_id.as_str()),
                w::kind.eq(WithdrawalKindWire::ResourceWithdraw),
                w::reason.eq(body.reason.as_deref().unwrap_or_default()),
                w::proof.eq(proof),
                w::effective_at.eq(effective_at),
                w::acked_at.eq(acked_at),
                w::operator.eq::<Option<&str>>(None),
                w::notified_at.eq::<Option<chrono::DateTime<Utc>>>(None),
            ))
            .execute(&mut *conn)
            .await?;

        diesel::delete(r::directory_resources)
            .filter(r::resource_kind.eq(resource_kind))
            .filter(r::resource_id.eq(body.resource_id.as_str()))
            .execute(&mut *conn)
            .await?;

        Ok(())
    })
    .await?;
    Ok(())
}

/// Resolve the `resource_kind` for a `resource_id` that does not carry the
/// kind on the wire (withdraw, takedown appeal): prefer the indexed
/// directory row, fall back to ak-id prefix inference. Shared with the appeal
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

/// Classify a `resource_id` by parsing it as the SDK typed id / canonical form
/// each kind actually uses, not by sniffing a prefix.
///
/// A prefix test is strictly looser than the wire contract: `ak:realm:x` and
/// `ak:applet:x` both pass `starts_with` while neither is a legal id, so a
/// caller could name a resource the announce face could never have indexed.
/// `RealmId` enforces the 44-character realm token layout and `AppletId` the
/// RFC 9562 UUIDv7 payload, so only a canonical id classifies.
///
/// There is no `handle` id kind in `registry/id-kind-registry.json` and no
/// `ak:handle:` wire form: handles are indexed under the canonical
/// `<localpart>:<domain>` form that `resolve_handle` looks up, so that is what
/// this recognises.
///
/// `organization` and `actor` are both plain `did_core_id` values and are not
/// distinguishable from the id alone; they resolve through the indexed row
/// instead, which is the caller's preferred path anyway.
fn infer_resource_kind(resource_id: &str) -> Option<DirectoryResourceKindDb> {
    if arkret_sdk::RealmId::new(resource_id).is_ok() {
        return Some(DirectoryResourceKindDb::Realm);
    }
    if arkret_sdk::AppletId::new(resource_id).is_ok() {
        return Some(DirectoryResourceKindDb::Applet);
    }
    if arkret_sdk::Handle::parse(resource_id).is_ok() {
        return Some(DirectoryResourceKindDb::Handle);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_kind_inference_requires_a_canonical_id() {
        assert_eq!(
            infer_resource_kind("ak:realm:AY0Z0alJlPB4P2wAIOCSTs_yNX_lm1mM5r3mhhQuKIFb"),
            Some(DirectoryResourceKindDb::Realm)
        );
        assert_eq!(
            infer_resource_kind("ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa"),
            Some(DirectoryResourceKindDb::Applet)
        );
        assert_eq!(
            infer_resource_kind("alice:example.com"),
            Some(DirectoryResourceKindDb::Handle)
        );

        // A bare prefix test would have accepted every one of these.
        assert_eq!(infer_resource_kind("ak:realm:not-a-realm-token"), None);
        assert_eq!(infer_resource_kind("ak:applet:not-a-uuid"), None);
        // `ak:handle:` is not a registered id kind at all.
        assert_eq!(infer_resource_kind("ak:handle:alice"), None);
        // A DID core id is not classifiable from the id alone.
        assert_eq!(infer_resource_kind("ak:did_core:web:acme.example"), None);
    }
}
