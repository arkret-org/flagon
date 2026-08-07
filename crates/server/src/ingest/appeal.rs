//! Operator takedown appeal and recovery loop.

use arkret_sdk::{DirectoryTakedownAppealOutcome, DirectoryTakedownAppealRequestBody};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl};
use salvo::prelude::*;
use serde_json::{Value as JsonValue, json};
use teabay_contracts::{
    DirectoryDecisionReceipt, TakedownAppealDecision, TakedownAppealDecisionOutcome,
    TakedownAppealDecisionRequestBody,
};

use crate::audit::{self, ActorIdentity, AuditEventKind};
use crate::error::ApiErrorCode;
use crate::ids::{self, IdClass, new_id};
use crate::ingest::rate_limit::enforce_ingest_rate_limit;
use crate::ingest::receipt::{takedown_appeal_decision_receipt, takedown_appeal_received_receipt};
use crate::ingest::withdraw::resolve_withdraw_resource_kind;
use crate::ingest::{DirectoryResourceKindDb, WithdrawalKindWire, verify};
use crate::middleware::{require_admin_csrf, verify_admin_credential};
use crate::state::AppState;

const APPEAL_STATUS_PENDING: &str = "pending";

#[handler]
pub async fn submit_takedown_appeal(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };

    let body: DirectoryTakedownAppealRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::BadJson.render(res, format!("malformed takedown appeal body: {error}"));
            return;
        }
    };
    if let Err((code, message)) = validate_appeal_body(&body) {
        code.render(res, message);
        return;
    }
    if !enforce_ingest_rate_limit(req, res, &state, &body.resource_id, None) {
        return;
    }

    // `resource_kind` is not on the wire (spec `resource_id` self-describes
    // its type); resolve it from the indexed row or ak-id prefix.
    let resource_kind = match resolve_withdraw_resource_kind(&state, &body.resource_id).await {
        Ok(resource_kind) => resource_kind,
        Err(message) => {
            ApiErrorCode::SchemaViolation.render(res, message);
            return;
        }
    };
    let unsigned_packet = match appeal_packet_without_jws(&body) {
        Ok(packet) => packet,
        Err((code, message)) => {
            code.render(res, message);
            return;
        }
    };
    let expected_controller = match crate::ingest::withdraw::governance_controller_for_withdraw(
        &state,
        resource_kind,
        &body.resource_id,
    )
    .await
    {
        Ok(controller) => controller,
        Err((code, message)) => {
            code.render(res, message);
            return;
        }
    };
    if let Err((code, message)) = verify::verify_governance_proof_payload(
        &unsigned_packet,
        &body.governance_proof,
        resource_kind,
        &body.resource_id,
        expected_controller.as_deref(),
        state.did_resolver(),
    ) {
        code.render(res, message);
        return;
    }

    match operator_takedown_in_force(&state, &body.takedown_id, resource_kind, &body.resource_id)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            ApiErrorCode::NotFound.render(res, "operator takedown is not active for this resource");
            return;
        }
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("takedown lookup: {error}"));
            return;
        }
    }

    let appeal_id = new_id(IdClass::Appeal);
    let received_at = Utc::now();
    let requested_outcome = requested_outcome_wire(body.requested_outcome);
    let appeal_packet = match serde_json::to_value(&body) {
        Ok(packet) => packet,
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("serialize appeal packet: {error}"));
            return;
        }
    };
    if let Err(error) = persist_takedown_appeal(
        &state,
        &body,
        resource_kind,
        requested_outcome,
        &appeal_id,
        received_at,
        &appeal_packet,
    )
    .await
    {
        ApiErrorCode::InternalError.render(res, format!("persist takedown appeal: {error}"));
        return;
    }

    // Spec `DirectoryTakedownAppealOutcome` returns a signed decision receipt
    // synchronously; status is `pending` until an operator adjudicates.
    let decision_receipt = match takedown_appeal_received_receipt(
        state.config(),
        &appeal_id,
        &body.takedown_id,
        resource_kind.as_pg(),
        &body.resource_id,
        body.appellant_did.as_str(),
        requested_outcome,
        body.argument_digest.as_str(),
        received_at,
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            ApiErrorCode::InternalError
                .render(res, format!("build appeal received receipt: {error}"));
            return;
        }
    };
    let decision_receipt = match serde_json::from_value(decision_receipt) {
        Ok(receipt) => receipt,
        Err(error) => {
            ApiErrorCode::InternalError.render(
                res,
                format!("appeal received receipt must be an object: {error}"),
            );
            return;
        }
    };

    let _ = audit::record(
        state.db(),
        AuditEventKind::TakedownAppealSubmitted,
        Some(resource_kind),
        Some(&body.resource_id),
        Some(body.appellant_did.as_str()),
        json!({
            "appeal_id": &appeal_id,
            "takedown_id": &body.takedown_id,
            "appellant_did": body.appellant_did.as_str(),
            "requested_outcome": requested_outcome,
            "argument_digest": body.argument_digest.as_str(),
            "received_at": received_at,
        }),
    )
    .await;

    res.render(Json(DirectoryTakedownAppealOutcome {
        appeal_id,
        received_at,
        decision_receipt,
    }));
}

/// Snake-case wire token for the spec `requested_outcome` enum
/// (`overturn` | `reduce_scope` | `reinstate`).
fn requested_outcome_wire(
    outcome: arkret_sdk::DirectoryTakedownAppealOutcomeRequest,
) -> &'static str {
    use arkret_sdk::DirectoryTakedownAppealOutcomeRequest as Outcome;
    match outcome {
        Outcome::Overturn => "overturn",
        Outcome::ReduceScope => "reduce_scope",
        Outcome::Reinstate => "reinstate",
    }
}

#[handler]
pub async fn decide_takedown_appeal(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
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

    let body: TakedownAppealDecisionRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ApiErrorCode::BadJson.render(res, format!("malformed appeal decision body: {error}"));
            return;
        }
    };
    if ids::parse(&body.appeal_id) != Some(IdClass::Appeal) {
        ApiErrorCode::InvalidParam.render(res, "appeal_id must be a teabay:appeal id");
        return;
    }
    if body.reason.trim().is_empty() {
        ApiErrorCode::MissingParam.render(res, "reason is required");
        return;
    }

    let appeal = match load_pending_appeal(&state, &body.appeal_id).await {
        Ok(Some(appeal)) => appeal,
        Ok(None) => {
            ApiErrorCode::NotFound.render(res, "appeal not found");
            return;
        }
        Err(error) => {
            ApiErrorCode::InternalError.render(res, format!("appeal lookup: {error}"));
            return;
        }
    };
    if appeal.status != APPEAL_STATUS_PENDING {
        ApiErrorCode::Conflict.render(res, "appeal already has a decision");
        return;
    }

    let decided_at = Utc::now();
    let authenticated_actor = credential.authenticated_actor();
    let decided_by = body
        .decided_by
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&authenticated_actor);
    let reason = body.reason.trim();
    let decision_receipt = match takedown_appeal_decision_receipt(
        state.config(),
        &appeal.appeal_id,
        &appeal.takedown_id,
        appeal.resource_kind.as_pg(),
        &appeal.resource_id,
        &appeal.appellant_did,
        &appeal.requested_outcome,
        &appeal.argument_digest,
        body.evidence_digest.as_deref(),
        body.decision,
        decided_by,
        reason,
        decided_at,
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            ApiErrorCode::InternalError
                .render(res, format!("build appeal decision receipt: {error}"));
            return;
        }
    };

    if let Err(error) = persist_appeal_decision(
        &state,
        &appeal,
        &body,
        decided_by,
        reason,
        decided_at,
        &decision_receipt,
    )
    .await
    {
        ApiErrorCode::InternalError.render(res, format!("persist appeal decision: {error}"));
        return;
    }

    let identity = ActorIdentity {
        authentication_method: Some(credential.authentication_method()),
        authenticated_actor: Some(&authenticated_actor),
        asserted_operator: Some(decided_by),
    };
    let _ = audit::record_with_identity(
        state.db(),
        AuditEventKind::TakedownAppealDecided,
        Some(appeal.resource_kind),
        Some(&appeal.resource_id),
        Some(decided_by),
        json!({
            "appeal_id": &appeal.appeal_id,
            "takedown_id": &appeal.takedown_id,
            "decision": body.decision.as_str(),
            "decision_evidence_digest": body.evidence_digest.as_deref(),
            "decided_at": decided_at,
            "credential_key_id": credential.key_id,
        }),
        identity,
    )
    .await;

    res.render(Json(TakedownAppealDecisionOutcome {
        appeal_id: appeal.appeal_id,
        takedown_id: appeal.takedown_id,
        decision: body.decision,
        decided_at,
        receipt: DirectoryDecisionReceipt::from_json(decision_receipt),
    }));
}

fn validate_appeal_body(
    body: &DirectoryTakedownAppealRequestBody,
) -> Result<(), (ApiErrorCode, String)> {
    if ids::parse(&body.takedown_id) != Some(IdClass::Withdraw) {
        return Err((
            ApiErrorCode::InvalidParam,
            "takedown_id must be a teabay:withdraw id".to_owned(),
        ));
    }
    if body.resource_id.trim().is_empty() {
        return Err((
            ApiErrorCode::MissingParam,
            "resource_id is required".to_owned(),
        ));
    }
    // `appellant_did` (Did), `argument_digest` (Hash), and `requested_outcome`
    // (closed enum) are validated structurally by the SDK types during
    // deserialization, so no further string checks are needed here.
    Ok(())
}

fn appeal_packet_without_jws(
    body: &DirectoryTakedownAppealRequestBody,
) -> Result<JsonValue, (ApiErrorCode, String)> {
    let mut payload = serde_json::to_value(body).map_err(|error| {
        (
            ApiErrorCode::InternalError,
            format!("serialize appeal packet: {error}"),
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

async fn operator_takedown_in_force(
    state: &AppState,
    takedown_id: &str,
    resource_kind: DirectoryResourceKindDb,
    resource_id: &str,
) -> anyhow::Result<bool> {
    use crate::schema::withdrawals::dsl as w;

    let mut conn = state.db().get().await?;
    let count: i64 = w::withdrawals
        .filter(w::withdraw_id.eq(takedown_id))
        .filter(w::resource_kind.eq(resource_kind))
        .filter(w::resource_id.eq(resource_id))
        .filter(w::kind.eq(WithdrawalKindWire::OperatorTakedown))
        .filter(w::overturned_at.is_null())
        .count()
        .get_result(&mut *conn)
        .await?;
    Ok(count > 0)
}

#[allow(clippy::too_many_arguments)]
async fn persist_takedown_appeal(
    state: &AppState,
    body: &DirectoryTakedownAppealRequestBody,
    resource_kind: DirectoryResourceKindDb,
    requested_outcome: &str,
    appeal_id: &str,
    accepted_at: DateTime<Utc>,
    appeal_packet: &JsonValue,
) -> anyhow::Result<()> {
    use crate::schema::takedown_appeals::dsl as a;

    let mut conn = state.db().get().await?;
    diesel::insert_into(a::takedown_appeals)
        .values((
            a::appeal_id.eq(appeal_id),
            a::takedown_id.eq(&body.takedown_id),
            a::resource_kind.eq(resource_kind),
            a::resource_id.eq(&body.resource_id),
            a::appellant_did.eq(body.appellant_did.as_str()),
            a::requested_outcome.eq(requested_outcome),
            a::argument_digest.eq(body.argument_digest.as_str()),
            a::appeal_packet.eq(appeal_packet),
            a::status.eq(APPEAL_STATUS_PENDING),
            a::created_at.eq(body.created_at),
            a::accepted_at.eq(accepted_at),
        ))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

#[derive(Debug, Queryable)]
struct AppealRow {
    appeal_id: String,
    takedown_id: String,
    resource_kind: DirectoryResourceKindDb,
    resource_id: String,
    appellant_did: String,
    requested_outcome: String,
    argument_digest: String,
    status: String,
}

async fn load_pending_appeal(
    state: &AppState,
    appeal_id: &str,
) -> anyhow::Result<Option<AppealRow>> {
    use crate::schema::takedown_appeals::dsl as a;

    let mut conn = state.db().get().await?;
    let row = a::takedown_appeals
        .filter(a::appeal_id.eq(appeal_id))
        .select((
            a::appeal_id,
            a::takedown_id,
            a::resource_kind,
            a::resource_id,
            a::appellant_did,
            a::requested_outcome,
            a::argument_digest,
            a::status,
        ))
        .first(&mut *conn)
        .await
        .optional()?;
    Ok(row)
}

async fn persist_appeal_decision(
    state: &AppState,
    appeal: &AppealRow,
    body: &TakedownAppealDecisionRequestBody,
    decided_by: &str,
    reason: &str,
    decided_at: DateTime<Utc>,
    receipt: &JsonValue,
) -> anyhow::Result<()> {
    use crate::schema::takedown_appeals::dsl as a;
    use crate::schema::withdrawals::dsl as w;

    let status = body.decision.as_str();
    let mut conn = state.db().get().await?;
    conn.transaction::<_, diesel::result::Error, _>(async move |conn| {
        diesel::update(a::takedown_appeals.filter(a::appeal_id.eq(&appeal.appeal_id)))
            .set((
                a::status.eq(status),
                a::decided_at.eq(Some(decided_at)),
                a::decided_by.eq(Some(decided_by)),
                a::decision.eq(Some(status)),
                a::decision_reason.eq(Some(reason)),
                a::decision_receipt.eq(Some(receipt.clone())),
            ))
            .execute(&mut *conn)
            .await?;

        if body.decision == TakedownAppealDecision::Overturned {
            diesel::update(
                w::withdrawals
                    .filter(w::withdraw_id.eq(&appeal.takedown_id))
                    .filter(w::kind.eq(WithdrawalKindWire::OperatorTakedown))
                    .filter(w::overturned_at.is_null()),
            )
            .set((
                w::overturned_at.eq(Some(decided_at)),
                w::overturn_appeal_id.eq(Some(&appeal.appeal_id)),
                w::overturn_receipt.eq(Some(receipt.clone())),
            ))
            .execute(&mut *conn)
            .await?;
        }
        Ok(())
    })
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn appeal_packet_without_jws_keeps_signed_fields() {
        use arkret_sdk::{Did, DirectoryTakedownAppealOutcomeRequest, Hash};

        let body = DirectoryTakedownAppealRequestBody {
            takedown_id: "teabay:withdraw:01904100-0000-7000-8000-000000000001".to_owned(),
            resource_id: "ak:realm:AT0jIIg6naB0Vkqbb-ip6eunf-bHr5-nh4pz2_kYNyVX".to_owned(),
            appellant_did: Did::new("did:webvh:realm.example").expect("did"),
            argument_digest: Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .expect("digest"),
            requested_outcome: DirectoryTakedownAppealOutcomeRequest::Overturn,
            created_at: Utc::now(),
            governance_proof: BTreeMap::from([
                ("kind".to_owned(), json!("detached_jws")),
                (
                    "verification_method".to_owned(),
                    json!("did:webvh:realm.example#key-1"),
                ),
                ("jws".to_owned(), json!("placeholder")),
            ]),
        };

        let unsigned = appeal_packet_without_jws(&body).expect("unsigned packet");

        assert!(unsigned["governance_proof"].get("jws").is_none());
        assert_eq!(
            unsigned["takedown_id"].as_str(),
            Some(body.takedown_id.as_str())
        );
        assert_eq!(unsigned["requested_outcome"], "overturn");
        assert!(unsigned.get("argument").is_none(), "no plaintext argument");
        assert!(unsigned["governance_proof"].is_object());
    }
}
