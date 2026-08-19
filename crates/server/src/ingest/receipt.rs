//! Verifiable withdrawal receipt material stored in `withdrawals.proof`.

use arkret_sdk::canonical;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use ed25519_dalek::Signer as _;
use serde_json::{Value as JsonValue, json};
use teabay_contracts::{
    OperatorTakedownRequestBody, TakedownAppealDecision, directory_resource_kind_token,
};

use crate::config::{AppConfig, ReceiptSigningKey};
use crate::ingest::DirectoryResourceKindDb;

pub(crate) const RECEIPT_VERSION: &str = "teabay.withdrawal_receipt.v1";

pub(crate) fn resource_withdrawal_proof(
    config: &AppConfig,
    resource_kind: DirectoryResourceKindDb,
    body: &arkret_sdk::DirectoryWithdrawRequestBody,
    withdraw_id: &str,
    acked_at: DateTime<Utc>,
    effective_at: DateTime<Utc>,
) -> anyhow::Result<JsonValue> {
    Ok(json!({
        "kind": "resource_withdraw",
        "receipt_version": RECEIPT_VERSION,
        "statement": withdrawal_statement(
            "resource_withdraw",
            resource_kind.as_pg(),
            &body.resource_id,
            body.reason.as_deref().unwrap_or_default(),
            withdraw_id,
            acked_at,
            effective_at,
            None,
        ),
        "signed_payload": body
            .unsigned_payload()
            .map_err(|error| anyhow::anyhow!("unsigned withdraw payload: {error}"))?,
        "governance_proof": serde_json::to_value(&body.governance_proof)
            .map_err(|error| anyhow::anyhow!("serialize governance proof: {error}"))?,
        "verification": {
            "status": "verified",
            "verified_by": config.service_id.as_str(),
            "verified_at": acked_at,
        },
    }))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn operator_takedown_proof(
    config: &AppConfig,
    body: &OperatorTakedownRequestBody,
    withdraw_id: &str,
    operator: &str,
    acked_at: DateTime<Utc>,
    effective_at: DateTime<Utc>,
    notification_status: &str,
) -> anyhow::Result<JsonValue> {
    let statement = withdrawal_statement(
        "operator_takedown",
        directory_resource_kind_token(body.resource_kind),
        &body.resource_id,
        &body.reason,
        withdraw_id,
        acked_at,
        effective_at,
        Some(json!({
            "takedown_id": withdraw_id,
            "operator": operator,
            "evidence": body.evidence.clone(),
            "notification_status": notification_status,
            "service_id": config.service_id.as_str(),
            "appeal_endpoint": takedown_appeal_endpoint(config),
        })),
    );
    let signing_key = config.receipt_signing_key.as_ref().ok_or_else(|| {
        anyhow::anyhow!("TEABAY_RECEIPT_SIGNING_KEY_B64 is required for operator takedown receipts")
    })?;
    let receipt_proof = sign_receipt_statement(signing_key, &statement)?;

    Ok(json!({
        "kind": "operator_takedown",
        "receipt_version": RECEIPT_VERSION,
        "statement": statement,
        "receipt_proof": receipt_proof,
    }))
}

/// Signed "appeal received" receipt returned synchronously from the submit
/// handler. The decision is `pending` until an operator adjudicates; the
/// resource holder gets a verifiable acknowledgement that the appeal entered
/// the queue (`discovery-directory.md §8.7`, `DirectoryTakedownAppealOutcome`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn takedown_appeal_received_receipt(
    config: &AppConfig,
    appeal_id: &str,
    takedown_id: &str,
    resource_kind: &str,
    resource_id: &str,
    appellant_actor_id: &str,
    requested_outcome: &str,
    argument_digest: &str,
    received_at: DateTime<Utc>,
) -> anyhow::Result<JsonValue> {
    let statement = json!({
        "receipt_version": RECEIPT_VERSION,
        "kind": "operator_takedown_appeal_received",
        "appeal_id": appeal_id,
        "takedown_id": takedown_id,
        "resource_kind": resource_kind,
        "resource_id": resource_id,
        "appellant_actor_id": appellant_actor_id,
        "requested_outcome": requested_outcome,
        "argument_digest": argument_digest,
        "decision": "pending",
        "received_at": received_at,
        "service_id": config.service_id.as_str(),
    });
    let signing_key = config.receipt_signing_key.as_ref().ok_or_else(|| {
        anyhow::anyhow!("TEABAY_RECEIPT_SIGNING_KEY_B64 is required for takedown appeal receipts")
    })?;
    let receipt_proof = sign_receipt_statement(signing_key, &statement)?;
    Ok(json!({
        "kind": "operator_takedown_appeal_received",
        "receipt_version": RECEIPT_VERSION,
        "statement": statement,
        "receipt_proof": receipt_proof,
    }))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn takedown_appeal_decision_receipt(
    config: &AppConfig,
    appeal_id: &str,
    takedown_id: &str,
    resource_kind: &str,
    resource_id: &str,
    appellant_actor_id: &str,
    requested_outcome: &str,
    argument_digest: &str,
    decision_evidence_digest: Option<&str>,
    decision: TakedownAppealDecision,
    decided_by: &str,
    reason: &str,
    decided_at: DateTime<Utc>,
) -> anyhow::Result<JsonValue> {
    let mut statement = json!({
        "receipt_version": RECEIPT_VERSION,
        "kind": "operator_takedown_appeal_decision",
        "appeal_id": appeal_id,
        "takedown_id": takedown_id,
        "resource_kind": resource_kind,
        "resource_id": resource_id,
        "appellant_actor_id": appellant_actor_id,
        "requested_outcome": requested_outcome,
        "argument_digest": argument_digest,
        "decision": decision.as_str(),
        "decided_by": decided_by,
        "reason": reason,
        "decided_at": decided_at,
        "service_id": config.service_id.as_str(),
    });
    if let Some(decision_evidence_digest) = decision_evidence_digest
        && let Some(object) = statement.as_object_mut()
    {
        object.insert(
            "decision_evidence_digest".to_owned(),
            JsonValue::String(decision_evidence_digest.to_owned()),
        );
    }
    let signing_key = config.receipt_signing_key.as_ref().ok_or_else(|| {
        anyhow::anyhow!("TEABAY_RECEIPT_SIGNING_KEY_B64 is required for takedown appeal decisions")
    })?;
    let receipt_proof = sign_receipt_statement(signing_key, &statement)?;
    Ok(json!({
        "kind": "operator_takedown_appeal_decision",
        "receipt_version": RECEIPT_VERSION,
        "statement": statement,
        "receipt_proof": receipt_proof,
    }))
}

pub(crate) fn takedown_appeal_endpoint(config: &AppConfig) -> String {
    format!(
        "{}/_arkret/find/directory/takedown/appeal",
        config.public_base_url.trim_end_matches('/')
    )
}

#[allow(clippy::too_many_arguments)]
fn withdrawal_statement(
    kind: &str,
    resource_kind: &str,
    resource_id: &str,
    reason: &str,
    withdraw_id: &str,
    acked_at: DateTime<Utc>,
    effective_at: DateTime<Utc>,
    extra: Option<JsonValue>,
) -> JsonValue {
    let mut statement = json!({
        "receipt_version": RECEIPT_VERSION,
        "withdraw_id": withdraw_id,
        "kind": kind,
        "resource_kind": resource_kind,
        "resource_id": resource_id,
        "reason": reason,
        "effective_at": effective_at,
        "acked_at": acked_at,
    });
    if let Some(extra) = extra
        && let Some(obj) = statement.as_object_mut()
    {
        obj.insert("extra".to_owned(), extra);
    }
    statement
}

fn sign_receipt_statement(
    signing_key: &ReceiptSigningKey,
    statement: &JsonValue,
) -> anyhow::Result<JsonValue> {
    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
        "alg": "Ed25519",
        "kid": signing_key.key_id(),
        "typ": RECEIPT_VERSION,
    }))?);
    let canonical = canonical_json_bytes(statement)?;
    let signing_input = format!("{protected}.{}", URL_SAFE_NO_PAD.encode(canonical));
    let signature = signing_key
        .signing_key()
        .sign(signing_input.as_bytes())
        .to_bytes();
    Ok(json!({
        "kind": "detached_jws",
        "alg": "Ed25519",
        "verification_method": signing_key.key_id(),
        "public_key_base64url": signing_key.public_key_base64url(),
        "jws": format!("{protected}..{}", URL_SAFE_NO_PAD.encode(signature)),
    }))
}

/// Arkret canonical JSON bytes via the SDK's `arkret_sdk::canonical`
/// implementation (UTF-16 key ordering, integer-only number profile).
///
/// Replaces a hand-written serializer that sorted object keys by byte
/// order — divergent from the SDK and every other Arkret service. The
/// receipt JWS signing input therefore now hashes byte-identical canonical
/// bytes to the rest of the federation.
fn canonical_json_bytes(value: &JsonValue) -> anyhow::Result<Vec<u8>> {
    Ok(canonical::canonical_json_bytes(value)?)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    use super::*;

    #[test]
    fn signed_operator_receipt_is_locally_verifiable() {
        let signing_key =
            ReceiptSigningKey::from_raw("did:web:directory.test#receipt-1".to_owned(), [13; 32]);
        let statement = json!({
            "receipt_version": RECEIPT_VERSION,
            "withdraw_id": "teabay:withdraw:test",
            "kind": "operator_takedown",
        });

        let proof = sign_receipt_statement(&signing_key, &statement).expect("receipt signs");

        let jws = proof["jws"].as_str().expect("jws");
        let (protected, signature) = jws
            .split_once("..")
            .expect("detached JWS compact serialization");
        let canonical = canonical_json_bytes(&statement).expect("canonical statement");
        let signing_input = format!("{protected}.{}", URL_SAFE_NO_PAD.encode(canonical));
        let signing_input_bytes = signing_input.into_bytes();
        let signature_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(signature)
            .expect("signature base64")
            .try_into()
            .expect("signature length");
        let public_key_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(proof["public_key_base64url"].as_str().expect("public key"))
            .expect("public key base64")
            .try_into()
            .expect("public key length");
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).expect("verifying key");
        verifying_key
            .verify(
                &signing_input_bytes,
                &Signature::from_bytes(&signature_bytes),
            )
            .expect("receipt signature verifies");
    }
}
