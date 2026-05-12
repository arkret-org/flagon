//! `cx.directory.subscribe` webhook registration and fanout.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use hmac::{Hmac, Mac};
use reqwest::Client;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::error::ErrorCode;
use crate::ids::{IdClass, new_id};
use crate::ingest::rate_limit::enforce_ingest_rate_limit;
use crate::ingest::{IngestModeWire, ResourceKindWire};
use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Deserialize)]
pub struct SubscribeRequest {
    pub subscriber_did: String,
    #[serde(default)]
    pub resource_filter: JsonValue,
    pub webhook_endpoint: String,
    #[serde(default)]
    pub webhook_secret: Option<String>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct SubscribeResponse {
    pub subscription_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub webhook_secret: String,
}

#[derive(Debug, Clone)]
pub struct AcceptedIngestEvent {
    pub announce_id: String,
    pub ingest_mode: IngestModeWire,
    pub resource_kind: ResourceKindWire,
    pub resource_id: String,
    pub principal_server_did: String,
    pub indexed_at: DateTime<Utc>,
    pub as_of: DateTime<Utc>,
    pub source_refs: Vec<String>,
    pub policy_revision: Option<String>,
    pub public_projection: JsonValue,
}

#[handler]
pub async fn subscribe(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };

    let body: SubscribeRequest = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ErrorCode::BadJson.render(res, format!("malformed subscribe body: {error}"));
            return;
        }
    };

    if !enforce_ingest_rate_limit(req, res, &state, &body.subscriber_did) {
        return;
    }
    if body.subscriber_did.trim().is_empty() {
        ErrorCode::MissingParam.render(res, "subscriber_did is required");
        return;
    }
    if body.resource_filter.is_null() {
        ErrorCode::SchemaViolation.render(res, "resource_filter must be an object");
        return;
    }
    if !body.resource_filter.is_object() {
        ErrorCode::SchemaViolation.render(res, "resource_filter must be an object");
        return;
    }
    if let Err(message) = validate_endpoint(&body.webhook_endpoint, state.config().development_mode)
    {
        ErrorCode::InvalidParam.render(res, message);
        return;
    }

    let subscription_id = new_id(IdClass::Subscription);
    let created_at = Utc::now();
    let secret = match body.webhook_secret.as_deref().map(secret_from_wire) {
        Some(Ok(secret)) => secret,
        Some(Err(error)) => {
            tracing::warn!(%error, "invalid supplied webhook_secret; generated a replacement");
            generate_secret(
                &subscription_id,
                &body.subscriber_did,
                &body.webhook_endpoint,
            )
        }
        None => generate_secret(
            &subscription_id,
            &body.subscriber_did,
            &body.webhook_endpoint,
        ),
    };
    let response_secret = URL_SAFE_NO_PAD.encode(&secret);

    if let Err(error) = persist_subscription(&state, &body, &subscription_id, &secret, created_at) {
        ErrorCode::InternalError.render(res, format!("persist subscription: {error}"));
        return;
    }

    res.render(Json(SubscribeResponse {
        subscription_id,
        created_at,
        expires_at: body.expires_at,
        webhook_secret: response_secret,
    }));
}

pub async fn fanout_accepted_ingest(state: AppState, event: AcceptedIngestEvent) {
    let subscriptions = match matching_subscriptions(&state, &event) {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "webhook fanout subscription load failed");
            return;
        }
    };
    if subscriptions.is_empty() {
        return;
    }

    let http = Client::new();
    for subscription in subscriptions {
        let event = event.clone();
        let http = http.clone();
        tokio::spawn(async move {
            if let Err(error) = deliver_webhook(http, subscription, event).await {
                tracing::warn!(%error, "webhook delivery failed");
            }
        });
    }
}

fn validate_endpoint(endpoint: &str, development_mode: bool) -> Result<(), String> {
    let url = Url::parse(endpoint).map_err(|error| format!("webhook_endpoint URL: {error}"))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" if development_mode => Ok(()),
        other => Err(format!("webhook_endpoint scheme `{other}` is not allowed")),
    }
}

fn secret_from_wire(raw: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(raw)
        .or_else(|_| Ok(raw.as_bytes().to_vec()))
        .and_then(|bytes| {
            if bytes.len() < 16 {
                Err("webhook_secret must be at least 16 bytes".to_owned())
            } else {
                Ok(bytes)
            }
        })
}

fn generate_secret(subscription_id: &str, subscriber_did: &str, endpoint: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(subscription_id.as_bytes());
    h.update(subscriber_did.as_bytes());
    h.update(endpoint.as_bytes());
    h.update(
        Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_default()
            .to_be_bytes(),
    );
    h.finalize().to_vec()
}

fn persist_subscription(
    state: &AppState,
    body: &SubscribeRequest,
    subscription_id: &str,
    secret: &[u8],
    created_at: DateTime<Utc>,
) -> anyhow::Result<()> {
    use crate::schema::webhook_subscriptions::dsl as s;
    let mut conn = state.db().get()?;
    diesel::insert_into(s::webhook_subscriptions)
        .values((
            s::subscription_id.eq(subscription_id),
            s::subscriber_did.eq(&body.subscriber_did),
            s::resource_filter.eq(&body.resource_filter),
            s::webhook_endpoint.eq(&body.webhook_endpoint),
            s::secret.eq(Some(secret)),
            s::expires_at.eq(body.expires_at),
            s::created_at.eq(created_at),
        ))
        .execute(&mut conn)?;
    Ok(())
}

#[derive(Debug, Queryable)]
struct WebhookSubscriptionRow {
    subscription_id: String,
    resource_filter: JsonValue,
    webhook_endpoint: String,
    secret: Option<Vec<u8>>,
}

fn matching_subscriptions(
    state: &AppState,
    event: &AcceptedIngestEvent,
) -> anyhow::Result<Vec<WebhookSubscriptionRow>> {
    use crate::schema::webhook_subscriptions::dsl as s;
    let mut conn = state.db().get()?;
    let rows: Vec<WebhookSubscriptionRow> = s::webhook_subscriptions
        .filter(s::expires_at.is_null().or(s::expires_at.gt(Utc::now())))
        .select((
            s::subscription_id,
            s::resource_filter,
            s::webhook_endpoint,
            s::secret,
        ))
        .load(&mut conn)?;
    Ok(rows
        .into_iter()
        .filter(|row| filter_matches(&row.resource_filter, event))
        .collect())
}

fn filter_matches(filter: &JsonValue, event: &AcceptedIngestEvent) -> bool {
    let Some(obj) = filter.as_object() else {
        return false;
    };
    field_matches(obj, "resource_kind", event.resource_kind.as_pg())
        && field_matches(obj, "resource_id", &event.resource_id)
        && field_matches(obj, "principal_server_did", &event.principal_server_did)
}

fn field_matches(obj: &serde_json::Map<String, JsonValue>, key: &str, actual: &str) -> bool {
    obj.get(key)
        .and_then(JsonValue::as_str)
        .map(|expected| expected == actual)
        .unwrap_or(true)
}

async fn deliver_webhook(
    http: Client,
    subscription: WebhookSubscriptionRow,
    event: AcceptedIngestEvent,
) -> anyhow::Result<()> {
    let body = json!({
        "subscription_id": subscription.subscription_id,
        "indexed_at": event.indexed_at,
        "announce_id": event.announce_id,
        "ingest_mode": event.ingest_mode,
        "resource_kind": event.resource_kind,
        "resource_id": event.resource_id,
        "principal_server_did": event.principal_server_did,
        "as_of": event.as_of,
        "source_refs": event.source_refs,
        "policy_revision": event.policy_revision,
        "public_projection": event.public_projection,
    });
    let bytes = serde_json::to_vec(&body)?;
    let secret = subscription
        .secret
        .filter(|secret| !secret.is_empty())
        .unwrap_or_else(|| generate_secret(&subscription.subscription_id, "", ""));
    let signature = sign_body(&secret, &bytes)?;
    let response = http
        .post(&subscription.webhook_endpoint)
        .header("content-type", "application/json")
        .header("x-contrix-webhook-id", &subscription.subscription_id)
        .header("x-contrix-webhook-signature", signature)
        .body(bytes)
        .send()
        .await?;
    if !response.status().is_success() {
        anyhow::bail!("webhook returned {}", response.status());
    }
    Ok(())
}

fn sign_body(secret: &[u8], body: &[u8]) -> anyhow::Result<String> {
    let mut mac = HmacSha256::new_from_slice(secret)?;
    mac.update(body);
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}
