//! `ak.find.directory.push.command.register` webhook registration and fanout.

use std::sync::Arc;
use std::time::Duration;

use arkret_sdk::{DirectoryPushRegisterOutcome, DirectoryPushRegisterRequestBody};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use hmac::{Hmac, KeyInit, Mac};
use reqwest::Client;
use salvo::prelude::*;
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use teabay_contracts::DirectoryPublicProjection;
use tokio::sync::Semaphore;
use url::Url;

use crate::error::ApiErrorCode;
use crate::filter::circle_isolation;
use crate::ids::{IdClass, new_id};
use crate::ingest::rate_limit::enforce_ingest_rate_limit;
use crate::ingest::{DirectoryResourceKindDb, DiscoverabilityDb, IngestModeWire};
use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;
const WEBHOOK_DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);
const WEBHOOK_FANOUT_CONCURRENCY: usize = 32;

#[derive(Debug, Clone)]
pub struct AcceptedIngestEvent {
    pub announce_id: String,
    pub ingest_mode: IngestModeWire,
    pub resource_kind: DirectoryResourceKindDb,
    pub resource_id: String,
    pub principal_server_service_id: String,
    pub indexed_at: DateTime<Utc>,
    pub as_of: DateTime<Utc>,
    pub source_refs: Vec<String>,
    pub policy_revision: Option<String>,
    pub discoverability: DiscoverabilityDb,
    pub public_projection: DirectoryPublicProjection,
}

#[derive(Debug, Clone)]
pub struct ReachabilityTombstone {
    pub kind: TombstoneKind,
    pub resource_kind: DirectoryResourceKindDb,
    pub resource_id: String,
    pub principal_server_service_id: String,
    pub reason: String,
    pub revoked_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TombstoneKind {
    RealmDestroyed,
    ReachabilityRevoked,
}

impl TombstoneKind {
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::RealmDestroyed => "realm_destroyed",
            Self::ReachabilityRevoked => "reachability_revoked",
        }
    }
}

#[handler]
pub async fn subscribe(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            ApiErrorCode::InternalError.render(res, "AppState not injected");
            return;
        }
    };
    let mut ingest_metric = state.metrics().ingest_guard("subscribe");

    let body: DirectoryPushRegisterRequestBody = match req.parse_json().await {
        Ok(body) => body,
        Err(error) => {
            ingest_metric.set_outcome("json_invalid");
            ApiErrorCode::JsonInvalid.render(res, format!("malformed subscribe body: {error}"));
            return;
        }
    };

    let subscriber_principal_id = body.subscriber_principal_id.as_str();
    if !enforce_ingest_rate_limit(req, res, &state, subscriber_principal_id, None) {
        ingest_metric.set_outcome("rate_limited");
        return;
    }
    let resource_filter = match serde_json::to_value(&body.resource_filter) {
        Ok(value) => value,
        Err(error) => {
            ingest_metric.set_outcome("schema_rejected");
            ApiErrorCode::SchemaViolation.render(
                res,
                format!("resource_filter serialization failed: {error}"),
            );
            return;
        }
    };
    if resource_filter.is_null() {
        ingest_metric.set_outcome("schema_rejected");
        ApiErrorCode::SchemaViolation.render(res, "resource_filter must be an object");
        return;
    }
    if !resource_filter.is_object() {
        ingest_metric.set_outcome("schema_rejected");
        ApiErrorCode::SchemaViolation.render(res, "resource_filter must be an object");
        return;
    }
    // AKP-0007 / P2E.2 — a subscribe filter carrying an explicit Circle
    // typed id is rejected before persist. The audit row captures the
    // JSON pointer for operator review; the wire response is the standard
    // low-information `schema_violation`.
    if let Err(rejection) = circle_isolation::reject_circle_payload(&resource_filter) {
        ingest_metric.set_outcome("circle_isolation_violation");
        let _ = crate::audit::record(
            state.db(),
            crate::audit::AuditEventKind::IngestRejected,
            None,
            None,
            Some(subscriber_principal_id),
            json!({
                "code": ApiErrorCode::SchemaViolation.wire_code(),
                "reason": "circle_isolation_violation",
                "violation": rejection.audit_label(),
                "endpoint": "directory.subscribe",
            }),
        )
        .await;
        ApiErrorCode::SchemaViolation.render(res, rejection.safe_message());
        return;
    }
    if let Err(message) = validate_endpoint(&body.webhook_endpoint, state.config().development_mode)
    {
        ingest_metric.set_outcome("invalid_endpoint");
        ApiErrorCode::ParamInvalid.render(res, message);
        return;
    }

    let subscription_id = arkret_sdk::SubscriptionId::new(new_id(IdClass::Subscription))
        .expect("generated subscription id must be valid");
    let created_at = Utc::now();
    let secret = match body.secret.as_deref().map(secret_from_wire) {
        Some(Ok(secret)) => secret,
        Some(Err(error)) => {
            tracing::warn!(%error, "invalid supplied webhook secret; generated a replacement");
            generate_secret(
                subscription_id.as_str(),
                subscriber_principal_id,
                &body.webhook_endpoint,
            )
        }
        None => generate_secret(
            subscription_id.as_str(),
            subscriber_principal_id,
            &body.webhook_endpoint,
        ),
    };

    if let Err(error) = persist_subscription(
        &state,
        &body,
        &resource_filter,
        subscription_id.as_str(),
        &secret,
        created_at,
    )
    .await
    {
        ingest_metric.set_outcome("persist_error");
        ApiErrorCode::InternalError.render(res, format!("persist subscription: {error}"));
        return;
    }

    ingest_metric.set_outcome("verify_ok");
    res.render(Json(DirectoryPushRegisterOutcome {
        subscription_id,
        effective_at: created_at,
    }));
}

/// Best-effort tombstone fanout. Sent when a
/// directory row is invalidated (either by `ak.realm.destroy` arriving
/// on the ingest face or by a `consent_revoke{scope=any}` admin
/// broadcast) so in-flight subscribers receive a canonical "this row is
/// no longer authoritative" notification on the same webhook channel
/// that delivers accepted ingest updates. Returns the count of webhook
/// subscriptions matched (delivery itself runs in the background).
pub async fn fanout_reachability_tombstone(
    state: AppState,
    tombstones: &[ReachabilityTombstone],
) -> usize {
    let mut delivered = 0usize;
    let now = Utc::now();
    let development_mode = state.config().development_mode;
    for tombstone in tombstones {
        let subscriptions = match matching_subscriptions(
            &state,
            &AcceptedIngestEvent {
                announce_id: String::new(),
                ingest_mode: IngestModeWire::Push,
                resource_kind: tombstone.resource_kind,
                resource_id: tombstone.resource_id.clone(),
                principal_server_service_id: tombstone.principal_server_service_id.clone(),
                indexed_at: now,
                as_of: now,
                source_refs: Vec::new(),
                policy_revision: None,
                discoverability: DiscoverabilityDb::Public,
                public_projection: DirectoryPublicProjection::from_json(JsonValue::Null),
            },
        )
        .await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(%error, "tombstone fanout subscription load failed");
                continue;
            }
        };
        delivered += subscriptions.len();
        let semaphore = Arc::new(Semaphore::new(WEBHOOK_FANOUT_CONCURRENCY));
        let tombstone = tombstone.clone();
        tokio::spawn(async move {
            for subscription in subscriptions {
                let Ok(permit) = semaphore.clone().acquire_owned().await else {
                    break;
                };
                let tombstone = tombstone.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) =
                        deliver_tombstone(subscription, tombstone, development_mode).await
                    {
                        tracing::warn!(%error, "tombstone webhook delivery failed");
                    }
                });
            }
        });
    }
    delivered
}

async fn deliver_tombstone(
    subscription: WebhookSubscriptionRow,
    tombstone: ReachabilityTombstone,
    development_mode: bool,
) -> anyhow::Result<()> {
    let body = json!({
        "subscription_id": subscription.subscription_id,
        "tombstone": {
            "kind": tombstone.kind.as_wire(),
            "reason": tombstone.reason,
            "revoked_at": tombstone.revoked_at,
        },
        "resource_kind": tombstone.resource_kind,
        "resource_id": tombstone.resource_id,
        "principal_server_service_id": tombstone.principal_server_service_id,
    });
    let bytes = serde_json::to_vec(&body)?;
    let secret = subscription
        .secret
        .filter(|secret| !secret.is_empty())
        .unwrap_or_else(|| generate_secret(&subscription.subscription_id, "", ""));
    let signature = sign_body(&secret, &bytes)?;
    let target = crate::egress::resolve_http_url_for_egress(
        &subscription.webhook_endpoint,
        "reachability tombstone webhook",
        development_mode,
    )
    .map_err(|error| anyhow::anyhow!(error))?;
    let http = locked_webhook_http_client(&target)?;
    let response = http
        .post(target.url().clone())
        .header("content-type", "application/json")
        .header("x-arkret-webhook-id", &subscription.subscription_id)
        .header("x-arkret-webhook-signature", signature)
        .header("x-arkret-webhook-event", "reachability_tombstone")
        .body(bytes)
        .send()
        .await?;
    if !response.status().is_success() {
        anyhow::bail!("tombstone webhook returned {}", response.status());
    }
    Ok(())
}

pub async fn fanout_accepted_ingest(state: AppState, event: AcceptedIngestEvent) {
    if !matches!(
        event.discoverability,
        DiscoverabilityDb::Public | DiscoverabilityDb::Listed
    ) {
        return;
    }
    let subscriptions = match matching_subscriptions(&state, &event).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "webhook fanout subscription load failed");
            return;
        }
    };
    if subscriptions.is_empty() {
        return;
    }

    let development_mode = state.config().development_mode;
    let semaphore = Arc::new(Semaphore::new(WEBHOOK_FANOUT_CONCURRENCY));
    tokio::spawn(async move {
        for subscription in subscriptions {
            let Ok(permit) = semaphore.clone().acquire_owned().await else {
                return;
            };
            let event = event.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(error) = deliver_webhook(subscription, event, development_mode).await {
                    tracing::warn!(%error, "webhook delivery failed");
                }
            });
        }
    });
}

fn locked_webhook_http_client(target: &crate::egress::LockedEgressUrl) -> anyhow::Result<Client> {
    target
        .apply_to_client_builder(
            Client::builder()
                .timeout(WEBHOOK_DELIVERY_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none()),
        )
        .build()
        .map_err(|error| anyhow::anyhow!("build webhook HTTP client: {error}"))
}

fn validate_endpoint(endpoint: &str, development_mode: bool) -> Result<(), String> {
    let url = Url::parse(endpoint).map_err(|error| format!("webhook_endpoint URL: {error}"))?;
    match url.scheme() {
        "https" => {}
        "http" if development_mode => {}
        other => return Err(format!("webhook_endpoint scheme `{other}` is not allowed")),
    };
    crate::egress::validate_url_for_egress(
        &url,
        "webhook_endpoint",
        crate::egress::local_development_enabled(development_mode),
    )
}

fn secret_from_wire(raw: &str) -> Result<Vec<u8>, String> {
    // The secret MUST be base64url (no padding). A decode failure is a
    // hard error rather than a silent "treat the literal string as key" fallback
    // — that fallback masked client misconfiguration and made the same string
    // produce different HMAC keys depending on whether it happened to be valid
    // base64url.
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| "secret must be base64url (unpadded) encoded".to_owned())?;
    if bytes.len() < 16 {
        return Err("secret must decode to at least 16 bytes".to_owned());
    }
    Ok(bytes)
}

fn generate_secret(
    subscription_id: &str,
    subscriber_principal_id: &str,
    endpoint: &str,
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(subscription_id.as_bytes());
    h.update(subscriber_principal_id.as_bytes());
    h.update(endpoint.as_bytes());
    h.update(
        Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_default()
            .to_be_bytes(),
    );
    h.finalize().to_vec()
}

async fn persist_subscription(
    state: &AppState,
    body: &DirectoryPushRegisterRequestBody,
    resource_filter: &JsonValue,
    subscription_id: &str,
    secret: &[u8],
    created_at: DateTime<Utc>,
) -> anyhow::Result<()> {
    use crate::schema::webhook_subscriptions::dsl as s;
    let mut conn = state.db().get().await?;
    diesel::insert_into(s::webhook_subscriptions)
        .values((
            s::subscription_id.eq(subscription_id),
            s::subscriber_principal_id.eq(body.subscriber_principal_id.as_str()),
            s::resource_filter.eq(resource_filter),
            s::webhook_endpoint.eq(&body.webhook_endpoint),
            s::secret.eq(Some(secret)),
            s::expires_at.eq(body.expires_at),
            s::created_at.eq(created_at),
        ))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

#[derive(Debug, Queryable)]
struct WebhookSubscriptionRow {
    subscription_id: String,
    resource_filter: JsonValue,
    webhook_endpoint: String,
    secret: Option<Vec<u8>>,
}

async fn matching_subscriptions(
    state: &AppState,
    event: &AcceptedIngestEvent,
) -> anyhow::Result<Vec<WebhookSubscriptionRow>> {
    use crate::schema::webhook_subscriptions::dsl as s;
    let mut conn = state.db().get().await?;
    let rows: Vec<WebhookSubscriptionRow> = s::webhook_subscriptions
        .filter(s::expires_at.is_null().or(s::expires_at.gt(Utc::now())))
        .select((
            s::subscription_id,
            s::resource_filter,
            s::webhook_endpoint,
            s::secret,
        ))
        .load(&mut *conn)
        .await?;
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
        && field_matches(
            obj,
            "principal_server_service_id",
            &event.principal_server_service_id,
        )
}

fn field_matches(obj: &serde_json::Map<String, JsonValue>, key: &str, actual: &str) -> bool {
    obj.get(key)
        .and_then(JsonValue::as_str)
        .map(|expected| expected == actual)
        .unwrap_or(true)
}

async fn deliver_webhook(
    subscription: WebhookSubscriptionRow,
    event: AcceptedIngestEvent,
    development_mode: bool,
) -> anyhow::Result<()> {
    let body = json!({
        "subscription_id": subscription.subscription_id,
        "indexed_at": event.indexed_at,
        "announce_id": event.announce_id,
        "ingest_mode": event.ingest_mode,
        "resource_kind": event.resource_kind,
        "resource_id": event.resource_id,
        "principal_server_service_id": event.principal_server_service_id,
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
    let target = crate::egress::resolve_http_url_for_egress(
        &subscription.webhook_endpoint,
        "accepted ingest webhook",
        development_mode,
    )
    .map_err(|error| anyhow::anyhow!(error))?;
    let http = locked_webhook_http_client(&target)?;
    let response = http
        .post(target.url().clone())
        .header("content-type", "application/json")
        .header("x-arkret-webhook-id", &subscription.subscription_id)
        .header("x-arkret-webhook-signature", signature)
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
