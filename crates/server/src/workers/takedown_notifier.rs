//! P5 HIGH — pending-takedown HMAC-signed webhook fanout.
//!
//! Scans `pending_takedowns` rows whose `notification_status` indicates
//! they still need fanout (`NULL`, `"pending"`, or `"retry"`) and dispatches
//! a signed POST to every endpoint registered in
//! `pending_takedown_webhooks`. Each attempt is HMAC-signed with the
//! webhook's per-row secret (HMAC-SHA256 of the JSON body) — subscribers
//! verify against the same secret to avoid spoofed takedown notices.
//!
//! Retry: minimum 3 attempts with exponential backoff (1 / 5 / 15 min).
//! After 3 consecutive permanent failures we mark
//! `notification_status = "dlq"` and emit
//! `teabay_takedown_notification_failures_total{stage="dlq"}` so
//! dashboards can alert. The DLQ row is preserved for operator review;
//! recovery is by manual `UPDATE` back to `"retry"`.
//!
//! TODO(P5-impl): treat 4xx and 5xx differently — 4xx terminal, 5xx
//! retryable. The current pass treats every non-2xx as retryable until
//! the attempt budget is exhausted, then DLQ.

use std::time::Duration;

use chrono::Utc;
use diesel::sql_types::{Int4, Nullable, Text, Timestamptz};
use diesel_async::RunQueryDsl;
use hmac::{Hmac, Mac};
use reqwest::Client;
use reqwest::redirect::Policy;
use serde_json::json;
use sha2::Sha256;
use tokio::time::interval;
use tracing::{info, warn};

use crate::observability::{
    TAKEDOWN_NOTIFICATION_STAGE_ATTEMPT_FAILED, TAKEDOWN_NOTIFICATION_STAGE_DLQ,
};
use crate::state::AppState;

type HmacSha256 = Hmac<Sha256>;

/// Default tick interval if `TEABAY_TAKEDOWN_NOTIFIER_INTERVAL_SECONDS`
/// is unset. 60s keeps notification latency low without hammering the
/// DB when there are no pending rows.
pub const DEFAULT_TAKEDOWN_NOTIFIER_TICK: Duration = Duration::from_secs(60);

/// Minimum number of attempts before a row is DLQed. Matches the
/// 1m / 5m / 15m backoff schedule.
pub const TAKEDOWN_MIN_ATTEMPTS: i32 = 3;

const BACKOFF_SCHEDULE_SECS: &[i64] = &[60, 300, 900];

#[derive(Debug, Clone, diesel::QueryableByName)]
struct PendingRow {
    #[diesel(sql_type = Text)]
    pending_id: String,
    #[diesel(sql_type = Text)]
    resource_kind: String,
    #[diesel(sql_type = Text)]
    resource_id: String,
    #[diesel(sql_type = Text)]
    reason: String,
    #[diesel(sql_type = Text)]
    proposed_by: String,
    #[diesel(sql_type = Timestamptz)]
    proposed_at: chrono::DateTime<chrono::Utc>,
    #[diesel(sql_type = Nullable<Int4>)]
    attempts: Option<i32>,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct WebhookRow {
    #[diesel(sql_type = Text)]
    webhook_id: String,
    #[diesel(sql_type = Text)]
    endpoint: String,
    #[diesel(sql_type = Nullable<diesel::sql_types::Bytea>)]
    secret: Option<Vec<u8>>,
}

pub struct TakedownNotifier {
    state: AppState,
    period: Duration,
}

impl TakedownNotifier {
    pub fn new(state: AppState, period: Duration) -> anyhow::Result<Self> {
        Ok(Self { state, period })
    }

    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!(
                period_seconds = self.period.as_secs(),
                "teabay takedown notifier started"
            );
            let mut tick = interval(self.period);
            loop {
                tick.tick().await;
                if let Err(e) = self.run_once().await {
                    warn!(%e, "takedown notifier pass failed");
                }
            }
        })
    }

    /// Single sweep. Returns the number of rows that received a
    /// dispatch attempt this pass. Public so tests can drive it without
    /// a scheduler.
    pub async fn run_once(&self) -> anyhow::Result<usize> {
        let pending = self.fetch_pending(50).await?;
        if pending.is_empty() {
            return Ok(0);
        }
        let webhooks = self.fetch_webhooks().await?;
        if webhooks.is_empty() {
            // Nothing to send to — mark the rows complete so we don't
            // loop forever.
            for row in &pending {
                self.mark_status(&row.pending_id, "no_subscribers", row.attempts.unwrap_or(0))
                    .await?;
            }
            return Ok(pending.len());
        }

        let mut dispatched = 0usize;
        for row in pending {
            let attempts = row.attempts.unwrap_or(0);
            let mut all_ok = true;
            for webhook in &webhooks {
                if let Err(e) = self.dispatch(&row, webhook).await {
                    warn!(
                        pending_id = %row.pending_id,
                        webhook_id = %webhook.webhook_id,
                        %e,
                        "takedown notification dispatch failed"
                    );
                    all_ok = false;
                    self.state.metrics().record_takedown_notification_failure(
                        TAKEDOWN_NOTIFICATION_STAGE_ATTEMPT_FAILED,
                    );
                }
            }
            let next_attempts = attempts.saturating_add(1);
            if all_ok {
                self.mark_status(&row.pending_id, "delivered", next_attempts)
                    .await?;
            } else if next_attempts >= TAKEDOWN_MIN_ATTEMPTS {
                self.mark_status(&row.pending_id, "dlq", next_attempts)
                    .await?;
                self.state
                    .metrics()
                    .record_takedown_notification_failure(TAKEDOWN_NOTIFICATION_STAGE_DLQ);
                warn!(
                    pending_id = %row.pending_id,
                    attempts = next_attempts,
                    "takedown notification moved to DLQ"
                );
            } else {
                let backoff = BACKOFF_SCHEDULE_SECS
                    .get(next_attempts.saturating_sub(1) as usize)
                    .copied()
                    .unwrap_or(900);
                self.schedule_retry(&row.pending_id, next_attempts, backoff)
                    .await?;
            }
            dispatched += 1;
        }
        Ok(dispatched)
    }

    async fn fetch_pending(&self, limit: i64) -> anyhow::Result<Vec<PendingRow>> {
        let mut conn = self.state.db().get().await?;
        let rows = diesel::sql_query(
            "SELECT pending_id, resource_kind::TEXT AS resource_kind, resource_id, reason, \
                    proposed_by, proposed_at, \
                    (regexp_match(coalesce(notification_status, ''), '^attempt:(\\d+)'))[1]::INT AS attempts \
             FROM pending_takedowns \
             WHERE notification_status IS NULL \
                OR notification_status = 'pending' \
                OR notification_status LIKE 'retry:%' \
             ORDER BY proposed_at ASC \
             LIMIT $1",
        )
        .bind::<diesel::sql_types::BigInt, _>(limit)
        .load::<PendingRow>(&mut *conn)
        .await?;
        Ok(rows)
    }

    async fn fetch_webhooks(&self) -> anyhow::Result<Vec<WebhookRow>> {
        let mut conn = self.state.db().get().await?;
        let now = Utc::now();
        let rows = diesel::sql_query(
            "SELECT webhook_id, endpoint, secret \
             FROM pending_takedown_webhooks \
             WHERE expires_at IS NULL OR expires_at > $1",
        )
        .bind::<diesel::sql_types::Timestamptz, _>(now)
        .load::<WebhookRow>(&mut *conn)
        .await?;
        Ok(rows)
    }

    async fn dispatch(&self, row: &PendingRow, webhook: &WebhookRow) -> anyhow::Result<()> {
        let target = crate::egress::resolve_http_url_for_egress(
            &webhook.endpoint,
            "takedown webhook",
            self.state.config().development_mode,
        )
        .map_err(|error| anyhow::anyhow!(error))?;
        let body = json!({
            "pending_id": row.pending_id,
            "resource_kind": row.resource_kind,
            "resource_id": row.resource_id,
            "reason": row.reason,
            "proposed_by": row.proposed_by,
            "proposed_at": row.proposed_at,
        });
        let body_bytes = serde_json::to_vec(&body)?;
        let signature = if let Some(secret) = webhook.secret.as_deref() {
            let mut mac = HmacSha256::new_from_slice(secret)
                .map_err(|e| anyhow::anyhow!("invalid HMAC secret: {e}"))?;
            mac.update(&body_bytes);
            let tag = mac.finalize().into_bytes();
            Some(hex_encode(&tag))
        } else {
            None
        };

        let http = target
            .apply_to_client_builder(
                Client::builder()
                    .timeout(Duration::from_secs(10))
                    .redirect(Policy::none()),
            )
            .build()
            .map_err(|error| anyhow::anyhow!("build locked takedown webhook client: {error}"))?;
        let mut req = http
            .post(target.url().clone())
            .header("content-type", "application/json")
            .header("x-teabay-event", "pending-takedown")
            .header("x-teabay-webhook-id", &webhook.webhook_id)
            .body(body_bytes);
        if let Some(sig) = signature {
            req = req.header("x-teabay-signature", format!("sha256={sig}"));
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("non-2xx status from webhook endpoint: {status}");
        }
        Ok(())
    }

    async fn mark_status(
        &self,
        pending_id: &str,
        status: &str,
        attempts: i32,
    ) -> anyhow::Result<()> {
        let mut conn = self.state.db().get().await?;
        let label = format!("{status}:attempt:{attempts}");
        diesel::sql_query(
            "UPDATE pending_takedowns \
             SET notification_status = $1 \
             WHERE pending_id = $2",
        )
        .bind::<Text, _>(label)
        .bind::<Text, _>(pending_id)
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    async fn schedule_retry(
        &self,
        pending_id: &str,
        attempts: i32,
        backoff_secs: i64,
    ) -> anyhow::Result<()> {
        let mut conn = self.state.db().get().await?;
        let label = format!("retry:attempt:{attempts}:after:{backoff_secs}s");
        diesel::sql_query(
            "UPDATE pending_takedowns \
             SET notification_status = $1 \
             WHERE pending_id = $2",
        )
        .bind::<Text, _>(label)
        .bind::<Text, _>(pending_id)
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
