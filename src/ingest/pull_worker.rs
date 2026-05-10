//! Pull-mode revalidation worker — spec §8.4 + §8.6.
//!
//! Wakes every `CHADEX_PULL_INTERVAL_SECONDS`, scans for entries whose
//! `next_revalidation_after` has passed, and re-pulls their signed
//! `cx.{kind}.discovery` state from the resource Principal Server using
//! the standard `cx.events.query` shape:
//!
//! ```text
//! GET /api/v1/events
//!   ?subject={resource_id}
//!   &kind=cx.{...}.discovery
//!   &state_only=true
//!   &after_revision={last_known_revision}
//! ```
//!
//! On success: rerun the verify chain (§8.5) and update the row exactly as
//! a fresh announce would. On failure: increment `consecutive_failures`,
//! and once TTL+grace expires mark the entry `stale=true`. After another
//! 24h of staleness without a successful pull, delete the entry.
//!
//! This is a skeleton: the actual HTTP fetch + JWS verify is deferred to
//! _todos.md M2-T5; today the worker simply logs eligible work.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use diesel::prelude::*;
use tokio::time::interval;
use tracing::{info, warn};

use crate::state::AppState;

pub struct PullWorker {
    state: AppState,
    period: Duration,
}

impl PullWorker {
    pub fn new(state: AppState, period: Duration) -> Self {
        Self { state, period }
    }

    /// Spawn the worker on the current Tokio runtime. Returns a handle —
    /// drop to detach (the task itself exits when the runtime is dropped).
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!(
                period_seconds = self.period.as_secs(),
                "chadex pull worker started"
            );
            let mut tick = interval(self.period);
            loop {
                tick.tick().await;
                if let Err(e) = self.run_once().await {
                    warn!(%e, "pull worker pass failed");
                }
            }
        })
    }

    async fn run_once(&self) -> anyhow::Result<()> {
        let due = self.fetch_due_entries(50)?;
        if due.is_empty() {
            return Ok(());
        }
        info!(count = due.len(), "pull worker: revalidation candidates");

        for (kind, id, principal_server_did) in due {
            // TODO M2-T5 — actually fetch + verify + upsert here.
            tracing::debug!(%kind, %id, %principal_server_did, "would refresh");
        }
        // Mark expired-without-refresh as stale.
        self.mark_stale_past_grace()?;
        Ok(())
    }

    fn fetch_due_entries(&self, limit: i64) -> anyhow::Result<Vec<(String, String, String)>> {
        use crate::schema::directory_resources::dsl as r;
        let mut conn = self.state.db().get()?;
        let now = Utc::now();
        let rows: Vec<(crate::ingest::ResourceKindWire, String, String)> = r::directory_resources
            .filter(r::stale.eq(false))
            .filter(r::next_revalidation_after.le(now))
            .select((r::resource_kind, r::resource_id, r::principal_server_did))
            .limit(limit)
            .load(&mut conn)?;
        Ok(rows
            .into_iter()
            .map(|(k, id, did)| (k.as_pg().to_string(), id, did))
            .collect())
    }

    fn mark_stale_past_grace(&self) -> anyhow::Result<()> {
        use crate::schema::directory_resources::dsl as r;
        let mut conn = self.state.db().get()?;
        let grace_seconds = self.state.config().revalidation_grace.as_secs() as i64;
        let cutoff = Utc::now() - chrono::Duration::seconds(grace_seconds);
        diesel::update(r::directory_resources)
            .filter(r::stale.eq(false))
            .filter(r::next_revalidation_after.le(cutoff))
            .set(r::stale.eq(true))
            .execute(&mut conn)?;
        Ok(())
    }
}

// Allow `Arc<AppState>` style usage in test fixtures without changing public API.
impl From<Arc<AppState>> for PullWorker {
    fn from(state: Arc<AppState>) -> Self {
        Self::new((*state).clone(), Duration::from_secs(300))
    }
}
