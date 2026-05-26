//! Freshness-expiry background worker — P2E.5 follow-up.
//!
//! The heartbeat ingest path (P2E.5) writes `expires_at` on every
//! refresh; this worker is the other half of the contract: every
//! `tick` (default 10 minutes) it sweeps `directory_resources` and
//! marks any row whose `expires_at < now()` as `stale = true`. Query
//! handlers (`actor`, `realm`, `organization`, `handle`) all filter
//! on `stale = false`, so this flips a row out of the search face
//! without deleting the audit history.
//!
//! Unlike `PullWorker`, this worker does NOT make outbound HTTP
//! calls — it is a pure database sweep, so it remains cheap to run
//! frequently and safe to run alongside the pull/divergence workers.
//! Rows already past the pull worker's 24h delete window are still
//! purged by `PullWorker::purge_stale_past_delete_window`; this
//! worker only owns the `expires_at`-driven stale flip.

use std::time::Duration;

use chrono::Utc;
use diesel::prelude::*;
use tokio::time::interval;
use tracing::{info, warn};

use crate::state::AppState;

/// Default tick interval if the operator does not override it.
/// 10 minutes is short enough that an expired row is hidden from
/// search within a single dashboard refresh, and long enough that
/// the sweep itself is negligible against the pool budget.
pub const DEFAULT_FRESHNESS_TICK: Duration = Duration::from_secs(600);

pub struct FreshnessWorker {
    state: AppState,
    period: Duration,
}

impl FreshnessWorker {
    pub fn new(state: AppState, period: Duration) -> Self {
        Self { state, period }
    }

    /// Spawn the worker on the current Tokio runtime.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!(
                period_seconds = self.period.as_secs(),
                "teabay freshness worker started"
            );
            let mut tick = interval(self.period);
            loop {
                tick.tick().await;
                if let Err(e) = self.run_once() {
                    warn!(%e, "freshness worker pass failed");
                }
            }
        })
    }

    /// Single sweep. Public so the integration tests can drive it
    /// without a running scheduler.
    pub fn run_once(&self) -> anyhow::Result<usize> {
        use crate::schema::directory_resources::dsl as r;
        let mut conn = self.state.db().get()?;
        let now = Utc::now();
        let flipped = diesel::update(r::directory_resources)
            .filter(r::stale.eq(false))
            .filter(r::expires_at.lt(now))
            .set(r::stale.eq(true))
            .execute(&mut conn)?;
        if flipped > 0 {
            info!(
                flipped,
                "freshness worker: rows flipped to stale by expires_at"
            );
        }
        Ok(flipped)
    }
}
