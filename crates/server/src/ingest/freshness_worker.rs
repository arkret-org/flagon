//! Freshness-expiry background worker — P2E.5 follow-up.
//!
//! Accepted announce requests write `expires_at` on every refresh; this
//! worker is the other half of the contract: every
//! `tick` (default 10 minutes) it sweeps `directory_resources` and
//! marks any row whose revalidation TTL plus configured grace has elapsed
//! as `stale = true`. Query handlers (`actor`, `realm`, `organization`,
//! `handle`) all filter on `stale = false`, so this flips a row out of the
//! search face without deleting the audit history.
//!
//! Unlike `PullWorker`, this worker does NOT make outbound HTTP
//! calls — it is a pure database sweep, so it remains cheap to run
//! frequently and safe to run alongside the pull/divergence workers.
//! Rows already past the pull worker's 24h delete window are still
//! purged by `PullWorker::purge_stale_past_delete_window`; this
//! worker only owns the `expires_at + revalidation_grace` stale flip.

use std::time::Duration;

use chrono::Utc;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
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
                if let Err(e) = self.run_once().await {
                    warn!(%e, "freshness worker pass failed");
                }
            }
        })
    }

    /// Single sweep. Public so the integration tests can drive it
    /// without a running scheduler.
    pub async fn run_once(&self) -> anyhow::Result<usize> {
        use crate::schema::directory_resources::dsl as r;
        let mut conn = self.state.db().get().await?;
        let now = Utc::now();
        let grace = chrono::Duration::from_std(self.state.config().revalidation_grace)?;
        let stale_cutoff = now - grace;
        // Atomically flip to stale and capture exactly the rows that were
        // flipped via `RETURNING`, so the set whose PSI tokens we delete can
        // never drift from the set the UPDATE actually mutated. A separate
        // SELECT-then-UPDATE would race a concurrent `announce` that refreshes
        // a row in between (pushing `expires_at` out and clearing `stale`),
        // leaving us to delete the tokens of a row that was *not* flipped.
        let stale_resources: Vec<(crate::ingest::DirectoryResourceKindDb, String)> =
            diesel::update(r::directory_resources)
                .filter(r::stale.eq(false))
                .filter(r::expires_at.lt(stale_cutoff))
                .set(r::stale.eq(true))
                .returning((r::resource_kind, r::resource_id))
                .get_results(&mut *conn)
                .await?;
        let flipped = stale_resources.len();
        for (resource_kind, resource_id) in stale_resources {
            crate::psi_index::delete_resource_tokens_on_conn(
                &mut conn,
                resource_kind,
                &resource_id,
            )
            .await?;
        }
        if flipped > 0 {
            info!(
                flipped,
                grace_seconds = self.state.config().revalidation_grace.as_secs(),
                "freshness worker: rows flipped to stale after revalidation grace"
            );
        }

        // TBY-ORG-03 — sweep expired `ck.realm.organization` relationships out of
        // the verified index so an expired official badge disappears on the next
        // directory refresh. The query layer also filters expiry at read time
        // (`load_verified_relationships`), but purging keeps the index bounded
        // and makes the badge removal observable in the stored projection.
        match crate::ingest::organization_statement::purge_expired_relationships(
            self.state.db(),
            now,
        )
        .await
        {
            Ok(purged) if purged > 0 => {
                info!(purged, "freshness worker: expired verified realm organizations purged");
            }
            Ok(_) => {}
            Err(e) => warn!(%e, "freshness worker: verified organization expiry purge failed"),
        }

        Ok(flipped)
    }
}
