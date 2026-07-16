//! P5 HIGH — background expiry purge worker.
//!
//! The freshness worker (see [`crate::ingest::freshness_worker`]) only
//! *flips* expired rows to `stale=true` so query handlers stop returning
//! them, preserving the row for audit history. This worker is the second
//! half: every `period` (default 30 minutes) it **deletes** any
//! `directory_resources` row whose `expires_at < now() - grace`, where
//! `grace` defaults to 24h. The grace window protects against operator
//! clock skew and gives a one-business-day rollback window before the
//! row is gone for good.
//!
//! Per-tick the worker counts deletions and emits
//! `teabay_expired_rows_purged_total{table}` so dashboards can alert if
//! the purge volume spikes (signals upstream announce drift).
use std::time::Duration;

use chrono::Utc;
use diesel::prelude::*;
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde_json::json;
use tokio::time::interval;
use tracing::{info, warn};

use crate::audit::{self, AuditEventKind};
use crate::ingest::DirectoryResourceKindDb;
use crate::observability::PURGE_TABLE_DIRECTORY_RESOURCES;
use crate::state::AppState;

/// Grace window beyond `expires_at` before a row is deleted. 24h
/// protects against transient clock skew and gives the operator a
/// one-day window to rescue a row that was wrongly expired.
pub const DEFAULT_EXPIRY_GRACE: Duration = Duration::from_secs(86_400);

pub struct ExpiryWorker {
    state: AppState,
    period: Duration,
    grace: Duration,
}

impl ExpiryWorker {
    pub fn new(state: AppState, period: Duration) -> Self {
        Self {
            state,
            period,
            grace: DEFAULT_EXPIRY_GRACE,
        }
    }

    /// Override the grace window — primarily for tests.
    pub fn with_grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!(
                period_seconds = self.period.as_secs(),
                grace_seconds = self.grace.as_secs(),
                "teabay expiry worker started"
            );
            let mut tick = interval(self.period);
            loop {
                tick.tick().await;
                if let Err(e) = self.run_once().await {
                    warn!(%e, "expiry worker pass failed");
                }
            }
        })
    }

    /// Single sweep. Public so tests can drive it without a scheduler.
    /// Returns the number of rows deleted.
    pub async fn run_once(&self) -> anyhow::Result<usize> {
        use crate::schema::directory_resources::dsl as r;
        let mut conn = self.state.db().get().await?;
        let cutoff = Utc::now() - chrono::Duration::from_std(self.grace)?;
        let purged = conn
            .transaction::<Vec<(DirectoryResourceKindDb, String)>, anyhow::Error, _>(
                async move |conn| {
                    let rows = diesel::delete(r::directory_resources)
                        .filter(r::expires_at.lt(cutoff))
                        .returning((r::resource_kind, r::resource_id))
                        .get_results::<(DirectoryResourceKindDb, String)>(&mut *conn)
                        .await?;
                    for (resource_kind, resource_id) in &rows {
                        crate::psi_index::delete_resource_tokens_on_conn(
                            &mut *conn,
                            *resource_kind,
                            resource_id,
                        )
                        .await?;
                    }
                    Ok(rows)
                },
            )
            .await?;
        let deleted = purged.len();
        if deleted > 0 {
            info!(
                deleted,
                grace_seconds = self.grace.as_secs(),
                "expiry worker: directory_resources rows purged"
            );
            self.state
                .metrics()
                .record_expired_rows_purged(PURGE_TABLE_DIRECTORY_RESOURCES, deleted as u64);
            for (resource_kind, resource_id) in purged {
                if let Err(error) = audit::record(
                    self.state.db(),
                    AuditEventKind::ExpiryPurged,
                    Some(resource_kind),
                    Some(&resource_id),
                    Some(self.state.config().service_id.as_str()),
                    json!({
                        "resource_kind": resource_kind.as_pg(),
                        "resource_id": resource_id,
                        "cutoff": cutoff,
                        "grace_seconds": self.grace.as_secs(),
                    }),
                )
                .await
                {
                    warn!(%error, "expiry worker audit write failed");
                }
            }
        }
        Ok(deleted)
    }
}
