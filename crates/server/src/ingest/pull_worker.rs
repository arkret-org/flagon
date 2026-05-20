//! Pull-mode revalidation worker — spec §8.4 + §8.6.
//!
//! Wakes every `TEABAY_PULL_INTERVAL_SECONDS`, scans for entries whose
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
//! Delivery is best-effort per pass; failed pulls are retried with
//! exponential backoff via `pull_subscriptions`.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};
use tokio::time::interval;
use tracing::{info, warn};

use crate::audit::{self, AuditEventKind};
use crate::ids::{IdClass, new_id};
use crate::ingest::announce::{
    AnnounceRequest, FederationCachePersist, derive_public_projection, derive_realm_terminal_state,
    digest_request, effective_ttl_seconds, latest_as_of_for, upsert_resource_and_audit,
};
use crate::ingest::subscribe::{AcceptedIngestEvent, fanout_accepted_ingest};
use crate::ingest::verify::{
    VerifyContext, endpoint_child, resolve_principal_server_endpoint, strict_http_client,
};
use crate::ingest::{IngestModeWire, ResourceKindWire};
use crate::state::AppState;

pub struct PullWorker {
    state: AppState,
    period: Duration,
    http: reqwest::Client,
}

impl PullWorker {
    pub fn new(state: AppState, period: Duration) -> Self {
        let http = strict_http_client().expect("pull worker HTTP client");
        Self {
            state,
            period,
            http,
        }
    }

    /// Spawn the worker on the current Tokio runtime. Returns a handle —
    /// drop to detach (the task itself exits when the runtime is dropped).
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            info!(
                period_seconds = self.period.as_secs(),
                "teabay pull worker started"
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

    pub async fn run_once_for_tests(&self) -> anyhow::Result<()> {
        self.run_once().await
    }

    async fn run_once(&self) -> anyhow::Result<()> {
        let due = self.fetch_due_entries(50)?;
        if due.is_empty() {
            return Ok(());
        }
        info!(count = due.len(), "pull worker: revalidation candidates");

        for entry in due {
            match self.refresh_entry(entry.clone()).await {
                Ok(outcome) => {
                    info!(
                        kind = %entry.resource_kind.as_pg(),
                        resource_id = %entry.resource_id,
                        announce_id = %outcome.announce_id,
                        "pull worker: revalidation succeeded"
                    );
                }
                Err(error) => {
                    warn!(
                        kind = %entry.resource_kind.as_pg(),
                        resource_id = %entry.resource_id,
                        %error,
                        "pull worker: revalidation failed"
                    );
                    self.record_failure(&entry, &error.to_string())?;
                }
            }
        }
        // Mark expired-without-refresh as stale.
        self.mark_stale_past_grace()?;
        self.purge_stale_past_delete_window()?;
        Ok(())
    }

    fn fetch_due_entries(&self, limit: i64) -> anyhow::Result<Vec<DueEntry>> {
        use crate::schema::directory_resources::dsl as r;
        let mut conn = self.state.db().get()?;
        let now = Utc::now();
        let rows: Vec<(ResourceKindWire, String, String, i32)> = r::directory_resources
            .filter(r::stale.eq(false))
            .filter(r::next_revalidation_after.le(now))
            .select((
                r::resource_kind,
                r::resource_id,
                r::principal_server_did,
                r::effective_ttl_seconds,
            ))
            .limit(limit)
            .load(&mut conn)?;
        let mut out = Vec::with_capacity(rows.len());
        for (resource_kind, resource_id, principal_server_did, effective_ttl_seconds) in rows {
            if let Some(last_revision) =
                self.last_revision_if_pull_due(&mut conn, resource_kind, &resource_id, now)?
            {
                out.push(DueEntry {
                    resource_kind,
                    resource_id,
                    principal_server_did,
                    effective_ttl_seconds,
                    last_revision,
                });
            }
        }
        Ok(out)
    }

    fn last_revision_if_pull_due(
        &self,
        conn: &mut diesel::pg::PgConnection,
        resource_kind: ResourceKindWire,
        resource_id: &str,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Option<Option<String>>> {
        use crate::schema::pull_subscriptions::dsl as p;
        let row: Option<(Option<String>, DateTime<Utc>)> = p::pull_subscriptions
            .filter(p::resource_kind.eq(resource_kind))
            .filter(p::resource_id.eq(resource_id))
            .select((p::last_revision, p::next_pull_after))
            .first(conn)
            .optional()?;
        Ok(match row {
            Some((_last_revision, next_pull_after)) if next_pull_after > now => None,
            Some((last_revision, _)) => Some(last_revision),
            None => Some(None),
        })
    }

    async fn refresh_entry(&self, entry: DueEntry) -> anyhow::Result<RefreshOutcome> {
        let pulled = self.fetch_discovery_state(&entry).await?;
        if pulled.kind != entry.resource_kind.discovery_event_kind() {
            anyhow::bail!(
                "Principal Server returned `{}`, expected `{}`",
                pulled.kind,
                entry.resource_kind.discovery_event_kind()
            );
        }

        let announce = AnnounceRequest {
            resource_kind: entry.resource_kind,
            resource_id: entry.resource_id.clone(),
            principal_server_did: entry.principal_server_did.clone(),
            discovery_state: pulled.content,
            source_refs: vec![pulled.event_id.clone()],
            as_of: pulled.created_at,
            ttl_seconds: Some(entry.effective_ttl_seconds as i64),
            supersedes_announce_id: None,
            trust_root_attestation: None,
        };

        let ctx = VerifyContext::new(self.state.config(), self.state.db());
        let verified = ctx.verify(&announce).await.map_err(|(code, message)| {
            anyhow::anyhow!("verify rejected with {}: {message}", code.wire_code())
        })?;

        if let Some(latest) = latest_as_of_for(
            self.state.db(),
            announce.resource_kind,
            &announce.resource_id,
        )? && announce.as_of < latest
        {
            anyhow::bail!(
                "pulled as_of {} is older than indexed {latest}",
                announce.as_of
            );
        }

        let effective_ttl = effective_ttl_seconds(announce.ttl_seconds, self.state.config());
        let indexed_at = Utc::now();
        let next_revalidation = indexed_at + chrono::Duration::seconds(effective_ttl);
        let announce_id = new_id(IdClass::Announce);
        let public_projection =
            derive_public_projection(&announce.discovery_state).map_err(|(code, message)| {
                anyhow::anyhow!("projection rejected with {}: {message}", code.wire_code())
            })?;
        let fanout_projection = public_projection.clone();

        // Round R2/R3 T07 — surface realm terminal state on the pull
        // path too. Pull-mode federation cache fields are intentionally
        // empty (the pull worker is internal and does not federate
        // through Source-Service-DID); see FederationCachePersist
        // TODO(round23-T14).
        let realm_terminal =
            derive_realm_terminal_state(announce.resource_kind, &announce.discovery_state);
        upsert_resource_and_audit(
            self.state.db(),
            &announce,
            &verified,
            IngestModeWire::Pull,
            &announce_id,
            indexed_at,
            effective_ttl,
            next_revalidation,
            digest_request(&announce),
            public_projection,
            FederationCachePersist::default(),
            realm_terminal,
        )?;

        self.record_success(&entry, &pulled.event_id, next_revalidation)?;
        let _ = audit::record(
            self.state.db(),
            AuditEventKind::RevalidationSucceeded,
            Some(entry.resource_kind),
            Some(&entry.resource_id),
            Some(&entry.principal_server_did),
            json!({
                "announce_id": announce_id,
                "source_ref": pulled.event_id,
                "as_of": announce.as_of,
                "realm_destroyed": realm_terminal.is_some(),
            }),
        );
        if realm_terminal.is_some() {
            let _ = audit::record(
                self.state.db(),
                AuditEventKind::RealmDestroyed,
                Some(entry.resource_kind),
                Some(&entry.resource_id),
                Some(&entry.principal_server_did),
                json!({
                    "announce_id": announce_id,
                    "as_of": announce.as_of,
                }),
            );
        }

        fanout_accepted_ingest(
            self.state.clone(),
            AcceptedIngestEvent {
                announce_id: announce_id.clone(),
                ingest_mode: IngestModeWire::Pull,
                resource_kind: announce.resource_kind,
                resource_id: announce.resource_id.clone(),
                principal_server_did: announce.principal_server_did.clone(),
                indexed_at,
                as_of: announce.as_of,
                source_refs: announce.source_refs.clone(),
                policy_revision: verified.policy_revision.clone(),
                public_projection: fanout_projection,
            },
        )
        .await;

        Ok(RefreshOutcome { announce_id })
    }

    async fn fetch_discovery_state(&self, entry: &DueEntry) -> anyhow::Result<PulledEvent> {
        let endpoint = resolve_principal_server_endpoint(
            self.state.config(),
            &entry.principal_server_did,
            &self.http,
        )
        .await?;
        let mut url = endpoint_child(&endpoint, "events")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("subject", &entry.resource_id);
            query.append_pair("kind", entry.resource_kind.discovery_event_kind());
            query.append_pair("state_only", "true");
            if let Some(last_revision) = entry.last_revision.as_deref() {
                query.append_pair("after_revision", last_revision);
            }
        }
        let response = self.http.get(url).send().await?;
        if !response.status().is_success() {
            anyhow::bail!("events query returned {}", response.status());
        }
        let body = response.json::<EventsQueryResBody>().await?;
        body.events
            .into_iter()
            .next()
            .map(|envelope| envelope.event)
            .ok_or_else(|| anyhow::anyhow!("events query returned no discovery state"))
    }

    fn record_success(
        &self,
        entry: &DueEntry,
        last_revision: &str,
        next_pull_after: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        use crate::schema::pull_subscriptions::dsl as p;
        let mut conn = self.state.db().get()?;
        diesel::insert_into(p::pull_subscriptions)
            .values((
                p::resource_kind.eq(entry.resource_kind),
                p::resource_id.eq(&entry.resource_id),
                p::principal_server_did.eq(&entry.principal_server_did),
                p::last_revision.eq(Some(last_revision)),
                p::last_pulled_at.eq(Some(Utc::now())),
                p::next_pull_after.eq(next_pull_after),
                p::consecutive_failures.eq(0),
                p::last_error.eq::<Option<&str>>(None),
            ))
            .on_conflict((p::resource_kind, p::resource_id))
            .do_update()
            .set((
                p::principal_server_did.eq(&entry.principal_server_did),
                p::last_revision.eq(Some(last_revision)),
                p::last_pulled_at.eq(Some(Utc::now())),
                p::next_pull_after.eq(next_pull_after),
                p::consecutive_failures.eq(0),
                p::last_error.eq::<Option<&str>>(None),
            ))
            .execute(&mut conn)?;
        Ok(())
    }

    fn record_failure(&self, entry: &DueEntry, error: &str) -> anyhow::Result<()> {
        use crate::schema::pull_subscriptions::dsl as p;
        let mut conn = self.state.db().get()?;
        let existing_failures: Option<i32> = p::pull_subscriptions
            .filter(p::resource_kind.eq(entry.resource_kind))
            .filter(p::resource_id.eq(&entry.resource_id))
            .select(p::consecutive_failures)
            .first(&mut conn)
            .optional()?;
        let failures = existing_failures.unwrap_or(0).saturating_add(1);
        let backoff = self.backoff_after_failures(failures);
        let next_pull_after = Utc::now() + chrono::Duration::seconds(backoff.as_secs() as i64);
        diesel::insert_into(p::pull_subscriptions)
            .values((
                p::resource_kind.eq(entry.resource_kind),
                p::resource_id.eq(&entry.resource_id),
                p::principal_server_did.eq(&entry.principal_server_did),
                p::last_revision.eq(entry.last_revision.as_deref()),
                p::last_pulled_at.eq::<Option<DateTime<Utc>>>(None),
                p::next_pull_after.eq(next_pull_after),
                p::consecutive_failures.eq(failures),
                p::last_error.eq(Some(error)),
            ))
            .on_conflict((p::resource_kind, p::resource_id))
            .do_update()
            .set((
                p::principal_server_did.eq(&entry.principal_server_did),
                p::next_pull_after.eq(next_pull_after),
                p::consecutive_failures.eq(failures),
                p::last_error.eq(Some(error)),
            ))
            .execute(&mut conn)?;
        Ok(())
    }

    fn backoff_after_failures(&self, failures: i32) -> Duration {
        let exponent = failures.saturating_sub(1).clamp(0, 8) as u32;
        let seconds = self
            .period
            .as_secs()
            .saturating_mul(2_u64.saturating_pow(exponent));
        Duration::from_secs(seconds.min(86_400))
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

    fn purge_stale_past_delete_window(&self) -> anyhow::Result<()> {
        use crate::schema::directory_resources::dsl as r;
        let mut conn = self.state.db().get()?;
        let grace_seconds = self.state.config().revalidation_grace.as_secs() as i64;
        let cutoff =
            Utc::now() - chrono::Duration::seconds(grace_seconds) - chrono::Duration::hours(24);
        let doomed: Vec<(ResourceKindWire, String, String)> = r::directory_resources
            .filter(r::stale.eq(true))
            .filter(r::next_revalidation_after.le(cutoff))
            .select((r::resource_kind, r::resource_id, r::principal_server_did))
            .load(&mut conn)?;
        for (resource_kind, resource_id, principal_server_did) in doomed {
            diesel::delete(r::directory_resources)
                .filter(r::resource_kind.eq(resource_kind))
                .filter(r::resource_id.eq(&resource_id))
                .execute(&mut conn)?;
            let _ = audit::record(
                self.state.db(),
                AuditEventKind::RevalidationFailed,
                Some(resource_kind),
                Some(&resource_id),
                Some(&principal_server_did),
                json!({
                    "action": "deleted_after_stale_grace",
                    "next_revalidation_after_cutoff": cutoff,
                }),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct DueEntry {
    resource_kind: ResourceKindWire,
    resource_id: String,
    principal_server_did: String,
    effective_ttl_seconds: i32,
    last_revision: Option<String>,
}

struct RefreshOutcome {
    announce_id: String,
}

#[derive(Debug, Deserialize)]
struct EventsQueryResBody {
    events: Vec<EventEnvelope>,
}

#[derive(Debug, Deserialize)]
struct EventEnvelope {
    event: PulledEvent,
}

#[derive(Debug, Deserialize)]
struct PulledEvent {
    event_id: String,
    kind: String,
    created_at: DateTime<Utc>,
    content: JsonValue,
}

// Allow `Arc<AppState>` style usage in test fixtures without changing public API.
impl From<Arc<AppState>> for PullWorker {
    fn from(state: Arc<AppState>) -> Self {
        Self::new((*state).clone(), Duration::from_secs(300))
    }
}
