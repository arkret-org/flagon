//! Pull-mode revalidation worker — spec §8.4 + §8.6.
//!
//! Wakes every `TEABAY_PULL_INTERVAL_SECONDS`, scans for entries whose
//! `next_revalidation_after` has passed, and re-pulls their signed
//! `ck.{kind}.discovery` state from the resource Principal Server using
//! the standard `ck.events.query` shape:
//!
//! ```text
//! GET /_cokret/self/events/query
//!   ?subject={resource_id}
//!   &kind=ck.{...}.discovery
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
use diesel_async::RunQueryDsl;
use reqwest::header::HeaderMap;
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};
use tokio::time::interval;
use tracing::{info, warn};

use crate::audit::{self, AuditEventKind};
use crate::ids::{IdClass, new_id};
use crate::ingest::announce::{
    AnnounceRequest, FederationCachePersist, canonical_json_string, derive_public_projection,
    derive_realm_terminal_state, digest_request, effective_ttl_seconds, latest_as_of_for,
    upsert_resource_and_audit,
};
use crate::ingest::subscribe::{AcceptedIngestEvent, fanout_accepted_ingest};
use crate::ingest::verify::{
    VerifyContext, endpoint_child, resolve_principal_server_endpoint, strict_http_client,
    strict_http_client_for_egress,
};
use crate::ingest::{IngestModeWire, ResourceKindWire};
use crate::state::{AppState, BackgroundWorker};

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
            self.state
                .worker_started(BackgroundWorker::Pull, self.period);
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
        self.state.worker_heartbeat(BackgroundWorker::Pull);
        let due = self.fetch_due_entries(50).await?;
        if due.is_empty() {
            return Ok(());
        }
        info!(count = due.len(), "pull worker: revalidation candidates");

        for entry in due {
            match self.refresh_entry(entry.clone()).await {
                Ok(outcome) => {
                    self.state.metrics().record_pull_revalidation("success");
                    info!(
                        kind = %entry.resource_kind.as_pg(),
                        resource_id = %entry.resource_id,
                        announce_id = %outcome.announce_id,
                        "pull worker: revalidation succeeded"
                    );
                }
                Err(error) => {
                    self.state.metrics().record_pull_revalidation("failure");
                    warn!(
                        kind = %entry.resource_kind.as_pg(),
                        resource_id = %entry.resource_id,
                        %error,
                        "pull worker: revalidation failed"
                    );
                    self.record_failure(&entry, &error.to_string()).await?;
                }
            }
        }
        // Mark expired-without-refresh as stale.
        self.mark_stale_past_grace().await?;
        self.purge_stale_past_delete_window().await?;
        Ok(())
    }

    async fn fetch_due_entries(&self, limit: i64) -> anyhow::Result<Vec<DueEntry>> {
        use crate::schema::directory_resources::dsl as r;
        let mut conn = self.state.db().get().await?;
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
            .load(&mut *conn)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for (resource_kind, resource_id, principal_server_did, effective_ttl_seconds) in rows {
            if let Some(last_revision) = self
                .last_revision_if_pull_due(&mut conn, resource_kind, &resource_id, now)
                .await?
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

    async fn last_revision_if_pull_due(
        &self,
        conn: &mut diesel_async::AsyncPgConnection,
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
            .await
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

        let federation_cache = FederationCachePersist::from_pull_event(&entry, &pulled);

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
        )
        .await?
            && announce.as_of < latest
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
            derive_public_projection(&announce.discovery_state, verified.discoverability).map_err(
                |(code, message)| {
                    anyhow::anyhow!("projection rejected with {}: {message}", code.wire_code())
                },
            )?;

        // Round R2/R3 T07/T14 — surface realm terminal state on the pull
        // path too, and persist the federation cache-key identity fields
        // observed from the upstream `ck.events.query` response/envelope.
        let realm_terminal =
            derive_realm_terminal_state(announce.resource_kind, &announce.discovery_state);
        let fanout_projection = upsert_resource_and_audit(
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
            federation_cache,
            realm_terminal,
        )
        .await?;

        self.record_success(&entry, &pulled.event_id, next_revalidation)
            .await?;
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
        )
        .await;
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
            )
            .await;
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
        let mut url = endpoint_child(&endpoint, "self/events/query")?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("subject", &entry.resource_id);
            query.append_pair("kind", entry.resource_kind.discovery_event_kind());
            query.append_pair("state_only", "true");
            if let Some(last_revision) = entry.last_revision.as_deref() {
                query.append_pair("after_revision", last_revision);
            }
        }
        let target = crate::egress::resolve_url_for_egress(
            &url,
            "pull worker events query",
            crate::egress::private_networks_allowed(self.state.config().development_mode),
        )
        .map_err(|error| anyhow::anyhow!(error))?;
        let http = strict_http_client_for_egress(&target)?;
        let response = http.get(target.url().clone()).send().await?;
        if !response.status().is_success() {
            anyhow::bail!("events query returned {}", response.status());
        }
        let source_service_did = response_header_value(response.headers(), "source-service-did");
        let service_binding_ref = response_header_value(response.headers(), "service-binding-ref");
        let origin_key_state_digest =
            response_header_value(response.headers(), "origin-key-state-digest");
        let body = response.json::<EventsQueryResBody>().await?;
        let mut event = body
            .events
            .into_iter()
            .next()
            .map(|envelope| envelope.event)
            .ok_or_else(|| anyhow::anyhow!("events query returned no discovery state"))?;
        if event.source_service_did.is_empty() {
            event.source_service_did = source_service_did.unwrap_or_default();
        }
        if event.service_binding_ref.is_none() {
            event.service_binding_ref = service_binding_ref.map(JsonValue::String);
        }
        if event.origin_key_state_digest.is_empty() {
            event.origin_key_state_digest = origin_key_state_digest.unwrap_or_default();
        }
        Ok(event)
    }

    async fn record_success(
        &self,
        entry: &DueEntry,
        last_revision: &str,
        next_pull_after: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        use crate::schema::pull_subscriptions::dsl as p;
        let mut conn = self.state.db().get().await?;
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
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    async fn record_failure(&self, entry: &DueEntry, error: &str) -> anyhow::Result<()> {
        use crate::schema::pull_subscriptions::dsl as p;
        let mut conn = self.state.db().get().await?;
        let existing_failures: Option<i32> = p::pull_subscriptions
            .filter(p::resource_kind.eq(entry.resource_kind))
            .filter(p::resource_id.eq(&entry.resource_id))
            .select(p::consecutive_failures)
            .first(&mut *conn)
            .await
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
            .execute(&mut *conn)
            .await?;
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

    async fn mark_stale_past_grace(&self) -> anyhow::Result<()> {
        use crate::schema::directory_resources::dsl as r;
        let mut conn = self.state.db().get().await?;
        let grace_seconds = self.state.config().revalidation_grace.as_secs() as i64;
        let cutoff = Utc::now() - chrono::Duration::seconds(grace_seconds);
        diesel::update(r::directory_resources)
            .filter(r::stale.eq(false))
            .filter(r::next_revalidation_after.le(cutoff))
            .set(r::stale.eq(true))
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    async fn purge_stale_past_delete_window(&self) -> anyhow::Result<()> {
        use crate::schema::directory_resources::dsl as r;
        let mut conn = self.state.db().get().await?;
        let grace_seconds = self.state.config().revalidation_grace.as_secs() as i64;
        let cutoff =
            Utc::now() - chrono::Duration::seconds(grace_seconds) - chrono::Duration::hours(24);
        let doomed: Vec<(ResourceKindWire, String, String)> = r::directory_resources
            .filter(r::stale.eq(true))
            .filter(r::next_revalidation_after.le(cutoff))
            .select((r::resource_kind, r::resource_id, r::principal_server_did))
            .load(&mut *conn)
            .await?;
        for (resource_kind, resource_id, principal_server_did) in doomed {
            diesel::delete(r::directory_resources)
                .filter(r::resource_kind.eq(resource_kind))
                .filter(r::resource_id.eq(&resource_id))
                .execute(&mut *conn)
                .await?;
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
            )
            .await;
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
    #[serde(default)]
    source_service_did: String,
    #[serde(default)]
    service_binding_ref: Option<JsonValue>,
    #[serde(default)]
    origin_key_state_digest: String,
}

impl FederationCachePersist {
    fn from_pull_event(entry: &DueEntry, pulled: &PulledEvent) -> Self {
        let source_service_did = if pulled.source_service_did.trim().is_empty() {
            entry.principal_server_did.clone()
        } else {
            pulled.source_service_did.trim().to_owned()
        };
        let verification_method = pulled
            .content
            .pointer("/proof/verification_method")
            .and_then(JsonValue::as_str)
            .unwrap_or_default()
            .to_owned();
        let service_binding_ref = pulled
            .service_binding_ref
            .as_ref()
            .map(canonical_field_value)
            .unwrap_or_default();
        let origin_key_state_digest = pulled.origin_key_state_digest.trim().as_bytes().to_vec();
        Self {
            source_service_did,
            verification_method,
            service_binding_ref,
            origin_key_state_digest,
            historical_only: false,
        }
    }
}

fn canonical_field_value(value: &JsonValue) -> String {
    match value {
        JsonValue::String(value) => value.trim().to_owned(),
        other => canonical_json_string(other).unwrap_or_default(),
    }
}

fn response_header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

// Allow `Arc<AppState>` style usage in test fixtures without changing public API.
impl From<Arc<AppState>> for PullWorker {
    fn from(state: Arc<AppState>) -> Self {
        Self::new((*state).clone(), Duration::from_secs(300))
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn pull_event_populates_federation_cache_fields() {
        let entry = DueEntry {
            resource_kind: ResourceKindWire::Realm,
            resource_id: "ck:realm:tea".to_owned(),
            principal_server_did: "did:web:principal.example".to_owned(),
            effective_ttl_seconds: 3600,
            last_revision: Some("rev-1".to_owned()),
        };
        let pulled = PulledEvent {
            event_id: "evt-1".to_owned(),
            kind: "ck.realm.discovery".to_owned(),
            created_at: Utc.timestamp_opt(0, 0).unwrap(),
            content: json!({
                "proof": {
                    "verification_method": "did:web:principal.example#key-1"
                }
            }),
            source_service_did: "did:web:source-service.example".to_owned(),
            service_binding_ref: Some(json!({
                "realm_id": "ck:realm:tea",
                "frontier": ["evt-0"]
            })),
            origin_key_state_digest: "sha256:abc123".to_owned(),
        };

        let cache = FederationCachePersist::from_pull_event(&entry, &pulled);

        assert_eq!(cache.source_service_did, "did:web:source-service.example");
        assert_eq!(cache.verification_method, "did:web:principal.example#key-1");
        assert!(cache.service_binding_ref.contains("\"frontier\""));
        assert_eq!(cache.origin_key_state_digest, b"sha256:abc123");
        assert!(!cache.historical_only);
    }
}
