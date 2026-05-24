//! Cross-directory divergence detector.
//!
//! Aggressive-mode implementation: when a resource advertises HTTPS Directory
//! endpoints in `via_services`, poll their resolve endpoint and compare
//! `policy_revision`. DID service resolution and actor/applet resolve surfaces
//! are explicit TODOs; this worker still gives operators a live `divergent`
//! flag for the resource classes we can query today.

use std::time::Duration;

use diesel::prelude::*;
use reqwest::{Client, Url};
use serde_json::{Value as JsonValue, json};
use tokio::time::interval;
use tracing::{info, warn};

use crate::audit::{self, AuditEventKind};
use crate::ingest::ResourceKindWire;
use crate::ingest::verify::strict_http_client;
use crate::state::{AppState, BackgroundWorker};

pub struct DivergenceWorker {
    state: AppState,
    period: Duration,
    http: Client,
}

#[derive(Debug, Clone)]
struct DivergenceCandidate {
    resource_kind: ResourceKindWire,
    resource_id: String,
    policy_revision: Option<String>,
    divergent: bool,
    via_services: Vec<String>,
}

#[derive(Debug)]
struct RemoteMismatch {
    endpoint: String,
    remote_policy_revision: Option<String>,
}

impl DivergenceWorker {
    pub fn new(state: AppState, period: Duration) -> Self {
        let http = strict_http_client().expect("divergence worker HTTP client");
        Self {
            state,
            period,
            http,
        }
    }

    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.state
                .worker_started(BackgroundWorker::Divergence, self.period);
            info!(
                period_seconds = self.period.as_secs(),
                "teabay divergence worker started"
            );
            let mut tick = interval(self.period);
            loop {
                tick.tick().await;
                if let Err(error) = self.run_once().await {
                    warn!(%error, "divergence worker pass failed");
                }
            }
        })
    }

    async fn run_once(&self) -> anyhow::Result<()> {
        self.state.worker_heartbeat(BackgroundWorker::Divergence);
        let candidates = self.fetch_candidates(100)?;
        if candidates.is_empty() {
            return Ok(());
        }

        let mut checked = 0usize;
        for candidate in candidates {
            match self.check_candidate(candidate.clone()).await {
                Ok(Some(mismatches)) if !mismatches.is_empty() => {
                    checked += 1;
                    self.set_divergent(&candidate, true, mismatches)?;
                }
                Ok(Some(_)) => {
                    checked += 1;
                    self.clear_divergent(&candidate)?;
                }
                Ok(None) => {}
                Err(error) => {
                    warn!(
                        kind = %candidate.resource_kind.as_pg(),
                        resource_id = %candidate.resource_id,
                        %error,
                        "divergence worker: candidate check failed"
                    );
                }
            }
        }
        if checked > 0 {
            info!(checked, "divergence worker: checked remote directories");
        }
        Ok(())
    }

    fn fetch_candidates(&self, limit: i64) -> anyhow::Result<Vec<DivergenceCandidate>> {
        use crate::schema::directory_resources::dsl as r;

        let mut conn = self.state.db().get()?;
        let rows: Vec<(ResourceKindWire, String, Option<String>, bool, Vec<String>)> =
            r::directory_resources
                .order(r::indexed_at.asc())
                .limit(limit)
                .select((
                    r::resource_kind,
                    r::resource_id,
                    r::policy_revision,
                    r::divergent,
                    r::via_services,
                ))
                .load(&mut conn)?;

        Ok(rows
            .into_iter()
            .map(
                |(resource_kind, resource_id, policy_revision, divergent, via_services)| {
                    DivergenceCandidate {
                        resource_kind,
                        resource_id,
                        policy_revision,
                        divergent,
                        via_services,
                    }
                },
            )
            .filter(|candidate| {
                directory_resolve_path(candidate.resource_kind).is_some()
                    && candidate
                        .via_services
                        .iter()
                        .any(|service| is_remote_https_service(&self.state, service))
            })
            .collect())
    }

    async fn check_candidate(
        &self,
        candidate: DivergenceCandidate,
    ) -> anyhow::Result<Option<Vec<RemoteMismatch>>> {
        let Some(path) = directory_resolve_path(candidate.resource_kind) else {
            return Ok(None);
        };
        let Some(payload) =
            directory_resolve_payload(candidate.resource_kind, &candidate.resource_id)
        else {
            return Ok(None);
        };

        let mut compared = false;
        let mut mismatches = Vec::new();
        for service in candidate
            .via_services
            .iter()
            .filter(|service| is_remote_https_service(&self.state, service))
        {
            let url = directory_endpoint(service, path)?;
            let Some(remote_policy_revision) = self.fetch_policy_revision(url, &payload).await?
            else {
                continue;
            };
            compared = true;
            if remote_policy_revision != candidate.policy_revision {
                mismatches.push(RemoteMismatch {
                    endpoint: service.clone(),
                    remote_policy_revision,
                });
            }
        }

        if compared {
            Ok(Some(mismatches))
        } else {
            Ok(None)
        }
    }

    async fn fetch_policy_revision(
        &self,
        url: Url,
        payload: &JsonValue,
    ) -> anyhow::Result<Option<Option<String>>> {
        let response = self.http.post(url.clone()).json(payload).send().await?;
        if !response.status().is_success() {
            return Ok(None);
        }
        let body = response.json::<JsonValue>().await?;
        Ok(extract_policy_revision(&body))
    }

    fn set_divergent(
        &self,
        candidate: &DivergenceCandidate,
        divergent: bool,
        mismatches: Vec<RemoteMismatch>,
    ) -> anyhow::Result<()> {
        if candidate.divergent == divergent {
            return Ok(());
        }
        if divergent {
            self.state.metrics().record_divergence_detected();
        }
        use crate::schema::directory_resources::dsl as r;
        let mut conn = self.state.db().get()?;
        diesel::update(
            r::directory_resources
                .filter(r::resource_kind.eq(candidate.resource_kind))
                .filter(r::resource_id.eq(&candidate.resource_id)),
        )
        .set(r::divergent.eq(divergent))
        .execute(&mut conn)?;

        audit::record(
            self.state.db(),
            AuditEventKind::RevalidationFailed,
            Some(candidate.resource_kind),
            Some(&candidate.resource_id),
            Some(&self.state.config().service_did),
            json!({
                "reason": "cross_directory_divergence",
                "local_policy_revision": candidate.policy_revision,
                "mismatches": mismatches.into_iter().map(|mismatch| {
                    json!({
                        "endpoint": mismatch.endpoint,
                        "remote_policy_revision": mismatch.remote_policy_revision,
                    })
                }).collect::<Vec<_>>(),
            }),
        )
    }

    fn clear_divergent(&self, candidate: &DivergenceCandidate) -> anyhow::Result<()> {
        if !candidate.divergent {
            return Ok(());
        }
        use crate::schema::directory_resources::dsl as r;
        let mut conn = self.state.db().get()?;
        diesel::update(
            r::directory_resources
                .filter(r::resource_kind.eq(candidate.resource_kind))
                .filter(r::resource_id.eq(&candidate.resource_id)),
        )
        .set(r::divergent.eq(false))
        .execute(&mut conn)?;

        audit::record(
            self.state.db(),
            AuditEventKind::RevalidationSucceeded,
            Some(candidate.resource_kind),
            Some(&candidate.resource_id),
            Some(&self.state.config().service_did),
            json!({ "reason": "cross_directory_divergence_cleared" }),
        )
    }
}

fn is_remote_https_service(state: &AppState, service: &str) -> bool {
    service != state.config().service_did
        && service != state.config().public_base_url
        && service.starts_with("https://")
}

fn directory_resolve_path(kind: ResourceKindWire) -> Option<&'static str> {
    match kind {
        ResourceKindWire::Realm => Some("resolve-realm"),
        ResourceKindWire::Organization => Some("resolve-organization"),
        ResourceKindWire::Handle => Some("resolve-handle"),
        ResourceKindWire::Space | ResourceKindWire::Actor | ResourceKindWire::Applet => None,
    }
}

fn directory_resolve_payload(kind: ResourceKindWire, resource_id: &str) -> Option<JsonValue> {
    match kind {
        ResourceKindWire::Realm => Some(json!({ "realm_id": resource_id })),
        ResourceKindWire::Organization => Some(json!({ "organization_did": resource_id })),
        ResourceKindWire::Handle => Some(json!({ "handle": resource_id })),
        ResourceKindWire::Space | ResourceKindWire::Actor | ResourceKindWire::Applet => None,
    }
}

fn directory_endpoint(base: &str, path: &str) -> anyhow::Result<Url> {
    let mut url = Url::parse(base)?;
    if url.scheme() != "https" {
        anyhow::bail!("remote directory endpoint must be HTTPS");
    }
    let base_path = url.path().trim_end_matches('/');
    url.set_path(&format!("{base_path}/api/v1/directory/{path}"));
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn extract_policy_revision(body: &JsonValue) -> Option<Option<String>> {
    if body.get("policy_revision").is_some() {
        return Some(
            body.get("policy_revision")
                .and_then(JsonValue::as_str)
                .map(str::to_string),
        );
    }
    if body.pointer("/result/policy_revision").is_some() {
        return Some(
            body.pointer("/result/policy_revision")
                .and_then(JsonValue::as_str)
                .map(str::to_string),
        );
    }
    None
}
