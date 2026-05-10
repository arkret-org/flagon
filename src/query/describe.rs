//! `cx.directory.describe` — service capability advertisement.
//!
//! Spec: discovery-directory.md §9 + §8.9 (ingest fields).

use salvo::prelude::*;
use serde::Serialize;
use serde_json::json;

use crate::{config::AppConfig, state::AppState};

#[derive(Debug, Serialize)]
struct DescribeResponse<'a> {
    service_did: &'a str,
    public_base_url: &'a str,
    resource_types: &'static [&'static str],
    discovery_profiles: Vec<&'static str>,
    restricted_query_proof: bool,
    // §8.9 ingest fields:
    ingest_modes: Vec<&'static str>,
    accept_policy_kind: &'static str,
    accept_policy_ref: Option<&'a str>,
    default_ttl_seconds: u64,
    max_ttl_seconds: u64,
    revalidation_grace_seconds: u64,
    accepted_resource_kinds: Vec<&'static str>,
    accepted_did_methods: &'a [String],
    takedown_contact: Option<&'a str>,
    rate_limits: serde_json::Value,
}

#[handler]
pub async fn describe(depot: &mut Depot, res: &mut Response) {
    let state = match depot.obtain::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            res.render(Json(json!({ "ok": false, "error": "AppState missing" })));
            return;
        }
    };
    let cfg = state.config();
    let mut discovery_profiles = vec!["cx.profile.directory_service.v1"];
    if cfg.private_contact_discovery_enabled {
        discovery_profiles.push("cx.private_contact_discovery.v1");
    }

    let body = DescribeResponse {
        service_did: &cfg.service_did,
        public_base_url: &cfg.public_base_url,
        resource_types: &["space", "organization", "actor", "applet", "handle"],
        discovery_profiles,
        restricted_query_proof: true,
        ingest_modes: cfg.ingest_modes.iter().map(|m| m.as_str()).collect(),
        accept_policy_kind: accept_policy_str(cfg),
        accept_policy_ref: cfg.accept_policy_ref.as_deref(),
        default_ttl_seconds: cfg.default_ttl.as_secs(),
        max_ttl_seconds: cfg.max_ttl.as_secs(),
        revalidation_grace_seconds: cfg.revalidation_grace.as_secs(),
        accepted_resource_kinds: cfg
            .accepted_resource_kinds
            .iter()
            .map(|k| k.as_str())
            .collect(),
        accepted_did_methods: &cfg.accepted_did_methods,
        takedown_contact: cfg.takedown_contact.as_deref(),
        rate_limits: json!({
            "per_resource_per_min": cfg.rate_limit_per_resource_per_min,
            "max_psi_queries_per_epoch": cfg.max_psi_queries_per_epoch,
            "psi_epoch_seconds": cfg.psi_epoch_seconds,
            "psi_key_retention_seconds": cfg.psi_key_retention_seconds,
            "query_latency_floor_ms": cfg.query_latency_floor.as_millis(),
            "query_latency_jitter_ms": cfg.query_latency_jitter.as_millis(),
        }),
    };
    res.render(Json(body));
}

fn accept_policy_str(cfg: &AppConfig) -> &'static str {
    use crate::config::AcceptPolicyKind::*;
    match cfg.accept_policy_kind {
        Open => "open",
        Allowlist => "allowlist",
        TrustRootSigned => "trust_root_signed",
        OperatorReview => "operator_review",
    }
}
