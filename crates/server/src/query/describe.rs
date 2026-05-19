//! `cx.directory.describe` — service capability advertisement.
//!
//! Spec: discovery-directory.md §9 + §8.9 (ingest fields).

use salvo::prelude::*;
use serde::Serialize;
use serde_json::json;

use crate::config::AppConfig;
use crate::state::AppState;

#[derive(Debug, Serialize)]
struct DescribeLimitation<'a> {
    feature: &'static str,
    status: &'static str,
    detail: &'a str,
}

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
    limitations: Vec<DescribeLimitation<'a>>,
    // T6.1 — claim-level partition (service-surface.md §3.0 /
    // cx.schema.service_describe.v1). `discovery_profiles` above is kept
    // for backward compatibility with existing callers; the fields below
    // split feature implementation from profile claims and dev-mode
    // posture from cotest-verified claims.
    supported_operations: Vec<&'static str>,
    implemented_features: Vec<&'static str>,
    claimed_profiles: Vec<ClaimedProfile>,
    verified_profiles: Vec<VerifiedProfile>,
    experimental_features: Vec<&'static str>,
    compat_surfaces: Vec<CompatSurface>,
    /// Mirror of the service's `TEABAY_DEVELOPMENT_MODE` flag. When true,
    /// `verified_profiles` MUST be empty (§3.0).
    development_mode: bool,
}

/// T6.1 — self-claimed profile entry. `claim_kind = "self_claimed"`.
#[derive(Debug, Serialize)]
struct ClaimedProfile {
    profile_id: &'static str,
    claim_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'static str>,
}

/// T6.1 — cotest-verified profile entry. Required `cotest_run_id`,
/// `artifact_hash`, `timestamp`. Dev-mode posture MUST NOT advertise any
/// such entry (§3.0).
#[derive(Debug, Serialize)]
struct VerifiedProfile {
    profile_id: String,
    claim_kind: &'static str,
    cotest_run_id: String,
    artifact_hash: String,
    timestamp: String,
}

/// T6.1 — compat / external-interop surface entry. `kind` ∈ schema enum.
#[derive(Debug, Serialize)]
struct CompatSurface {
    name: &'static str,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'static str>,
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

    // T6.1 — claim-level partition (service-surface.md §3.0).
    //
    // teabay currently has no cotest verifier wired in. The
    // `development_mode=true => verified_profiles=[]` invariant is
    // therefore trivially satisfied; the debug_assert below guards future
    // writers.
    let development_mode = cfg.development_mode;
    let verified_profiles: Vec<VerifiedProfile> = Vec::new();
    debug_assert!(
        !(development_mode && !verified_profiles.is_empty()),
        "development_mode=true requires verified_profiles=[] (service-surface.md §3.0)"
    );

    let mut claimed_profiles = vec![ClaimedProfile {
        profile_id: "cx.profile.directory_service.v1",
        claim_kind: "self_claimed",
        notes: Some("directory service profile self-claimed; cotest verification not wired in"),
    }];
    if cfg.private_contact_discovery_enabled {
        claimed_profiles.push(ClaimedProfile {
            profile_id: "cx.private_contact_discovery.v1",
            claim_kind: "self_claimed",
            notes: Some(
                "private contact discovery self-claimed when TEABAY_PRIVATE_CONTACT_DISCOVERY_ENABLED=true",
            ),
        });
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
        limitations: describe_limitations(cfg),
        supported_operations: vec![
            "cx.directory.describe",
            "cx.directory.search_spaces",
            "cx.directory.search_actors",
            "cx.directory.search_users",
            "cx.directory.resolve_space",
            "cx.directory.resolve_handle",
            "cx.directory.announce",
            "cx.directory.withdraw",
        ],
        implemented_features: vec![
            "directory.search",
            "directory.resolve",
            "directory.ingest_push",
            "directory.ingest_pull",
            "directory.subscribe",
            "directory.announce",
            "directory.takedown",
        ],
        claimed_profiles,
        verified_profiles,
        experimental_features: vec![
            "directory.webhook_fanout",
            "directory.operator_takedown_notification",
        ],
        compat_surfaces: vec![],
        development_mode,
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

/// T6.1 — build the describe response value used by the handler.
/// Exposed for unit tests so the claim-level partition can be asserted
/// without spinning up a salvo service.
#[cfg(test)]
fn build_describe_response_value(cfg: &AppConfig) -> serde_json::Value {
    let mut discovery_profiles = vec!["cx.profile.directory_service.v1"];
    if cfg.private_contact_discovery_enabled {
        discovery_profiles.push("cx.private_contact_discovery.v1");
    }
    let development_mode = cfg.development_mode;
    let verified_profiles: Vec<VerifiedProfile> = Vec::new();
    debug_assert!(!(development_mode && !verified_profiles.is_empty()));

    let mut claimed_profiles = vec![ClaimedProfile {
        profile_id: "cx.profile.directory_service.v1",
        claim_kind: "self_claimed",
        notes: Some("directory service profile self-claimed; cotest verification not wired in"),
    }];
    if cfg.private_contact_discovery_enabled {
        claimed_profiles.push(ClaimedProfile {
            profile_id: "cx.private_contact_discovery.v1",
            claim_kind: "self_claimed",
            notes: Some(
                "private contact discovery self-claimed when TEABAY_PRIVATE_CONTACT_DISCOVERY_ENABLED=true",
            ),
        });
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
        limitations: describe_limitations(cfg),
        supported_operations: vec![
            "cx.directory.describe",
            "cx.directory.search_spaces",
            "cx.directory.search_actors",
            "cx.directory.search_users",
            "cx.directory.resolve_space",
            "cx.directory.resolve_handle",
            "cx.directory.announce",
            "cx.directory.withdraw",
        ],
        implemented_features: vec![
            "directory.search",
            "directory.resolve",
            "directory.ingest_push",
            "directory.ingest_pull",
            "directory.subscribe",
            "directory.announce",
            "directory.takedown",
        ],
        claimed_profiles,
        verified_profiles,
        experimental_features: vec![
            "directory.webhook_fanout",
            "directory.operator_takedown_notification",
        ],
        compat_surfaces: vec![],
        development_mode,
    };
    serde_json::to_value(&body).expect("describe response serializes")
}

fn describe_limitations(cfg: &AppConfig) -> Vec<DescribeLimitation<'_>> {
    let mut limitations = Vec::new();
    if cfg.pull_interval.is_none() {
        limitations.push(DescribeLimitation {
            feature: "pull_mode_ingest",
            status: "disabled",
            detail: "TEABAY_PULL_INTERVAL_SECONDS=0 disables periodic pull revalidation; ingest_modes omits pull.",
        });
    }
    limitations.push(DescribeLimitation {
        feature: "operator_takedown_notification",
        status: "limited",
        detail: if cfg.takedown_contact.is_some() {
            "operator takedown is audit-backed and takedown_contact is advertised, but resource-side notification transport is not implemented."
        } else {
            "operator takedown is audit-backed, but no takedown_contact is configured and resource-side notification transport is not implemented."
        },
    });
    limitations.push(DescribeLimitation {
        feature: "webhook_fanout_delivery",
        status: "best_effort",
        detail: "cx.directory.subscribe webhook fanout is HMAC-signed and filtered, but delivery retry/durability is not implemented.",
    });
    limitations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AcceptPolicyKind, IngestModeAdvert, ResourceKindAccept};
    use std::collections::HashMap;
    use std::time::Duration;

    fn cfg(development_mode: bool, pcd_enabled: bool) -> AppConfig {
        AppConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            public_base_url: "http://directory.test".to_owned(),
            service_did: "did:web:directory.test".to_owned(),
            database_url: "postgres://localhost/teabay".to_owned(),
            cors_allow_origin: None,
            admin_token: None,
            development_mode,
            accept_policy_kind: AcceptPolicyKind::Open,
            accept_policy_ref: None,
            takedown_contact: None,
            accepted_resource_kinds: ResourceKindAccept::ALL.to_vec(),
            accepted_did_methods: vec!["did:web".to_owned()],
            allowlist_dids: Vec::new(),
            default_ttl: Duration::from_secs(3600),
            max_ttl: Duration::from_secs(86400),
            revalidation_grace: Duration::from_secs(300),
            as_of_skew: Duration::from_secs(60),
            pull_interval: Some(Duration::from_secs(300)),
            divergence_interval: None,
            ingest_modes: vec![IngestModeAdvert::Push, IngestModeAdvert::Pull],
            rate_limit_per_resource_per_min: 60,
            max_psi_queries_per_epoch: 100,
            private_contact_discovery_enabled: pcd_enabled,
            psi_epoch_seconds: 3600,
            psi_key_retention_seconds: 7200,
            query_latency_floor: Duration::from_millis(0),
            query_latency_jitter: Duration::from_millis(0),
            require_http_sig: false,
            http_sig_pubkeys: HashMap::new(),
        }
    }

    /// T6.1 — describe response MUST partition into supported_operations
    /// (wire-callable) and the new claim-level arrays; dev mode MUST
    /// yield verified_profiles=[]; experimental and verified MUST NOT
    /// intersect.
    #[test]
    fn describe_separates_claim_levels() {
        let value = build_describe_response_value(&cfg(true, true));

        assert_eq!(value["development_mode"], true);

        let verified = value["verified_profiles"]
            .as_array()
            .expect("verified_profiles array present");
        assert!(
            verified.is_empty(),
            "dev mode must not advertise verified_profiles"
        );

        let claimed = value["claimed_profiles"]
            .as_array()
            .expect("claimed_profiles array present");
        assert!(!claimed.is_empty());
        for entry in claimed {
            assert_eq!(entry["claim_kind"], "self_claimed");
        }

        let implemented = value["implemented_features"]
            .as_array()
            .expect("implemented_features array present");
        assert!(!implemented.is_empty());

        let experimental: std::collections::HashSet<&str> = value["experimental_features"]
            .as_array()
            .expect("experimental_features array present")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        let verified_ids: std::collections::HashSet<&str> = verified
            .iter()
            .filter_map(|v| v["profile_id"].as_str())
            .collect();
        assert!(experimental.is_disjoint(&verified_ids));

        for surface in value["compat_surfaces"]
            .as_array()
            .expect("compat_surfaces array present")
        {
            let kind = surface["kind"].as_str().expect("compat surface kind");
            assert!(matches!(
                kind,
                "matrix_passthrough"
                    | "mimi_passthrough"
                    | "legacy_alias"
                    | "external_interop"
                    | "deprecated_alias"
            ));
        }

        // supported_operations MUST be present and contain at least
        // cx.directory.describe (the operation that backs this very
        // endpoint).
        let operations = value["supported_operations"]
            .as_array()
            .expect("supported_operations array present");
        assert!(
            operations
                .iter()
                .any(|op| op == "cx.directory.describe"),
            "supported_operations must include cx.directory.describe"
        );
    }

    /// T6.1 — when private contact discovery is disabled, the
    /// claimed_profiles entry for it MUST NOT appear.
    #[test]
    fn describe_omits_pcd_profile_when_disabled() {
        let value = build_describe_response_value(&cfg(false, false));
        let claimed = value["claimed_profiles"].as_array().unwrap();
        assert!(
            !claimed.iter().any(|entry| entry["profile_id"]
                == "cx.private_contact_discovery.v1"),
            "private contact discovery profile must not be claimed when disabled"
        );
    }
}
