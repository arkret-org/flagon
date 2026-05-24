//! `cx.directory.describe` — service capability advertisement.
//!
//! Round 4 (spec a77b995) — the response is the canonical `ServerDescription`
//! v2 (17 required top-level fields, `trust_domain` included). Validated via
//! [`contrix_sdk::ServerDescription::validate_v2`] BEFORE serialisation; a
//! validation failure renders an `internal_error` rather than letting a
//! malformed `verified_profiles + development_mode=true` slip through.
//!
//! Directory-service-specific extension fields (`accept_policy`,
//! `accepted_resource_kinds`, `ingest_modes`, `ttl`, etc.) ride alongside
//! the canonical 17 as non-required extensions so the rest of the
//! `discovery-directory.md` §9 surface stays intact.

use salvo::prelude::*;
use serde_json::{Value as JsonValue, json};

use contrix_sdk::{
    ClaimedProfileEntry, CompatSurfaceEntry, Did, ServerDescription, TypedTrustDomainId,
    VerifiedProfileEntry,
};

use crate::config::AppConfig;
use crate::state::AppState;

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
    match build_describe_response_value(state.config()) {
        Ok(value) => res.render(Json(value)),
        Err(message) => {
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            res.render(Json(json!({
                "ok": false,
                "error": { "code": "internal_error", "message": message },
            })));
        }
    }
}

/// Round 4 — build the `ServiceDescribe` v2 envelope plus the
/// directory-service-specific extension fields. Runs
/// [`ServerDescription::validate_v2`] before returning so a mis-configured
/// deployment (e.g. `development_mode=true` paired with non-empty
/// `verified_profiles`) fails closed.
pub(crate) fn build_describe_response_value(cfg: &AppConfig) -> Result<JsonValue, String> {
    let service_did = Did::new(cfg.service_did.clone())
        .map_err(|err| format!("TEABAY_SERVICE_DID is not a valid DID: {err}"))?;
    let trust_domain = TypedTrustDomainId::new(cfg.trust_domain.clone())
        .map_err(|err| format!("TEABAY_TRUST_DOMAIN is not a valid cx:trust_domain: {err}"))?;

    let development_mode = cfg.development_mode;

    // Round 4 — `supported_profiles` is the union of the directory
    // baseline profile and (optionally) the private-contact-discovery
    // extension profile. Empty array is valid; missing is not.
    let mut supported_profiles = vec!["cx.profile.directory_service.v1".to_owned()];
    if cfg.private_contact_discovery_enabled {
        supported_profiles.push("cx.private_contact_discovery.v1".to_owned());
    }

    // Operations the directory publishes (mirrors `crate::kinds::DIRECTORY_OPERATIONS`).
    let supported_operations: Vec<String> = vec![
        "cx.directory.describe",
        "cx.directory.search_realms",
        "cx.directory.resolve_realm",
        "cx.directory.search_organizations",
        "cx.directory.resolve_organization",
        "cx.directory.search_actors",
        "cx.directory.search_users",
        "cx.directory.resolve_handle",
        "cx.directory.announce",
        "cx.directory.withdraw",
        "cx.directory.push.register",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();

    // Transport / encoding bindings this service speaks.
    let supported_bindings = vec![json!({
        "kind": "http_json",
        "media_type": "application/json",
        "transport": "rfc9421_http_message_signature",
    })];

    let supported_features: Vec<String> = vec![
        "directory.search",
        "directory.resolve",
        "directory.ingest_push",
        "directory.ingest_pull",
        "directory.subscribe",
        "directory.announce",
        "directory.takedown",
        "federation.idempotency_historical_only",
        "federation.s2s_trust_domain_headers",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();

    // `auth_metadata` advertises the transport-layer auth that ingest
    // mounts (RFC 9421 HTTP Message Signature) and the admin bearer.
    let auth_metadata = json!({
        "ingest": {
            "kind": "rfc9421_http_message_signature",
            "required": cfg.require_http_sig,
            "algorithms": ["ed25519"],
        },
        "admin": {
            "kind": "bearer_token",
            "required": cfg.admin_token.is_some(),
        },
    });

    let limits = json!({
        "per_resource_per_min": cfg.rate_limit_per_resource_per_min,
        "max_psi_queries_per_epoch": cfg.max_psi_queries_per_epoch,
        "psi_epoch_seconds": cfg.psi_epoch_seconds,
        "psi_key_retention_seconds": cfg.psi_key_retention_seconds,
        "query_latency_floor_ms": cfg.query_latency_floor.as_millis() as u64,
        "query_latency_jitter_ms": cfg.query_latency_jitter.as_millis() as u64,
        "default_ttl_seconds": cfg.default_ttl.as_secs(),
        "max_ttl_seconds": cfg.max_ttl.as_secs(),
        "revalidation_grace_seconds": cfg.revalidation_grace.as_secs(),
    });

    // `plaintext_visibility` advertises that the directory does NOT
    // surface plaintext message bodies — directory entries are
    // resource-authored projections. Receivers MUST treat a missing
    // value as `untrusted` (round-4 spec); we declare `none` explicitly.
    let plaintext_visibility = json!({
        "kind": "none",
        "scope": "directory_resources_only",
    });

    let implemented_features: Vec<String> = vec![
        "directory.search",
        "directory.resolve",
        "directory.ingest_push",
        "directory.ingest_pull",
        "directory.subscribe",
        "directory.announce",
        "directory.takedown",
        "federation.idempotency_historical_only",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();

    // `claimed_profiles` mirrors `supported_profiles` here — every
    // profile the directory advertises is self-claimed. `verified_profiles`
    // is empty until a cotest verifier is wired in; the
    // `development_mode=true ⇒ verified_profiles=[]` invariant is
    // enforced by `ServerDescription::validate_v2`.
    //
    // Round 4 — `claimed_profiles` / `verified_profiles` / `compat_surfaces`
    // are typed entries in the SDK (`ClaimedProfileEntry` /
    // `VerifiedProfileEntry` / `CompatSurfaceEntry`), not bare strings.
    let claimed_profiles: Vec<ClaimedProfileEntry> = supported_profiles
        .iter()
        .map(ClaimedProfileEntry::self_claimed)
        .collect();
    let verified_profiles: Vec<VerifiedProfileEntry> = Vec::new();

    let experimental_features: Vec<String> = vec![
        "directory.webhook_fanout",
        "directory.operator_takedown_notification",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();

    // `compat_surfaces` — none yet. Reserve the field for back-compat
    // shims (e.g. a future pre-round-4 frontier-shape adapter).
    let compat_surfaces: Vec<CompatSurfaceEntry> = Vec::new();

    let describe_body = ServerDescription {
        service_did,
        trust_domain,
        service_type: "directory".to_owned(),
        protocol_version: contrix_sdk::PROTOCOL_VERSION.to_owned(),
        supported_profiles,
        supported_operations,
        supported_bindings,
        supported_features,
        auth_metadata,
        limits,
        plaintext_visibility,
        implemented_features,
        claimed_profiles,
        verified_profiles,
        experimental_features,
        compat_surfaces,
        development_mode,
        rate_limit: json!({
            "kind": "windowed",
            "per_resource_per_minute": cfg.rate_limit_per_resource_per_min,
        }),
        supported_reducer_profiles: Vec::new(),
        supported_schema_profiles: Vec::new(),
        frontier: Vec::new(),
        snapshot_frontier: Vec::new(),
        reducer_profile: None,
        last_materialized_at: None,
    };
    describe_body
        .validate_v2()
        .map_err(|err| format!("ServiceDescribe v2 validation failed: {err}"))?;

    let mut value = serde_json::to_value(&describe_body)
        .map_err(|err| format!("ServiceDescribe v2 serialisation failed: {err}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "ServiceDescribe v2 must serialise as a JSON object".to_owned())?;

    // Directory-specific extension fields (non-required, ride alongside
    // the canonical 17). The directory surface specification
    // (discovery-directory.md §9) requires these; ServiceDescribe v2 only
    // tightens the *shared* required surface.
    object.insert(
        "public_base_url".to_owned(),
        JsonValue::String(cfg.public_base_url.clone()),
    );
    object.insert(
        "resource_types".to_owned(),
        json!(["space", "organization", "actor", "applet", "handle"]),
    );
    object.insert("restricted_query_proof".to_owned(), JsonValue::Bool(true));
    object.insert(
        "ingest_modes".to_owned(),
        JsonValue::Array(
            cfg.ingest_modes
                .iter()
                .map(|m| JsonValue::String(m.as_str().to_owned()))
                .collect(),
        ),
    );
    object.insert(
        "accept_policy_kind".to_owned(),
        JsonValue::String(accept_policy_str(cfg).to_owned()),
    );
    object.insert(
        "accept_policy_ref".to_owned(),
        cfg.accept_policy_ref
            .as_ref()
            .map(|s| JsonValue::String(s.clone()))
            .unwrap_or(JsonValue::Null),
    );
    object.insert(
        "default_ttl_seconds".to_owned(),
        json!(cfg.default_ttl.as_secs()),
    );
    object.insert("max_ttl_seconds".to_owned(), json!(cfg.max_ttl.as_secs()));
    object.insert(
        "revalidation_grace_seconds".to_owned(),
        json!(cfg.revalidation_grace.as_secs()),
    );
    object.insert(
        "accepted_resource_kinds".to_owned(),
        JsonValue::Array(
            cfg.accepted_resource_kinds
                .iter()
                .map(|k| JsonValue::String(k.as_str().to_owned()))
                .collect(),
        ),
    );
    object.insert(
        "accepted_did_methods".to_owned(),
        JsonValue::Array(
            cfg.accepted_did_methods
                .iter()
                .map(|m| JsonValue::String(m.clone()))
                .collect(),
        ),
    );
    object.insert(
        "takedown_contact".to_owned(),
        cfg.takedown_contact
            .as_ref()
            .map(|s| JsonValue::String(s.clone()))
            .unwrap_or(JsonValue::Null),
    );
    object.insert(
        "rate_limits".to_owned(),
        json!({
            "per_resource_per_min": cfg.rate_limit_per_resource_per_min,
            "max_psi_queries_per_epoch": cfg.max_psi_queries_per_epoch,
            "psi_epoch_seconds": cfg.psi_epoch_seconds,
            "psi_key_retention_seconds": cfg.psi_key_retention_seconds,
            "query_latency_floor_ms": cfg.query_latency_floor.as_millis() as u64,
            "query_latency_jitter_ms": cfg.query_latency_jitter.as_millis() as u64,
        }),
    );
    object.insert(
        "limitations".to_owned(),
        JsonValue::Array(describe_limitations(cfg)),
    );

    Ok(value)
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

fn describe_limitations(cfg: &AppConfig) -> Vec<JsonValue> {
    let mut limitations: Vec<JsonValue> = Vec::new();
    if cfg.pull_interval.is_none() {
        limitations.push(json!({
            "feature": "pull_mode_ingest",
            "status": "disabled",
            "detail": "TEABAY_PULL_INTERVAL_SECONDS=0 disables periodic pull revalidation; ingest_modes omits pull.",
        }));
    }
    limitations.push(json!({
        "feature": "operator_takedown_notification",
        "status": "limited",
        "detail": if cfg.takedown_contact.is_some() {
            "operator takedown is audit-backed and takedown_contact is advertised, but resource-side notification transport is not implemented."
        } else {
            "operator takedown is audit-backed, but no takedown_contact is configured and resource-side notification transport is not implemented."
        },
    }));
    limitations.push(json!({
        "feature": "webhook_fanout_delivery",
        "status": "best_effort",
        "detail": "cx.directory.push.register webhook fanout is HMAC-signed and filtered, but delivery retry/durability is not implemented.",
    }));
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
            trust_domain: "cx:trust_domain:local.test".to_owned(),
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

    /// Round 4 — the describe response MUST carry every one of the 17
    /// required `ServerDescription` v2 fields, including `trust_domain`.
    #[test]
    fn describe_emits_v2_required_fields() {
        let value = build_describe_response_value(&cfg(true, true)).expect("describe builds");

        for required in [
            "service_did",
            "trust_domain",
            "service_type",
            "protocol_version",
            "supported_profiles",
            "supported_operations",
            "supported_bindings",
            "supported_features",
            "auth_metadata",
            "limits",
            "plaintext_visibility",
            "implemented_features",
            "claimed_profiles",
            "verified_profiles",
            "experimental_features",
            "compat_surfaces",
            "development_mode",
        ] {
            assert!(
                value.get(required).is_some(),
                "ServiceDescribe v2 must carry required field `{required}`"
            );
        }

        assert_eq!(value["development_mode"], true);
        assert_eq!(value["trust_domain"], "cx:trust_domain:local.test");
        assert_eq!(value["service_did"], "did:web:directory.test");
        assert_eq!(value["service_type"], "directory");
        // verified_profiles MUST be empty when development_mode = true.
        assert!(
            value["verified_profiles"].as_array().unwrap().is_empty(),
            "dev mode must not advertise verified_profiles"
        );
    }

    /// Round 4 — directory-specific extensions ride alongside the
    /// canonical 17. The §9 surface still ships
    /// `accepted_resource_kinds`, `ingest_modes`, `rate_limits`, etc.
    #[test]
    fn describe_carries_directory_extensions() {
        let value = build_describe_response_value(&cfg(false, true)).expect("describe builds");
        assert!(value.get("accepted_resource_kinds").is_some());
        assert!(value.get("ingest_modes").is_some());
        assert!(value.get("rate_limits").is_some());
        assert!(value.get("accept_policy_kind").is_some());
        assert_eq!(value["accept_policy_kind"], "open");
        assert_eq!(value["public_base_url"], "http://directory.test");
        assert!(
            value["supported_operations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|op| op == "cx.directory.describe")
        );
    }

    /// Round 4 — `validate_v2` fails closed when development mode is set
    /// alongside a non-empty `verified_profiles`. The handler short-
    /// circuits through `internal_error`; here we exercise the
    /// validator directly to assert the contract.
    #[test]
    fn describe_rejects_dev_mode_with_verified_profiles() {
        let describe_body = ServerDescription {
            service_did: Did::new("did:web:directory.test").unwrap(),
            trust_domain: TypedTrustDomainId::new("cx:trust_domain:local.test").unwrap(),
            service_type: "directory".to_owned(),
            protocol_version: contrix_sdk::PROTOCOL_VERSION.to_owned(),
            supported_profiles: vec!["cx.profile.directory_service.v1".to_owned()],
            supported_operations: Vec::new(),
            supported_bindings: Vec::new(),
            supported_features: Vec::new(),
            auth_metadata: json!({}),
            limits: json!({}),
            plaintext_visibility: json!({"kind": "none"}),
            implemented_features: Vec::new(),
            claimed_profiles: Vec::new(),
            verified_profiles: vec![VerifiedProfileEntry {
                profile_id: "cx.profile.directory_service.v1".to_owned(),
                claim_kind: contrix_sdk::CotestVerifiedKind::CotestVerified,
                cotest_run_id: "test-run".to_owned(),
                artifact_digest:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_owned(),
                artifact_ref: "file:///tmp/verified-profiles.json".to_owned(),
                cotest_issuer_did: Did::new("did:web:cotest.example").unwrap(),
                signature: "eddsa-jcs-b64url:test-signature".to_owned(),
                timestamp: chrono::Utc::now(),
                expires_at: None,
                extra: Default::default(),
            }],
            experimental_features: Vec::new(),
            compat_surfaces: Vec::new(),
            development_mode: true,
            rate_limit: JsonValue::Null,
            supported_reducer_profiles: Vec::new(),
            supported_schema_profiles: Vec::new(),
            frontier: Vec::new(),
            snapshot_frontier: Vec::new(),
            reducer_profile: None,
            last_materialized_at: None,
        };
        assert!(describe_body.validate_v2().is_err());
    }

    /// Round R2/R3 carry-forward — when private contact discovery is
    /// disabled, the profile MUST NOT appear in either
    /// `supported_profiles` or `claimed_profiles`.
    #[test]
    fn describe_omits_pcd_profile_when_disabled() {
        let value = build_describe_response_value(&cfg(false, false)).expect("describe builds");
        let supported = value["supported_profiles"].as_array().unwrap();
        assert!(
            !supported
                .iter()
                .any(|p| p == "cx.private_contact_discovery.v1"),
            "PCD must not appear in supported_profiles when disabled"
        );
        let claimed = value["claimed_profiles"].as_array().unwrap();
        assert!(
            !claimed
                .iter()
                .any(|p| p["profile_id"] == "cx.private_contact_discovery.v1"),
            "PCD must not be claimed when disabled"
        );
    }
}
