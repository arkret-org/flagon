//! `ak.find.directory.read.describe` — service capability advertisement.
//!
//! The response is the canonical `ServiceDescribe`
//! shape (17 required top-level fields, `trust_domain` included). Validated via
//! [`arkret_sdk::ServiceDescribe::validate`] BEFORE serialisation; a
//! validation failure renders an `internal_error` rather than letting a
//! malformed `verified_profiles + development_mode=true` slip through.
//!
//! Directory-service-specific fields (`resource_kinds`,
//! `accepted_resource_kinds`, `ingest_modes`, `ttl`, etc.) are registered
//! ServiceDescribe overlay fields, not vendor-specific `x_*` extensions.

use std::collections::BTreeMap;

use arkret_sdk::{
    AuthMetadata, BindingKind, ClaimedProfileEntry, DidCoreId, DirectoryAcceptPolicyKind,
    DirectoryIngestMode, DirectoryResourceKind, EgressNetworkPolicy, InteropSurfaceEntry,
    PlaintextVisibility, RateLimitPolicy, ServerLimits, ServiceDescribe, SupportedBinding,
    TrustDomainId, VerifiedProfileEntry,
};
use salvo::prelude::*;
use serde_json::{Value as JsonValue, json};

use crate::config::{AcceptPolicyKind, AppConfig, IngestModeAdvert};
use crate::state::AppState;

#[handler]
pub async fn describe(depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
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

/// Build the `ServiceDescribe` envelope plus the registered
/// directory-service overlay fields. Runs
/// [`ServiceDescribe::validate`] before returning so a misconfigured
/// deployment (e.g. `development_mode=true` paired with non-empty
/// `verified_profiles`) fails closed.
pub(crate) fn build_describe_response_value(cfg: &AppConfig) -> Result<JsonValue, String> {
    let service_id = DidCoreId::new(cfg.service_id.clone())
        .map_err(|err| format!("configured service core id is invalid: {err}"))?;
    let trust_domain = TrustDomainId::new(cfg.trust_domain.clone())
        .map_err(|err| format!("TEABAY_TRUST_DOMAIN is not a valid ak:trust_domain: {err}"))?;

    let development_mode = cfg.development_mode;

    // `supported_profiles` is the union of the directory
    // baseline profile and (optionally) the private-contact-discovery
    // extension profile. Empty array is valid; missing is not.
    let mut supported_profiles = vec![arkret_wire::ProfileId::DIRECTORY_SERVICE_V1.to_owned()];
    if cfg.private_contact_discovery_enabled {
        supported_profiles.push("ak.private_contact_discovery.v1".to_owned());
    }
    let directory_discovery_profiles = supported_profiles.clone();

    // Operations the directory publishes. Single source of truth:
    // `crate::kinds::SUPPORTED_OPERATIONS` (no parallel string literals here).
    let mut supported_operations: Vec<String> = crate::kinds::SUPPORTED_OPERATIONS
        .iter()
        .map(|op| (*op).to_owned())
        .collect();
    if cfg.private_contact_discovery_enabled {
        supported_operations.push(
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_PRIVATE_CONTACT_DISCOVERY
                .to_owned(),
        );
    }

    // Transport / encoding bindings this service speaks. Strongly typed
    // (`SupportedBinding`); the transport-specific keys ride in `extra`.
    let supported_bindings = vec![
        SupportedBinding::new(BindingKind::HttpJson)
            .with_base_url(cfg.public_base_url.clone())
            .with_extra(
                "media_type",
                JsonValue::String("application/json".to_owned()),
            )
            .with_extra(
                "transport",
                JsonValue::String("rfc9421_http_message_signature".to_owned()),
            ),
    ];

    let supported_features: Vec<String> = vec![
        "directory.search",
        "directory.resolve",
        "directory.ingest_push",
        "directory.subscribe",
        "directory.announce",
        "directory.takedown",
        "directory.takedown_appeal",
        "federation.idempotency_historical_only",
        "federation.s2s_trust_domain_headers",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();

    // `auth_metadata` advertises the transport-layer auth that ingest
    // mounts (RFC 9421 HTTP Message Signature) and the admin HMAC
    // surface. Static bearer auth is development-only. The directory has
    // no end-user account surface, so `mode` is `service_transport`; the
    // ingest/admin descriptors ride in `x_teabay_*` extension keys
    // (`auth_metadata` is `additionalProperties: true`).
    let mut auth_metadata = AuthMetadata::minimal("service_transport");
    auth_metadata.extra.insert(
        "x_teabay_ingest".to_owned(),
        json!({
            "kind": "rfc9421_http_message_signature",
            "required": cfg.require_http_sig,
            "algorithms": ["ed25519"],
        }),
    );
    auth_metadata.extra.insert(
        "x_teabay_admin".to_owned(),
        json!({
            "kind": "rotating_hmac",
            "required": true,
            "development_static_bearer": cfg.development_mode && cfg.admin_token.is_some(),
        }),
    );

    let limits = ServerLimits {
        extensions: BTreeMap::from([
            (
                "per_resource_per_min".to_owned(),
                json!(cfg.rate_limit_per_resource_per_min),
            ),
            (
                "max_psi_queries_per_window".to_owned(),
                json!(cfg.max_psi_queries_per_window),
            ),
            (
                "psi_quota_window_seconds".to_owned(),
                json!(cfg.psi_quota_window_seconds),
            ),
            ("psi_epoch_seconds".to_owned(), json!(cfg.psi_epoch_seconds)),
            (
                "psi_key_retention_seconds".to_owned(),
                json!(cfg.psi_key_retention_seconds),
            ),
            (
                "psi_ciphersuite".to_owned(),
                json!(crate::query::psi::VOPRF_CIPHERSUITE),
            ),
            (
                "psi_key_epoch".to_owned(),
                json!(crate::query::psi::current_epoch(cfg)),
            ),
            (
                "psi_batch_item_count".to_owned(),
                json!(crate::query::psi::PSI_BATCH_SIZE),
            ),
            (
                "psi_digest_prefix_length".to_owned(),
                json!(crate::psi_index::PSI_DIGEST_PREFIX_LENGTH),
            ),
            (
                "query_latency_floor_ms".to_owned(),
                json!(cfg.query_latency_floor.as_millis() as u64),
            ),
            (
                "query_latency_jitter_ms".to_owned(),
                json!(cfg.query_latency_jitter.as_millis() as u64),
            ),
            (
                "default_ttl_seconds".to_owned(),
                json!(cfg.default_ttl.as_secs()),
            ),
            ("max_ttl_seconds".to_owned(), json!(cfg.max_ttl.as_secs())),
            (
                "revalidation_grace_seconds".to_owned(),
                json!(cfg.revalidation_grace.as_secs()),
            ),
        ]),
    };
    let directory_rate_limits = BTreeMap::from([
        (
            "per_resource_per_min".to_owned(),
            json!(cfg.rate_limit_per_resource_per_min),
        ),
        (
            "max_psi_queries_per_window".to_owned(),
            json!(cfg.max_psi_queries_per_window),
        ),
        (
            "psi_quota_window_seconds".to_owned(),
            json!(cfg.psi_quota_window_seconds),
        ),
        ("psi_epoch_seconds".to_owned(), json!(cfg.psi_epoch_seconds)),
        (
            "psi_key_retention_seconds".to_owned(),
            json!(cfg.psi_key_retention_seconds),
        ),
        (
            "psi_ciphersuite".to_owned(),
            json!(crate::query::psi::VOPRF_CIPHERSUITE),
        ),
        (
            "psi_key_epoch".to_owned(),
            json!(crate::query::psi::current_epoch(cfg)),
        ),
        (
            "psi_batch_item_count".to_owned(),
            json!(crate::query::psi::PSI_BATCH_SIZE),
        ),
        (
            "psi_digest_prefix_length".to_owned(),
            json!(crate::psi_index::PSI_DIGEST_PREFIX_LENGTH),
        ),
        (
            "query_latency_floor_ms".to_owned(),
            json!(cfg.query_latency_floor.as_millis() as u64),
        ),
        (
            "query_latency_jitter_ms".to_owned(),
            json!(cfg.query_latency_jitter.as_millis() as u64),
        ),
    ]);

    // `plaintext_visibility` advertises that the directory does NOT
    // surface plaintext message bodies — directory entries are
    // resource-authored projections. Receivers MUST treat a missing
    // value as `untrusted`; we declare `none` explicitly
    // via the strongly typed (closed) `PlaintextVisibility`. The
    // directory-scope note rides in an `x_teabay_*` extension key since
    // the object is `additionalProperties: false` apart from `x_*`.
    let mut plaintext_visibility = PlaintextVisibility::none();
    plaintext_visibility.max_visibility = Some(arkret_sdk::PlaintextMaxVisibility::None);
    plaintext_visibility
        .extra
        .insert(
            "x_teabay_scope".to_owned(),
            JsonValue::String("directory_resources_only".to_owned()),
        )
        .map_err(|error| format!("invalid plaintext visibility extension: {error}"))?;

    let implemented_features: Vec<String> = vec![
        "directory.search",
        "directory.resolve",
        "directory.ingest_push",
        "directory.subscribe",
        "directory.announce",
        "directory.takedown",
        "directory.takedown_appeal",
        "federation.idempotency_historical_only",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();

    // `claimed_profiles` mirrors `supported_profiles` here — every
    // profile the directory advertises is self-claimed. `verified_profiles`
    // is empty until a cotest verifier is wired in; the
    // `development_mode=true ⇒ verified_profiles=[]` invariant is
    // enforced by `ServiceDescribe::validate`.
    //
    // `claimed_profiles` / `verified_profiles` / `interop_surfaces`
    // are typed entries in the SDK (`ClaimedProfileEntry` /
    // `VerifiedProfileEntry` / `InteropSurfaceEntry`), not bare strings.
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

    // `interop_surfaces` — the directory bridges no foreign protocol and
    // serves no delegated resolver surface.
    let interop_surfaces: Vec<InteropSurfaceEntry> = Vec::new();

    let describe_body = ServiceDescribe {
        service_id,
        service_resolution: cfg.service_resolution.clone(),
        trust_domain,
        service_kind: arkret_sdk::ServiceKind::DirectoryService,
        protocol_version: arkret_sdk::PROTOCOL_VERSION.to_owned(),
        supported_profiles,
        profile_bindings: BTreeMap::new(),
        supported_operations,
        supported_bindings,
        supported_features,
        calendar_tzdb_versions: Vec::new(),
        auth_metadata,
        limits,
        plaintext_visibility,
        privacy_derivation: None,
        implemented_features,
        claimed_profiles,
        verified_profiles,
        experimental_features,
        interop_surfaces,
        extensions: BTreeMap::new(),
        egress_network_policy: Some(EgressNetworkPolicy::deny_private_defaults()),
        development_mode,
        receive_policy_constraints: None,
        // Canonical inline rate-limit policy. The directory enforces a
        // per-resource windowed limit; expressed as a windowed policy entry. The
        // ServiceDescribe `anyOf` requires `rate_limit_policy` or
        // `rate_limit_policy_id`.
        rate_limit_policy: Some(RateLimitPolicy::windowed_per_minute(
            cfg.rate_limit_per_resource_per_min,
        )),
        rate_limit_policy_id: None,
        resource_kinds: all_directory_resource_kinds(),
        discovery_profiles: directory_discovery_profiles,
        restricted_query_proof: Some(true),
        ingest_modes: cfg.ingest_modes.iter().map(directory_ingest_mode).collect(),
        accept_policy_kind: Some(directory_accept_policy_kind(cfg.accept_policy_kind)),
        accept_policy_ref: cfg.accept_policy_ref.as_ref().map(|reference| {
            BTreeMap::from([(
                "policy_ref".to_owned(),
                JsonValue::String(reference.clone()),
            )])
        }),
        default_ttl_seconds: Some(cfg.default_ttl.as_secs()),
        max_ttl_seconds: Some(cfg.max_ttl.as_secs()),
        revalidation_grace_seconds: Some(cfg.revalidation_grace.as_secs()),
        accepted_resource_kinds: cfg.accepted_resource_kinds.iter().copied().collect(),
        accepted_did_methods: cfg.accepted_did_methods.clone(),
        takedown_contact: cfg.takedown_contact.clone(),
        rate_limits: Some(directory_rate_limits),
        supported_reducer_profiles: Vec::new(),
        frontier: Vec::new(),
        snapshot_frontier: Vec::new(),
        last_materialized_at: None,
    };
    describe_body
        .validate()
        .map_err(|err| format!("ServiceDescribe validation failed: {err}"))?;

    let mut value = serde_json::to_value(&describe_body)
        .map_err(|err| format!("ServiceDescribe serialisation failed: {err}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "ServiceDescribe must serialise as a JSON object".to_owned())?;

    // Teabay-private describe fields stay namespaced under `x_teabay_*`.
    // The routable base URL is part of the canonical `http_json` binding,
    // never inferred from `service_id` or duplicated as an authority hint.
    object.insert(
        "x_teabay_limitations".to_owned(),
        JsonValue::Array(describe_limitations(cfg)),
    );

    Ok(value)
}

fn all_directory_resource_kinds() -> Vec<DirectoryResourceKind> {
    DirectoryResourceKind::ALL.to_vec()
}

fn directory_ingest_mode(mode: &IngestModeAdvert) -> DirectoryIngestMode {
    match mode {
        IngestModeAdvert::Push => DirectoryIngestMode::Push,
    }
}

fn directory_accept_policy_kind(kind: AcceptPolicyKind) -> DirectoryAcceptPolicyKind {
    match kind {
        AcceptPolicyKind::Open => DirectoryAcceptPolicyKind::Open,
        AcceptPolicyKind::Allowlist => DirectoryAcceptPolicyKind::Allowlist,
        AcceptPolicyKind::OperatorReview => DirectoryAcceptPolicyKind::OperatorReview,
    }
}

fn describe_limitations(cfg: &AppConfig) -> Vec<JsonValue> {
    let mut limitations: Vec<JsonValue> = Vec::new();
    limitations.push(json!({
        "feature": "pull_mode_ingest",
        "status": "unsupported",
        "detail": "The v1 specification does not yet define the required Directory-specific state-only pull operation or DTO; this service only advertises push ingest.",
    }));
    limitations.push(json!({
        "feature": "cross_directory_divergence",
        "status": "unsupported",
        "detail": "Peer directory core ids have no configured verified current-resolution carrier. The worker cannot be enabled and no id is interpreted as a URL authority.",
    }));
    limitations.push(json!({
        "feature": "operator_takedown_notification",
        "status": if cfg.takedown_contact.is_some() { "best_effort" } else { "no_contact_configured" },
        "detail": if cfg.takedown_contact.is_some() {
            "operator takedown is audit-backed; notification_status starts as pending and the notifier performs HMAC-signed webhook fanout with retry/DLQ tracking."
        } else {
            "operator takedown is audit-backed, but no takedown_contact is configured; notification_status starts as no_takedown_contact_configured."
        },
    }));
    limitations.push(json!({
        "feature": "webhook_fanout_delivery",
        "status": "best_effort",
        "detail": "ak.find.directory.push.command.register webhook fanout is HMAC-signed and filtered, but delivery retry/durability is not implemented.",
    }));
    limitations
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use arkret_sdk::{DidFullId, ResolutionCommitment};

    use super::*;
    use crate::config::{AcceptPolicyKind, IngestModeAdvert};

    fn cfg(development_mode: bool, pcd_enabled: bool) -> AppConfig {
        AppConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            metrics_bind: "127.0.0.1:9095".parse().unwrap(),
            public_base_url: "http://directory.test".to_owned(),
            service_id: "ak:did_core:web:directory.test".to_owned(),
            service_full_id: DidFullId::new("did:web:directory.test").unwrap(),
            service_resolution: ResolutionCommitment {
                full_id: DidFullId::new("did:web:directory.test").unwrap(),
                method_history_head: "did-web-document-etag-fixture".to_owned(),
                version_id: "did-web-document-version-fixture".to_owned(),
            },
            trust_domain: "ak:trust_domain:local.test".to_owned(),
            database_url: "postgres://localhost/teabay".to_owned(),
            cors_allow_origin: None,
            admin_csrf_token: None,
            admin_token: None,
            admin_token_rotation_window: Duration::from_secs(1800),
            development_mode,
            accept_policy_kind: AcceptPolicyKind::Open,
            accept_policy_ref: None,
            takedown_contact: None,
            accepted_resource_kinds: DirectoryResourceKind::ALL.to_vec(),
            accepted_did_methods: vec!["did:web".to_owned()],
            default_ttl: Duration::from_secs(3600),
            max_ttl: Duration::from_secs(86400),
            revalidation_grace: Duration::from_secs(300),
            as_of_skew: Duration::from_secs(60),
            ingest_modes: vec![IngestModeAdvert::Push],
            rate_limit_per_resource_per_min: 60,
            query_max_queries_per_ip_per_min: 0,
            query_max_resolves_per_resource_per_min: 0,
            max_psi_queries_per_window: 100,
            psi_quota_window_seconds: 86_400,
            private_contact_discovery_enabled: pcd_enabled,
            psi_epoch_seconds: 3600,
            psi_key_retention_seconds: 7200,
            query_latency_floor: Duration::from_millis(0),
            query_latency_jitter: Duration::from_millis(0),
            require_http_sig: false,
            http_sig_pubkeys: HashMap::new(),
            receipt_signing_key: None,
            db_pool: crate::config::DbPoolConfig::default(),
            expiry_interval: Some(Duration::from_secs(1800)),
            takedown_notifier_interval: Some(Duration::from_secs(60)),
            trusted_proxy: None,
        }
    }

    /// The describe response MUST carry every one of the 17
    /// required `ServiceDescribe` fields, including `trust_domain`.
    #[test]
    fn describe_emits_required_fields() {
        let value = build_describe_response_value(&cfg(true, true)).expect("describe builds");

        for required in [
            "service_id",
            "service_resolution",
            "trust_domain",
            "service_kind",
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
            "interop_surfaces",
            "development_mode",
        ] {
            assert!(
                value.get(required).is_some(),
                "ServiceDescribe must carry required field `{required}`"
            );
        }

        assert_eq!(value["development_mode"], true);
        assert_eq!(value["trust_domain"], "ak:trust_domain:local.test");
        assert_eq!(value["service_id"], "ak:did_core:web:directory.test");
        assert_eq!(
            value["service_resolution"]["full_id"],
            "did:web:directory.test"
        );
        assert_eq!(value["service_kind"], "directory_service");
        // verified_profiles MUST be empty when development_mode = true.
        assert!(
            value["verified_profiles"].as_array().unwrap().is_empty(),
            "dev mode must not advertise verified_profiles"
        );
    }

    /// Directory-specific fields are standard ServiceDescribe
    /// overlay fields. They are emitted as bare top-level keys, while
    /// teabay-private fields stay under `x_teabay_*`.
    #[test]
    fn describe_carries_directory_overlay_fields() {
        let value = build_describe_response_value(&cfg(false, true)).expect("describe builds");
        assert!(value.get("accepted_resource_kinds").is_some());
        assert!(value.get("discovery_profiles").is_some());
        assert!(value.get("ingest_modes").is_some());
        assert!(value.get("rate_limits").is_some());
        assert!(value.get("accept_policy_kind").is_some());
        assert_eq!(value["accept_policy_kind"], "open");
        assert_eq!(
            value["supported_bindings"][0]["base_url"],
            "http://directory.test"
        );
        assert!(value.get("x_teabay_accepted_resource_kinds").is_none());
        assert_eq!(value["ingest_modes"], json!(["push"]));
        assert_eq!(
            value["rate_limits"]["psi_ciphersuite"],
            crate::query::psi::VOPRF_CIPHERSUITE
        );
        assert_eq!(
            value["rate_limits"]["psi_batch_item_count"],
            crate::query::psi::PSI_BATCH_SIZE
        );
        assert_eq!(value["rate_limits"]["psi_digest_prefix_length"], 16);
        assert!(
            value["supported_operations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|op| op == "ak.find.directory.read.describe")
        );
        let limitation_features: std::collections::BTreeSet<_> = value["x_teabay_limitations"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|entry| entry.get("feature").and_then(JsonValue::as_str))
            .collect();
        assert!(limitation_features.contains("pull_mode_ingest"));
        assert!(!limitation_features.contains("resolve_target.preview_link"));
    }

    /// `validate` fails closed when development mode is set
    /// alongside a non-empty `verified_profiles`. The handler short-
    /// circuits through `internal_error`; here we exercise the
    /// validator directly to assert the contract.
    #[test]
    fn describe_rejects_dev_mode_with_verified_profiles() {
        let describe_body = ServiceDescribe {
            service_id: DidCoreId::new("ak:did_core:web:directory.test").unwrap(),
            service_resolution: ResolutionCommitment {
                full_id: DidFullId::new("did:web:directory.test").unwrap(),
                method_history_head: "did-web-document-etag-fixture".to_owned(),
                version_id: "did-web-document-version-fixture".to_owned(),
            },
            trust_domain: TrustDomainId::new("ak:trust_domain:local.test").unwrap(),
            service_kind: arkret_sdk::ServiceKind::DirectoryService,
            protocol_version: arkret_sdk::PROTOCOL_VERSION.to_owned(),
            supported_profiles: vec!["ak.profile.directory_service.v1".to_owned()],
            profile_bindings: BTreeMap::new(),
            supported_operations: Vec::new(),
            supported_bindings: Vec::new(),
            supported_features: Vec::new(),
            calendar_tzdb_versions: Vec::new(),
            auth_metadata: AuthMetadata::minimal("service_transport"),
            limits: ServerLimits::default(),
            egress_network_policy: None,
            plaintext_visibility: PlaintextVisibility::none(),
            privacy_derivation: None,
            receive_policy_constraints: None,
            implemented_features: Vec::new(),
            claimed_profiles: Vec::new(),
            verified_profiles: vec![VerifiedProfileEntry {
                profile_id: "ak.profile.directory_service.v1".to_owned(),
                claim_kind: arkret_sdk::ConformanceVerifiedKind::ConformanceVerified,
                verification_run_id: "test-run".to_owned(),
                artifact_digest:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_owned(),
                artifact_ref: "file:///tmp/verified-profiles.json".to_owned(),
                verifier_service_id: DidCoreId::new("ak:did_core:web:cotest.example").unwrap(),
                signature: "eddsa-jcs-b64url:test-signature".to_owned(),
                timestamp: chrono::Utc::now(),
                expires_at: None,
                extra: Default::default(),
            }],
            experimental_features: Vec::new(),
            interop_surfaces: Vec::new(),
            development_mode: true,
            rate_limit_policy: Some(RateLimitPolicy::unspecified()),
            rate_limit_policy_id: None,
            resource_kinds: all_directory_resource_kinds(),
            discovery_profiles: vec!["ak.profile.directory_service.v1".to_owned()],
            restricted_query_proof: Some(true),
            ingest_modes: vec![DirectoryIngestMode::Push],
            accept_policy_kind: Some(DirectoryAcceptPolicyKind::Open),
            accept_policy_ref: None,
            default_ttl_seconds: Some(3_600),
            max_ttl_seconds: Some(86_400),
            revalidation_grace_seconds: Some(300),
            accepted_resource_kinds: all_directory_resource_kinds(),
            accepted_did_methods: vec!["did:web".to_owned()],
            takedown_contact: None,
            rate_limits: Some(BTreeMap::new()),
            supported_reducer_profiles: Vec::new(),
            frontier: Vec::new(),
            snapshot_frontier: Vec::new(),
            last_materialized_at: None,
            extensions: BTreeMap::new(),
        };
        assert!(describe_body.validate().is_err());
        assert!(serde_json::to_value(&describe_body).unwrap()["rate_limits"].is_object());
    }

    /// TEABAY-01 regression — the describe response MUST conform to the
    /// `service-describe.schema.json` top-level shape: `additionalProperties:
    /// false` apart from the `^x_[a-z][a-z0-9_]{0,63}$` extension pattern.
    /// So every top-level key is either one of the canonical ServiceDescribe
    /// properties or a namespaced `x_teabay_*` extension. A top-level
    /// `rate_limit` key MUST NOT appear; the policy is carried by
    /// `rate_limit_policy`.
    #[test]
    fn describe_top_level_keys_are_canonical_or_x_namespaced() {
        // Canonical ServiceDescribe top-level properties (required + optional).
        const CANONICAL: &[&str] = &[
            "service_id",
            "service_resolution",
            "trust_domain",
            "service_kind",
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
            "interop_surfaces",
            "development_mode",
            "rate_limit_policy",
            "rate_limit_policy_id",
            "egress_network_policy",
            "resource_kinds",
            "discovery_profiles",
            "restricted_query_proof",
            "ingest_modes",
            "accept_policy_kind",
            "accept_policy_ref",
            "default_ttl_seconds",
            "max_ttl_seconds",
            "revalidation_grace_seconds",
            "accepted_resource_kinds",
            "accepted_did_methods",
            "takedown_contact",
            "rate_limits",
            "supported_reducer_profiles",
            "frontier",
            "snapshot_frontier",
            "last_materialized_at",
        ];

        let x_ext = regex_lite_matcher();

        for development_mode in [false, true] {
            let value = build_describe_response_value(&cfg(development_mode, true))
                .expect("describe builds");
            let object = value.as_object().expect("describe is an object");

            // The canonical shape has no top-level `rate_limit`; the policy
            // is carried by `rate_limit_policy`.
            assert!(
                !object.contains_key("rate_limit"),
                "top-level `rate_limit` must not be emitted"
            );
            assert!(
                object.contains_key("rate_limit_policy"),
                "canonical `rate_limit_policy` must be emitted"
            );

            for key in object.keys() {
                let ok = CANONICAL.contains(&key.as_str()) || x_ext(key);
                assert!(
                    ok,
                    "top-level key `{key}` is neither a canonical ServiceDescribe \
                     property nor an `x_teabay_*` extension; ServiceDescribe is \
                     additionalProperties:false apart from `^x_[a-z][a-z0-9_]{{0,63}}$`"
                );
            }

            // Teabay-private fields remain under `x_teabay_*`.
            let ext = "x_teabay_limitations";
            assert!(
                object.contains_key(ext),
                "teabay-private extension `{ext}` must ride as an x_teabay_* key"
            );
            for standard in [
                "resource_kinds",
                "discovery_profiles",
                "ingest_modes",
                "accept_policy_kind",
                "accepted_resource_kinds",
                "rate_limits",
            ] {
                assert!(
                    object.contains_key(standard),
                    "standard directory field `{standard}` must be emitted as a bare key"
                );
            }
        }
    }

    /// Minimal `^x_[a-z][a-z0-9_]{0,63}$` matcher (no regex dependency in
    /// this crate's test surface).
    fn regex_lite_matcher() -> impl Fn(&str) -> bool {
        |key: &str| {
            let rest = match key.strip_prefix("x_") {
                Some(rest) => rest,
                None => return false,
            };
            let mut chars = rest.chars();
            match chars.next() {
                Some(c) if c.is_ascii_lowercase() => {}
                _ => return false,
            }
            let body_len = rest.len() - 1;
            if body_len > 63 {
                return false;
            }
            chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        }
    }

    /// When private contact discovery is
    /// disabled, the profile MUST NOT appear in either
    /// `supported_profiles` or `claimed_profiles`.
    #[test]
    fn describe_omits_pcd_profile_when_disabled() {
        let value = build_describe_response_value(&cfg(false, false)).expect("describe builds");
        let supported = value["supported_profiles"].as_array().unwrap();
        assert!(
            !supported
                .iter()
                .any(|p| p == "ak.private_contact_discovery.v1"),
            "PCD must not appear in supported_profiles when disabled"
        );
        let claimed = value["claimed_profiles"].as_array().unwrap();
        assert!(
            !claimed
                .iter()
                .any(|p| p["profile_id"] == "ak.private_contact_discovery.v1"),
            "PCD must not be claimed when disabled"
        );
    }
}
