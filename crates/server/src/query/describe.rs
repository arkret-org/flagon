//! `ak.find.directory.read.describe.v1` — service capability advertisement.
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
    AuthMetadata, ClaimedProfileEntry, DirectoryAcceptPolicyKind, DirectoryIngestMode,
    DirectoryResourceKind, EgressNetworkPolicy, InteropSurfaceEntry, PlaintextVisibility,
    RateLimitPolicy, ServerLimits, ServiceDescribe, TransportBinding, TrustDomainId,
    VerifiedProfileEntry,
};
use salvo::prelude::*;
use serde_json::{Value as JsonValue, json};

use crate::config::{AcceptPolicyKind, AppConfig, IngestModeAdvert};
use crate::state::AppState;

pub(crate) const SUPPORTED_OPERATION_BUNDLES: &[&str] = &[
    "ak.operation_bundle.directory_service.describe.v1",
    "ak.operation_bundle.directory_service.http_core.v1",
];
const PRIVATE_CONTACT_DISCOVERY_OPERATION_BUNDLE: &str =
    "ak.operation_bundle.directory_service.private_contact_discovery.v1";

pub(crate) fn supports_http_operation(
    operation: arkret_wire::ServiceOperationId,
    private_contact_discovery_active: bool,
) -> bool {
    SUPPORTED_OPERATION_BUNDLES
        .iter()
        .copied()
        .chain(
            private_contact_discovery_active.then_some(PRIVATE_CONTACT_DISCOVERY_OPERATION_BUNDLE),
        )
        .any(|bundle_id| {
            arkret_wire::operation_bundle_descriptor(bundle_id).is_some_and(|bundle| {
                bundle.contains(operation, arkret_wire::BindingKind::HttpJson)
            })
        })
}

#[handler]
pub async fn describe(depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(s) => s.clone(),
        Err(_) => {
            crate::error::ApiErrorCode::InternalError.render(res, "AppState missing");
            return;
        }
    };
    match build_describe_response_value(state.config()) {
        Ok(value) => res.render(Json(value)),
        Err(message) => {
            crate::error::ApiErrorCode::InternalError.render(res, message);
        }
    }
}

/// Build the `ServiceDescribe` envelope plus the registered
/// directory-service overlay fields. Runs
/// [`ServiceDescribe::validate`] before returning so a misconfigured
/// deployment (e.g. `development_mode=true` paired with non-empty
/// `verified_profiles`) fails closed.
pub(crate) fn build_describe_response_value(cfg: &AppConfig) -> Result<JsonValue, String> {
    let service_id = cfg.service_id.clone();
    let trust_domain = TrustDomainId::new(cfg.trust_domain.clone())
        .map_err(|err| format!("TEABAY_TRUST_DOMAIN is not a valid ak:trust_domain: {err}"))?;

    let development_mode = cfg.development_mode;

    // The full directory-service profile currently requires
    // resolve_agent_selector, whose canonical evidence ingest carrier is not
    // yet defined. Do not self-claim it. PCD is an optional capability
    // expressed by its operation bundle plus closed configuration, not a
    // conformance profile claim.
    let supported_profiles = Vec::new();
    let supported_operation_bundles = SUPPORTED_OPERATION_BUNDLES
        .iter()
        .copied()
        .chain(
            cfg.private_contact_discovery
                .is_some()
                .then_some(PRIVATE_CONTACT_DISCOVERY_OPERATION_BUNDLE),
        )
        .map(str::to_owned)
        .collect();
    let transport_bindings = vec![TransportBinding::HttpJson {
        base_url: cfg.public_base_url.clone(),
        extension_profile_required: (),
    }];
    let supported_features = Vec::new();

    // `auth_metadata` advertises the transport-layer auth that ingest
    // mounts (RFC 9421 HTTP Message Signature) and the admin HMAC
    // surface. Static bearer auth is development-only. The directory has
    // no end-user account surface, so `mode` is `service_transport`; the
    // ingest/admin descriptors ride in `x_teabay_*` extension keys
    // (`auth_metadata` is `additionalProperties: true`).
    let mut auth_metadata = AuthMetadata::minimal();
    auth_metadata
        .extra
        .insert(
            "x_teabay_ingest".to_owned(),
            json!({
                "kind": "rfc9421_http_message_signature",
                "required": cfg.require_http_sig,
                "algorithms": ["ed25519"],
            }),
        )
        .expect("x_teabay_ingest is a valid extension key");
    auth_metadata
        .extra
        .insert(
            "x_teabay_admin".to_owned(),
            json!({
                "kind": "rotating_hmac",
                "required": true,
                "development_static_bearer": cfg.development_mode && cfg.admin_token.is_some(),
            }),
        )
        .expect("x_teabay_admin is a valid extension key");
    if cfg.private_contact_discovery.is_some() {
        auth_metadata
            .extra
            .insert(
                "x_teabay_private_contact_discovery".to_owned(),
                json!({
                    "kind": "device_scoped_hmac_bearer",
                    "required": true,
                }),
            )
            .expect("x_teabay_private_contact_discovery is a valid extension key");
    }

    let limits = ServerLimits {
        extensions: BTreeMap::from([
            (
                "per_resource_per_min".to_owned(),
                json!(cfg.rate_limit_per_resource_per_min),
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

    // `claimed_profiles` mirrors `supported_profiles` here: every profile
    // advertised here is self-claimed. `verified_profiles` is
    // empty until a cotest verifier is wired in; the
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
        supported_operation_bundles,
        transport_bindings,
        supported_features,
        calendar_tzdb_versions: Vec::new(),
        auth_metadata,
        limits,
        plaintext_visibility,
        privacy_derivation: None,
        claimed_profiles,
        verified_profiles,
        interop_surfaces,
        invite_addressing: None,
        extensions: Default::default(),
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
        private_contact_discovery: cfg
            .private_contact_discovery
            .as_ref()
            .map(|runtime| runtime.describe.clone()),
        resource_kinds: all_directory_resource_kinds(),
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
        accepted_resource_kinds: cfg.accepted_resource_kinds.to_vec(),
        accepted_did_methods: cfg.accepted_did_methods.clone(),
        takedown_contact: cfg.takedown_contact.clone(),
        rate_limits: Some(directory_rate_limits),
        supported_reducer_profiles: Vec::new(),
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
        "detail": "ak.find.directory.push.command.register.v1 webhook fanout is HMAC-signed and filtered, but delivery retry/durability is not implemented.",
    }));
    limitations
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use arkret_sdk::{
        AntiEnumerationDelay, AntiEnumerationDelayDistribution, Did, DidCoreId,
        PrivateContactDiscovery, PrivateContactDiscoveryHandoffStubsMode, ResolutionCommitment,
    };

    use super::*;
    use crate::config::{AcceptPolicyKind, IngestModeAdvert, PrivateContactDiscoveryRuntimeConfig};

    fn cfg(development_mode: bool) -> AppConfig {
        AppConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            metrics_bind: "127.0.0.1:9095".parse().unwrap(),
            public_base_url: "http://directory.test".to_owned(),
            service_id: arkret_sdk::DidCoreId::new("ak:did_core:web:directory.test")
                .expect("valid service id"),
            service_did: Did::new("did:web:directory.test").unwrap(),
            service_resolution: ResolutionCommitment {
                did: Did::new("did:web:directory.test").unwrap(),
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
            query_latency_floor: Duration::from_millis(0),
            query_latency_jitter: Duration::from_millis(0),
            require_http_sig: false,
            http_sig_pubkeys: HashMap::new(),
            receipt_signing_key: None,
            db_pool: crate::config::DbPoolConfig::default(),
            expiry_interval: Some(Duration::from_secs(1800)),
            takedown_notifier_interval: Some(Duration::from_secs(60)),
            trusted_proxy: None,
            private_contact_discovery: None,
        }
    }

    fn pcd_runtime() -> PrivateContactDiscoveryRuntimeConfig {
        let pcd_describe = PrivateContactDiscovery::new(
            "yAPizGsF_BUGRUm1kgZZykp3ssym8E9rNXAJM1R2rU4",
            14,
            8,
            PrivateContactDiscoveryHandoffStubsMode::Never,
            4096,
            4096,
            3_600,
            1,
            86_400,
            AntiEnumerationDelay {
                minimum_ms: 100,
                jitter_ms: 50,
                distribution: AntiEnumerationDelayDistribution::Uniform,
            },
        );
        pcd_describe.validate().expect("valid PCD configuration");
        PrivateContactDiscoveryRuntimeConfig {
            describe: pcd_describe,
            custody_key_ref: "kms://teabay/pcd/epoch/14".to_owned(),
            custody_manifest_path: "custody.json".into(),
            index_manifest_path: "index.json".into(),
            device_authentication_key_path: "device-authentication.key".into(),
            key_activated_at: chrono::Utc::now(),
            evaluation_lease_seconds: 30,
            garbage_collection_interval: Duration::from_secs(60),
        }
    }

    /// The describe response MUST carry every required
    /// `ServiceDescribe` field, including `trust_domain`.
    #[test]
    fn describe_emits_required_fields() {
        let value = build_describe_response_value(&cfg(true)).expect("describe builds");

        for required in [
            "service_id",
            "service_resolution",
            "trust_domain",
            "service_kind",
            "protocol_version",
            "supported_profiles",
            "supported_operation_bundles",
            "transport_bindings",
            "supported_features",
            "auth_metadata",
            "limits",
            "plaintext_visibility",
            "claimed_profiles",
            "verified_profiles",
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
        assert_eq!(value["service_resolution"]["did"], "did:web:directory.test");
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
        let value = build_describe_response_value(&cfg(false)).expect("describe builds");
        assert!(value.get("accepted_resource_kinds").is_some());
        assert!(value.get("ingest_modes").is_some());
        assert!(value.get("rate_limits").is_some());
        assert!(value.get("accept_policy_kind").is_some());
        assert_eq!(value["accept_policy_kind"], "open");
        assert_eq!(
            value["transport_bindings"][0]["base_url"],
            "http://directory.test"
        );
        assert!(value.get("x_teabay_accepted_resource_kinds").is_none());
        assert_eq!(value["ingest_modes"], json!(["push"]));
        assert!(
            value["supported_operation_bundles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|bundle| bundle == "ak.operation_bundle.directory_service.http_core.v1")
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
                did: Did::new("did:web:directory.test").unwrap(),
                method_history_head: "did-web-document-etag-fixture".to_owned(),
                version_id: "did-web-document-version-fixture".to_owned(),
            },
            trust_domain: TrustDomainId::new("ak:trust_domain:local.test").unwrap(),
            service_kind: arkret_sdk::ServiceKind::DirectoryService,
            protocol_version: arkret_sdk::PROTOCOL_VERSION.to_owned(),
            supported_profiles: vec!["ak.profile.directory_service.v1".to_owned()],
            profile_bindings: BTreeMap::new(),
            supported_operation_bundles: vec![
                "ak.operation_bundle.directory_service.describe.v1".to_owned(),
                "ak.operation_bundle.directory_service.http_core.v1".to_owned(),
            ],
            transport_bindings: vec![TransportBinding::HttpJson {
                base_url: "http://directory.test".to_owned(),
                extension_profile_required: (),
            }],
            supported_features: Vec::new(),
            calendar_tzdb_versions: Vec::new(),
            auth_metadata: AuthMetadata::minimal(),
            limits: ServerLimits::default(),
            egress_network_policy: None,
            plaintext_visibility: PlaintextVisibility::none(),
            privacy_derivation: None,
            receive_policy_constraints: None,
            claimed_profiles: Vec::new(),
            verified_profiles: vec![VerifiedProfileEntry {
                profile_id: "ak.profile.directory_service.v1".to_owned(),
                claim_kind: arkret_sdk::ConformanceVerifiedKind::ConformanceVerified,
                verification_run_id: "test-run".to_owned(),
                artifact_digest:
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_owned(),
                artifact_ref: "file:///tmp/verified-profiles.json".to_owned(),
                verifier_id: DidCoreId::new("ak:did_core:web:cotest.example").unwrap(),
                signature: "eddsa-jcs-b64url:test-signature".to_owned(),
                timestamp: chrono::Utc::now(),
                expires_at: None,
                extra: Default::default(),
            }],
            interop_surfaces: Vec::new(),
            invite_addressing: None,
            development_mode: true,
            rate_limit_policy: Some(RateLimitPolicy::unspecified()),
            rate_limit_policy_id: None,
            private_contact_discovery: None,
            resource_kinds: all_directory_resource_kinds(),
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
            extensions: Default::default(),
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
            "supported_operation_bundles",
            "transport_bindings",
            "supported_features",
            "auth_metadata",
            "limits",
            "plaintext_visibility",
            "claimed_profiles",
            "verified_profiles",
            "interop_surfaces",
            "invite_addressing",
            "development_mode",
            "rate_limit_policy",
            "rate_limit_policy_id",
            "egress_network_policy",
            "resource_kinds",
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
            let value =
                build_describe_response_value(&cfg(development_mode)).expect("describe builds");
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

    /// PCD remains absent until startup has fully activated its custody key
    /// and derived index and has installed the runtime into AppState.
    #[test]
    fn describe_omits_pcd_without_an_activated_runtime() {
        let value = build_describe_response_value(&cfg(false)).expect("describe builds");
        let supported = value["supported_profiles"].as_array().unwrap();
        assert!(
            !supported
                .iter()
                .any(|p| p == "ak.private_contact_discovery.v1"),
            "PCD must not appear in supported_profiles"
        );
        let claimed = value["claimed_profiles"].as_array().unwrap();
        assert!(
            !claimed
                .iter()
                .any(|p| p["profile_id"] == "ak.private_contact_discovery.v1"),
            "PCD must not be claimed"
        );
        assert!(
            !value["supported_operation_bundles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|bundle| bundle
                    == "ak.operation_bundle.directory_service.private_contact_discovery.v1")
        );
        assert!(value.get("private_contact_discovery").is_none());
    }

    #[test]
    fn describe_advertises_only_the_activated_closed_pcd_configuration() {
        let mut config = cfg(false);
        let runtime = pcd_runtime();
        config.private_contact_discovery = Some(runtime.clone());

        let value = build_describe_response_value(&config).expect("describe builds");

        assert!(
            value["supported_operation_bundles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|bundle| bundle
                    == "ak.operation_bundle.directory_service.private_contact_discovery.v1")
        );
        assert_eq!(
            value["private_contact_discovery"],
            serde_json::to_value(&runtime.describe).unwrap()
        );
        assert_eq!(
            value["auth_metadata"]["x_teabay_private_contact_discovery"]["kind"],
            "device_scoped_hmac_bearer"
        );
    }
}
