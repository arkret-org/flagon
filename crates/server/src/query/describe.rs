//! `ak.find.directory.read.describe.v1` — service capability advertisement.
//!
//! The response is the canonical `ServiceDescribe`
//! shape (`trust_domain` included). Validated via
//! [`arkret_sdk::ServiceDescribe::validate`] BEFORE serialisation; a
//! validation failure renders an `internal_error` rather than letting a
//! malformed `verified_profiles + development_mode=true` slip through.
//!
//! The Directory overlay advertises only the public Realm metadata index.

use std::collections::BTreeMap;

use arkret_sdk::{
    AuthMetadata, DirectoryResourceKind, EgressNetworkPolicy, InteropSurfaceEntry,
    PlaintextVisibility, RateLimitPolicy, ServerLimits, ServiceDescribe, TransportBinding,
    TrustDomainId, VerifiedProfileEntry,
};
use salvo::prelude::*;
use serde_json::{Value as JsonValue, json};

use crate::config::AppConfig;
use crate::state::AppState;

pub(crate) const SUPPORTED_OPERATION_BUNDLES: &[&str] = &[
    "ak.operation_bundle.directory_service.describe.v1",
    "ak.operation_bundle.directory_service.public_read.v1",
];
pub(crate) fn supports_http_operation(operation: arkret_wire::ServiceOperationId) -> bool {
    SUPPORTED_OPERATION_BUNDLES
        .iter()
        .copied()
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
        .map_err(|err| format!("FLAGON_TRUST_DOMAIN is not a valid ak:trust_domain: {err}"))?;

    let development_mode = cfg.development_mode;

    // The current-v1 Directory profile is itself read-only. Advertising it
    // does not imply third-party verification; that stronger evidence belongs
    // exclusively in `verified_profiles`.
    let supported_profiles = vec!["ak.profile.directory_service.v1".to_owned()];
    let supported_operation_bundles = SUPPORTED_OPERATION_BUNDLES
        .iter()
        .copied()
        .map(str::to_owned)
        .collect();
    let transport_bindings = vec![TransportBinding::HttpJson {
        base_url: cfg.public_base_url.clone(),
        extension_profile_required: (),
    }];
    let supported_features = Vec::new();

    // `auth_metadata` advertises the admin HMAC surface. The read-only
    // service has no protocol ingest transport; static bearer
    // auth is development-only. Admin descriptors ride in `x_flagon_*` extension keys
    // (`auth_metadata` is `additionalProperties: true`).
    let mut auth_metadata = AuthMetadata::minimal();
    auth_metadata
        .extra
        .insert(
            "x_flagon_admin".to_owned(),
            json!({
                "kind": "rotating_hmac",
                "required": true,
                "development_static_bearer": cfg.development_mode && cfg.admin_token.is_some(),
            }),
        )
        .expect("x_flagon_admin is a valid extension key");

    let limits = ServerLimits {
        extensions: BTreeMap::from([(
            "query_per_ip_per_min".to_owned(),
            json!(cfg.query_max_queries_per_ip_per_min),
        )]),
    };

    // `plaintext_visibility` advertises that the directory does NOT
    // surface plaintext message bodies — directory entries are
    // resource-authored projections. Receivers MUST treat a missing
    // value as `untrusted`; we declare `none` explicitly
    // via the strongly typed (closed) `PlaintextVisibility`. The
    // directory-scope note rides in an `x_flagon_*` extension key since
    // the object is `additionalProperties: false` apart from `x_*`.
    let mut plaintext_visibility = PlaintextVisibility::none();
    plaintext_visibility.max_visibility = Some(arkret_sdk::PlaintextMaxVisibility::None);
    plaintext_visibility
        .extra
        .insert(
            "x_flagon_scope".to_owned(),
            JsonValue::String("public_realm_metadata_only".to_owned()),
        )
        .map_err(|error| format!("invalid plaintext visibility extension: {error}"))?;

    // Verification evidence is absent until a cotest verifier is configured.
    let verified_profiles: Vec<VerifiedProfileEntry> = Vec::new();

    // `interop_surfaces` — the directory bridges no foreign protocol and
    // serves no delegated resolver surface.
    let interop_surfaces: Vec<InteropSurfaceEntry> = Vec::new();

    let describe_body = ServiceDescribe {
        service_id,
        service_resolution: cfg.service_resolution.clone(),
        trust_domain,
        service_kind: arkret_sdk::ServiceKind::DirectoryService,
        protocol_version: arkret_sdk::ServiceProtocolVersion::V1,
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
        verified_profiles,
        interop_surfaces,
        invite_addressing: None,
        extensions: Default::default(),
        egress_network_policy: Some(EgressNetworkPolicy::deny_private_defaults()),
        development_mode,
        receive_policy_constraints: None,
        // Canonical inline rate-limit policy. The directory enforces a
        // per-IP query windowed limit; expressed as a windowed policy entry. The
        // ServiceDescribe `anyOf` requires `rate_limit_policy` or
        // `rate_limit_policy_id`.
        rate_limit_policy: Some(RateLimitPolicy::windowed_per_minute(
            cfg.query_max_queries_per_ip_per_min,
        )),
        rate_limit_policy_id: None,
        resource_kinds: vec![DirectoryResourceKind::Realm],
    };
    describe_body
        .validate()
        .map_err(|err| format!("ServiceDescribe validation failed: {err}"))?;

    serde_json::to_value(&describe_body)
        .map_err(|err| format!("ServiceDescribe serialisation failed: {err}"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use arkret_sdk::{Did, DidCoreId, ResolutionCommitment};

    use super::*;

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
            database_url: "postgres://localhost/flagon".to_owned(),
            cors_allow_origin: None,
            admin_csrf_token: None,
            admin_token: None,
            admin_token_rotation_window: Duration::from_secs(1800),
            development_mode,
            query_max_queries_per_ip_per_min: 0,
            query_max_resolves_per_resource_per_min: 0,
            db_pool: crate::config::DbPoolConfig::default(),
            trusted_proxy: None,
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

    /// The Directory overlay advertises only Realm indexing; stale
    /// multi-resource and private discovery fields must not reappear.
    #[test]
    fn describe_carries_directory_overlay_fields() {
        let value = build_describe_response_value(&cfg(false)).expect("describe builds");
        assert_eq!(value["resource_kinds"], json!(["realm"]));
        assert!(value.get("accepted_resource_kinds").is_none());
        assert!(value.get("ingest_modes").is_none());
        assert!(value.get("claimed_profiles").is_none());
        assert!(value.get("rate_limits").is_none());
        assert!(value.get("accept_policy_kind").is_none());
        assert_eq!(
            value["transport_bindings"][0]["base_url"],
            "http://directory.test"
        );
        assert!(value.get("x_flagon_accepted_resource_kinds").is_none());
        assert_eq!(
            value["supported_profiles"],
            json!(["ak.profile.directory_service.v1"])
        );
        assert_eq!(
            value["supported_operation_bundles"],
            json!([
                "ak.operation_bundle.directory_service.describe.v1",
                "ak.operation_bundle.directory_service.public_read.v1"
            ])
        );
        assert!(value.get("x_flagon_limitations").is_none());
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
            protocol_version: arkret_sdk::ServiceProtocolVersion::V1,
            supported_profiles: vec!["ak.profile.directory_service.v1".to_owned()],
            profile_bindings: BTreeMap::new(),
            supported_operation_bundles: vec![
                "ak.operation_bundle.directory_service.describe.v1".to_owned(),
                "ak.operation_bundle.directory_service.public_read.v1".to_owned(),
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
            resource_kinds: vec![DirectoryResourceKind::Realm],
            extensions: Default::default(),
        };
        assert!(describe_body.validate().is_err());
        assert_eq!(
            serde_json::to_value(&describe_body).unwrap()["resource_kinds"],
            json!(["realm"])
        );
    }

    /// FLAGON-01 regression — the describe response MUST conform to the
    /// `service-describe.schema.json` top-level shape: `additionalProperties:
    /// false` apart from the `^x_[a-z][a-z0-9_]{0,63}$` extension pattern.
    /// So every top-level key is either one of the canonical ServiceDescribe
    /// properties or a namespaced `x_flagon_*` extension. A top-level
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
            "verified_profiles",
            "interop_surfaces",
            "invite_addressing",
            "development_mode",
            "rate_limit_policy",
            "rate_limit_policy_id",
            "egress_network_policy",
            "resource_kinds",
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
                     property nor an `x_flagon_*` extension; ServiceDescribe is \
                     additionalProperties:false apart from `^x_[a-z][a-z0-9_]{{0,63}}$`"
                );
            }

            assert!(
                object.contains_key("resource_kinds"),
                "standard directory field `resource_kinds` must be emitted as a bare key"
            );
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

    /// Private contact discovery has no current Directory operation.
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
}
