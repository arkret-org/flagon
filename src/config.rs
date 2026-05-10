//! Environment-driven configuration.
//!
//! Mirrors the spec `cx.directory.describe` ingest fields (§8.9) so the
//! runtime can both honor and advertise them coherently.

use std::{net::SocketAddr, str::FromStr, time::Duration};

use serde::{Deserialize, Serialize};

const HARD_MAX_TTL_SECONDS: i64 = 2_592_000; // 30 days, per spec §8.9

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind: SocketAddr,
    pub public_base_url: String,
    pub service_did: String,
    pub database_url: String,
    pub cors_allow_origin: Option<String>,
    pub development_mode: bool,

    pub accept_policy_kind: AcceptPolicyKind,
    pub accept_policy_ref: Option<String>,
    pub takedown_contact: Option<String>,
    pub accepted_resource_kinds: Vec<ResourceKindAccept>,
    pub accepted_did_methods: Vec<String>,
    pub allowlist_dids: Vec<String>,

    pub default_ttl: Duration,
    pub max_ttl: Duration,
    pub revalidation_grace: Duration,
    pub as_of_skew: Duration,

    pub pull_interval: Option<Duration>,

    pub ingest_modes: Vec<IngestModeAdvert>,

    pub rate_limit_per_resource_per_min: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptPolicyKind {
    Open,
    Allowlist,
    TrustRootSigned,
    OperatorReview,
}

impl AcceptPolicyKind {
    pub fn from_env_value(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "open" => Ok(Self::Open),
            "allowlist" => Ok(Self::Allowlist),
            "trust_root_signed" => Ok(Self::TrustRootSigned),
            "operator_review" => Ok(Self::OperatorReview),
            other => Err(anyhow::anyhow!(
                "invalid CHADEX_ACCEPT_POLICY_KIND={other}; \
                 expected open|allowlist|trust_root_signed|operator_review"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKindAccept {
    Space,
    Organization,
    Actor,
    Applet,
    Handle,
}

impl ResourceKindAccept {
    pub const ALL: &'static [Self] = &[
        Self::Space,
        Self::Organization,
        Self::Actor,
        Self::Applet,
        Self::Handle,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Space => "space",
            Self::Organization => "organization",
            Self::Actor => "actor",
            Self::Applet => "applet",
            Self::Handle => "handle",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestModeAdvert {
    Push,
    Pull,
}

impl IngestModeAdvert {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::Pull => "pull",
        }
    }
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let bind = std::env::var("CHADEX_BIND").unwrap_or_else(|_| "0.0.0.0:7781".to_string());
        let bind: SocketAddr = bind
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid CHADEX_BIND={bind}: {e}"))?;

        let public_base_url = std::env::var("CHADEX_PUBLIC_BASE_URL")
            .unwrap_or_else(|_| format!("http://{bind}"));

        let service_did = std::env::var("CHADEX_SERVICE_DID")
            .map_err(|_| anyhow::anyhow!("CHADEX_SERVICE_DID is required"))?;

        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("DATABASE_URL is required"))?;

        let cors_allow_origin = std::env::var("CHADEX_CORS_ALLOW_ORIGIN").ok();

        let development_mode = read_bool("CHADEX_DEVELOPMENT_MODE", false)?;

        let accept_policy_kind = match std::env::var("CHADEX_ACCEPT_POLICY_KIND") {
            Ok(v) => AcceptPolicyKind::from_env_value(&v)?,
            Err(_) => AcceptPolicyKind::Open,
        };

        let accept_policy_ref = std::env::var("CHADEX_ACCEPT_POLICY_REF").ok();
        let takedown_contact = std::env::var("CHADEX_TAKEDOWN_CONTACT").ok();

        let accepted_did_methods = csv_env(
            "CHADEX_ACCEPTED_DID_METHODS",
            &["did:web", "did:webvh", "did:key", "did:plc"],
        );

        let allowlist_dids = csv_env("CHADEX_ALLOWLIST_DIDS", &[]);

        let default_ttl_seconds = read_u64("CHADEX_DEFAULT_TTL_SECONDS", 86_400)?;
        let max_ttl_seconds = read_u64("CHADEX_MAX_TTL_SECONDS", 604_800)?;
        let revalidation_grace_seconds = read_u64("CHADEX_REVALIDATION_GRACE_SECONDS", 3_600)?;
        let as_of_skew_seconds = read_u64("CHADEX_AS_OF_SKEW_SECONDS", 300)?;

        if max_ttl_seconds as i64 > HARD_MAX_TTL_SECONDS {
            anyhow::bail!(
                "CHADEX_MAX_TTL_SECONDS={max_ttl_seconds} exceeds spec hard ceiling \
                 of {HARD_MAX_TTL_SECONDS} (discovery-directory.md §8.9)"
            );
        }
        if default_ttl_seconds > max_ttl_seconds {
            anyhow::bail!(
                "CHADEX_DEFAULT_TTL_SECONDS ({default_ttl_seconds}) must be <= \
                 CHADEX_MAX_TTL_SECONDS ({max_ttl_seconds})"
            );
        }

        let pull_interval_seconds = read_u64("CHADEX_PULL_INTERVAL_SECONDS", 300)?;
        let pull_interval = if pull_interval_seconds == 0 {
            None
        } else {
            Some(Duration::from_secs(pull_interval_seconds))
        };

        let mut ingest_modes = vec![IngestModeAdvert::Push];
        if pull_interval.is_some() {
            ingest_modes.push(IngestModeAdvert::Pull);
        }

        let rate_limit_per_resource_per_min =
            read_u64("CHADEX_RATE_LIMIT_PER_RESOURCE_PER_MIN", 60)? as u32;

        Ok(Self {
            bind,
            public_base_url,
            service_did,
            database_url,
            cors_allow_origin,
            development_mode,
            accept_policy_kind,
            accept_policy_ref,
            takedown_contact,
            accepted_resource_kinds: ResourceKindAccept::ALL.to_vec(),
            accepted_did_methods,
            allowlist_dids,
            default_ttl: Duration::from_secs(default_ttl_seconds),
            max_ttl: Duration::from_secs(max_ttl_seconds),
            revalidation_grace: Duration::from_secs(revalidation_grace_seconds),
            as_of_skew: Duration::from_secs(as_of_skew_seconds),
            pull_interval,
            ingest_modes,
            rate_limit_per_resource_per_min,
        })
    }
}

fn read_bool(key: &str, default: bool) -> anyhow::Result<bool> {
    match std::env::var(key) {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" | "" => Ok(false),
            other => Err(anyhow::anyhow!("invalid boolean {key}={other}")),
        },
        Err(_) => Ok(default),
    }
}

fn read_u64(key: &str, default: u64) -> anyhow::Result<u64> {
    match std::env::var(key) {
        Ok(v) if v.is_empty() => Ok(default),
        Ok(v) => u64::from_str(v.trim())
            .map_err(|e| anyhow::anyhow!("invalid integer {key}={v}: {e}")),
        Err(_) => Ok(default),
    }
}

fn csv_env(key: &str, fallback: &[&str]) -> Vec<String> {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => fallback.iter().map(|s| s.to_string()).collect(),
    }
}
