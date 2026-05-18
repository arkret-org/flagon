//! Environment-driven configuration.
//!
//! Mirrors the spec `cx.directory.describe` ingest fields (§8.9) so the
//! runtime can both honor and advertise them coherently.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::middleware::http_sig::{DidResolverKeyDirectory, Ed25519PublicKey};

const HARD_MAX_TTL_SECONDS: i64 = 2_592_000; // 30 days, per spec §8.9

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind: SocketAddr,
    pub public_base_url: String,
    pub service_did: String,
    pub database_url: String,
    pub cors_allow_origin: Option<String>,
    pub admin_token: Option<String>,
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
    pub divergence_interval: Option<Duration>,

    pub ingest_modes: Vec<IngestModeAdvert>,

    pub rate_limit_per_resource_per_min: u32,
    pub max_psi_queries_per_epoch: u32,
    pub private_contact_discovery_enabled: bool,
    pub psi_epoch_seconds: u64,
    pub psi_key_retention_seconds: u64,
    pub query_latency_floor: Duration,
    pub query_latency_jitter: Duration,

    /// When `true`, the RFC 9421 HTTP Message Signature middleware
    /// (see [`crate::middleware::http_sig`]) is mounted on the ingest
    /// route group with enforcement enabled. When `false`, the middleware
    /// is mounted in passthrough mode so the existing conformance
    /// harness (which posts unsigned envelopes) keeps working. Defaults
    /// to `true` — that's the secure default for any non-test deploy.
    pub require_http_sig: bool,
    /// `keyid → Ed25519 verifying key` allowlist for the ingest HTTP
    /// signature middleware. Operators populate this at boot via
    /// `TEABAY_HTTP_SIG_PUBKEYS` (comma-separated `keyid=BASE64URL32`
    /// pairs). Empty when `require_http_sig=false`.
    pub http_sig_pubkeys: HashMap<String, Ed25519PublicKey>,
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
                "invalid TEABAY_ACCEPT_POLICY_KIND={other}; \
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
        let bind = std::env::var("TEABAY_BIND").unwrap_or_else(|_| "0.0.0.0:7781".to_string());
        let bind: SocketAddr = bind
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid TEABAY_BIND={bind}: {e}"))?;

        let public_base_url =
            std::env::var("TEABAY_PUBLIC_BASE_URL").unwrap_or_else(|_| format!("http://{bind}"));

        let service_did = std::env::var("TEABAY_SERVICE_DID")
            .map_err(|_| anyhow::anyhow!("TEABAY_SERVICE_DID is required"))?;

        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("DATABASE_URL is required"))?;

        let cors_allow_origin = std::env::var("TEABAY_CORS_ALLOW_ORIGIN").ok();
        let admin_token = std::env::var("TEABAY_ADMIN_TOKEN")
            .ok()
            .filter(|token| !token.trim().is_empty());

        let development_mode = read_bool("TEABAY_DEVELOPMENT_MODE", false)?;

        let accept_policy_kind = match std::env::var("TEABAY_ACCEPT_POLICY_KIND") {
            Ok(v) => AcceptPolicyKind::from_env_value(&v)?,
            Err(_) => AcceptPolicyKind::Open,
        };

        let accept_policy_ref = std::env::var("TEABAY_ACCEPT_POLICY_REF").ok();
        let takedown_contact = std::env::var("TEABAY_TAKEDOWN_CONTACT").ok();

        let accepted_did_methods = csv_env(
            "TEABAY_ACCEPTED_DID_METHODS",
            &["did:web", "did:webvh", "did:key"],
        );

        let allowlist_dids = csv_env("TEABAY_ALLOWLIST_DIDS", &[]);

        let default_ttl_seconds = read_u64("TEABAY_DEFAULT_TTL_SECONDS", 86_400)?;
        let max_ttl_seconds = read_u64("TEABAY_MAX_TTL_SECONDS", 604_800)?;
        let revalidation_grace_seconds = read_u64("TEABAY_REVALIDATION_GRACE_SECONDS", 3_600)?;
        let as_of_skew_seconds = read_u64("TEABAY_AS_OF_SKEW_SECONDS", 300)?;

        if max_ttl_seconds as i64 > HARD_MAX_TTL_SECONDS {
            anyhow::bail!(
                "TEABAY_MAX_TTL_SECONDS={max_ttl_seconds} exceeds spec hard ceiling \
                 of {HARD_MAX_TTL_SECONDS} (discovery-directory.md §8.9)"
            );
        }
        if default_ttl_seconds > max_ttl_seconds {
            anyhow::bail!(
                "TEABAY_DEFAULT_TTL_SECONDS ({default_ttl_seconds}) must be <= \
                 TEABAY_MAX_TTL_SECONDS ({max_ttl_seconds})"
            );
        }

        let pull_interval_seconds = read_u64("TEABAY_PULL_INTERVAL_SECONDS", 300)?;
        let pull_interval = if pull_interval_seconds == 0 {
            None
        } else {
            Some(Duration::from_secs(pull_interval_seconds))
        };
        let divergence_interval_seconds = read_u64("TEABAY_DIVERGENCE_INTERVAL_SECONDS", 0)?;
        let divergence_interval = if divergence_interval_seconds == 0 {
            None
        } else {
            Some(Duration::from_secs(divergence_interval_seconds))
        };

        let mut ingest_modes = vec![IngestModeAdvert::Push];
        if pull_interval.is_some() {
            ingest_modes.push(IngestModeAdvert::Pull);
        }

        let rate_limit_per_resource_per_min =
            read_u64("TEABAY_RATE_LIMIT_PER_RESOURCE_PER_MIN", 60)? as u32;
        let max_psi_queries_per_epoch = read_u64("TEABAY_MAX_PSI_QUERIES_PER_EPOCH", 60)? as u32;
        let private_contact_discovery_enabled =
            read_bool("TEABAY_PRIVATE_CONTACT_DISCOVERY_ENABLED", true)?;
        let psi_epoch_seconds = read_u64("TEABAY_PSI_EPOCH_SECONDS", 604_800)?;
        let psi_key_retention_seconds = read_u64("TEABAY_PSI_KEY_RETENTION_SECONDS", 7_776_000)?;
        let query_latency_floor_ms = read_u64("TEABAY_QUERY_LATENCY_FLOOR_MS", 25)?;
        let query_latency_jitter_ms = read_u64("TEABAY_QUERY_LATENCY_JITTER_MS", 10)?;

        let require_http_sig = read_bool("TEABAY_REQUIRE_HTTP_SIG", true)?;
        let http_sig_pubkeys =
            parse_http_sig_pubkeys(std::env::var("TEABAY_HTTP_SIG_PUBKEYS").ok().as_deref())?;
        if psi_epoch_seconds == 0 {
            anyhow::bail!("TEABAY_PSI_EPOCH_SECONDS must be > 0");
        }
        if psi_key_retention_seconds > 7_776_000 {
            anyhow::bail!("TEABAY_PSI_KEY_RETENTION_SECONDS must be <= 90 days");
        }

        Ok(Self {
            bind,
            public_base_url,
            service_did,
            database_url,
            cors_allow_origin,
            admin_token,
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
            divergence_interval,
            ingest_modes,
            rate_limit_per_resource_per_min,
            max_psi_queries_per_epoch,
            private_contact_discovery_enabled,
            psi_epoch_seconds,
            psi_key_retention_seconds,
            query_latency_floor: Duration::from_millis(query_latency_floor_ms),
            query_latency_jitter: Duration::from_millis(query_latency_jitter_ms),
            require_http_sig,
            http_sig_pubkeys,
        })
    }

    /// Materialise the ingest HTTP signature key directory. Static keys
    /// remain a deterministic fallback, while DID-URL keyids can resolve
    /// through the configured DID resolver chain.
    pub fn http_sig_key_directory(&self) -> DidResolverKeyDirectory {
        DidResolverKeyDirectory::new(
            self.http_sig_pubkeys.clone(),
            self.accepted_did_methods.clone(),
        )
    }
}

/// Parse `TEABAY_HTTP_SIG_PUBKEYS` into a `keyid → Ed25519PublicKey`
/// map. The wire format is comma-separated `keyid=base64url(pubkey)`
/// pairs; both `base64url` (no padding) and standard padded base64 are
/// tolerated. Empty / unset is `Ok(HashMap::new())`.
fn parse_http_sig_pubkeys(
    value: Option<&str>,
) -> anyhow::Result<HashMap<String, Ed25519PublicKey>> {
    let mut map = HashMap::new();
    let Some(raw) = value else {
        return Ok(map);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(map);
    }
    for entry in trimmed.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (key_id, encoded) = entry.split_once('=').ok_or_else(|| {
            anyhow::anyhow!(
                "TEABAY_HTTP_SIG_PUBKEYS entry `{entry}` is not `keyid=base64url(pubkey)`"
            )
        })?;
        let key_id = key_id.trim().to_owned();
        if key_id.is_empty() {
            anyhow::bail!("TEABAY_HTTP_SIG_PUBKEYS entry has empty keyid");
        }
        let encoded = encoded.trim();
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
            .map_err(|e| {
                anyhow::anyhow!(
                    "TEABAY_HTTP_SIG_PUBKEYS keyid `{key_id}` pubkey is not base64: {e}"
                )
            })?;
        let key = Ed25519PublicKey::try_from(bytes.as_slice()).map_err(|e| {
            anyhow::anyhow!(
                "TEABAY_HTTP_SIG_PUBKEYS keyid `{key_id}` is not a valid Ed25519 public key: {e}"
            )
        })?;
        map.insert(key_id, key);
    }
    Ok(map)
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
        Ok(v) => {
            u64::from_str(v.trim()).map_err(|e| anyhow::anyhow!("invalid integer {key}={v}: {e}"))
        }
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
