//! Environment-driven configuration.
//!
//! Mirrors the spec `ak.find.directory.read.describe.v1` ingest fields (§8.9) so the
//! runtime can both honor and advertise them coherently.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use arkret_sdk::{
    Did, DidCoreId, DirectoryResourceKind, ResolutionCommitment, project_did_to_core_id,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::did_resolver::SharedDidResolver;
use crate::middleware::http_sig::{DidResolverKeyDirectory, VerifyingKey};

const HARD_MAX_TTL_SECONDS: i64 = 2_592_000; // 30 days, per spec §8.9
const CONFIG_ARG: &str = "--config";
const NO_ENV_OVERRIDES_ARG: &str = "--no-env-overrides";

/// Apply the common Arkret server configuration-source contract before any
/// worker threads are created.
pub fn prepare_process_environment() -> anyhow::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let Some(config_path) = config_path_from_args(&args)? else {
        dotenvy::dotenv().ok();
        return Ok(());
    };

    let no_env_overrides = args.iter().any(|arg| arg == NO_ENV_OVERRIDES_ARG);
    let ambient = relevant_environment();
    clear_relevant_environment();
    let file_values = read_config_environment(&config_path)?;
    install_environment(file_values);
    if !no_env_overrides {
        install_environment(ambient);
    }
    Ok(())
}

fn config_path_from_args(args: &[String]) -> anyhow::Result<Option<PathBuf>> {
    let mut index = 1;
    while index < args.len() {
        let arg = &args[index];
        if arg == CONFIG_ARG {
            let value = args
                .get(index + 1)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("--config requires a file path"))?;
            return Ok(Some(PathBuf::from(value)));
        }
        if let Some(value) = arg.strip_prefix("--config=") {
            if value.trim().is_empty() {
                anyhow::bail!("--config requires a file path");
            }
            return Ok(Some(PathBuf::from(value)));
        }
        index += 1;
    }
    Ok(None)
}

fn read_config_environment(path: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let mut values = Vec::new();
    for entry in dotenvy::from_path_iter(path)
        .map_err(|error| anyhow::anyhow!("failed to read config {}: {error}", path.display()))?
    {
        let (key, value) = entry.map_err(|error| {
            anyhow::anyhow!("failed to parse config {}: {error}", path.display())
        })?;
        if !is_allowed_config_key(&key) {
            anyhow::bail!(
                "config {} contains unsupported key {key}; expected TEABAY_*, DATABASE_URL, or RUST_LOG",
                path.display()
            );
        }
        values.push((key, value));
    }
    Ok(values)
}

fn is_allowed_config_key(key: &str) -> bool {
    key.starts_with("TEABAY_") || matches!(key, "DATABASE_URL" | "RUST_LOG")
}

fn relevant_environment() -> Vec<(String, String)> {
    std::env::vars()
        .filter(|(key, _)| is_allowed_config_key(key))
        .collect()
}

#[allow(
    unsafe_code,
    reason = "startup configuration mutates process environment before the Tokio runtime exists"
)]
fn clear_relevant_environment() {
    for (key, _) in relevant_environment() {
        // SAFETY: `main` calls this before constructing the Tokio runtime.
        unsafe { std::env::remove_var(key) };
    }
}

#[allow(
    unsafe_code,
    reason = "startup configuration mutates process environment before the Tokio runtime exists"
)]
fn install_environment(values: Vec<(String, String)>) {
    for (key, value) in values {
        // SAFETY: `main` calls this before constructing the Tokio runtime.
        unsafe { std::env::set_var(key, value) };
    }
}

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind: SocketAddr,
    pub metrics_bind: SocketAddr,
    pub public_base_url: String,
    /// Stable business identity projected from [`Self::service_did`].
    /// This is never interpreted as a network locator.
    pub service_id: DidCoreId,
    /// Current resolvable service DID retained for method verification and
    /// DID-URL verification-method construction.
    pub service_did: Did,
    /// Operator-verified current resolution commitment published by
    /// `ServiceDescribe`. Teabay never manufactures history heads or version
    /// identifiers from the DID text.
    pub service_resolution: ResolutionCommitment,
    /// Typed trust domain advertised in
    /// `/directory/describe` and required on every cross-trust-domain
    /// federation request. Sourced from `TEABAY_TRUST_DOMAIN`; defaults
    /// to `ak:trust_domain:local.test` so the in-process conformance
    /// harness keeps working without operator hand-holding.
    pub trust_domain: String,
    pub database_url: String,
    pub cors_allow_origin: Option<String>,
    /// C.10.10 — require browser callers to mint an X-CSRF-Token header
    /// matching this configured value on every state-changing admin
    /// call. Required in production mode (startup fails closed without
    /// it); optional only when `TEABAY_DEVELOPMENT_MODE=true`. When set,
    /// Set-Cookie is also emitted with `SameSite=Strict` so cookie-bearing
    /// strands are additionally CSRF-hardened.
    pub admin_csrf_token: Option<String>,
    pub admin_token: Option<String>,
    /// A.8.4 — sliding window during which a rotating HMAC token
    /// remains valid. Defaults to 30 minutes; clients sign
    /// `HMAC_SHA256(secret, format!("{key_id}:{timestamp}"))` and
    /// teabay accepts the proof when `now - timestamp <=
    /// admin_token_rotation_window`. Env:
    /// `TEABAY_ADMIN_TOKEN_ROTATION_WINDOW_SECS` (default 1800).
    pub admin_token_rotation_window: std::time::Duration,
    pub development_mode: bool,

    pub accept_policy_kind: AcceptPolicyKind,
    pub accept_policy_ref: Option<String>,
    pub takedown_contact: Option<String>,
    pub accepted_resource_kinds: Vec<DirectoryResourceKind>,
    pub accepted_did_methods: Vec<String>,

    pub default_ttl: Duration,
    pub max_ttl: Duration,
    pub revalidation_grace: Duration,
    pub as_of_skew: Duration,

    pub ingest_modes: Vec<IngestModeAdvert>,

    pub rate_limit_per_resource_per_min: u32,
    /// Query-face rate limit (per IP, per 60s window). Applies to every
    /// `ak.directory.search_*` / `ak.directory.resolve_*` endpoint. 0
    /// means disabled. Env: `TEABAY_QUERY_MAX_QUERIES_PER_IP_PER_MIN`.
    pub query_max_queries_per_ip_per_min: u32,
    /// Per-`resource_id` resolve rate limit. Cools off enumeration
    /// attempts against a single resource without affecting general
    /// search traffic. 0 means disabled. Env:
    /// `TEABAY_QUERY_MAX_RESOLVES_PER_RESOURCE_PER_MIN`.
    pub query_max_resolves_per_resource_per_min: u32,
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
    pub http_sig_pubkeys: HashMap<String, VerifyingKey>,
    /// Optional Ed25519 signing key for operator-takedown receipts stored in
    /// `withdrawals.proof`. Resource-initiated withdrawals carry the resource
    /// governance signature; operator takedowns need a service receipt key.
    pub receipt_signing_key: Option<ReceiptSigningKey>,
    /// P2E.6 — diesel + r2d2 connection pool tunables. Operators surface
    /// these as env vars; see `docs/scaling.md` for sizing guidance and
    /// `Db::connect_with` for the live behaviour.
    pub db_pool: DbPoolConfig,
    /// P5 — period for the [`crate::workers::expiry::ExpiryWorker`]
    /// background purge. Env: `TEABAY_EXPIRY_INTERVAL_SECONDS`
    /// (default 1800). Set to `0` to disable the worker entirely.
    pub expiry_interval: Option<Duration>,
    /// P5 — period for the
    /// [`crate::workers::takedown_notifier::TakedownNotifier`]
    /// background dispatcher. Env:
    /// `TEABAY_TAKEDOWN_NOTIFIER_INTERVAL_SECONDS` (default 60). Set to
    /// `0` to disable the notifier entirely (development only).
    pub takedown_notifier_interval: Option<Duration>,
    /// P5 — list of IPs that are allowed to inject `X-Forwarded-For`
    /// (or equivalent) when the rate-limiter resolves a client address.
    /// When unset, the rate-limiter trusts `req.remote_addr()` only.
    /// Env: `TEABAY_TRUSTED_PROXY` (comma-separated IPs).
    pub trusted_proxy: Option<Vec<IpAddr>>,
}

/// Pool sizing knobs for the diesel + deadpool PostgreSQL connection pool.
/// Every field is overridable via env. Defaults match the "small
/// production" sizing recommended in `docs/scaling.md`.
#[derive(Clone, Debug)]
pub struct DbPoolConfig {
    /// Hard ceiling on concurrent Postgres connections this teabay
    /// instance will open. Includes connections held by background
    /// workers (expiry, freshness, takedown notifier) and admin queries.
    /// Default: 16. Env: `TEABAY_DB_POOL_MAX_SIZE`.
    pub max_size: u32,
    /// How long `pool.get()` waits for an available connection before
    /// returning a `Timeout` error. Tune this together with the
    /// ingest rate limit so a burst can't tarpit the request thread.
    /// Default: 5 s. Env: `TEABAY_DB_POOL_CONNECTION_TIMEOUT_SECS`.
    pub connection_timeout: Duration,
}

impl Default for DbPoolConfig {
    fn default() -> Self {
        Self {
            max_size: 16,
            connection_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Clone)]
pub struct ReceiptSigningKey {
    key_id: String,
    signing_key: SigningKey,
}

impl ReceiptSigningKey {
    pub(crate) fn from_raw(key_id: String, bytes: [u8; 32]) -> Self {
        Self {
            key_id,
            signing_key: SigningKey::from_bytes(&bytes),
        }
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub(crate) fn public_key_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.verifying_key().as_bytes())
    }
}

impl fmt::Debug for ReceiptSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiptSigningKey")
            .field("key_id", &self.key_id)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptPolicyKind {
    Open,
    Allowlist,
    OperatorReview,
}

impl AcceptPolicyKind {
    pub fn from_env_value(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "open" => Ok(Self::Open),
            "allowlist" => Ok(Self::Allowlist),
            "trust_root_signed" => Err(anyhow::anyhow!(
                "TEABAY_ACCEPT_POLICY_KIND=trust_root_signed is reserved until the directory \
                 trust-seal envelope is defined in arkret-spec and arkret-rust-sdk"
            )),
            "operator_review" => Ok(Self::OperatorReview),
            other => Err(anyhow::anyhow!(
                "invalid TEABAY_ACCEPT_POLICY_KIND={other}; \
                 expected open|allowlist|operator_review"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestModeAdvert {
    Push,
}

impl IngestModeAdvert {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Push => "push",
        }
    }
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let bind = arg_value("--bind")
            .or_else(|| std::env::var("TEABAY_BIND").ok())
            .unwrap_or_else(|| "0.0.0.0:7781".to_string());
        let bind: SocketAddr = bind
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid TEABAY_BIND={bind}: {e}"))?;
        let metrics_bind =
            std::env::var("TEABAY_METRICS_BIND").unwrap_or_else(|_| "127.0.0.1:9095".to_string());
        let metrics_bind: SocketAddr = metrics_bind
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid TEABAY_METRICS_BIND={metrics_bind}: {e}"))?;

        let public_base_url =
            std::env::var("TEABAY_PUBLIC_BASE_URL").unwrap_or_else(|_| format!("http://{bind}"));

        // The configured identity is the current resolvable DID. Business
        // DTOs and persistence keys use only its adapter-projected core id.
        let service_did_raw = required_non_empty_env("TEABAY_SERVICE_DID")?;
        let service_did = Did::new(service_did_raw.clone())
            .map_err(|error| anyhow::anyhow!("TEABAY_SERVICE_DID is not a valid DID: {error}"))?;
        let service_id = project_did_to_core_id(&service_did).map_err(|error| {
            anyhow::anyhow!("TEABAY_SERVICE_DID has no active method adapter: {error}")
        })?;
        let method_history_head = required_non_empty_env("TEABAY_SERVICE_METHOD_HISTORY_HEAD")?;
        let version_id = required_non_empty_env("TEABAY_SERVICE_VERSION_ID")?;
        let service_resolution = ResolutionCommitment {
            did: service_did.clone(),
            method_history_head,
            version_id,
        };

        // Required trust domain on ServiceDescribe. Operators
        // SHOULD set TEABAY_TRUST_DOMAIN explicitly; the fallback only
        // exists so the in-process conformance harness keeps booting.
        let trust_domain = std::env::var("TEABAY_TRUST_DOMAIN")
            .unwrap_or_else(|_| "ak:trust_domain:local.test".to_owned());
        if arkret_sdk::TrustDomainId::new(trust_domain.clone()).is_err() {
            anyhow::bail!(
                "TEABAY_TRUST_DOMAIN={trust_domain} is not a valid `ak:trust_domain:` identifier"
            );
        }

        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("DATABASE_URL is required"))?;

        let cors_allow_origin = std::env::var("TEABAY_CORS_ALLOW_ORIGIN").ok();
        let development_mode = read_bool("TEABAY_DEVELOPMENT_MODE", false)?;
        let admin_token = if development_mode {
            std::env::var("TEABAY_ADMIN_TOKEN")
                .ok()
                .filter(|token| !token.trim().is_empty())
        } else {
            if std::env::var("TEABAY_ADMIN_TOKEN")
                .ok()
                .is_some_and(|token| !token.trim().is_empty())
            {
                tracing::warn!(
                    "TEABAY_ADMIN_TOKEN is ignored when TEABAY_DEVELOPMENT_MODE=false; \
                     provision rotating HMAC admin credentials in admin_tokens instead"
                );
            }
            None
        };
        let admin_csrf_token = std::env::var("TEABAY_ADMIN_CSRF_TOKEN")
            .ok()
            .filter(|token| !token.trim().is_empty());

        // P5 HIGH — CSRF is required in production mode (i.e. not
        // development_mode). Fail-closed at startup so an operator cannot
        // expose the admin SPA without CSRF protection. There is no opt-out.
        // See docs/deployment.md hardening checklist.
        if !development_mode && admin_csrf_token.is_none() {
            anyhow::bail!(
                "TEABAY_ADMIN_CSRF_TOKEN is required in production mode \
                 (TEABAY_DEVELOPMENT_MODE=false)"
            );
        }
        let admin_token_rotation_window_secs =
            read_u64("TEABAY_ADMIN_TOKEN_ROTATION_WINDOW_SECS", 1_800)?;
        let admin_token_rotation_window =
            Duration::from_secs(admin_token_rotation_window_secs.max(60));

        let accept_policy_kind = match std::env::var("TEABAY_ACCEPT_POLICY_KIND") {
            Ok(v) => AcceptPolicyKind::from_env_value(&v)?,
            // Fail closed in production: `open` accepts any validly-signed
            // source, widening the poisoning / anti-enumeration surface.
            // Operators MUST make the accept-policy choice explicit, mirroring
            // the CSRF fail-closed guard above.
            Err(_) if !development_mode => anyhow::bail!(
                "TEABAY_ACCEPT_POLICY_KIND must be set explicitly in production \
                 (development_mode=false). Choose one of \
                 open|allowlist|operator_review. \
                 `open` is intentionally not the production default."
            ),
            Err(_) => AcceptPolicyKind::Open,
        };

        let accept_policy_ref = std::env::var("TEABAY_ACCEPT_POLICY_REF").ok();
        let takedown_contact = std::env::var("TEABAY_TAKEDOWN_CONTACT").ok();

        // did:webvh is the only v1-core accepted DID method. did:web is a
        // no-history identity (DNS/TLS-takeover risk) and must never be a
        // default for a discovery index; operators that run an explicit
        // no-history service/personal_node profile can opt in via
        // TEABAY_ACCEPTED_DID_METHODS. did:key (ephemeral, self-contained) is
        // likewise opt-in only.
        let accepted_did_methods = csv_env("TEABAY_ACCEPTED_DID_METHODS", &["did:webvh"]);

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

        let ingest_modes = vec![IngestModeAdvert::Push];

        let rate_limit_per_resource_per_min =
            read_u64("TEABAY_RATE_LIMIT_PER_RESOURCE_PER_MIN", 60)? as u32;
        // Query-face rate limit (per IP). Default 600/min keeps every
        // realistic browser dashboard happy while breaking obvious
        // enumeration sweeps. Set to 0 to disable.
        let query_max_queries_per_ip_per_min =
            read_u64("TEABAY_QUERY_MAX_QUERIES_PER_IP_PER_MIN", 600)? as u32;
        let query_max_resolves_per_resource_per_min =
            read_u64("TEABAY_QUERY_MAX_RESOLVES_PER_RESOURCE_PER_MIN", 120)? as u32;
        let query_latency_floor_ms = read_u64("TEABAY_QUERY_LATENCY_FLOOR_MS", 25)?;
        let query_latency_jitter_ms = read_u64("TEABAY_QUERY_LATENCY_JITTER_MS", 10)?;

        let require_http_sig = read_bool("TEABAY_REQUIRE_HTTP_SIG", true)?;
        let http_sig_pubkeys =
            parse_http_sig_pubkeys(std::env::var("TEABAY_HTTP_SIG_PUBKEYS").ok().as_deref())?;
        let receipt_signing_key = parse_receipt_signing_key(
            std::env::var("TEABAY_RECEIPT_SIGNING_KEY_B64")
                .ok()
                .as_deref(),
            std::env::var("TEABAY_RECEIPT_KEY_ID")
                .ok()
                .unwrap_or_else(|| format!("{service_did}#teabay-receipt-1")),
        )?;
        // P2E.6 — db pool tunables.
        let defaults = DbPoolConfig::default();
        let pool_max = read_u64("TEABAY_DB_POOL_MAX_SIZE", defaults.max_size as u64)? as u32;
        if pool_max == 0 {
            anyhow::bail!("TEABAY_DB_POOL_MAX_SIZE must be > 0");
        }
        let pool_connection_timeout_secs = read_u64(
            "TEABAY_DB_POOL_CONNECTION_TIMEOUT_SECS",
            defaults.connection_timeout.as_secs(),
        )?;
        if pool_connection_timeout_secs == 0 {
            anyhow::bail!("TEABAY_DB_POOL_CONNECTION_TIMEOUT_SECS must be > 0");
        }
        let db_pool = DbPoolConfig {
            max_size: pool_max,
            connection_timeout: Duration::from_secs(pool_connection_timeout_secs),
        };

        // P5 — new background worker periods.
        let expiry_interval_seconds = read_u64("TEABAY_EXPIRY_INTERVAL_SECONDS", 1_800)?;
        let expiry_interval = if expiry_interval_seconds == 0 {
            None
        } else {
            Some(Duration::from_secs(expiry_interval_seconds))
        };
        let takedown_notifier_interval_seconds =
            read_u64("TEABAY_TAKEDOWN_NOTIFIER_INTERVAL_SECONDS", 60)?;
        let takedown_notifier_interval = if takedown_notifier_interval_seconds == 0 {
            None
        } else {
            Some(Duration::from_secs(takedown_notifier_interval_seconds))
        };

        // P5 — trusted proxy allowlist for the rate-limiter.
        let trusted_proxy = parse_trusted_proxy(std::env::var("TEABAY_TRUSTED_PROXY").ok())?;

        // Operator-configurable subset of the §8.3 resource-kind enum this
        // directory accepts for ingest. Unset ⇒ full enum. Each token MUST be
        // a valid §8.3 kind (`space` is not a kind and is rejected).
        let accepted_resource_kinds = match std::env::var("TEABAY_ACCEPTED_RESOURCE_KINDS") {
            Ok(raw) if !raw.trim().is_empty() => {
                let mut kinds = Vec::new();
                for token in raw.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                    let kind = token.parse::<DirectoryResourceKind>().map_err(|_| {
                        anyhow::anyhow!(
                            "invalid TEABAY_ACCEPTED_RESOURCE_KINDS token {token:?}; \
                             valid: realm|organization|actor|applet|handle"
                        )
                    })?;
                    if !kinds.contains(&kind) {
                        kinds.push(kind);
                    }
                }
                if kinds.is_empty() {
                    anyhow::bail!("TEABAY_ACCEPTED_RESOURCE_KINDS must list at least one kind");
                }
                kinds
            }
            _ => DirectoryResourceKind::ALL.to_vec(),
        };

        Ok(Self {
            bind,
            metrics_bind,
            public_base_url,
            service_id,
            service_did,
            service_resolution,
            trust_domain,
            database_url,
            cors_allow_origin,
            admin_csrf_token,
            admin_token,
            admin_token_rotation_window,
            development_mode,
            accept_policy_kind,
            accept_policy_ref,
            takedown_contact,
            accepted_resource_kinds,
            accepted_did_methods,
            default_ttl: Duration::from_secs(default_ttl_seconds),
            max_ttl: Duration::from_secs(max_ttl_seconds),
            revalidation_grace: Duration::from_secs(revalidation_grace_seconds),
            as_of_skew: Duration::from_secs(as_of_skew_seconds),
            ingest_modes,
            rate_limit_per_resource_per_min,
            query_max_queries_per_ip_per_min,
            query_max_resolves_per_resource_per_min,
            query_latency_floor: Duration::from_millis(query_latency_floor_ms),
            query_latency_jitter: Duration::from_millis(query_latency_jitter_ms),
            require_http_sig,
            http_sig_pubkeys,
            receipt_signing_key,
            db_pool,
            expiry_interval,
            takedown_notifier_interval,
            trusted_proxy,
        })
    }

    /// Materialise the ingest HTTP signature key directory. Static keys
    /// remain a deterministic fallback, while DID-URL keyids resolve through
    /// the process-wide resolver the caller passes in.
    ///
    /// DID-P0-C01: the resolver is an argument rather than something this
    /// method builds, so the accepted-method allowlist and the egress
    /// decision come from the single `AppState` instance instead of being
    /// re-derived (and potentially re-widened) per middleware.
    pub fn http_sig_key_directory(
        &self,
        resolver: Arc<SharedDidResolver>,
    ) -> DidResolverKeyDirectory {
        DidResolverKeyDirectory::new(self.http_sig_pubkeys.clone(), resolver)
    }
}

/// Parse `TEABAY_HTTP_SIG_PUBKEYS` into a `keyid → VerifyingKey`
/// map. The wire format is comma-separated `keyid=base64url(pubkey)`
/// pairs; both `base64url` (no padding) and standard padded base64 are
/// tolerated. Empty / unset is `Ok(HashMap::new())`.
fn parse_http_sig_pubkeys(value: Option<&str>) -> anyhow::Result<HashMap<String, VerifyingKey>> {
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
        let key = VerifyingKey::try_from(bytes.as_slice()).map_err(|e| {
            anyhow::anyhow!(
                "TEABAY_HTTP_SIG_PUBKEYS keyid `{key_id}` is not a valid Ed25519 public key: {e}"
            )
        })?;
        map.insert(key_id, key);
    }
    Ok(map)
}

fn parse_receipt_signing_key(
    value: Option<&str>,
    key_id: String,
) -> anyhow::Result<Option<ReceiptSigningKey>> {
    let Some(raw) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(raw))
        .map_err(|error| {
            anyhow::anyhow!("TEABAY_RECEIPT_SIGNING_KEY_B64 is not base64: {error}")
        })?;
    let bytes: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "TEABAY_RECEIPT_SIGNING_KEY_B64 must decode to a 32-byte Ed25519 signing key"
        )
    })?;
    let key_id = key_id.trim();
    if key_id.is_empty() {
        anyhow::bail!("TEABAY_RECEIPT_KEY_ID must not be empty when receipt signing is enabled");
    }
    Ok(Some(ReceiptSigningKey::from_raw(key_id.to_owned(), bytes)))
}

/// Parse `TEABAY_TRUSTED_PROXY` into a list of IPs that the
/// rate-limiter trusts as the source of `X-Forwarded-For`. Empty /
/// unset returns `Ok(None)` which means "trust only the direct
/// `remote_addr`".
fn parse_trusted_proxy(value: Option<String>) -> anyhow::Result<Option<Vec<IpAddr>>> {
    let Some(raw) = value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let ip: IpAddr = part
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid TEABAY_TRUSTED_PROXY entry `{part}`: {e}"))?;
        out.push(ip);
    }
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

fn required_non_empty_env(key: &str) -> anyhow::Result<String> {
    std::env::var(key)
        .map_err(|_| anyhow::anyhow!("{key} is required"))
        .and_then(|value| {
            let value = value.trim();
            if value.is_empty() {
                anyhow::bail!("{key} must not be empty");
            }
            Ok(value.to_owned())
        })
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

fn arg_value(name: &str) -> Option<String> {
    let mut args = std::env::args();
    while let Some(arg) = args.next() {
        if arg == name {
            return args.next();
        }
    }
    None
}
