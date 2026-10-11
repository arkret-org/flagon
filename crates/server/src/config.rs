//! Environment-driven configuration.
//!
//! Read-only service configuration. There are no ingest policy knobs.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use arkret_sdk::{Did, DidCoreId, ResolutionCommitment, project_did_to_core_id};
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
                "config {} contains unsupported key {key}; expected FLAGON_*, DATABASE_URL, or RUST_LOG",
                path.display()
            );
        }
        values.push((key, value));
    }
    Ok(values)
}

fn is_allowed_config_key(key: &str) -> bool {
    key.starts_with("FLAGON_") || matches!(key, "DATABASE_URL" | "RUST_LOG")
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
    /// `ServiceDescribe`. Flagon never manufactures history heads or version
    /// identifiers from the DID text.
    pub service_resolution: ResolutionCommitment,
    /// Typed trust domain advertised in `/directory/describe`.
    pub trust_domain: String,
    pub database_url: String,
    pub cors_allow_origin: Option<String>,
    /// C.10.10 — require browser callers to mint an X-CSRF-Token header
    /// matching this configured value on every state-changing admin
    /// call. Required in production mode (startup fails closed without
    /// it); optional only when `FLAGON_DEVELOPMENT_MODE=true`. When set,
    /// Set-Cookie is also emitted with `SameSite=Strict` so cookie-bearing
    /// strands are additionally CSRF-hardened.
    pub admin_csrf_token: Option<String>,
    pub admin_token: Option<String>,
    /// A.8.4 — sliding window during which a rotating HMAC token
    /// remains valid. Defaults to 30 minutes; clients sign
    /// `HMAC_SHA256(secret, format!("{key_id}:{timestamp}"))` and
    /// flagon accepts the proof when `now - timestamp <=
    /// admin_token_rotation_window`. Env:
    /// `FLAGON_ADMIN_TOKEN_ROTATION_WINDOW_SECS` (default 1800).
    pub admin_token_rotation_window: std::time::Duration,
    pub development_mode: bool,

    /// Query-face rate limit (per IP, per 60s window). Applies to every
    /// `ak.directory.search_*` / `ak.directory.resolve_*` endpoint. 0
    /// means disabled. Env: `FLAGON_QUERY_MAX_QUERIES_PER_IP_PER_MIN`.
    pub query_max_queries_per_ip_per_min: u32,
    /// Per-`resource_id` resolve rate limit. Cools off enumeration
    /// attempts against a single resource without affecting general
    /// search traffic. 0 means disabled. Env:
    /// `FLAGON_QUERY_MAX_RESOLVES_PER_RESOURCE_PER_MIN`.
    pub query_max_resolves_per_resource_per_min: u32,

    /// P2E.6 — diesel + r2d2 connection pool tunables. Operators surface
    /// these as env vars; see `docs/scaling.md` for sizing guidance and
    /// `Db::connect_with` for the live behaviour.
    pub db_pool: DbPoolConfig,
    /// P5 — list of IPs that are allowed to inject `X-Forwarded-For`
    /// (or equivalent) when the rate-limiter resolves a client address.
    /// When unset, the rate-limiter trusts `req.remote_addr()` only.
    /// Env: `FLAGON_TRUSTED_PROXY` (comma-separated IPs).
    pub trusted_proxy: Option<Vec<IpAddr>>,
}

/// Pool sizing knobs for the diesel + deadpool PostgreSQL connection pool.
/// Every field is overridable via env. Defaults match the "small
/// production" sizing recommended in `docs/scaling.md`.
#[derive(Clone, Debug)]
pub struct DbPoolConfig {
    /// Hard ceiling on concurrent Postgres connections this flagon
    /// instance will open, including admin queries.
    /// Default: 16. Env: `FLAGON_DB_POOL_MAX_SIZE`.
    pub max_size: u32,
    /// How long `pool.get()` waits for an available connection before
    /// returning a `Timeout` error. Tune this together with the
    /// query rate limit so a burst can't tarpit the request thread.
    /// Default: 5 s. Env: `FLAGON_DB_POOL_CONNECTION_TIMEOUT_SECS`.
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

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let bind = arg_value("--bind")
            .or_else(|| std::env::var("FLAGON_BIND").ok())
            .unwrap_or_else(|| "0.0.0.0:7781".to_string());
        let bind: SocketAddr = bind
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid FLAGON_BIND={bind}: {e}"))?;
        let metrics_bind =
            std::env::var("FLAGON_METRICS_BIND").unwrap_or_else(|_| "127.0.0.1:9095".to_string());
        let metrics_bind: SocketAddr = metrics_bind
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid FLAGON_METRICS_BIND={metrics_bind}: {e}"))?;

        let public_base_url =
            std::env::var("FLAGON_PUBLIC_BASE_URL").unwrap_or_else(|_| format!("http://{bind}"));

        // The configured identity is the current resolvable DID. Business
        // DTOs and persistence keys use only its adapter-projected core id.
        let service_did_raw = required_non_empty_env("FLAGON_SERVICE_DID")?;
        let service_did = Did::new(service_did_raw.clone())
            .map_err(|error| anyhow::anyhow!("FLAGON_SERVICE_DID is not a valid DID: {error}"))?;
        let service_id = project_did_to_core_id(&service_did).map_err(|error| {
            anyhow::anyhow!("FLAGON_SERVICE_DID has no active method adapter: {error}")
        })?;
        let method_history_head = required_non_empty_env("FLAGON_SERVICE_METHOD_HISTORY_HEAD")?;
        let version_id = required_non_empty_env("FLAGON_SERVICE_VERSION_ID")?;
        let service_resolution = ResolutionCommitment {
            did: service_did.clone(),
            method_history_head,
            version_id,
        };

        // Required trust domain on ServiceDescribe. Operators
        // SHOULD set FLAGON_TRUST_DOMAIN explicitly; the fallback only
        // exists so the in-process conformance harness keeps booting.
        let trust_domain = std::env::var("FLAGON_TRUST_DOMAIN")
            .unwrap_or_else(|_| "ak:trust_domain:local.test".to_owned());
        if arkret_sdk::TrustDomainId::new(trust_domain.clone()).is_err() {
            anyhow::bail!(
                "FLAGON_TRUST_DOMAIN={trust_domain} is not a valid `ak:trust_domain:` identifier"
            );
        }

        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("DATABASE_URL is required"))?;

        let cors_allow_origin = std::env::var("FLAGON_CORS_ALLOW_ORIGIN").ok();
        let development_mode = read_bool("FLAGON_DEVELOPMENT_MODE", false)?;
        let admin_token = if development_mode {
            std::env::var("FLAGON_ADMIN_TOKEN")
                .ok()
                .filter(|token| !token.trim().is_empty())
        } else {
            if std::env::var("FLAGON_ADMIN_TOKEN")
                .ok()
                .is_some_and(|token| !token.trim().is_empty())
            {
                tracing::warn!(
                    "FLAGON_ADMIN_TOKEN is ignored when FLAGON_DEVELOPMENT_MODE=false; \
                     provision rotating HMAC admin credentials in admin_tokens instead"
                );
            }
            None
        };
        let admin_csrf_token = std::env::var("FLAGON_ADMIN_CSRF_TOKEN")
            .ok()
            .filter(|token| !token.trim().is_empty());

        // P5 HIGH — CSRF is required in production mode (i.e. not
        // development_mode). Fail-closed at startup so an operator cannot
        // expose the admin SPA without CSRF protection. There is no opt-out.
        // See docs/deployment.md hardening checklist.
        if !development_mode && admin_csrf_token.is_none() {
            anyhow::bail!(
                "FLAGON_ADMIN_CSRF_TOKEN is required in production mode \
                 (FLAGON_DEVELOPMENT_MODE=false)"
            );
        }
        let admin_token_rotation_window_secs =
            read_u64("FLAGON_ADMIN_TOKEN_ROTATION_WINDOW_SECS", 1_800)?;
        let admin_token_rotation_window =
            Duration::from_secs(admin_token_rotation_window_secs.max(60));

        // Query-face rate limit (per IP). Default 600/min keeps every
        // realistic browser dashboard happy while breaking obvious
        // enumeration sweeps. Set to 0 to disable.
        let query_max_queries_per_ip_per_min =
            read_u64("FLAGON_QUERY_MAX_QUERIES_PER_IP_PER_MIN", 600)? as u32;
        let query_max_resolves_per_resource_per_min =
            read_u64("FLAGON_QUERY_MAX_RESOLVES_PER_RESOURCE_PER_MIN", 120)? as u32;

        // P2E.6 — db pool tunables.
        let defaults = DbPoolConfig::default();
        let pool_max = read_u64("FLAGON_DB_POOL_MAX_SIZE", defaults.max_size as u64)? as u32;
        if pool_max == 0 {
            anyhow::bail!("FLAGON_DB_POOL_MAX_SIZE must be > 0");
        }
        let pool_connection_timeout_secs = read_u64(
            "FLAGON_DB_POOL_CONNECTION_TIMEOUT_SECS",
            defaults.connection_timeout.as_secs(),
        )?;
        if pool_connection_timeout_secs == 0 {
            anyhow::bail!("FLAGON_DB_POOL_CONNECTION_TIMEOUT_SECS must be > 0");
        }
        let db_pool = DbPoolConfig {
            max_size: pool_max,
            connection_timeout: Duration::from_secs(pool_connection_timeout_secs),
        };

        // P5 — trusted proxy allowlist for the rate-limiter.
        let trusted_proxy = parse_trusted_proxy(std::env::var("FLAGON_TRUSTED_PROXY").ok())?;

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
            query_max_queries_per_ip_per_min,
            query_max_resolves_per_resource_per_min,
            db_pool,
            trusted_proxy,
        })
    }
}

/// Parse `FLAGON_TRUSTED_PROXY` into a list of IPs that the
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
            .map_err(|e| anyhow::anyhow!("invalid FLAGON_TRUSTED_PROXY entry `{part}`: {e}"))?;
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

fn arg_value(name: &str) -> Option<String> {
    let mut args = std::env::args();
    while let Some(arg) = args.next() {
        if arg == name {
            return args.next();
        }
    }
    None
}

#[cfg(test)]
#[allow(
    unsafe_code,
    reason = "configuration tests restore their process-local environment after synchronous validation"
)]
mod tests {
    use super::*;

    struct Environment(Vec<(String, Option<String>)>);
    impl Environment {
        fn set(&mut self, key: &str, value: &str) {
            if !self.0.iter().any(|(saved, _)| saved == key) {
                self.0.push((key.into(), std::env::var(key).ok()));
            }
            // SAFETY: this module has one synchronous test; no other lib test reads these keys.
            unsafe { std::env::set_var(key, value) };
        }
    }
    impl Drop for Environment {
        fn drop(&mut self) {
            for (key, value) in &self.0 {
                // SAFETY: restore only keys owned by the synchronous configuration test.
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
    }

    #[test]
    fn operator_configuration_rejects_invalid_posture_and_values() -> anyhow::Result<()> {
        let mut env = Environment(Vec::new());
        for (key, value) in [
            ("FLAGON_BIND", "127.0.0.1:7781"),
            ("FLAGON_METRICS_BIND", "127.0.0.1:9095"),
            ("FLAGON_SERVICE_DID", "did:web:directory.test"),
            ("FLAGON_SERVICE_METHOD_HISTORY_HEAD", "verified-head"),
            ("FLAGON_SERVICE_VERSION_ID", "verified-version"),
            ("DATABASE_URL", "postgres://localhost/unused"),
            ("FLAGON_TRUST_DOMAIN", "ak:trust_domain:local.test"),
            ("FLAGON_DEVELOPMENT_MODE", "false"),
            ("FLAGON_ADMIN_CSRF_TOKEN", "csrf-proof"),
            ("FLAGON_ADMIN_TOKEN", "development-only-secret"),
            ("FLAGON_ADMIN_TOKEN_ROTATION_WINDOW_SECS", "1"),
            ("FLAGON_QUERY_MAX_QUERIES_PER_IP_PER_MIN", "100"),
            ("FLAGON_QUERY_MAX_RESOLVES_PER_RESOURCE_PER_MIN", "20"),
            ("FLAGON_DB_POOL_MAX_SIZE", "2"),
            ("FLAGON_DB_POOL_CONNECTION_TIMEOUT_SECS", "1"),
            ("FLAGON_TRUSTED_PROXY", "127.0.0.1, ::1"),
        ] {
            env.set(key, value);
        }
        let good = AppConfig::from_env()?;
        assert!(good.admin_token.is_none());
        assert_eq!(good.admin_token_rotation_window, Duration::from_secs(60));
        assert_eq!(good.trusted_proxy.as_ref().unwrap().len(), 2);
        for (key, invalid, restore) in [
            ("FLAGON_BIND", "invalid", "127.0.0.1:7781"),
            ("FLAGON_METRICS_BIND", "invalid", "127.0.0.1:9095"),
            ("FLAGON_SERVICE_DID", "invalid", "did:web:directory.test"),
            ("FLAGON_SERVICE_METHOD_HISTORY_HEAD", " ", "verified-head"),
            ("FLAGON_TRUST_DOMAIN", "bad", "ak:trust_domain:local.test"),
            ("FLAGON_DEVELOPMENT_MODE", "maybe", "false"),
            ("FLAGON_ADMIN_CSRF_TOKEN", "", "csrf-proof"),
            ("FLAGON_DB_POOL_MAX_SIZE", "0", "2"),
            ("FLAGON_DB_POOL_CONNECTION_TIMEOUT_SECS", "0", "1"),
            ("FLAGON_TRUSTED_PROXY", "localhost", "127.0.0.1, ::1"),
            (
                "FLAGON_QUERY_MAX_QUERIES_PER_IP_PER_MIN",
                "not-an-integer",
                "100",
            ),
        ] {
            env.set(key, invalid);
            assert!(
                AppConfig::from_env().is_err(),
                "invalid {key} must fail closed"
            );
            env.set(key, restore);
        }
        assert_eq!(
            config_path_from_args(&["flagon".into(), "--config=a.env".into()])?,
            Some("a.env".into())
        );
        assert_eq!(
            config_path_from_args(&["flagon".into(), "--config".into(), "a.env".into()])?,
            Some("a.env".into())
        );
        assert!(config_path_from_args(&["flagon".into(), "--config".into()]).is_err());
        assert!(config_path_from_args(&["flagon".into(), "--config=".into()]).is_err());
        assert!(
            config_path_from_args(&["flagon".into(), "--bind".into(), "127.0.0.1:0".into()])?
                .is_none()
        );
        let path =
            std::env::temp_dir().join(format!("flagon-config-test-{}.env", std::process::id()));
        std::fs::write(
            &path,
            "FLAGON_BIND=127.0.0.1:0\nDATABASE_URL=postgres://localhost/unused\nRUST_LOG=info\n",
        )?;
        assert_eq!(read_config_environment(&path)?.len(), 3);
        std::fs::write(&path, "UNSUPPORTED_SECRET=not-used\n")?;
        assert!(read_config_environment(&path).is_err());
        std::fs::write(&path, "malformed [ config\n")?;
        assert!(read_config_environment(&path).is_err());
        std::fs::remove_file(path)?;
        assert!(parse_trusted_proxy(None)?.is_none());
        assert!(parse_trusted_proxy(Some(" , ".into()))?.is_none());
        for boolean in ["true", "YES", "on", "1"] {
            env.set("FLAGON_DEVELOPMENT_MODE", boolean);
            assert!(read_bool("FLAGON_DEVELOPMENT_MODE", false)?);
        }
        for boolean in ["false", "OFF", "0", ""] {
            env.set("FLAGON_DEVELOPMENT_MODE", boolean);
            assert!(!read_bool("FLAGON_DEVELOPMENT_MODE", true)?);
        }
        env.set("FLAGON_QUERY_MAX_QUERIES_PER_IP_PER_MIN", "");
        assert_eq!(read_u64("FLAGON_QUERY_MAX_QUERIES_PER_IP_PER_MIN", 42)?, 42);
        Ok(())
    }
}
