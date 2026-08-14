//! Directory-service binding of the shared Arkret egress guard.
//!
//! The parse/judge/resolve/bind sequence lives in `arkret-egress-reqwest`. What
//! is directory-specific is only which posture a given deployment runs under,
//! which is derived here from the startup `development_mode` flag.

use arkret_egress_reqwest::EgressGuard;
pub(crate) use arkret_egress_reqwest::LockedEgressUrl;
use reqwest::Url;

pub(crate) const fn local_development_enabled(development_mode: bool) -> bool {
    development_mode
}

pub(crate) fn guard(development_mode: bool) -> EgressGuard {
    if development_mode {
        EgressGuard::local_development()
    } else {
        EgressGuard::public_https()
    }
}

pub(crate) fn resolve_http_url_for_egress(
    raw_url: &str,
    purpose: &str,
    development_mode: bool,
) -> Result<LockedEgressUrl, String> {
    guard(development_mode)
        .lock_str(raw_url, purpose)
        .map_err(|error| error.to_string())
}

pub(crate) fn validate_url_for_egress(
    url: &Url,
    purpose: &str,
    development_mode: bool,
) -> Result<(), String> {
    resolve_url_for_egress(url, purpose, development_mode).map(|_| ())
}

pub(crate) fn resolve_url_for_egress(
    url: &Url,
    purpose: &str,
    development_mode: bool,
) -> Result<LockedEgressUrl, String> {
    guard(development_mode)
        .lock_url(url, purpose)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_rejects_http_and_non_public_targets() {
        for raw in [
            "http://93.184.216.34/path",
            "https://127.0.0.1:8080/sink",
            "https://10.0.0.2/.well-known/did.json",
            "https://169.254.169.254/latest/meta-data",
            "https://[fd00::1]/sink",
            "https://198.18.0.1/path",
            "https://192.0.2.1/path",
        ] {
            let url = Url::parse(raw).unwrap();
            assert!(validate_url_for_egress(&url, "test", false).is_err());
        }
    }

    #[test]
    fn development_only_adds_http_loopback() {
        let loopback = Url::parse("http://127.0.0.1:8080/sink").unwrap();
        assert!(validate_url_for_egress(&loopback, "test", true).is_ok());

        let private = Url::parse("http://10.0.0.1:8080/sink").unwrap();
        assert!(validate_url_for_egress(&private, "test", true).is_err());
    }

    #[test]
    fn development_locks_resolved_host_to_current_addresses() {
        let url = Url::parse("http://localhost:8080/sink").unwrap();
        let target = resolve_url_for_egress(&url, "test", true).unwrap();

        assert_eq!(target.url().as_str(), "http://localhost:8080/sink");
        let (host, addrs) = target.dns_override().expect("named host is pinned");
        assert_eq!(host, "localhost");
        assert!(
            addrs
                .iter()
                .any(|addr| addr.port() == 8080 && addr.ip().is_loopback())
        );
    }

    #[test]
    fn production_rejects_all_transition_forms() {
        for raw in [
            "https://[64:ff9b::a9fe:a9fe]/latest/meta-data",
            "https://[2002:0a00:0001::]/sink",
            "https://[::ffff:10.0.0.1]/sink",
            "https://[2001:0000:7f00:0001:0000:0000:3f57:fefe]/sink",
        ] {
            let url = Url::parse(raw).unwrap();
            assert!(
                validate_url_for_egress(&url, "test", false).is_err(),
                "{raw} should be blocked"
            );
        }
    }

    #[test]
    fn ip_literal_does_not_need_dns_override() {
        let url = Url::parse("https://93.184.216.34/path").unwrap();
        let target = resolve_url_for_egress(&url, "test", false).unwrap();

        assert_eq!(target.url().as_str(), "https://93.184.216.34/path");
        assert!(target.dns_override().is_none());
    }
}
