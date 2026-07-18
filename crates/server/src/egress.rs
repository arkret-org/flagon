use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use arkret_network_policy::OutboundPolicy;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{ClientBuilder, Url};

type DnsError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) const fn local_development_enabled(development_mode: bool) -> bool {
    development_mode
}

#[derive(Clone, Debug)]
pub(crate) struct ValidatingDnsResolver {
    development_mode: bool,
}

impl ValidatingDnsResolver {
    pub(crate) fn new(development_mode: bool) -> Self {
        Self { development_mode }
    }
}

impl Resolve for ValidatingDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let development_mode = self.development_mode;
        Box::pin(async move {
            let addrs = tokio::task::spawn_blocking(move || {
                resolve_host_addrs(&host, 0, "reqwest egress DNS resolver", development_mode)
            })
            .await
            .map_err(|join_err| dns_error(format!("egress DNS resolver task failed: {join_err}")))?
            .map_err(dns_error)?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

pub(crate) fn resolve_http_url_for_egress(
    raw_url: &str,
    purpose: &str,
    development_mode: bool,
) -> Result<LockedEgressUrl, String> {
    let url = Url::parse(raw_url).map_err(|error| format!("{purpose}: invalid URL: {error}"))?;
    resolve_url_for_egress(&url, purpose, development_mode)
}

pub(crate) fn validate_url_for_egress(
    url: &Url,
    purpose: &str,
    development_mode: bool,
) -> Result<(), String> {
    resolve_url_for_egress(url, purpose, development_mode).map(|_| ())
}

#[derive(Debug, Clone)]
pub(crate) struct LockedEgressUrl {
    url: Url,
    resolve_host: Option<String>,
    resolved_addrs: Vec<SocketAddr>,
}

impl LockedEgressUrl {
    pub(crate) fn url(&self) -> &Url {
        &self.url
    }

    pub(crate) fn apply_to_client_builder(&self, builder: ClientBuilder) -> ClientBuilder {
        match self.resolve_host.as_deref() {
            Some(host) if !self.resolved_addrs.is_empty() => {
                builder.resolve_to_addrs(host, &self.resolved_addrs)
            }
            _ => builder,
        }
    }

    #[cfg(test)]
    fn resolved_addrs(&self) -> &[SocketAddr] {
        &self.resolved_addrs
    }
}

pub(crate) fn resolve_url_for_egress(
    url: &Url,
    purpose: &str,
    development_mode: bool,
) -> Result<LockedEgressUrl, String> {
    let policy = policy(development_mode);
    policy
        .validate_url(url)
        .map_err(|error| format!("{purpose}: {error}"))?;
    let host = url.host_str().expect("validated URL has a host");
    let port = url.port_or_known_default().unwrap_or(443);
    let literal_ip = match url.host() {
        Some(url::Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
        _ => None,
    };
    if let Some(ip) = literal_ip {
        policy
            .validate_ip(ip)
            .map_err(|error| format!("{purpose}: {error}"))?;
        return Ok(LockedEgressUrl {
            url: url.clone(),
            resolve_host: None,
            resolved_addrs: Vec::new(),
        });
    }
    let resolved = resolve_host_addrs(host, port, purpose, development_mode)?;
    Ok(LockedEgressUrl {
        url: url.clone(),
        resolve_host: Some(host.to_owned()),
        resolved_addrs: resolved,
    })
}

fn resolve_host_addrs(
    host: &str,
    port: u16,
    purpose: &str,
    development_mode: bool,
) -> Result<Vec<SocketAddr>, String> {
    let policy = policy(development_mode);
    if let Ok(ip) = host.parse::<IpAddr>() {
        policy
            .validate_ip(ip)
            .map_err(|error| format!("{purpose}: {error}"))?;
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let resolved = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("{purpose}: DNS resolution for {host} failed: {error}"))?
        .collect::<Vec<_>>();
    policy
        .validate_resolved_addresses(&resolved)
        .map_err(|error| format!("{purpose}: {error}"))?;
    Ok(resolved)
}

fn policy(development_mode: bool) -> OutboundPolicy {
    if development_mode {
        OutboundPolicy::local_development()
    } else {
        OutboundPolicy::public_https()
    }
}

fn dns_error(message: String) -> DnsError {
    Box::new(std::io::Error::other(message))
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
        assert!(
            target
                .resolved_addrs()
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
        assert!(target.resolved_addrs().is_empty());
    }
}
