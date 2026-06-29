use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{ClientBuilder, Url};

const TEABAY_EGRESS_ALLOW_PRIVATE_NETWORKS: &str = "TEABAY_EGRESS_ALLOW_PRIVATE_NETWORKS";

type DnsError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) fn private_networks_allowed(development_mode: bool) -> bool {
    env_bool(TEABAY_EGRESS_ALLOW_PRIVATE_NETWORKS).unwrap_or(development_mode)
}

#[derive(Clone, Debug)]
pub(crate) struct ValidatingDnsResolver {
    allow_private_networks: bool,
}

impl ValidatingDnsResolver {
    pub(crate) fn new(allow_private_networks: bool) -> Self {
        Self {
            allow_private_networks,
        }
    }
}

impl Resolve for ValidatingDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let allow_private_networks = self.allow_private_networks;
        Box::pin(async move {
            // `resolve_host_addrs` performs a blocking `getaddrinfo`; run it on
            // the blocking pool so we never stall a tokio worker thread.
            let addrs = tokio::task::spawn_blocking(move || {
                resolve_host_addrs(
                    &host,
                    0,
                    "reqwest egress DNS resolver",
                    allow_private_networks,
                )
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
    resolve_url_for_egress(&url, purpose, private_networks_allowed(development_mode))
}

pub(crate) fn validate_url_for_egress(
    url: &Url,
    purpose: &str,
    allow_private_networks: bool,
) -> Result<(), String> {
    resolve_url_for_egress(url, purpose, allow_private_networks).map(|_| ())
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
    allow_private_networks: bool,
) -> Result<LockedEgressUrl, String> {
    match url.scheme() {
        "http" | "https" => {}
        scheme => return Err(format!("{purpose}: URL scheme {scheme:?} is not allowed")),
    }
    let host = url
        .host_str()
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| format!("{purpose}: URL host is required"))?;
    if !allow_private_networks
        && (host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost"))
    {
        return Err(format!("{purpose}: localhost egress target is not allowed"));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !allow_private_networks {
            validate_resolved_ip(ip, purpose)?;
        }
        return Ok(LockedEgressUrl {
            url: url.clone(),
            resolve_host: None,
            resolved_addrs: Vec::new(),
        });
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let resolved = resolve_host_addrs(host, port, purpose, allow_private_networks)?;
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
    allow_private_networks: bool,
) -> Result<Vec<SocketAddr>, String> {
    if !allow_private_networks
        && (host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost"))
    {
        return Err(format!("{purpose}: localhost egress target is not allowed"));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !allow_private_networks {
            validate_resolved_ip(ip, purpose)?;
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let resolved: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("{purpose}: DNS resolution for {host} failed: {error}"))?
        .collect();
    if resolved.is_empty() {
        return Err(format!(
            "{purpose}: DNS resolution for {host} returned no addresses"
        ));
    }
    if !allow_private_networks {
        for addr in &resolved {
            validate_resolved_ip(addr.ip(), purpose)?;
        }
    }
    Ok(resolved)
}

fn dns_error(message: String) -> DnsError {
    Box::new(std::io::Error::other(message))
}

fn validate_resolved_ip(ip: IpAddr, purpose: &str) -> Result<(), String> {
    if blocked_ip(ip) {
        return Err(format!(
            "{purpose}: egress target resolved to blocked address {ip}"
        ));
    }
    Ok(())
}

fn blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => blocked_ipv4(ip),
        IpAddr::V6(ip) => {
            // Any IPv6 form that embeds an IPv4 address (IPv4-mapped,
            // IPv4-compatible, NAT64, 6to4) is judged by the embedded v4 so
            // none of them can smuggle a request to a private / metadata IPv4
            // (e.g. `[64:ff9b::a9fe:a9fe]` → 169.254.169.254).
            if let Some(v4) = embedded_ipv4(ip) {
                return blocked_ipv4(v4);
            }
            blocked_ipv6(ip)
        }
    }
}

fn blocked_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _d] = ip.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        // 169.254.0.0/16 link-local, which already covers the cloud
        // metadata endpoint 169.254.169.254.
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0) // 192.0.0.0/24 IETF protocol assignments
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 224
}

fn blocked_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
        || (segments[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        || (segments[0] == 0x2001 && segments[1] == 0x0db8) // 2001:db8::/32 doc
}

/// Extract the embedded IPv4 address from the IPv6 forms that carry one:
/// IPv4-mapped (`::ffff:0:0/96`), NAT64 (`64:ff9b::/96`), 6to4 (`2002::/16`),
/// and the deprecated IPv4-compatible (`::/96`, excluding `::`/`::1`).
fn embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();
    let last_v4 = || {
        let high = segments[6].to_be_bytes();
        let low = segments[7].to_be_bytes();
        Ipv4Addr::new(high[0], high[1], low[0], low[1])
    };
    // IPv4-mapped ::ffff:a.b.c.d
    if segments[..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff {
        return Some(last_v4());
    }
    // NAT64 64:ff9b::/96 (well-known prefix)
    if segments[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        return Some(last_v4());
    }
    // 6to4 2002:WWXX:YYZZ::/16 — embedded IPv4 is segments[1..3]
    if segments[0] == 0x2002 {
        let high = segments[1].to_be_bytes();
        let low = segments[2].to_be_bytes();
        return Some(Ipv4Addr::new(high[0], high[1], low[0], low[1]));
    }
    // IPv4-compatible ::a.b.c.d (deprecated), excluding :: and ::1
    if segments[..6] == [0, 0, 0, 0, 0, 0]
        && !(segments[6] == 0 && (segments[7] == 0 || segments[7] == 1))
    {
        return Some(last_v4());
    }
    None
}

fn env_bool(name: &str) -> Option<bool> {
    std::env::var(name)
        .ok()
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_rejects_private_targets() {
        for raw in [
            "http://127.0.0.1:8080/sink",
            "https://10.0.0.2/.well-known/did.json",
            "http://169.254.169.254/latest/meta-data",
            "http://[fd00::1]/sink",
        ] {
            let url = Url::parse(raw).unwrap();
            assert!(validate_url_for_egress(&url, "test", false).is_err());
        }
    }

    #[test]
    fn development_can_allow_loopback() {
        let url = Url::parse("http://127.0.0.1:8080/sink").unwrap();
        assert!(validate_url_for_egress(&url, "test", true).is_ok());
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
    fn production_rejects_ipv6_embedded_metadata_v4() {
        // NAT64, IPv4-compatible, 6to4 and IPv4-mapped forms of
        // 169.254.169.254 / private space must all be blocked.
        for raw in [
            "http://[64:ff9b::a9fe:a9fe]/latest/meta-data", // NAT64 169.254.169.254
            "http://[::a9fe:a9fe]/sink",                    // IPv4-compatible 169.254.169.254
            "http://[2002:0a00:0001::]/sink",               // 6to4 10.0.0.1
            "http://[::ffff:10.0.0.1]/sink",                // IPv4-mapped 10.0.0.1
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
        let url = Url::parse("http://93.184.216.34/path").unwrap();
        let target = resolve_url_for_egress(&url, "test", false).unwrap();

        assert_eq!(target.url().as_str(), "http://93.184.216.34/path");
        assert!(target.resolved_addrs().is_empty());
    }
}
