use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use reqwest::Url;

const TEABAY_EGRESS_ALLOW_PRIVATE_NETWORKS: &str = "TEABAY_EGRESS_ALLOW_PRIVATE_NETWORKS";

pub(crate) fn private_networks_allowed(development_mode: bool) -> bool {
    env_bool(TEABAY_EGRESS_ALLOW_PRIVATE_NETWORKS).unwrap_or(development_mode)
}

pub(crate) fn validate_http_url_for_egress(
    raw_url: &str,
    purpose: &str,
    development_mode: bool,
) -> Result<Url, String> {
    let url = Url::parse(raw_url).map_err(|error| format!("{purpose}: invalid URL: {error}"))?;
    validate_url_for_egress(&url, purpose, private_networks_allowed(development_mode))?;
    Ok(url)
}

pub(crate) fn validate_url_for_egress(
    url: &Url,
    purpose: &str,
    allow_private_networks: bool,
) -> Result<(), String> {
    match url.scheme() {
        "http" | "https" => {}
        scheme => return Err(format!("{purpose}: URL scheme {scheme:?} is not allowed")),
    }
    let host = url
        .host_str()
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| format!("{purpose}: URL host is required"))?;
    if allow_private_networks {
        return Ok(());
    }
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return Err(format!("{purpose}: localhost egress target is not allowed"));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return validate_resolved_ip(ip, purpose);
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let resolved = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("{purpose}: DNS resolution for {host} failed: {error}"))?;
    for addr in resolved {
        validate_resolved_ip(addr.ip(), purpose)?;
    }
    Ok(())
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
            if let Some(v4) = ipv4_mapped(ip) {
                return blocked_ipv4(v4);
            }
            blocked_ipv6(ip)
        }
    }
}

fn blocked_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 169 && b == 254 && c == 169 && d == 254)
        || a >= 224
}

fn blocked_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}

fn ipv4_mapped(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();
    if segments[..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff {
        let high = segments[6].to_be_bytes();
        let low = segments[7].to_be_bytes();
        Some(Ipv4Addr::new(high[0], high[1], low[0], low[1]))
    } else {
        None
    }
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
}
