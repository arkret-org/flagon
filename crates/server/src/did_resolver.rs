//! Shared DID resolver construction for ingest proof and HTTP signature
//! verification.

use std::sync::Arc;
use std::time::Duration;

use contrix_sdk::identity::{DidKeyResolver, ResolverPolicy};
use contrix_sdk::{CompositeDidResolver, HttpDidResolver};
use reqwest::Client;

/// Build the production resolver chain for the DID methods accepted by
/// this teabay instance.
///
/// `allow_private_networks` is the single source of truth for SSRF egress
/// policy and MUST be derived by the caller from `AppConfig`
/// (`crate::egress::private_networks_allowed(config.development_mode)`), not
/// re-read from the environment here — that keeps the egress decision tied to
/// the startup config snapshot.
pub(crate) fn did_resolver_chain(
    accepted_did_methods: &[String],
    allow_private_networks: bool,
) -> Result<CompositeDidResolver, String> {
    let policy = resolver_policy(accepted_did_methods);
    let http_client = Client::builder()
        .timeout(Duration::from_millis(2_000))
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(crate::egress::ValidatingDnsResolver::new(
            allow_private_networks,
        )))
        .build()
        .map_err(|e| format!("HTTP DID resolver client init failed: {e}"))?;
    let http = HttpDidResolver::with_client(http_client, policy.clone())
        .map_err(|e| format!("HTTP DID resolver init failed: {e}"))?;
    let mut resolver = CompositeDidResolver::new().with_policy(policy);
    resolver.push(DidKeyResolver::new());
    resolver.push(http);
    Ok(resolver)
}

/// Build a policy that accepts the configured DID methods.
pub(crate) fn resolver_policy(accepted_did_methods: &[String]) -> ResolverPolicy {
    ResolverPolicy {
        allowed_methods: accepted_did_methods
            .iter()
            .map(|method| normalize_did_method_prefix(method))
            .collect(),
        ..ResolverPolicy::default()
    }
}

pub(crate) fn normalize_did_method_prefix(method: &str) -> String {
    let trimmed = method.trim();
    if trimmed.ends_with(':') {
        trimmed.to_owned()
    } else {
        format!("{trimmed}:")
    }
}
