//! Shared DID resolver construction for ingest proof and HTTP signature
//! verification.

use contrix_sdk::identity::{DidKeyResolver, ResolverPolicy};
use contrix_sdk::{CompositeDidResolver, HttpDidResolver};

/// Build the production resolver chain for the DID methods accepted by
/// this teabay instance.
pub(crate) fn did_resolver_chain(
    accepted_did_methods: &[String],
) -> Result<CompositeDidResolver, String> {
    let policy = resolver_policy(accepted_did_methods);
    let http = HttpDidResolver::with_policy(policy.clone())
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
