//! The **authority** half of teabay's DID surface: the one process-wide
//! resolver chain, and the only code allowed to reach the network for a DID.
//!
//! # DID-P0-C01 — one resolver per process, not one per request
//!
//! [`did_resolver_chain`] builds a brand-new `reqwest::Client` (with its own
//! connection pool, DNS resolver and TLS state) every time it is called. It
//! therefore has exactly **one** legitimate call site: [`SharedDidResolver::new`],
//! which `AppState::new` invokes once at startup. Every request path takes the
//! already-built [`SharedDidResolver`] out of `AppState`.
//!
//! That is not only a performance property. `arkret-spec/spec/v1/zh/identity/
//! did-usage-and-verification.md` §6 requires business code to consume verified
//! bindings rather than to hold a general-purpose network resolver, and §5
//! requires resolution results to be reusable — impossible when the resolver
//! (and its document cache) is thrown away after each request.
//!
//! # DID-P0-C02 / C03 — the chain is private, and only one face can see it
//!
//! [`SharedDidResolver`] has **no `chain()` accessor**. The chain is a private
//! field; the only ways out of this module are purpose-scoped operations that
//! establish or refresh a [`crate::did_binding`] acceptance, and the RFC 9421
//! HTTP-signature key lookup. Consequently:
//!
//! - the query / filter face is handed a [`crate::did_binding::DidBindingDirectory`], which has no
//!   resolver at all — "a query handler holds a general-purpose network resolver" is not
//!   expressible;
//! - even the ingest face, which *does* hold a `SharedDidResolver`, cannot obtain a `&dyn
//!   DidResolver` and call `resolve_did` on an arbitrary DID of its choosing outside the
//!   purpose-scoped entry points below.
//!
//! Every outbound resolution funnels through [`MeteredAuthorityResolver`], so
//! `teabay_did_resolve_total{source="network"}` — the joint contract's
//! `authority_network_call_count` — cannot drift from reality.

use std::sync::Arc;
use std::time::Duration;

use arkret_identity::binding::{DidBindingPurpose, FreshnessRequirement, LimitedTrustReason};
use arkret_identity::binding_digest::normalize_did_method_prefix;
use arkret_identity::binding_store::AcceptedDidBinding;
use arkret_identity::jws::resolve_ed25519_pubkey;
use arkret_identity::verifier::{
    BindingAcceptanceTerms, BindingEvidenceError, DeferredEvidenceResolveRequest,
    resolve_and_verify_binding_with_evidence,
};
use arkret_sdk::identity::{
    DidDocument, DidKeyResolver, DidResolver, ResolverPolicy, Result as IdentityResult,
};
use arkret_sdk::{CompositeDidResolver, Did, HttpDidResolver};
use arkret_signatures::http_signature::Ed25519PublicKey;
use chrono::{DateTime, Utc};
use reqwest::Client;

use crate::did_binding::{BindingEvidence, BindingFailure, DidBindingDirectory};
use crate::observability::{
    DID_RESOLVE_SOURCE_DID_KEY, DID_RESOLVE_SOURCE_NETWORK, Metrics, SIGNATURE_OUTCOME_OK,
};

/// Process-wide DID resolver handle — the authority face.
///
/// Built exactly once, in `AppState::new`, from the startup `AppConfig`
/// snapshot; borrowed (never rebuilt) by every request path. Because the
/// accepted-method allowlist and the `allow_private_networks` egress decision
/// are captured *inside* this value, a request handler has no way to widen
/// either one: it cannot pass a different allowlist, and it cannot ask for a
/// client that skips [`crate::egress::ValidatingDnsResolver`].
///
/// ## What is deliberately NOT shared
///
/// The outbound clients produced by
/// `crate::ingest::verify::strict_http_client_for_egress(&target)` are pinned
/// to the single IP address that `crate::egress::resolve_url_for_egress`
/// already validated for one specific target URL. That pinning is the
/// DNS-rebinding guard; reusing one such client for a second target would
/// send the request to the first target's address. Those clients therefore
/// stay per-target and per-request, on purpose.
///
/// The resolver chain's own client is different: it is bound to no particular
/// target, only to the egress *policy* (`https_only` + `ValidatingDnsResolver`),
/// which is exactly why it is safe — and required — to share.
pub struct SharedDidResolver {
    /// The zero-network acceptance directory. Shared with the query face.
    bindings: Arc<DidBindingDirectory>,
    allow_private_networks: bool,
    /// PRIVATE, and deliberately without an accessor. See the module docs.
    chain: Arc<dyn DidResolver + Send + Sync>,
    /// Zero-sized, zero-network `did:key` decoder. `did:key` is
    /// self-describing key material (spec §2.4), so resolving it is pure
    /// multibase decoding and MUST NOT be routed through the HTTP chain.
    did_key: DidKeyResolver,
}

impl std::fmt::Debug for SharedDidResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedDidResolver")
            .field(
                "accepted_did_methods",
                &self.bindings.accepted_did_methods(),
            )
            .field("allow_private_networks", &self.allow_private_networks)
            .finish_non_exhaustive()
    }
}

impl SharedDidResolver {
    /// Build the process-wide resolver from the startup config snapshot.
    ///
    /// `development_mode` is the `AppConfig` flag; the egress decision is
    /// derived from it here via `crate::egress::local_development_enabled` so a
    /// caller cannot pass a *different* (wider) egress decision than the one
    /// the config implies.
    pub fn new(accepted_did_methods: &[String], development_mode: bool) -> Result<Self, String> {
        Self::with_metrics(
            accepted_did_methods,
            development_mode,
            "did:web:teabay.invalid",
            Metrics::default(),
        )
    }

    /// Same as [`Self::new`], but wired to the process `Metrics` instance and
    /// the configured service DID (which scopes the binding trust domain).
    pub fn with_metrics(
        accepted_did_methods: &[String],
        development_mode: bool,
        service_id: &str,
        metrics: Metrics,
    ) -> Result<Self, String> {
        let allow_private_networks = crate::egress::local_development_enabled(development_mode);
        let bindings = Arc::new(DidBindingDirectory::new(
            accepted_did_methods,
            allow_private_networks,
            development_mode,
            service_id,
            metrics,
        )?);
        Ok(Self {
            allow_private_networks,
            chain: Arc::new(did_resolver_chain(
                accepted_did_methods,
                allow_private_networks,
            )?),
            did_key: DidKeyResolver::new(),
            bindings,
        })
    }

    /// Test-only constructor that swaps the network chain for an injected
    /// resolver (a counting spy). Not reachable from any handler: it takes the
    /// resolver as an argument, so it can only be used where one is already
    /// available — i.e. in a test.
    #[cfg(test)]
    pub(crate) fn with_chain_for_test(
        accepted_did_methods: &[String],
        chain: Arc<dyn DidResolver + Send + Sync>,
        metrics: Metrics,
    ) -> Result<Self, String> {
        Ok(Self {
            allow_private_networks: false,
            chain,
            did_key: DidKeyResolver::new(),
            bindings: Arc::new(DidBindingDirectory::new(
                accepted_did_methods,
                false,
                false,
                "did:web:directory.example",
                metrics,
            )?),
        })
    }

    /// The shared, zero-network acceptance directory.
    pub fn bindings(&self) -> &Arc<DidBindingDirectory> {
        &self.bindings
    }

    pub fn metrics(&self) -> &Metrics {
        self.bindings.metrics()
    }

    /// The startup accepted-DID-method allowlist.
    ///
    /// Callers still need this because an **empty** list is fail-open at the
    /// `ResolverPolicy` layer ("empty `allowed_methods` means any method"), so
    /// every verification entry point rejects up-front on an empty allowlist.
    pub fn accepted_did_methods(&self) -> &[String] {
        self.bindings.accepted_did_methods()
    }

    /// The startup egress decision. Exposed for assertions/tests only; request
    /// paths must not recompute it.
    pub fn allow_private_networks(&self) -> bool {
        self.allow_private_networks
    }

    pub fn method_allowed(&self, expected: &str) -> bool {
        self.bindings.method_allowed(expected)
    }

    /// Whether the chain can serve this DID at all (method allowlist + adapter
    /// support). Read-only; hands out no resolver.
    pub fn supports(&self, did: &Did) -> bool {
        self.chain.supports(did)
    }

    /// Verify a detached Ed25519 JWS on an **authority** path (spec §4).
    ///
    /// Consumes an accepted binding when one exists — repeat announce /
    /// withdraw / appeal for the same DID, key and policy therefore cost zero
    /// network calls. Only a miss (new verification method, new source service,
    /// changed document digest, policy revision, or an invalidation) reaches
    /// [`Self::accepted_or_resolved`], which resolves exactly once.
    ///
    /// Records exactly one `teabay_signature_verify_total{kind,outcome}`.
    // Same independent-inputs argument as `verify_detached_jws`.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_detached_jws_with_authority(
        &self,
        canonical_bytes: &[u8],
        jws: &str,
        verification_method: &str,
        issuer: &str,
        purpose: DidBindingPurpose,
        kind: &'static str,
        now: DateTime<Utc>,
    ) -> Result<(), BindingFailure> {
        let outcome = self.verify_detached_jws_with_authority_inner(
            canonical_bytes,
            jws,
            verification_method,
            issuer,
            purpose,
            now,
        );
        self.metrics().record_signature_verify(
            kind,
            match &outcome {
                Ok(()) => SIGNATURE_OUTCOME_OK,
                Err(failure) => failure.outcome_label(),
            },
        );
        outcome
    }

    fn verify_detached_jws_with_authority_inner(
        &self,
        canonical_bytes: &[u8],
        jws: &str,
        verification_method: &str,
        issuer: &str,
        purpose: DidBindingPurpose,
        now: DateTime<Utc>,
    ) -> Result<(), BindingFailure> {
        let (issuer, verification_method) =
            self.bindings
                .parse_signer(verification_method, issuer, purpose)?;
        let accepted =
            self.accepted_or_resolved(&issuer, purpose, Some(&verification_method), now)?;
        arkret_identity::verifier::verify_jws_with_binding(
            canonical_bytes,
            jws,
            &verification_method,
            &accepted,
        )
        .map_err(|error| BindingFailure::Invalid(error.to_string()))
    }

    /// Reuse an accepted binding, or establish one with **exactly one**
    /// upstream resolution.
    ///
    /// `did:key` never reaches the network: it is decoded locally (spec §2.4).
    ///
    /// A `DirectoryIngest` acceptance is mirrored into a
    /// [`DidBindingPurpose::DirectoryIssuer`] acceptance from the *same*
    /// document, at no extra network cost. That is what gives the zero-network
    /// query face something to consume: a DID that has announced itself to this
    /// directory becomes an accepted directory issuer, and an issuer that never
    /// announced stays unknown and fails closed (blinded `not_found`).
    pub fn accepted_or_resolved(
        &self,
        did: &Did,
        purpose: DidBindingPurpose,
        verification_method: Option<&arkret_wire::DidUrl>,
        now: DateTime<Utc>,
    ) -> Result<AcceptedDidBinding, BindingFailure> {
        self.accepted_or_resolved_with_evidence(
            did,
            purpose,
            verification_method,
            BindingEvidence::SharedResolverChain,
            now,
        )
    }

    /// [`Self::accepted_or_resolved`] with a caller-chosen evidence descriptor.
    ///
    /// The whole authority path is the SDK's
    /// [`resolve_and_verify_binding_with_evidence`] — the one API allowed to
    /// touch the network — so teabay inherits its guarantees rather than
    /// re-deriving them:
    ///
    /// - the store is consulted first, and a satisfying hit returns **without** calling the
    ///   resolver;
    /// - a miss calls `resolve_did` **exactly once** and writes the acceptance back;
    /// - the resolved document must belong to the requested DID *and* actually carry the requested
    ///   verification method, so a bogus `(did, key)` pair cannot pollute the store.
    ///
    /// # Why the *deferred* evidence variant
    ///
    /// `BindingAcceptance::evidence_digest` is a finished `Hash`, so the eager
    /// [`arkret_identity::verifier::resolve_and_verify_binding`] forces the
    /// evidence to be computed **before** the document exists — which shut out
    /// everything the document itself publishes, the
    /// `ArkretPrincipalServer` service endpoint above all. The deferred variant
    /// takes a closure over the already-resolved, already-checked document, so
    /// [`crate::did_binding::DidBindingDirectory::evidence_envelope`] can fold
    /// the endpoint digest in. On a store hit the closure is never called, so a
    /// reused acceptance keeps the evidence it was originally accepted with
    /// instead of re-stamping itself.
    ///
    /// Freshness is [`FreshnessRequirement::any_accepted`]: a stale (past
    /// `refresh_after`, not hard-expired) acceptance is reused rather than
    /// refreshed, which is the §5 rule that "cache TTL expiry alone MUST NOT
    /// turn an ordinary business request into an online DID resolution".
    pub fn accepted_or_resolved_with_evidence(
        &self,
        did: &Did,
        purpose: DidBindingPurpose,
        verification_method: Option<&arkret_wire::DidUrl>,
        evidence: BindingEvidence,
        now: DateTime<Utc>,
    ) -> Result<AcceptedDidBinding, BindingFailure> {
        if let Some(accepted) = self
            .bindings
            .accepted(did, purpose, verification_method, now)
        {
            return Ok(accepted);
        }

        let request = DeferredEvidenceResolveRequest {
            did: did.clone(),
            trust_domain: self.bindings.trust_domain().clone(),
            purpose,
            policy_digest: self.bindings.policy_digest().clone(),
            verification_method: verification_method.cloned(),
            freshness: FreshnessRequirement::any_accepted(),
            acceptance: BindingAcceptanceTerms {
                // The SDK resolver surface returns a document, not a webvh log
                // head or a version id, so teabay pins neither and *records*
                // the limited-trust capability, which §5 requires.
                history_head: None,
                version_id: None,
                limited_trust: Some(LimitedTrustReason::MethodHasNeitherHistoryNorVersion),
                refresh_interval: Some(crate::did_binding::BINDING_REFRESH_AFTER),
                hard_expiry: Some(crate::did_binding::BINDING_HARD_EXPIRY),
            },
        };

        // Computed on the resolved document, so post-resolution material — the
        // published service endpoint set — reaches the evidence envelope.
        let bindings = self.bindings.as_ref();
        let evidence_digest =
            move |document: &DidDocument| -> Result<arkret_wire::Hash, BindingEvidenceError> {
                Ok(bindings.evidence_digest(document, purpose, evidence)?)
            };

        // `did:key` is decoded locally; only the chain is an outbound call, and
        // the two are labelled differently on `teabay_did_resolve_total`.
        let accepted = if did.method() == "key" {
            let metered = MeteredAuthorityResolver::new(
                &self.did_key,
                self.metrics(),
                DID_RESOLVE_SOURCE_DID_KEY,
            );
            resolve_and_verify_binding_with_evidence(
                &metered,
                bindings.store(),
                &request,
                evidence_digest,
                now,
            )
        } else {
            let metered = MeteredAuthorityResolver::new(
                self.chain.as_ref(),
                self.metrics(),
                DID_RESOLVE_SOURCE_NETWORK,
            );
            resolve_and_verify_binding_with_evidence(
                &metered,
                bindings.store(),
                &request,
                evidence_digest,
                now,
            )
        }
        .map_err(|error| BindingFailure::NoBinding(error.to_string()))?;

        self.mirror_ingest_to_issuer(&accepted, purpose, verification_method, now);
        Ok(accepted)
    }

    fn mirror_ingest_to_issuer(
        &self,
        accepted: &AcceptedDidBinding,
        purpose: DidBindingPurpose,
        verification_method: Option<&arkret_wire::DidUrl>,
        now: DateTime<Utc>,
    ) {
        if purpose != DidBindingPurpose::DirectoryIngest {
            return;
        }
        let evidence = match accepted.binding().method() {
            "key" => BindingEvidence::DidKeyLocalDecode,
            _ => BindingEvidence::SharedResolverChain,
        };
        if let Err(error) = self.bindings.accept_document(
            accepted.document(),
            DidBindingPurpose::DirectoryIssuer,
            verification_method,
            evidence,
            now,
        ) {
            tracing::debug!(%error, "directory issuer binding mirror failed");
        }
    }

    /// RFC 9421 HTTP Message Signature key lookup for a DID-URL `keyid`.
    ///
    /// This is spec §4 trigger 5 territory (a peer service pushing into this
    /// directory), so it is allowed to resolve — but it is exposed as "give me
    /// the Ed25519 key for this keyid", never as "here is a resolver".
    ///
    /// The result is filed as a [`DidBindingPurpose::Service`] acceptance, so a
    /// second push from the same source service under the same key resolves
    /// **zero** times. `keyid` must be a full DID URL: a bare DID is rejected
    /// (`DidUrl` requires a fragment, spec §2.2).
    pub fn http_signature_public_key(&self, key_id: &str) -> Option<Ed25519PublicKey> {
        let verification_method = arkret_wire::DidUrl::new(key_id.trim().to_owned()).ok()?;
        let (did, _) = verification_method.as_str().split_once('#')?;
        let did = Did::new(did.to_owned()).ok()?;
        if !self.method_allowed(&format!("did:{}", did.method())) {
            return None;
        }
        let accepted = match self.accepted_or_resolved(
            &did,
            DidBindingPurpose::Service,
            Some(&verification_method),
            Utc::now(),
        ) {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::debug!(%err, %key_id, "HTTP signature DID key resolve failed");
                return None;
            }
        };
        // Reuse the SDK's exact verification-method lookup + key decode, but
        // against the **pinned** document rather than a resolver.
        let pinned = PinnedDocumentResolver(accepted.document().clone());
        match resolve_ed25519_pubkey(&pinned, key_id) {
            Ok(public_key) => Some(public_key),
            Err(err) => {
                tracing::debug!(%err, %key_id, "HTTP signature key material rejected");
                None
            }
        }
    }
}

/// Zero-network resolver over exactly one already-pinned document.
///
/// Lets the HTTP-signature path reuse `arkret_identity::jws::resolve_ed25519_pubkey`
/// (relative `#key-1` handling, multibase/JWK decode) without granting it a
/// resolver that could reach anything.
struct PinnedDocumentResolver(DidDocument);

impl DidResolver for PinnedDocumentResolver {
    fn supports(&self, did: &Did) -> bool {
        did == &self.0.id
    }

    fn resolve_did(&self, did: &Did) -> IdentityResult<DidDocument> {
        if did == &self.0.id {
            Ok(self.0.clone())
        } else {
            Err(arkret_sdk::identity::IdentityError::Protocol(format!(
                "pinned document is for `{}`, not `{did}`",
                self.0.id
            )))
        }
    }
}

/// Counting wrapper around the upstream chain.
///
/// The **single** place `teabay_did_resolve_total{source="network"}` is
/// incremented, and it is incremented in `resolve_did` itself — so the counter
/// is by construction the number of outbound resolutions, never an estimate
/// derived from cache-miss bookkeeping. `authority_network_call_count` in the
/// cotest joint contract is exactly this series' increment.
pub(crate) struct MeteredAuthorityResolver<'a> {
    inner: &'a (dyn DidResolver + Send + Sync),
    metrics: &'a Metrics,
    /// `network` for the outbound chain, `did_key` for the local decoder.
    source: &'static str,
}

impl<'a> MeteredAuthorityResolver<'a> {
    pub(crate) fn new(
        inner: &'a (dyn DidResolver + Send + Sync),
        metrics: &'a Metrics,
        source: &'static str,
    ) -> Self {
        Self {
            inner,
            metrics,
            source,
        }
    }
}

impl DidResolver for MeteredAuthorityResolver<'_> {
    fn supports(&self, did: &Did) -> bool {
        self.inner.supports(did)
    }

    fn resolve_did(&self, did: &Did) -> IdentityResult<DidDocument> {
        self.metrics.record_did_resolve(did.method(), self.source);
        self.inner.resolve_did(did)
    }
}

/// The bare DID that owns a `verification_method` DID URL.
///
/// Single copy of what `filter::discoverers` and `query::target` each used to
/// define privately, byte-for-byte identically.
pub fn verification_method_issuer(verification_method: &str) -> Option<&str> {
    let issuer = verification_method
        .split_once('#')
        .map(|(did, _)| did)
        .unwrap_or(verification_method)
        .trim();
    (!issuer.is_empty()).then_some(issuer)
}

/// Build the production resolver chain for the DID methods accepted by
/// this teabay instance.
///
/// **Do not call this from a request path.** It allocates a fresh
/// `reqwest::Client`; the only supported caller is [`SharedDidResolver::new`],
/// which `AppState::new` runs once at startup. See the module docs.
///
/// `allow_private_networks` is the single source of truth for SSRF egress
/// policy and MUST be derived by the caller from `AppConfig`
/// (`crate::egress::local_development_enabled(config.development_mode)`), not
/// re-read from the environment here — that keeps the egress decision tied to
/// the startup config snapshot.
fn did_resolver_chain(
    accepted_did_methods: &[String],
    allow_private_networks: bool,
) -> Result<CompositeDidResolver, String> {
    let policy = resolver_policy(accepted_did_methods);
    let http_client = Client::builder()
        .https_only(!allow_private_networks)
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

pub(crate) fn did_method_allowed(accepted_did_methods: &[String], expected: &str) -> bool {
    let expected = normalize_did_method_prefix(expected);
    accepted_did_methods
        .iter()
        .map(|method| normalize_did_method_prefix(method))
        .any(|method| method.eq_ignore_ascii_case(&expected))
}

pub(crate) fn did_method_prefix_for_did(did: &str) -> Option<String> {
    let mut parts = did.trim().splitn(3, ':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("did"), Some(method), Some(_)) if !method.is_empty() => {
            Some(format!("did:{method}:"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use arkret_signatures::jws::sign_jws_ed25519;
    use arkret_wire::DidUrl;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::observability::{
        DID_RESOLVE_SOURCE_BINDING_STORE, SIGNATURE_KIND_INGEST_PROOF, SIGNATURE_OUTCOME_NO_BINDING,
    };

    fn crate_source_files() -> Vec<std::path::PathBuf> {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("read crate source dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    out.push(path);
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        walk(&src, &mut out);
        out
    }

    /// DID-P0-C01 acceptance gate.
    ///
    /// Before this change `did_resolver_chain` had five business call sites
    /// (`ingest::verify` x2, `filter::discoverers`, `query::target`,
    /// `middleware::http_sig`), every one of them inside a request path and
    /// every one of them allocating a fresh `reqwest::Client`. It must now be
    /// reachable only from this module, i.e. only from
    /// `SharedDidResolver::with_metrics`, which `AppState::new` calls once at
    /// startup.
    ///
    /// This is a source-level assertion on purpose: it fails loudly if someone
    /// reintroduces a per-request resolver, which a behavioural test could
    /// only catch with live network traffic.
    #[test]
    fn resolver_chain_is_constructed_in_exactly_one_place() {
        // Assembled at runtime so this test's own source does not count as a
        // call site.
        let chain_fn = format!("{}{}", "did_resolver", "_chain(");
        let composite = format!("{}{}", "CompositeDidResolver", "::new");
        let this_file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("did_resolver.rs");
        for path in crate_source_files() {
            let source = std::fs::read_to_string(&path).expect("read crate source file");
            if path == this_file {
                assert_eq!(
                    source.matches(chain_fn.as_str()).count(),
                    2,
                    "did_resolver.rs must contain exactly the definition and the \
                     single SharedDidResolver call site"
                );
                continue;
            }
            assert!(
                !source.contains(chain_fn.as_str()),
                "{} must not build a DID resolver chain; take the shared one from AppState",
                path.display()
            );
            assert!(
                !source.contains(composite.as_str()),
                "{} must not build a DID resolver chain; take the shared one from AppState",
                path.display()
            );
        }
    }

    /// DID-P0-C03 acceptance gate: the directory query / filter face must not
    /// mention the authority resolver at all.
    ///
    /// The type-level guarantee is that `DidBindingDirectory` owns no resolver
    /// and `SharedDidResolver` exposes no chain accessor. This source gate adds
    /// the belt to those braces: it fails if a query or filter module ever
    /// starts importing the authority handle.
    #[test]
    fn query_and_filter_face_never_touches_the_authority_resolver() {
        let needle = format!("{}{}", "Shared", "DidResolver");
        for path in crate_source_files() {
            let display = path.display().to_string().replace('\\', "/");
            if !(display.contains("/src/query/") || display.contains("/src/filter/")) {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("read crate source file");
            assert!(
                !source.contains(needle.as_str()),
                "{display} is on the directory query face and must take a \
                 DidBindingDirectory (zero network), not the authority resolver"
            );
        }
    }

    /// The startup egress snapshot is captured inside the handle, so no
    /// request path can pass a different one.
    ///
    /// `#[tokio::test]`, not `#[test]`: the SDK's `HttpDidResolver` captures a
    /// `tokio::runtime::Handle` when it is built, which is exactly the
    /// startup-time coupling we want — `AppState::new` runs inside the server
    /// runtime, so the resolver is bound to it once and for all.
    #[tokio::test]
    async fn shared_resolver_freezes_the_startup_egress_decision() {
        let strict = SharedDidResolver::new(&["did:web".to_owned()], false).expect("builds");
        assert!(!strict.allow_private_networks());
        assert_eq!(strict.accepted_did_methods(), &["did:web".to_owned()]);
        assert!(strict.method_allowed("did:web"));
        assert!(!strict.method_allowed("did:key"));
    }

    /// An empty accepted-method list is fail-OPEN at the `ResolverPolicy`
    /// layer ("empty means any method"), so the verification entry point has
    /// to reject it before it reaches the policy.
    ///
    /// This closes the ingest-side gap: `discoverers` and `target` already had
    /// this guard, `ingest::verify` did not.
    #[tokio::test]
    async fn empty_accepted_methods_fails_closed_on_ingest_verify() {
        let resolver = SharedDidResolver::new(&[], false).expect("builds");
        let failure = resolver
            .verify_detached_jws_with_authority(
                b"payload",
                "jws",
                "did:key:z6mk#z6mk",
                "did:key:z6mk",
                DidBindingPurpose::DirectoryIngest,
                SIGNATURE_KIND_INGEST_PROOF,
                Utc::now(),
            )
            .expect_err("empty allowlist must fail closed");
        assert_eq!(failure.message(), "no accepted DID methods configured");
        assert_eq!(
            resolver
                .metrics()
                .did_resolve_count(DID_RESOLVE_SOURCE_NETWORK),
            0
        );
    }

    #[tokio::test]
    async fn bare_did_verification_method_is_rejected() {
        let resolver = SharedDidResolver::new(&["did:web".to_owned()], false).expect("builds");
        let failure = resolver
            .verify_detached_jws_with_authority(
                b"payload",
                "jws",
                "did:web:a.example",
                "did:web:a.example",
                DidBindingPurpose::DirectoryIngest,
                SIGNATURE_KIND_INGEST_PROOF,
                Utc::now(),
            )
            .expect_err("a bare DID is not a verification method");
        assert!(failure.message().contains("verification_method"));
    }

    #[test]
    fn verification_method_issuer_strips_fragment_and_rejects_empty() {
        assert_eq!(
            verification_method_issuer("did:web:a.example#key-1"),
            Some("did:web:a.example")
        );
        assert_eq!(
            verification_method_issuer("  did:web:a.example  "),
            Some("did:web:a.example")
        );
        assert_eq!(verification_method_issuer("#key-1"), None);
    }

    // ------------------------------------------------------------------
    // DID-P0-C04 — counting resolver spy
    // ------------------------------------------------------------------

    /// Counts every upstream resolution, exactly like the SDK's
    /// `crates/identity/tests/binding_resolver_spy.rs::CountingDidResolver`.
    /// Teabay has no HTTP mock, so this is the only way to observe
    /// `authority_network_call_count` in a unit test.
    struct CountingDidResolver {
        documents: BTreeMap<String, DidDocument>,
        calls: AtomicUsize,
    }

    impl CountingDidResolver {
        fn new() -> Self {
            Self {
                documents: BTreeMap::new(),
                calls: AtomicUsize::new(0),
            }
        }

        fn with_document(mut self, document: DidDocument) -> Self {
            self.documents
                .insert(document.id.as_str().to_owned(), document);
            self
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl DidResolver for CountingDidResolver {
        fn supports(&self, did: &Did) -> bool {
            self.documents.contains_key(did.as_str())
        }

        fn resolve_did(&self, did: &Did) -> IdentityResult<DidDocument> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.documents.get(did.as_str()).cloned().ok_or_else(|| {
                arkret_sdk::identity::IdentityError::Protocol(format!("unknown did {did}"))
            })
        }
    }

    fn web_signer(seed: u8) -> (SigningKey, Did, DidUrl, DidDocument) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signing_key.verifying_key().as_bytes(),
        );
        let did = Did::new(format!("did:web:signer{seed}.example")).expect("did");
        let verification_method = DidUrl::new(format!("{did}#key-1")).expect("did url");
        let document = DidDocument {
            id: did.clone(),
            verification_methods: BTreeMap::from([(
                verification_method.as_str().to_owned(),
                multibase,
            )]),
            also_known_as: Vec::new(),
            updated_at: None,
            raw_properties: BTreeMap::new(),
        };
        (signing_key, did, verification_method, document)
    }

    fn spy_resolver(
        documents: Vec<DidDocument>,
    ) -> (Arc<CountingDidResolver>, SharedDidResolver, Metrics) {
        let mut spy = CountingDidResolver::new();
        for document in documents {
            spy = spy.with_document(document);
        }
        let spy = Arc::new(spy);
        let metrics = Metrics::default();
        let resolver = SharedDidResolver::with_chain_for_test(
            &["did:key".to_owned(), "did:web".to_owned()],
            Arc::clone(&spy) as Arc<dyn DidResolver + Send + Sync>,
            metrics.clone(),
        )
        .expect("builds");
        (spy, resolver, metrics)
    }

    /// DID-P0-C04: a brand-new issuer costs exactly one network call, and every
    /// repeat costs zero.
    #[test]
    fn first_ingest_resolves_once_and_repeats_resolve_zero_times() {
        let (signing_key, did, verification_method, document) = web_signer(31);
        let (spy, resolver, metrics) = spy_resolver(vec![document]);
        let payload = b"canonical-announce-payload";
        let jws = sign_jws_ed25519(payload, &signing_key).expect("sign");

        for _ in 0..4 {
            resolver
                .verify_detached_jws_with_authority(
                    payload,
                    &jws,
                    verification_method.as_str(),
                    did.as_str(),
                    DidBindingPurpose::DirectoryIngest,
                    SIGNATURE_KIND_INGEST_PROOF,
                    Utc::now(),
                )
                .expect("ingest proof verifies");
        }

        assert_eq!(spy.calls(), 1, "one authority resolution for four ingests");
        assert_eq!(metrics.did_resolve_count(DID_RESOLVE_SOURCE_NETWORK), 1);
        assert_eq!(
            metrics.did_resolve_count(DID_RESOLVE_SOURCE_BINDING_STORE),
            3
        );
        assert_eq!(
            metrics.signature_verify_count(SIGNATURE_KIND_INGEST_PROOF, SIGNATURE_OUTCOME_OK),
            4,
            "signature verifications and authority calls are independent counters"
        );
    }

    /// DID-P0-C04: the ingest acceptance seeds the zero-network query face, and
    /// consuming it there adds no network calls at all.
    #[test]
    fn ingest_seeds_the_issuer_binding_that_query_consumes_with_zero_calls() {
        let (signing_key, did, verification_method, document) = web_signer(37);
        let (spy, resolver, metrics) = spy_resolver(vec![document]);
        let payload = b"canonical-announce-payload";
        let jws = sign_jws_ed25519(payload, &signing_key).expect("sign");
        let now = Utc::now();

        resolver
            .verify_detached_jws_with_authority(
                payload,
                &jws,
                verification_method.as_str(),
                did.as_str(),
                DidBindingPurpose::DirectoryIngest,
                SIGNATURE_KIND_INGEST_PROOF,
                now,
            )
            .expect("ingest proof verifies");
        assert_eq!(spy.calls(), 1);

        // The query face only ever sees the binding directory: no chain, no
        // resolver, not even transitively.
        let bindings = Arc::clone(resolver.bindings());
        for _ in 0..3 {
            bindings
                .verify_detached_jws(
                    payload,
                    &jws,
                    verification_method.as_str(),
                    did.as_str(),
                    DidBindingPurpose::DirectoryIssuer,
                    crate::observability::SIGNATURE_KIND_RESTRICTED_CLAIM,
                    now,
                )
                .expect("restricted claim verifies against the mirrored issuer binding");
        }
        assert_eq!(spy.calls(), 1, "restricted queries add zero network calls");
        assert_eq!(metrics.did_resolve_count(DID_RESOLVE_SOURCE_NETWORK), 1);
    }

    /// DID-P0-C02: the evidence digest is computed on the **resolved** document.
    ///
    /// With the eager `resolve_and_verify_binding` the digest had to exist
    /// before the resolution, so it could not depend on the document at all —
    /// the endpoint set the `PrincipalServiceEndpoint` acceptance is about was
    /// structurally excluded. Recomputing the stored digest from
    /// `accepted.document()` and getting the same value is only possible if the
    /// deferred closure actually saw that document.
    #[test]
    fn deferred_evidence_is_computed_on_the_resolved_document() {
        let (_, did, verification_method, mut document) = web_signer(59);
        document.raw_properties.insert(
            "service".to_owned(),
            serde_json::json!([{
                "id": format!("{did}#ps"),
                "type": crate::ingest::verify::ARKRET_PRINCIPAL_SERVER,
                "serviceEndpoint": "https://principal.example/",
            }]),
        );
        let (spy, resolver, _metrics) = spy_resolver(vec![document]);
        let purpose = DidBindingPurpose::PrincipalServiceEndpoint;
        let evidence = BindingEvidence::PrincipalServiceEndpoint {
            service_kind: crate::ingest::verify::ARKRET_PRINCIPAL_SERVER,
        };

        let accepted = resolver
            .accepted_or_resolved_with_evidence(
                &did,
                purpose,
                Some(&verification_method),
                evidence,
                Utc::now(),
            )
            .expect("endpoint acceptance");
        assert_eq!(spy.calls(), 1);

        let recomputed = resolver
            .bindings()
            .evidence_digest(accepted.document(), purpose, evidence)
            .expect("recompute the evidence digest from the pinned document");
        assert_eq!(
            accepted.binding().evidence_digest(),
            &recomputed,
            "the stored evidence must be recomputable from the document it rests on"
        );

        // Strip the service entry and the evidence changes: the published
        // endpoint set really is bound, not merely alongside.
        let mut without_service = accepted.document().clone();
        without_service.raw_properties.remove("service");
        assert_ne!(
            resolver
                .bindings()
                .evidence_digest(&without_service, purpose, evidence)
                .expect("digest"),
            recomputed
        );
    }

    /// DID-P0-C04: a key change re-enters the authority path exactly once and
    /// replaces the binding; the old key is not silently reused.
    #[test]
    fn key_change_triggers_exactly_one_refresh() {
        let (signing_key, did, verification_method, mut document) = web_signer(41);
        let rotated_method = DidUrl::new(format!("{did}#key-2")).expect("did url");
        let rotated_key = SigningKey::from_bytes(&[42u8; 32]);
        document.verification_methods.insert(
            rotated_method.as_str().to_owned(),
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                rotated_key.verifying_key().as_bytes(),
            ),
        );
        let (spy, resolver, _metrics) = spy_resolver(vec![document]);
        let payload = b"canonical-announce-payload";
        let now = Utc::now();

        let jws = sign_jws_ed25519(payload, &signing_key).expect("sign");
        resolver
            .verify_detached_jws_with_authority(
                payload,
                &jws,
                verification_method.as_str(),
                did.as_str(),
                DidBindingPurpose::DirectoryIngest,
                SIGNATURE_KIND_INGEST_PROOF,
                now,
            )
            .expect("first key verifies");
        assert_eq!(spy.calls(), 1);

        // A new verification method is a §4 trigger: one more resolution.
        let rotated_jws = sign_jws_ed25519(payload, &rotated_key).expect("sign");
        resolver
            .verify_detached_jws_with_authority(
                payload,
                &rotated_jws,
                rotated_method.as_str(),
                did.as_str(),
                DidBindingPurpose::DirectoryIngest,
                SIGNATURE_KIND_INGEST_PROOF,
                now,
            )
            .expect("rotated key verifies");
        assert_eq!(spy.calls(), 2, "a new verification method resolves once");

        // Both bindings are now cached; neither adds a call.
        resolver
            .verify_detached_jws_with_authority(
                payload,
                &rotated_jws,
                rotated_method.as_str(),
                did.as_str(),
                DidBindingPurpose::DirectoryIngest,
                SIGNATURE_KIND_INGEST_PROOF,
                now,
            )
            .expect("rotated key verifies from the store");
        assert_eq!(spy.calls(), 2);
    }

    /// DID-P0-C04: a binding that has crossed `refresh_after` (status `Stale`)
    /// is still consumed; TTL expiry alone MUST NOT turn a request into an
    /// online resolution (spec §5), and there is no live fallback.
    #[test]
    fn stale_binding_does_not_trigger_a_refresh() {
        let (signing_key, did, verification_method, document) = web_signer(53);
        let (spy, resolver, metrics) = spy_resolver(vec![document]);
        let payload = b"canonical-announce-payload";
        let jws = sign_jws_ed25519(payload, &signing_key).expect("sign");
        let accepted_at = Utc::now();

        resolver
            .verify_detached_jws_with_authority(
                payload,
                &jws,
                verification_method.as_str(),
                did.as_str(),
                DidBindingPurpose::DirectoryIngest,
                SIGNATURE_KIND_INGEST_PROOF,
                accepted_at,
            )
            .expect("verifies");
        assert_eq!(spy.calls(), 1);

        // Past `refresh_after`, well before `expires_at`.
        let stale_at = accepted_at + chrono::Duration::hours(1);
        resolver
            .verify_detached_jws_with_authority(
                payload,
                &jws,
                verification_method.as_str(),
                did.as_str(),
                DidBindingPurpose::DirectoryIngest,
                SIGNATURE_KIND_INGEST_PROOF,
                stale_at,
            )
            .expect("a stale binding still verifies");
        assert_eq!(spy.calls(), 1, "stale is not expired: no refresh");
        assert_eq!(metrics.did_resolve_count(DID_RESOLVE_SOURCE_NETWORK), 1);

        // Past `expires_at` the entry is gone for readers, so the next
        // authority call resolves again — exactly once.
        let expired_at = accepted_at + chrono::Duration::hours(48);
        resolver
            .verify_detached_jws_with_authority(
                payload,
                &jws,
                verification_method.as_str(),
                did.as_str(),
                DidBindingPurpose::DirectoryIngest,
                SIGNATURE_KIND_INGEST_PROOF,
                expired_at,
            )
            .expect("re-established after hard expiry");
        assert_eq!(spy.calls(), 2);
    }

    /// DID-P0-C04: a policy revision changes the policy digest, which changes
    /// every store key — so the next authority call re-resolves, and the query
    /// face stops accepting bindings taken under the old policy.
    #[test]
    fn policy_revision_invalidates_every_acceptance() {
        let (signing_key, did, verification_method, document) = web_signer(43);
        let (_spy, resolver, _metrics) = spy_resolver(vec![document.clone()]);
        let payload = b"canonical-announce-payload";
        let jws = sign_jws_ed25519(payload, &signing_key).expect("sign");
        let now = Utc::now();
        resolver
            .verify_detached_jws_with_authority(
                payload,
                &jws,
                verification_method.as_str(),
                did.as_str(),
                DidBindingPurpose::DirectoryIngest,
                SIGNATURE_KIND_INGEST_PROOF,
                now,
            )
            .expect("verifies");

        // A directory started with a different accepted-method policy derives a
        // different policy digest, so it has no acceptance for the same DID.
        let (spy_b, resolver_b, _) = {
            let spy = Arc::new(CountingDidResolver::new().with_document(document));
            let resolver = SharedDidResolver::with_chain_for_test(
                &["did:key".to_owned()],
                Arc::clone(&spy) as Arc<dyn DidResolver + Send + Sync>,
                Metrics::default(),
            )
            .expect("builds");
            (spy, resolver, ())
        };
        assert_ne!(
            resolver.bindings().policy_digest(),
            resolver_b.bindings().policy_digest(),
            "changing the accepted-method allowlist MUST change the policy digest"
        );
        // ...and under the narrower policy the did:web signer is not even
        // allowed, so it fails closed rather than resolving.
        let failure = resolver_b
            .verify_detached_jws_with_authority(
                payload,
                &jws,
                verification_method.as_str(),
                did.as_str(),
                DidBindingPurpose::DirectoryIngest,
                SIGNATURE_KIND_INGEST_PROOF,
                now,
            )
            .expect_err("did:web is outside the narrowed allowlist");
        assert!(failure.message().contains("TEABAY_ACCEPTED_DID_METHODS"));
        assert_eq!(spy_b.calls(), 0);
    }

    /// DID-P0-C04: a deactivation invalidation quarantines the binding, and the
    /// **query** face then fails closed without ever attempting a refresh.
    #[test]
    fn deactivation_quarantines_and_the_query_face_does_not_live_fallback() {
        let (signing_key, did, verification_method, document) = web_signer(47);
        let (spy, resolver, metrics) = spy_resolver(vec![document]);
        let payload = b"canonical-announce-payload";
        let jws = sign_jws_ed25519(payload, &signing_key).expect("sign");
        let now = Utc::now();
        resolver
            .verify_detached_jws_with_authority(
                payload,
                &jws,
                verification_method.as_str(),
                did.as_str(),
                DidBindingPurpose::DirectoryIngest,
                SIGNATURE_KIND_INGEST_PROOF,
                now,
            )
            .expect("verifies");
        assert_eq!(spy.calls(), 1);

        let bindings = Arc::clone(resolver.bindings());
        let removed = bindings
            .invalidate(&arkret_identity::binding_store::BindingInvalidation::for_did(did.clone()));
        assert_eq!(removed, 2, "ingest + mirrored issuer acceptance");

        let failure = bindings
            .verify_detached_jws(
                payload,
                &jws,
                verification_method.as_str(),
                did.as_str(),
                DidBindingPurpose::DirectoryIssuer,
                crate::observability::SIGNATURE_KIND_RESTRICTED_CLAIM,
                now,
            )
            .expect_err("an invalidated issuer must fail closed on the query face");
        assert_eq!(failure.outcome_label(), SIGNATURE_OUTCOME_NO_BINDING);
        assert_eq!(spy.calls(), 1, "the query face never live-resolves");
        assert_eq!(metrics.did_resolve_count(DID_RESOLVE_SOURCE_NETWORK), 1);
    }
}
