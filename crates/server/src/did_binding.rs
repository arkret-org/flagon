//! Accepted DID bindings — the **zero-network** half of teabay's DID surface.
//!
//! # DID-P0-C02 / C03 — what this module is for
//!
//! `arkret-spec/spec/v1/zh/identity/did-usage-and-verification.md` §3 and §6
//! split "verify a signature" from "resolve a DID". Ordinary business paths
//! (§3: reading, rendering, routing, directory query) verify signatures against
//! **already accepted** material and MUST NOT resolve; only the closed §4
//! trigger table may reach the network.
//!
//! [`DidBindingDirectory`] is the ordinary half. It owns the process-wide
//! [`VerifiedDidBindingStore`] and a `did:key` decoder, and it has **no
//! resolver field and no resolver accessor**. A handler holding a
//! `&DidBindingDirectory` therefore cannot express "resolve this DID over the
//! network" — that is the DID-P0-C03 requirement "query handler 不直接持有通用
//! 网络 resolver", enforced by the type rather than by review.
//!
//! The authority half lives in [`crate::did_resolver::SharedDidResolver`],
//! which holds the network chain *privately* and writes its results back into
//! this directory. `AppState` hands the query/filter face
//! [`crate::state::AppState::did_bindings`] and hands the ingest / HTTP-signature
//! face `AppState::did_resolver`; the two faces are different types, and only
//! one of them can touch the network.
//!
//! # Purpose scoping
//!
//! Every acceptance is scoped to a closed [`DidBindingPurpose`]. Teabay uses
//! exactly three:
//!
//! | purpose | established by | consumed by |
//! | --- | --- | --- |
//! | [`DidBindingPurpose::DirectoryIngest`] | `ingest::verify` governance proof | repeat announce / withdraw / appeal |
//! | [`DidBindingPurpose::DirectoryIssuer`] | mirrored from a `DirectoryIngest` acceptance | `filter::discoverers` restricted claims, `query::target` invite / preview tokens |
//! | [`DidBindingPurpose::PrincipalServiceEndpoint`] | `ingest::verify::resolve_principal_server_endpoint` | first-ingest source-ref anchor fetch |
//!
//! A `DirectoryIngest` acceptance never authorizes an invite token on its own
//! and vice versa: the store key carries the purpose, so the lookups cannot
//! collide.

use std::sync::Arc;

use arkret_identity::binding::{
    DidBindingPurpose, DidBindingStatus, FreshnessProfile, LimitedTrust, VerifiedDidBinding,
    VerifiedDidBindingDocumentInput, VerifiedDidBindingKey,
};
use arkret_identity::binding_digest::{EvidenceReceipt, MethodEvidence};
use arkret_identity::binding_store::{
    AcceptedDidBinding, BindingInvalidation, InMemoryVerifiedDidBindingStore,
    VerifiedDidBindingStore,
};
use arkret_identity::verifier::verify_jws_with_binding;
use arkret_sdk::identity::{DidDocument, DidKeyResolver, DidResolver};
use arkret_wire::{Did, DidUrl, Hash, TrustDomainId};
use chrono::{DateTime, Utc};

use crate::did_resolver::did_method_allowed;
use crate::observability::{
    DID_RESOLVE_SOURCE_BINDING_STORE, DID_RESOLVE_SOURCE_DID_KEY, Metrics,
    SIGNATURE_OUTCOME_INVALID, SIGNATURE_OUTCOME_NO_BINDING, SIGNATURE_OUTCOME_OK,
    SIGNATURE_OUTCOME_POLICY_REJECTED,
};

/// Upper bound on cached acceptances. Bounded so a hostile stream of unknown
/// DIDs cannot grow the store without limit; the SDK store evicts the entry
/// with the oldest `verified_at`, deterministically.
const MAX_BINDINGS: usize = 4096;

/// The freshness profile every teabay DID authority call site references
/// (`did-usage-and-verification.md` §5.4).
///
/// §5.4 makes `fresh_for_seconds` the **single** freshness threshold:
/// `refresh_after = verified_at + fresh_for_seconds` and an authority call's
/// `max_age` are the same value, so the two constants this replaced
/// (`BINDING_REFRESH_AFTER` for the former, `FreshnessRequirement::any_accepted`
/// for the latter) can no longer drift apart.
///
/// The id is `ongoing_governance`, the profile the three registered directory
/// ingest call sites name: `ak.find.directory.command.announce.v1`,
/// `ak.find.directory.command.withdraw.v1` and
/// `ak.find.directory.command.takedown_appeal.v1` each carry a `did_authority`
/// row with `evidence_class = ongoing_governance`, and
/// `did-freshness-profile-registry.json` lists all three in `call_sites[]`.
/// What this path verifies is the governance signer of a service or
/// organization — the closed `ongoing_governance` trigger scenario — not a
/// human principal's operation, so it does not collide with the §4 exclusion
/// list. Behaviour is unchanged from the previous fallback id: both rows are
/// `high` with `synchronous_refresh_or_fail_closed`.
///
/// Tier is `high`, and that is not a behaviour change for ordinary requests.
/// The §5 rule "cache TTL expiry alone MUST NOT turn an ordinary business
/// request into an online DID resolution" is carried by
/// [`DidBindingDirectory::accepted`], which reads the store directly and returns
/// a `Stale` entry unchanged; both faces consult it *before* any authority path
/// exists. This profile is only ever exercised when there is no usable entry at
/// all, where "refresh synchronously or fail closed" is the only correct
/// answer. The §5.4 `high` constraints hold: both windows are finite and
/// `0 < 600 <= 86400`, with no stale-consumption window.
pub(crate) fn binding_freshness_profile() -> FreshnessProfile {
    FreshnessProfile::high_tier(
        arkret_wire::DidFreshnessProfileId::OngoingGovernanceV1,
        chrono::Duration::seconds(600),
        Some(chrono::Duration::seconds(24 * 3_600)),
    )
}

/// The default trust-domain scope when the configured `service_id` yields no
/// usable `ak:trust_domain:` payload.
const FALLBACK_TRUST_DOMAIN_SCOPE: &str = "teabay";

/// Failure of an ordinary (zero-network) binding operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingFailure {
    /// Rejected by local policy before any cryptography: empty accepted-method
    /// allowlist, DID method outside the allowlist, malformed DID / DID URL.
    PolicyRejected(String),
    /// No accepted binding, and no zero-network way to obtain one. The query
    /// face turns this into its existing blinded `not_found` / fail-closed
    /// outcome rather than resolving online.
    NoBinding(String),
    /// A binding was available and the signature did not verify against it.
    Invalid(String),
}

impl BindingFailure {
    pub fn outcome_label(&self) -> &'static str {
        match self {
            Self::PolicyRejected(_) => SIGNATURE_OUTCOME_POLICY_REJECTED,
            Self::NoBinding(_) => SIGNATURE_OUTCOME_NO_BINDING,
            Self::Invalid(_) => SIGNATURE_OUTCOME_INVALID,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::PolicyRejected(message) | Self::NoBinding(message) | Self::Invalid(message) => {
                message
            }
        }
    }
}

impl std::fmt::Display for BindingFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message())
    }
}

/// Process-wide accepted-binding directory.
///
/// Cloned handles (via `Arc`) all point at one store: an acceptance made on the
/// ingest face is immediately visible to the query face, which is the whole
/// point of §5's "reusable" requirement.
pub struct DidBindingDirectory {
    store: Arc<InMemoryVerifiedDidBindingStore>,
    /// Zero-sized, zero-network `did:key` decoder. Present here on purpose:
    /// decoding `did:key` is pure multibase work, so it does not weaken the
    /// "this type cannot reach the network" property.
    did_key: DidKeyResolver,
    accepted_did_methods: Vec<String>,
    trust_domain: TrustDomainId,
    policy_digest: Hash,
    metrics: Metrics,
}

impl std::fmt::Debug for DidBindingDirectory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DidBindingDirectory")
            .field("accepted_did_methods", &self.accepted_did_methods)
            .field("trust_domain", &self.trust_domain)
            .field("policy_digest", &self.policy_digest)
            .field("entries", &self.store.len())
            .finish_non_exhaustive()
    }
}

impl DidBindingDirectory {
    /// Build the directory from the startup config snapshot.
    ///
    /// `service_id` is this directory's stable service core ID; it scopes the trust
    /// domain so two teabay deployments never share acceptances even if they
    /// somehow shared a store.
    pub fn new(
        accepted_did_methods: &[String],
        service_id: &str,
        metrics: Metrics,
    ) -> Result<Self, String> {
        Ok(Self {
            store: Arc::new(InMemoryVerifiedDidBindingStore::new(MAX_BINDINGS)),
            did_key: DidKeyResolver::new(),
            accepted_did_methods: accepted_did_methods.to_vec(),
            trust_domain: trust_domain_for_service(service_id)?,
            policy_digest: resolver_policy_digest(accepted_did_methods)?,
            metrics,
        })
    }

    /// The startup accepted-DID-method allowlist.
    ///
    /// Callers still need this because an **empty** list is fail-open at the
    /// SDK `ResolverPolicy` layer ("empty `allowed_methods` means any method"),
    /// so every verification entry point rejects up-front on an empty
    /// allowlist.
    pub fn accepted_did_methods(&self) -> &[String] {
        &self.accepted_did_methods
    }

    pub fn method_allowed(&self, expected: &str) -> bool {
        did_method_allowed(&self.accepted_did_methods, expected)
    }

    /// Digest of the resolver policy in force. Part of every store key, so a
    /// policy revision invalidates every acceptance by construction.
    pub fn policy_digest(&self) -> &Hash {
        &self.policy_digest
    }

    /// The local trust domain every acceptance is scoped to.
    pub fn trust_domain(&self) -> &TrustDomainId {
        &self.trust_domain
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// The backing store, for the authority face only.
    ///
    /// `pub(crate)` and returned as the SDK trait object so
    /// [`crate::did_resolver::SharedDidResolver`] can hand it to
    /// `arkret_identity::verifier::resolve_and_verify_binding`. Handing out a
    /// store does not weaken the DID-P0-C03 property — a store is not a
    /// resolver, and nothing reachable from it can perform I/O.
    pub(crate) fn store(&self) -> &dyn VerifiedDidBindingStore {
        self.store.as_ref()
    }

    /// Number of stored acceptances (assertions / tests).
    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// Store key for `(did, purpose, verification_method)` under this
    /// directory's trust domain and policy digest.
    pub fn binding_key(
        &self,
        did: &Did,
        purpose: DidBindingPurpose,
        verification_method: Option<&DidUrl>,
    ) -> VerifiedDidBindingKey {
        VerifiedDidBindingKey {
            did: did.clone(),
            trust_domain: self.trust_domain.clone(),
            purpose,
            policy_digest: self.policy_digest.clone(),
            verification_method: verification_method.cloned(),
        }
    }

    /// Look up an accepted binding. **Never resolves.**
    ///
    /// A hard-expired entry reads as absent (SDK `get` contract); a stale one is
    /// returned with its status downgraded to `Stale`, which ordinary
    /// verification still accepts — that is the §5 "TTL expiry marks stale, it
    /// does not force an online resolution" rule.
    pub fn accepted(
        &self,
        did: &Did,
        purpose: DidBindingPurpose,
        verification_method: Option<&DidUrl>,
        now: DateTime<Utc>,
    ) -> Option<AcceptedDidBinding> {
        let hit = self
            .store
            .get(&self.binding_key(did, purpose, verification_method), now);
        if hit.is_some() {
            self.metrics
                .record_did_resolve(did.method(), DID_RESOLVE_SOURCE_BINDING_STORE);
        }
        hit
    }

    /// Turn an already-verified DID document plus its §5.2 evidence receipt into
    /// an acceptance and store it.
    ///
    /// This performs no I/O: the caller supplies both, whether they came from
    /// the local `did:key` decoder or from the authority chain.
    ///
    /// The receipt is a parameter rather than something recomputed here on
    /// purpose. Evidence is a product of the *resolution*, so the only honest
    /// receipt is the one that resolution produced; re-deriving one from the
    /// document alone would be exactly the "caller invents the evidence" shape
    /// §5.2 rules out. `AcceptedDidBinding::new` re-digests it and rejects a
    /// receipt that disagrees with `binding.evidence_digest()`, so a mismatched
    /// pair cannot be stored.
    pub fn accept_document(
        &self,
        document: &DidDocument,
        purpose: DidBindingPurpose,
        verification_method: Option<&DidUrl>,
        receipt: EvidenceReceipt,
        now: DateTime<Utc>,
    ) -> Result<AcceptedDidBinding, String> {
        let profile = binding_freshness_profile();
        let binding = VerifiedDidBinding::from_verified_document(
            document,
            VerifiedDidBindingDocumentInput {
                trust_domain: self.trust_domain.clone(),
                purpose,
                verification_method: verification_method.cloned(),
                // Neither pin is available: `did:key` has no history by
                // construction, and the `did:web` / `did:webvh` documents this
                // chain serves surface no log head or version id. §5.5 requires
                // that to be *recorded per pin* rather than silently omitted.
                history_head: None,
                version_id: None,
                limited_trust: LimitedTrust::for_proofless_method(None, None).record_for(),
                evidence_digest: receipt
                    .digest()
                    .map_err(|error| format!("evidence digest failed: {error}"))?,
                evidence_dependencies: receipt
                    .evidence_dependencies()
                    .map_err(|error| format!("evidence dependencies failed: {error}"))?,
                policy_digest: self.policy_digest.clone(),
                verified_at: now,
                refresh_after: profile.refresh_after(now),
                expires_at: profile.expires_at(now),
                status: DidBindingStatus::Active,
            },
        )
        .map_err(|error| format!("binding construction failed: {error}"))?;
        let accepted = AcceptedDidBinding::new(binding, document.clone(), receipt)
            .map_err(|error| format!("binding/document pairing rejected: {error}"))?;
        self.store
            .accept(accepted.clone())
            .map_err(|error| format!("binding store rejected the acceptance: {error}"))?;
        Ok(accepted)
    }

    /// The evidence receipt for a document this process did not resolve over the
    /// network: the local `did:key` decode, and the mirror of an already-accepted
    /// document into a second purpose.
    ///
    /// `did:key` is self-describing key material (spec §2.4), so it publishes no
    /// verifiable method evidence at all — [`MethodEvidence::none`] is the
    /// normative degenerate form for it, not a stand-in for evidence teabay
    /// failed to collect.
    pub fn proofless_receipt(document: &DidDocument) -> Result<EvidenceReceipt, String> {
        Ok(EvidenceReceipt::new(
            document.id.method(),
            arkret_identity::binding::document_canonical_digest(document)
                .map_err(|error| format!("document digest failed: {error}"))?,
            &MethodEvidence::none(),
        ))
    }

    /// Decode a `did:key` locally and accept it. Zero network by construction —
    /// `did:key` carries its own key material (spec §2.4).
    pub fn accept_did_key(
        &self,
        did: &Did,
        purpose: DidBindingPurpose,
        verification_method: Option<&DidUrl>,
        now: DateTime<Utc>,
    ) -> Result<AcceptedDidBinding, String> {
        let document = self
            .did_key
            .resolve_did_document(did)
            .map_err(|error| format!("did:key decode failed: {error}"))?;
        self.metrics
            .record_did_resolve(did.method(), DID_RESOLVE_SOURCE_DID_KEY);
        let receipt = Self::proofless_receipt(&document)?;
        self.accept_document(&document, purpose, verification_method, receipt, now)
    }

    /// Precise invalidation (spec §5). Exposed so rotation / deactivation /
    /// policy-revision handling can drop exactly the affected acceptances
    /// without clearing an unrelated trust domain or purpose.
    pub fn invalidate(&self, selector: &BindingInvalidation) -> usize {
        self.store.invalidate(selector)
    }

    /// Quarantine every acceptance matching `selector` instead of removing it.
    ///
    /// Used for received deactivation / witness-fork evidence: a quarantined
    /// binding stops authorizing signatures immediately (`verify_jws_with_binding`
    /// refuses it) **without** any resolver call, and the entry stays visible to
    /// operators.
    pub fn quarantine(&self, selector: &BindingInvalidation) -> usize {
        self.set_status(selector, DidBindingStatus::Quarantined)
    }

    fn set_status(&self, selector: &BindingInvalidation, status: DidBindingStatus) -> usize {
        let mut changed = 0usize;
        for accepted in self.store.snapshot() {
            if !selector.matches(accepted.binding()) {
                continue;
            }
            if self
                .store
                .accept(accepted.with_binding_status(status))
                .is_ok()
            {
                changed += 1;
            }
        }
        changed
    }

    /// Verify a detached Ed25519 JWS **without any possibility of resolving**.
    ///
    /// Order:
    ///
    /// 1. empty accepted-method allowlist → fail closed (the SDK policy layer treats "empty" as
    ///    "any method", so this guard has to sit above it);
    /// 2. `verification_method` must parse as a `DidUrl` and its DID part must equal `issuer_id`;
    /// 3. the issuer_id's DID method must be on the allowlist;
    /// 4. an accepted binding for `(issuer_id, purpose, verification_method)` → verify against its
    ///    pinned document;
    /// 5. otherwise, `did:key` issuers are decoded locally and accepted (still zero network);
    /// 6. otherwise fail closed with [`BindingFailure::NoBinding`]. **No live resolution**, which
    ///    is the DID-P0-C03 requirement for the query face.
    ///
    /// Records exactly one `teabay_signature_verify_total{kind,outcome}`.
    // Each parameter is an independent part of the verification question
    // (bytes, signature, key, issuer_id, purpose); a bundle type would make a
    // mismatched pair constructible.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_detached_jws(
        &self,
        canonical_bytes: &[u8],
        jws: &str,
        verification_method: &str,
        issuer_id: &str,
        purpose: DidBindingPurpose,
        kind: &'static str,
        now: DateTime<Utc>,
    ) -> Result<(), BindingFailure> {
        let outcome = self.verify_detached_jws_inner(
            canonical_bytes,
            jws,
            verification_method,
            issuer_id,
            purpose,
            now,
        );
        self.metrics.record_signature_verify(
            kind,
            match &outcome {
                Ok(()) => SIGNATURE_OUTCOME_OK,
                Err(failure) => failure.outcome_label(),
            },
        );
        outcome
    }

    fn verify_detached_jws_inner(
        &self,
        canonical_bytes: &[u8],
        jws: &str,
        verification_method: &str,
        issuer_id: &str,
        purpose: DidBindingPurpose,
        now: DateTime<Utc>,
    ) -> Result<(), BindingFailure> {
        let (issuer_id, verification_method) =
            self.parse_signer(verification_method, issuer_id, purpose)?;
        let accepted = match self.accepted(&issuer_id, purpose, Some(&verification_method), now) {
            Some(accepted) => accepted,
            None if issuer_id.method() == "key" => self
                .accept_did_key(&issuer_id, purpose, Some(&verification_method), now)
                .map_err(BindingFailure::NoBinding)?,
            None => {
                return Err(BindingFailure::NoBinding(format!(
                    "no accepted `{purpose}` binding for `{issuer_id}`"
                )));
            }
        };
        verify_jws_with_binding(canonical_bytes, jws, &verification_method, &accepted)
            .map_err(|error| BindingFailure::Invalid(error.to_string()))
    }

    /// Shared policy gate + typed parse for every signer teabay accepts.
    ///
    /// Split out because the authority face
    /// ([`crate::did_resolver::SharedDidResolver`]) runs the identical gate
    /// before it is allowed to resolve.
    pub(crate) fn parse_signer(
        &self,
        verification_method: &str,
        issuer_id: &str,
        purpose: DidBindingPurpose,
    ) -> Result<(Did, DidUrl), BindingFailure> {
        // No empty-allowlist guard is needed here any more, and one would be
        // dead code. `ResolverPolicy::allowed_methods` still treats an empty
        // list as "every method is allowed", but §5.3 forbids *declaring* that
        // policy at all, so `resolver_policy_digest` — and therefore
        // `DidBindingDirectory::new`, and therefore `AppState::new` — fails on
        // an empty `TEABAY_ACCEPTED_DID_METHODS`. A directory that could reach
        // this line cannot exist. See
        // `an_empty_allowlist_cannot_be_configured_at_all`.
        let verification_method =
            DidUrl::new(verification_method.trim().to_owned()).map_err(|error| {
                BindingFailure::PolicyRejected(format!("verification_method: {error}"))
            })?;
        let issuer_id = Did::new(issuer_id.trim().to_owned())
            .map_err(|error| BindingFailure::PolicyRejected(format!("issuer_id: {error}")))?;
        let method_did = verification_method
            .as_str()
            .split_once('#')
            .map(|(did, _)| did)
            .unwrap_or(verification_method.as_str());
        if method_did != issuer_id.as_str() {
            return Err(BindingFailure::PolicyRejected(format!(
                "verification_method `{verification_method}` is not controlled by `{issuer_id}`"
            )));
        }
        if !self.method_allowed(&format!("did:{}", issuer_id.method())) {
            return Err(BindingFailure::PolicyRejected(format!(
                "DID method did:{} is outside TEABAY_ACCEPTED_DID_METHODS (purpose {purpose})",
                issuer_id.method()
            )));
        }
        Ok((issuer_id, verification_method))
    }
}

/// The §5.3 `policy_digest` of teabay's effective `ResolverPolicy`.
///
/// # Algorithm: the SDK's, and only the SDK's
///
/// `did-usage-and-verification.md` §5.3 defines the canonical resolver policy
/// snapshot (`ak.did.resolver_policy.v1`) and its digest, and
/// `ResolverPolicy::policy_digest()` is the single implementation of it. Teabay
/// adds nothing: two deployments with equal policies agree by construction
/// rather than by coincidence, and a language-native `Debug` rendering of an
/// enum — the encoding fork this replaced — is not expressible.
///
/// # Why `allow_private_networks` / `development_mode` are not inputs
///
/// They used to be digest extensions, on the reasoning that flipping the egress
/// boundary must invalidate acceptances taken under the old one. §5.3 closed the
/// snapshot: a deployment with extra admissibility dimensions MUST register its
/// own `policy_profile` with a closed `profile_policy` schema, and v1 registers
/// only `ak.did_resolver_policy_profile.base.v1` (`profile_policy` = `{}`).
///
/// Registering a teabay profile would be the right move if the dimension could
/// ever discriminate anything here. It cannot:
///
/// - both flags are derived once in `AppState::new` from the startup `AppConfig` snapshot and
///   frozen inside [`crate::did_resolver::SharedDidResolver`]; no request path can supply a
///   different value;
/// - the acceptance store is [`InMemoryVerifiedDidBindingStore`], created in the same constructor
///   and never persisted or shared between processes.
///
/// So an acceptance made under one value of these flags can never be read by a
/// process running under another — the process that could observe the
/// difference does not outlive the flags. Keeping them as digest inputs would
/// state a scoping property that the store already provides structurally.
///
/// A deployment that gives this store a **durable** backend must revisit this:
/// at that point the flags become genuinely discriminating and a registered
/// profile is required, not optional.
///
/// Everything that *is* discriminating stays covered: the accepted-method
/// allowlist, the fail mode and the trust roots are the snapshot's three
/// required members, and any change to them changes the digest, which changes
/// every [`VerifiedDidBindingKey`], which makes every acceptance taken under the
/// old policy structurally unreachable.
pub fn resolver_policy_digest(accepted_did_methods: &[String]) -> Result<Hash, String> {
    crate::did_resolver::resolver_policy(accepted_did_methods)
        .policy_digest()
        .map_err(|error| format!("resolver policy digest failed: {error}"))
}

/// Derive the `ak:trust_domain:<scope>` this directory accepts under.
///
/// The scope is the configured service DID, lowercased and reduced to the
/// `[a-z0-9._:-]` charset the identifier layer requires. Binding acceptances
/// are therefore scoped to *this* directory: the same DID accepted by another
/// deployment is a different key.
fn trust_domain_for_service(service_id: &str) -> Result<TrustDomainId, String> {
    let mut scope = String::new();
    for ch in service_id.trim().to_ascii_lowercase().chars() {
        match ch {
            'a'..='z' | '0'..='9' | '.' | '_' | '-' | ':' => scope.push(ch),
            _ => scope.push('-'),
        }
    }
    let scope = scope
        .trim_start_matches(|ch: char| !ch.is_ascii_alphanumeric())
        .chars()
        .take(120)
        .collect::<String>();
    let scope = if scope.is_empty() {
        FALLBACK_TRUST_DOMAIN_SCOPE.to_owned()
    } else {
        scope
    };
    TrustDomainId::new(format!("ak:trust_domain:{scope}"))
        .map_err(|error| format!("trust domain for service `{service_id}` is invalid: {error}"))
}

#[cfg(test)]
mod tests {
    use arkret_signatures::jws::sign_jws_ed25519;
    use ed25519_dalek::SigningKey;

    use super::*;

    fn directory() -> DidBindingDirectory {
        DidBindingDirectory::new(
            &["did:key".to_owned(), "did:web".to_owned()],
            "did:web:directory.example",
            Metrics::default(),
        )
        .expect("directory builds")
    }

    fn did_key_multibase(signing_key: &SigningKey) -> String {
        let mut bytes = vec![0xed, 0x01];
        bytes.extend_from_slice(signing_key.verifying_key().as_bytes());
        format!("z{}", bs58::encode(bytes).into_string())
    }

    fn did_key_signer(seed: u8) -> (SigningKey, Did, DidUrl) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let multibase = did_key_multibase(&signing_key);
        let did = Did::new(format!("did:key:{multibase}")).expect("did");
        let verification_method =
            DidUrl::new(format!("{did}#{multibase}")).expect("verification method");
        (signing_key, did, verification_method)
    }

    #[test]
    fn policy_digest_is_stable_and_order_insensitive() {
        let a = resolver_policy_digest(&["did:key".to_owned(), "did:web".to_owned()]).unwrap();
        let b = resolver_policy_digest(&["did:web:".to_owned(), "did:key".to_owned()]).unwrap();
        assert_eq!(a, b, "normalization + sort must make ordering irrelevant");
    }

    /// The accepted-method allowlist is a required member of the §5.3 snapshot,
    /// so changing it necessarily changes the digest — and therefore every
    /// store key taken under the old allowlist.
    #[test]
    fn policy_digest_changes_when_the_accepted_method_set_changes() {
        let base = resolver_policy_digest(&["did:key".to_owned()]).expect("base digest");
        assert_ne!(
            base,
            resolver_policy_digest(&["did:key".to_owned(), "did:web".to_owned()]).unwrap()
        );
        assert_ne!(
            base,
            resolver_policy_digest(&["did:web".to_owned()]).unwrap()
        );
    }

    /// The three spellings the SDK normalizes must all key the same acceptance.
    ///
    /// The teabay-local `normalize_did_method_prefix` this replaced mapped a
    /// bare `"web"` to `"web:"`, i.e. to a token that matched nothing — so a
    /// deployment configured with bare method names silently got a *different*
    /// policy digest from one configured with prefixes.
    #[test]
    fn policy_digest_folds_every_method_spelling_together() {
        let bare = resolver_policy_digest(&["key".to_owned(), "web".to_owned()]).expect("digest");
        let prefixed =
            resolver_policy_digest(&["did:key".to_owned(), "did:web".to_owned()]).expect("digest");
        let terminated = resolver_policy_digest(&["did:key:".to_owned(), "did:web:".to_owned()])
            .expect("digest");
        assert_eq!(bare, prefixed);
        assert_eq!(prefixed, terminated);
    }

    /// An empty allowlist is fail-open ("any method"), which §5.3 forbids a
    /// snapshot from declaring at all — so it has no digest, and a directory
    /// configured that way cannot even be constructed.
    #[test]
    fn an_empty_allowlist_has_no_declarable_policy_digest() {
        assert!(resolver_policy_digest(&[]).is_err());
    }

    /// The acceptance is a `{binding, document, receipt}` triple, and the SDK
    /// re-digests the receipt on construction. Pairing a binding with a receipt
    /// it was not made from is therefore unrepresentable, which is what makes
    /// `evidence_digest` an auditable claim rather than an opaque field.
    #[test]
    fn evidence_is_a_recomputable_receipt_over_the_pinned_document() {
        let directory = directory();
        let (_, did, verification_method) = did_key_signer(29);
        let now = Utc::now();

        let accepted = directory
            .accept_did_key(
                &did,
                DidBindingPurpose::DirectoryIssuer,
                Some(&verification_method),
                now,
            )
            .expect("acceptance");

        let receipt = accepted.evidence_receipt();
        assert_eq!(
            accepted.binding().evidence_digest(),
            &receipt.digest().expect("digest")
        );
        // `did:key` is self-describing key material: no method proofs exist, and
        // the receipt says so rather than carrying a stand-in.
        assert_eq!(receipt.method, "key");
        assert!(receipt.method_proofs.is_empty());
        // The degenerate `evidence_digest = document_digest` form is unreachable.
        assert_ne!(
            accepted.binding().evidence_digest(),
            accepted.binding().document_digest()
        );
        // §5.5: both pins are absent, and `did:key` genuinely cannot supply
        // either, so the record is `method_unsupported` rather than omitted.
        assert_eq!(
            accepted.binding().limited_trust(),
            LimitedTrust::for_proofless_method(None, None).record_for()
        );
    }

    #[test]
    fn trust_domain_is_scoped_to_the_service_did() {
        assert_eq!(
            trust_domain_for_service("did:web:directory.example")
                .unwrap()
                .as_str(),
            "ak:trust_domain:did:web:directory.example"
        );
        // Uppercase / illegal bytes are folded rather than rejected, and an
        // empty payload still yields a valid identifier.
        assert!(trust_domain_for_service("DID:WEB:Directory.Example%20x").is_ok());
        assert_eq!(
            trust_domain_for_service("").unwrap().as_str(),
            "ak:trust_domain:teabay"
        );
    }

    /// An empty accepted-method list is fail-OPEN at the `ResolverPolicy` layer
    /// ("empty means any method"), so teabay used to guard against it on every
    /// verification entry point.
    ///
    /// §5.3 makes that guard unnecessary **and** unreachable: the canonical
    /// resolver policy snapshot refuses to declare an empty
    /// `accepted_did_methods`, so the policy has no digest, the directory has no
    /// store key dimension, and construction fails. The misconfiguration is now
    /// a boot failure rather than a per-request rejection — which is strictly
    /// better, since a deployment that answers `/readyz` and then rejects every
    /// signature is harder to diagnose than one that refuses to start.
    #[test]
    fn an_empty_allowlist_cannot_be_configured_at_all() {
        let error = DidBindingDirectory::new(&[], "did:web:directory.example", Metrics::default())
            .expect_err("an empty allowlist must not be configurable");
        assert!(
            error.contains("accepted_did_methods"),
            "the failure must name the offending configuration, got: {error}"
        );
    }

    #[test]
    fn did_key_signature_verifies_with_zero_network_and_caches() {
        let directory = directory();
        let (signing_key, did, verification_method) = did_key_signer(11);
        let payload = b"canonical-payload";
        let jws = sign_jws_ed25519(payload, &signing_key).expect("sign");

        for _ in 0..3 {
            directory
                .verify_detached_jws(
                    payload,
                    &jws,
                    verification_method.as_str(),
                    did.as_str(),
                    DidBindingPurpose::DirectoryIssuer,
                    crate::observability::SIGNATURE_KIND_INVITE_TOKEN,
                    Utc::now(),
                )
                .expect("did:key verification succeeds");
        }

        let metrics = directory.metrics();
        assert_eq!(
            metrics.did_resolve_count(crate::observability::DID_RESOLVE_SOURCE_NETWORK),
            0,
            "did:key must never reach the network"
        );
        assert_eq!(
            metrics.did_resolve_count(DID_RESOLVE_SOURCE_DID_KEY),
            1,
            "only the first verification decodes; the rest reuse the binding"
        );
        assert_eq!(
            metrics.did_resolve_count(DID_RESOLVE_SOURCE_BINDING_STORE),
            2
        );
        assert_eq!(
            metrics.signature_verify_count(
                crate::observability::SIGNATURE_KIND_INVITE_TOKEN,
                SIGNATURE_OUTCOME_OK
            ),
            3,
            "every signature is counted, not every resolution"
        );
    }

    #[test]
    fn unknown_did_web_issuer_fails_closed_instead_of_resolving() {
        let directory = directory();
        let failure = directory
            .verify_detached_jws(
                b"payload",
                "jws",
                "did:web:issuer_id.example#key-1",
                "did:web:issuer_id.example",
                DidBindingPurpose::DirectoryIssuer,
                crate::observability::SIGNATURE_KIND_RESTRICTED_CLAIM,
                Utc::now(),
            )
            .expect_err("unknown issuer_id must fail closed");
        assert!(matches!(failure, BindingFailure::NoBinding(_)), "{failure}");
        assert_eq!(
            directory
                .metrics()
                .did_resolve_count(crate::observability::DID_RESOLVE_SOURCE_NETWORK),
            0
        );
    }

    #[test]
    fn purposes_do_not_cross_authorize() {
        let directory = directory();
        let (signing_key, did, verification_method) = did_key_signer(13);
        let payload = b"canonical-payload";
        let jws = sign_jws_ed25519(payload, &signing_key).expect("sign");
        let now = Utc::now();

        directory
            .accept_did_key(
                &did,
                DidBindingPurpose::DirectoryIngest,
                Some(&verification_method),
                now,
            )
            .expect("ingest acceptance");

        // A `DirectoryIngest` acceptance is keyed under its own purpose, so an
        // issuer_id lookup misses it. For a `did:key` issuer_id the local decode then
        // establishes the issuer_id binding separately (still zero network); for
        // anything else this would fail closed.
        assert!(
            directory
                .accepted(
                    &did,
                    DidBindingPurpose::DirectoryIssuer,
                    Some(&verification_method),
                    now
                )
                .is_none()
        );
        directory
            .verify_detached_jws(
                payload,
                &jws,
                verification_method.as_str(),
                did.as_str(),
                DidBindingPurpose::DirectoryIssuer,
                crate::observability::SIGNATURE_KIND_INVITE_TOKEN,
                now,
            )
            .expect("issuer_id purpose gets its own acceptance");
        assert_eq!(directory.len(), 2);
    }

    #[test]
    fn deactivated_binding_stops_authorizing_without_any_resolution() {
        let directory = directory();
        let (signing_key, did, verification_method) = did_key_signer(17);
        let payload = b"canonical-payload";
        let jws = sign_jws_ed25519(payload, &signing_key).expect("sign");
        let now = Utc::now();

        directory
            .verify_detached_jws(
                payload,
                &jws,
                verification_method.as_str(),
                did.as_str(),
                DidBindingPurpose::DirectoryIngest,
                crate::observability::SIGNATURE_KIND_INGEST_PROOF,
                now,
            )
            .expect("first acceptance");

        let quarantined = directory.quarantine(&BindingInvalidation::for_did(did.clone()));
        assert_eq!(quarantined, 1);

        let failure = directory
            .verify_detached_jws(
                payload,
                &jws,
                verification_method.as_str(),
                did.as_str(),
                DidBindingPurpose::DirectoryIngest,
                crate::observability::SIGNATURE_KIND_INGEST_PROOF,
                now,
            )
            .expect_err("a quarantined binding must not authorize");
        assert!(matches!(failure, BindingFailure::Invalid(_)), "{failure}");
        assert_eq!(
            directory
                .metrics()
                .did_resolve_count(crate::observability::DID_RESOLVE_SOURCE_NETWORK),
            0,
            "quarantine must not trigger a 'resolve once more to be safe' path"
        );
    }

    #[test]
    fn stale_binding_is_still_consumed_by_an_ordinary_read() {
        let directory = directory();
        let (signing_key, did, verification_method) = did_key_signer(19);
        let payload = b"canonical-payload";
        let jws = sign_jws_ed25519(payload, &signing_key).expect("sign");
        let accepted_at = Utc::now();

        directory
            .accept_did_key(
                &did,
                DidBindingPurpose::DirectoryIssuer,
                Some(&verification_method),
                accepted_at,
            )
            .expect("acceptance");

        // Past `refresh_after`, before `expires_at`: the entry is Stale.
        // Both windows come from the one declared profile, so this cannot drift
        // away from what the acceptance actually recorded.
        let later = binding_freshness_profile()
            .refresh_after(accepted_at)
            .expect("the declared profile has a finite refresh window")
            + chrono::Duration::minutes(1);
        let before = directory
            .metrics()
            .did_resolve_count(DID_RESOLVE_SOURCE_DID_KEY);
        directory
            .verify_detached_jws(
                payload,
                &jws,
                verification_method.as_str(),
                did.as_str(),
                DidBindingPurpose::DirectoryIssuer,
                crate::observability::SIGNATURE_KIND_INVITE_TOKEN,
                later,
            )
            .expect("a stale binding still verifies an ordinary read");
        assert_eq!(
            directory
                .metrics()
                .did_resolve_count(DID_RESOLVE_SOURCE_DID_KEY),
            before,
            "a stale binding must not be re-derived on a low-risk read"
        );
        assert_eq!(
            directory
                .metrics()
                .did_resolve_count(crate::observability::DID_RESOLVE_SOURCE_NETWORK),
            0
        );
    }

    #[test]
    fn invalidating_one_purpose_leaves_the_other_intact() {
        let directory = directory();
        let (_, did, verification_method) = did_key_signer(23);
        let now = Utc::now();
        for purpose in [
            DidBindingPurpose::DirectoryIngest,
            DidBindingPurpose::DirectoryIssuer,
        ] {
            directory
                .accept_did_key(&did, purpose, Some(&verification_method), now)
                .expect("acceptance");
        }
        assert_eq!(directory.len(), 2);

        let removed = directory.invalidate(
            &BindingInvalidation::for_did(did.clone())
                .with_purpose(DidBindingPurpose::DirectoryIngest),
        );
        assert_eq!(removed, 1);
        assert!(
            directory
                .accepted(
                    &did,
                    DidBindingPurpose::DirectoryIssuer,
                    Some(&verification_method),
                    now
                )
                .is_some()
        );
    }
}
