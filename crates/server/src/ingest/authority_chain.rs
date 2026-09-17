//! The production [`CommittedEventAuthorityVerifier`].
//!
//! §8.5 step 4 makes the Directory resolve a carrier `CommittedEventRef` from
//! the resource's own governance Station on first ingest. Resolving it proves
//! only that the Station echoed the coordinates back; `CommittedEventRef::
//! matches` compares four identifiers and no signature. What turns that echo
//! into evidence is the Realm's authority chain, and this module is where
//! teabay obtains and applies it:
//!
//! 1. ask the source Station for a **nonce-bound** `RealmAuthorityBundle`
//!    (`ak.open.realm_authority.read.bundle.v1`, `sync/service-http-binding.md`
//!    §4.1) using a nonce this process just generated;
//! 2. hand the bundle to [`arkret_identity::verify_realm_authority_bundle`],
//!    which verifies genesis → current cryptographically. The rule lives in the
//!    SDK precisely so that teabay cannot drift away from the services it is
//!    mirroring, and nothing here re-implements any part of it;
//! 3. require the Station that answered to *be* the Realm's current governance
//!    authority — otherwise any Station could serve somebody else's valid
//!    chain; and
//! 4. verify the resolved `(RealmCommit, Event)` pair against the generation
//!    that actually held authority when the commit was made.
//!
//! Key material comes from the process DID resolver, which implements
//! [`arkret_identity::RealmAuthorityKeyDirectory`]. A verification method it
//! cannot produce is a rejection, never a pass. The resolution happens
//! inside announce admission, which `discovery-directory.md` §8.5 names as part
//! of `ak.find.directory.command.announce.v1`: "announce admission 内为解析
//! Station endpoint 而发起的 DID 解析属于该 operation 的组成部分，MUST NOT
//! 另立 call site."

use std::sync::Arc;

use arkret_identity::{RealmAuthorityFreshness, verify_realm_authority_bundle};
use arkret_sdk::Did;
use arkret_wire::{AuthorityBundleRequest, Base64UrlString, RealmAuthorityBundle, RealmId};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use rand::RngExt as _;
use salvo::async_trait;
use url::Url;

use crate::config::AppConfig;
use crate::did_resolver::SharedDidResolver;
use crate::ingest::verify::{
    CommittedEventAuthorityVerifier, SourceStation, endpoint_child, resolve_station_endpoint,
    response_json_limited, strict_http_client_for_egress,
};

/// How stale a bundle may be, measured from its own `bundle_issued_at`.
///
/// This is the same 300 seconds §8.7.1 allows a governance proof to deviate
/// from receipt time. A bundle is a *live* statement ("no later handoff exists
/// than the one I am showing you"), so the window is a skew tolerance and not a
/// cache lifetime; a deployment MUST NOT widen it, which is why it is a
/// constant rather than a config knob.
const MAX_AUTHORITY_BUNDLE_AGE_SECONDS: i64 = 300;

/// Number of random bytes behind the bundle request nonce. 32 bytes is 43
/// base64url characters, inside the wire range of 22..=128.
const AUTHORITY_BUNDLE_NONCE_BYTES: usize = 32;

/// Verifies resolved committed Events against the Realm's cryptographically
/// verified genesis-to-current authority chain.
pub struct RealmAuthorityChainVerifier {
    config: AppConfig,
    resolver: Arc<SharedDidResolver>,
}

impl std::fmt::Debug for RealmAuthorityChainVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RealmAuthorityChainVerifier")
            .finish_non_exhaustive()
    }
}

impl RealmAuthorityChainVerifier {
    pub fn new(config: AppConfig, resolver: Arc<SharedDidResolver>) -> Self {
        Self { config, resolver }
    }

    /// Fetch the nonce-bound bundle from the source Station's open face.
    async fn fetch_bundle(
        &self,
        station_did: &Did,
        realm_id: &RealmId,
        nonce: &Base64UrlString,
        source_ref: &str,
    ) -> Result<RealmAuthorityBundle, String> {
        let accepted =
            resolve_station_endpoint(&self.config, &self.resolver, station_did, source_ref)
                .await
                .map_err(|error| format!("Station did not resolve to an endpoint: {error}"))?;
        let url = authority_bundle_url(&accepted.endpoint)
            .map_err(|error| format!("authority bundle URL: {error}"))?;
        let target = crate::egress::resolve_url_for_egress(
            &url,
            "realm authority bundle fetch",
            crate::egress::local_development_enabled(self.config.development_mode),
        )?;
        let client = strict_http_client_for_egress(&target)
            .map_err(|error| format!("authority bundle HTTP client: {error}"))?;

        let request = AuthorityBundleRequest {
            realm_id: realm_id.clone(),
            nonce: nonce.clone(),
        };
        request
            .validate()
            .map_err(|error| format!("authority bundle request is invalid: {error}"))?;
        let body = arkret_sdk::canonical::canonical_json_bytes(&request)
            .map_err(|error| format!("authority bundle request encoding: {error}"))?;

        // `ak.open.realm_authority.read.bundle.v1` is an OPEN operation: it
        // carries no caller authentication, and it MUST NOT — the bundle is
        // self-authenticating and binding it to a caller identity would make
        // the Directory's view of the chain unreproducible by an auditor.
        let response = client
            .post(target.url().clone())
            .header(
                "arkret-operation",
                arkret_wire::ServiceOperationId::OPEN_REALM_AUTHORITY_READ_BUNDLE_V1,
            )
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|error| format!("authority bundle fetch failed: {error:?}"))?;
        if !response.status().is_success() {
            return Err(format!(
                "authority bundle fetch returned {}",
                response.status()
            ));
        }
        response_json_limited::<RealmAuthorityBundle>(response, "authority bundle response")
            .await
            .map_err(|error| format!("authority bundle response was not JSON: {error}"))
    }
}

#[async_trait]
impl CommittedEventAuthorityVerifier for RealmAuthorityChainVerifier {
    async fn verify(
        &self,
        station: SourceStation<'_>,
        reference: &arkret_wire::CommittedEventRef,
        item: &arkret_wire::StreamRow,
    ) -> Result<(), String> {
        let realm_id = reference.stream_ref.realm_id().clone();

        let nonce = fresh_nonce()?;
        let bundle = self
            .fetch_bundle(station.did, &realm_id, &nonce, reference.event_id.as_str())
            .await?;

        let freshness = RealmAuthorityFreshness::new(
            Utc::now(),
            nonce,
            Duration::seconds(MAX_AUTHORITY_BUNDLE_AGE_SECONDS),
        )
        .map_err(|error| error.to_string())?;
        let keys = self.resolver.as_ref();
        let verified = verify_realm_authority_bundle(&bundle, &freshness, keys)
            .map_err(|error| format!("Realm authority bundle did not verify: {error}"))?;

        // A valid chain for *some* Realm served by *some* Station is not
        // authority over this announce. The bundle must be this Realm's, and
        // the Station that answered must be the generation currently holding
        // authority over it — otherwise a Station could relay a chain whose
        // private keys it does not hold.
        if verified.realm_id() != &realm_id {
            return Err(format!(
                "authority bundle is for Realm {} but the source ref belongs to {realm_id}",
                verified.realm_id()
            ));
        }
        if verified.current_service_id() != station.service_id {
            return Err(format!(
                "authority bundle names {} as the current governance Station, but the announce \
                 was carried by {}",
                verified.current_service_id(),
                station.service_id
            ));
        }

        verified
            .verify_committed_item(item, keys)
            .map_err(|error| format!("resolved RealmCommit did not verify: {error}"))
    }
}

/// The open-face bundle URL for a Station whose accepted `ArkretStation`
/// endpoint is its `_arkret/peer` base.
///
/// teabay already treats the published endpoint as that base — it is what
/// `streams/resolve` is appended to — so the open face is its sibling. The
/// substitution is on the **last path segment only**, and a base that is not
/// the peer face is an error rather than a guess: silently posting an
/// authority-bundle request at an unrelated path would turn a misconfigured
/// DID document into a confusing network failure instead of a clear one.
fn authority_bundle_url(peer_endpoint: &Url) -> anyhow::Result<Url> {
    let path = peer_endpoint.path().trim_end_matches('/');
    let Some(parent) = path.strip_suffix("/peer") else {
        anyhow::bail!(
            "published ArkretStation endpoint `{peer_endpoint}` is not an `_arkret/peer` base, \
             so its `_arkret/open` face cannot be derived"
        );
    };
    let mut open_face = peer_endpoint.clone();
    open_face.set_path(&format!("{parent}/open"));
    endpoint_child(&open_face, "realm-authority/bundle")
}

/// A nonce this process generated, for this one bundle request.
///
/// Reusing a nonce, or accepting one the peer chose, would let a Station replay
/// a bundle it captured while it still held authority.
fn fresh_nonce() -> Result<Base64UrlString, String> {
    let mut bytes = [0_u8; AUTHORITY_BUNDLE_NONCE_BYTES];
    rand::rng().fill(&mut bytes);
    Base64UrlString::new(URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|error| format!("authority bundle nonce encoding: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_open_face_is_the_peer_face_sibling() {
        let peer = Url::parse("https://station.example/_arkret/peer").unwrap();
        assert_eq!(
            authority_bundle_url(&peer).unwrap().as_str(),
            "https://station.example/_arkret/open/realm-authority/bundle"
        );
        let trailing = Url::parse("https://station.example/base/_arkret/peer/").unwrap();
        assert_eq!(
            authority_bundle_url(&trailing).unwrap().as_str(),
            "https://station.example/base/_arkret/open/realm-authority/bundle"
        );
    }

    #[test]
    fn a_non_peer_endpoint_is_refused_rather_than_guessed() {
        let root = Url::parse("https://station.example/").unwrap();
        let error = authority_bundle_url(&root).expect_err("the open face is underivable");
        assert!(error.to_string().contains("_arkret/peer"), "{error}");
    }

    #[test]
    fn each_nonce_is_fresh_and_wire_valid() {
        let first = fresh_nonce().unwrap();
        let second = fresh_nonce().unwrap();
        assert_ne!(first, second);
        for nonce in [first, second] {
            assert!((22..=128).contains(&nonce.as_str().len()));
        }
    }
}
