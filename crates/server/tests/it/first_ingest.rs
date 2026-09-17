//! End-to-end **first ingest**: the success path, over HTTP, against a real
//! `did:web` Station.
//!
//! # What was missing
//!
//! `conformance.rs` covers first ingest only as a refusal
//! (`assert_first_ingest_rejects_unresolvable_station_then_refreshes_seeded_resource`):
//! its fixture Station is a `did:key`, which publishes no DID document and no
//! `ArkretStation` endpoint, so admission can never get as far as resolving a
//! carrier `CommittedEventRef`. The follow-up announce in that same function
//! succeeds only because the row was seeded first — a **refresh**, which by
//! construction skips §8.5 step 4 entirely. The in-crate tests in
//! `ingest::verify` do drive the production authority verifier, but they stop
//! at `verify_first_source_ref_resolves`: nothing there renders a preview or
//! writes a row.
//!
//! So the one path a real deployment takes when it meets a resource for the
//! first time — resolve the Station, resolve the carrier commit, verify the
//! Realm's authority chain, project the announce, index it, serve it — had
//! never run end to end.
//!
//! # What this test actually exercises
//!
//! Everything in that sentence, with no substitutions:
//!
//! - the Station is a **`did:web`** whose document this fixture really serves over HTTP, and which
//!   the running `AppState`'s own resolver really fetches and validates;
//! - the discovery Event carries a real `ProducerEventProof` that §8.5 step 2 verifies against a
//!   key resolved from that document;
//! - the carrier `CommittedEventRef` is resolved from the Station's **peer** face, and its
//!   `RealmCommit` is then verified by `RealmAuthorityChainVerifier` — the production
//!   implementation — against a nonce-bound `RealmAuthorityBundle` fetched from the Station's
//!   **open** face and checked by `arkret_identity::verify_realm_authority_bundle`;
//! - the announce is projected and that projection is rendered as the closed `RealmPreview` before
//!   the row is written; and
//! - the row lands in PostgreSQL and `resolve-realm` serves it.
//!
//! Every signature in the fixture is a real Ed25519 signature over the
//! canonical unsigned body. No verifier is injected: the service is built by
//! `server::AppState::new` exactly as `main.rs` builds it, so the verifier
//! under test is the default one a deployment gets.
//!
//! # What it does not prove
//!
//! - The `did:web` document is served over **loopback HTTP**, which only
//!   `TEABAY_DEVELOPMENT_MODE=true` admits. Public-HTTPS `did:web` resolution, certificate
//!   handling and the egress guard's public path are not exercised here: a loopback address
//!   cannot present a certificate the chain's roots accept. That is a property of local testing,
//!   not a relaxation of the ingest rules — every signature, generation, freshness and
//!   Station-binding check on this path is the production one.
//! - The authority chain is **genesis-only** (`current_generation == 0`, no handoffs).
//!   Multi-generation handoff verification is the SDK's own `realm_authority_chain` test surface.
//! - Only the Realm resource kind is driven end to end.

use std::sync::Arc;

use arkret_sdk::{Did, DidCoreId, Hash};
use arkret_signatures::jws::sign_jws_ed25519;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use diesel::sql_types::Text;
use diesel_async::RunQueryDsl;
use ed25519_dalek::SigningKey;
use salvo::http::StatusCode;
use salvo::prelude::Service;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value as JsonValue, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::conformance::{realm_discovery_state, signed_realm_discovery_event};

/// The Directory under test, as the conformance harness configures it
/// (`TEABAY_SERVICE_DID=did:web:directory.test`).
const DIRECTORY_SERVICE_ID: &str = "ak:did_core:web:directory.test";

/// Millisecond-truncated `now`.
///
/// The canonical timestamp encoding carries milliseconds, so a finer-grained
/// value does not survive the round trip through the announce body — and a
/// proof signed over the un-truncated value would then verify against a
/// different transcript than the one that arrives.
fn now_ms() -> DateTime<Utc> {
    DateTime::from_timestamp_millis(Utc::now().timestamp_millis())
        .expect("the current time is representable in milliseconds")
}

/// The `did:web` identity of the fixture Station, and the Realm it governs.
///
/// The port has to exist before the DID does — `did:web:127.0.0.1%3A<port>`
/// *is* the port — so the listener is bound first and its port handed in here.
struct StationIdentity {
    service_id: DidCoreId,
    verification_method: arkret_wire::DidUrl,
    signing_key: SigningKey,
    /// The W3C document served at `/.well-known/did.json`.
    document: JsonValue,
    /// The `AuthenticatedServiceResolution` for `service_id`, derived from
    /// that very document.
    route_record: JsonValue,
    /// Generation 0 of the Realm's authority: the `ak.realm.create` Event that
    /// defines the Realm, and the commit that seals it at stream position 0.
    genesis_event: arkret_wire::Event,
    genesis_commit: arkret_wire::RealmCommit,
}

impl StationIdentity {
    fn new(port: u16) -> anyhow::Result<Self> {
        let signing_key = SigningKey::from_bytes(&[91; 32]);
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signing_key.verifying_key().as_bytes(),
        );
        let did = Did::new(format!("did:web:127.0.0.1%3A{port}"))?;
        let service_id = arkret_sdk::project_did_to_core_id(&did)?;
        let verification_method =
            arkret_wire::DidUrl::new(format!("{did}#station-key")).map_err(anyhow::Error::msg)?;

        // One document, two service entries. `ArkretStation` is the peer face
        // the Directory actually dials, and it is a loopback HTTP URL, which
        // `service_endpoint_url` admits only in development mode.
        // `ArkretService` is the canonical https route that the authority
        // bundle's `current_route_record` projects; nothing in ingest dials
        // it, and a loopback address has no canonical public https form to
        // offer.
        let document = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did.as_str(),
            "verificationMethod": [{
                "id": verification_method.as_str(),
                "controller": did.as_str(),
                "type": "Multikey",
                "publicKeyMultibase": multibase,
            }],
            "authentication": [verification_method.as_str()],
            "assertionMethod": [verification_method.as_str()],
            "service": [
                {
                    "id": format!("{did}#peer"),
                    "type": "ArkretStation",
                    "serviceEndpoint": format!("http://127.0.0.1:{port}/_arkret/peer"),
                },
                {
                    "id": format!("{did}#station"),
                    "type": "ArkretService",
                    "serviceEndpoint": "https://station.example/",
                    "serviceKind": "station",
                },
            ],
        });
        let route_record = serde_json::to_value(
            arkret_identity::build_authenticated_did_web_service_resolution(
                service_id.clone(),
                "station".to_owned(),
                serde_json::from_value(document.clone())?,
                Utc::now(),
            )?,
        )?;

        // `ak.realm.create` carries the `realm_genesis` scope and omits
        // `realm_id` on the wire — `models/realm-and-space.md` §2.5.0 has
        // receivers derive it from the Event's own id — so the Realm this
        // whole fixture is about is *defined by* this Event rather than
        // chosen next to it.
        let genesis_event = arkret_wire::test_support::raw_event(
            "ak.realm.create",
            arkret_wire::ScopeRef::RealmGenesis,
            service_id.clone(),
            service_id.clone(),
            json!({"value": {"name": "did:web first-ingest fixture realm"}}),
        )?;
        let genesis_commit = seal_realm_commit(
            arkret_wire::RealmCommit {
                commit_id: realm_commit_id_for(&genesis_event.event_id),
                realm_id: genesis_event.realm_id.clone(),
                stream_ref: arkret_wire::CommitStreamRef::Realm {
                    realm_id: genesis_event.realm_id.clone(),
                },
                stream_position: 0,
                previous_commit_ref: None,
                event_ref: genesis_event.event_id.clone(),
                authority_generation: 0,
                authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    genesis_event.event_id.clone(),
                ),
                committed_at: Utc::now(),
                signature: unsealed_signature(
                    arkret_wire::DetachedSignatureContext::RealmCommit,
                    &verification_method,
                ),
            },
            &verification_method,
            &signing_key,
        );

        Ok(Self {
            service_id,
            verification_method,
            signing_key,
            document,
            route_record,
            genesis_event,
            genesis_commit,
        })
    }

    fn realm_id(&self) -> &arkret_wire::RealmId {
        &self.genesis_event.realm_id
    }

    /// Commit the announce's discovery Event at stream position 1, under
    /// generation 0, naming the genesis Event as the record that installed the
    /// authority behind it.
    fn commit(
        self,
        event: arkret_wire::Event,
    ) -> (arkret_wire::CommittedEventRef, FixtureWebStation) {
        let stream_ref = arkret_wire::CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        };
        let commit_id = realm_commit_id_for(&event.event_id);
        let commit = seal_realm_commit(
            arkret_wire::RealmCommit {
                commit_id: commit_id.clone(),
                realm_id: event.realm_id.clone(),
                stream_ref: stream_ref.clone(),
                stream_position: 1,
                previous_commit_ref: Some(self.genesis_commit.commit_id.clone()),
                event_ref: event.event_id.clone(),
                authority_generation: 0,
                authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    self.genesis_commit.event_ref.clone(),
                ),
                committed_at: Utc::now(),
                signature: unsealed_signature(
                    arkret_wire::DetachedSignatureContext::RealmCommit,
                    &self.verification_method,
                ),
            },
            &self.verification_method,
            &self.signing_key,
        );
        let reference = arkret_wire::CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: commit_id.clone(),
            stream_ref: stream_ref.clone(),
            stream_position: 1,
        };
        let stream_head = arkret_wire::CommitStreamHead {
            stream_ref,
            stream_position: 1,
            commit_id,
        };
        (
            reference,
            FixtureWebStation {
                identity: self,
                committed: arkret_wire::StreamRow { commit, event },
                stream_head,
            },
        )
    }
}

/// The fixture Station, answering on all three surfaces a first ingest touches.
///
/// In a real deployment these are one host, so they are one listener here:
///
/// | request | surface | who asks |
/// | --- | --- | --- |
/// | `GET /.well-known/did.json` | the `did:web` document | the Directory's DID resolver |
/// | `POST /_arkret/peer/streams/resolve` | exact committed-event resolve | §8.5 step 4 |
/// | `POST /_arkret/open/realm-authority/bundle` | the nonce-bound authority bundle | the authority chain verifier |
struct FixtureWebStation {
    identity: StationIdentity,
    committed: arkret_wire::StreamRow,
    stream_head: arkret_wire::CommitStreamHead,
}

impl FixtureWebStation {
    /// Answer exactly one nonce.
    ///
    /// The current assertion is signed here, at request time, over the nonce
    /// the Directory actually sent. A fixture that served a pre-baked
    /// assertion would be serving precisely the replay the freshness check
    /// exists to refuse.
    fn bundle(&self, nonce: arkret_wire::Base64UrlString) -> arkret_wire::RealmAuthorityBundle {
        let issued_at = Utc::now() - ChronoDuration::seconds(1);
        let identity = &self.identity;
        let mut assertion = arkret_wire::RealmAuthorityCurrentAssertion {
            realm_id: identity.realm_id().clone(),
            current_generation: 0,
            current_service_id: identity.service_id.clone(),
            last_handoff_ref: None,
            realm_stream_head: self.stream_head.clone(),
            nonce,
            expires_at: issued_at + ChronoDuration::minutes(5),
            signature: unsealed_signature(
                arkret_wire::DetachedSignatureContext::RealmAuthorityCurrentAssertion,
                &identity.verification_method,
            ),
        };
        let unsigned = arkret_canonical::canonical::unsigned_value(&assertion, &["signature"])
            .expect("current assertion has an unsigned projection");
        assertion.signature = arkret_signatures::detached_object::sign_detached_object(
            &unsigned,
            arkret_wire::DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            identity.verification_method.clone(),
            issued_at,
            &identity.signing_key,
        )
        .expect("current assertion signs");
        arkret_wire::RealmAuthorityBundle {
            realm_id: identity.realm_id().clone(),
            genesis_event: identity.genesis_event.clone(),
            genesis_commit: identity.genesis_commit.clone(),
            authority_transitions: Vec::new(),
            current_generation: 0,
            current_service_id: identity.service_id.clone(),
            current_route_record: identity.route_record.clone(),
            realm_stream_head: self.stream_head.clone(),
            bundle_issued_at: issued_at,
            current_assertion: assertion,
        }
    }

    /// Route one request.
    fn respond(&self, request_line: &str, body: &str) -> (u16, String) {
        if request_line.starts_with("GET /.well-known/did.json ") {
            (200, self.identity.document.to_string())
        } else if request_line.starts_with("POST /_arkret/open/realm-authority/bundle ") {
            match serde_json::from_str::<arkret_wire::AuthorityBundleRequest>(body) {
                Ok(request) if request.validate().is_ok() => (
                    200,
                    serde_json::to_string(&self.bundle(request.nonce))
                        .expect("authority bundle serializes"),
                ),
                _ => (400, "{}".to_owned()),
            }
        } else if request_line.starts_with("POST /_arkret/peer/streams/resolve ") {
            (
                200,
                serde_json::to_string(&json!({"items": [&self.committed]}))
                    .expect("resolve outcome serializes"),
            )
        } else {
            (404, "{}".to_owned())
        }
    }
}

/// Serve the fixture Station until the returned task is aborted.
///
/// A hand-rolled one-request-per-connection HTTP/1.1 responder, the same shape
/// the `ingest::verify` in-crate tests use. It is deliberately an unbounded
/// loop rather than a fixed number of exchanges: how many times admission
/// resolves the DID document is a property of the binding store, and pinning
/// it here would turn a caching change into a failure of this test.
fn serve_station(
    listener: TcpListener,
    station: Arc<FixtureWebStation>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let station = Arc::clone(&station);
            tokio::spawn(async move {
                let mut received = Vec::new();
                let header_end = loop {
                    let mut chunk = [0_u8; 4096];
                    let Ok(count) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if count == 0 {
                        return;
                    }
                    received.extend_from_slice(&chunk[..count]);
                    if let Some(position) =
                        received.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        break position + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&received[..header_end]).into_owned();
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                while received.len() < header_end + content_length {
                    let mut chunk = [0_u8; 4096];
                    let Ok(count) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if count == 0 {
                        return;
                    }
                    received.extend_from_slice(&chunk[..count]);
                }
                let body =
                    String::from_utf8_lossy(&received[header_end..header_end + content_length])
                        .into_owned();
                let request_line = headers.lines().next().unwrap_or_default().to_owned();
                let (status, payload) = station.respond(&request_line, &body);
                let reason = match status {
                    200 => "OK",
                    400 => "Bad Request",
                    _ => "Not Found",
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
                    payload.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    })
}

/// A `DetachedObjectSignature` shaped correctly and signed by nobody.
///
/// The signed projection of a detached object is the canonical object *minus*
/// its `signature` member, so the member has to exist before it can be
/// dropped. Every use below is overwritten by a real signature immediately.
fn unsealed_signature(
    context: arkret_wire::DetachedSignatureContext,
    verification_method: &arkret_wire::DidUrl,
) -> arkret_wire::DetachedObjectSignature {
    arkret_wire::DetachedObjectSignature {
        context,
        signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
        verification_method: verification_method.clone(),
        signed_digest: Hash::new(arkret_canonical::sha256_digest(b"unsealed"))
            .expect("placeholder digest is well formed"),
        created_at: Utc::now(),
        sig: arkret_wire::Base64UrlString::new("AA").expect("placeholder signature is base64url"),
    }
}

/// Seal a `RealmCommit` the way the verifier reconstructs it: the signed body
/// is the canonical object minus its own `signature` member.
fn seal_realm_commit(
    mut commit: arkret_wire::RealmCommit,
    verification_method: &arkret_wire::DidUrl,
    signing_key: &SigningKey,
) -> arkret_wire::RealmCommit {
    let unsigned = arkret_canonical::canonical::unsigned_value(&commit, &["signature"])
        .expect("a commit has an unsigned projection");
    commit.signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        verification_method.clone(),
        Utc::now(),
        signing_key,
    )
    .expect("realm commit signs");
    commit
}

fn realm_commit_id_for(event_id: &arkret_wire::EventId) -> arkret_wire::RealmCommitId {
    arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        event_id.as_str().as_bytes(),
    ))
}

/// The source-ref access proof for exactly one carrier ref.
///
/// Deliberately not `conformance.rs`'s two-ref helper: first ingest resolves
/// **every** ref it is given, so a second ref would demand a second committed
/// Event from the fixture Station without testing anything the first does not.
fn signed_single_ref_access(
    event: &arkret_wire::Event,
    committed_ref: arkret_wire::CommittedEventRef,
    source_id: DidCoreId,
    verification_method: arkret_wire::DidUrl,
    signing_key: &SigningKey,
) -> anyhow::Result<arkret_wire::DirectorySourceRefAccess> {
    let as_of = now_ms();
    let mut access = arkret_wire::DirectorySourceRefAccess {
        kind: arkret_wire::DirectorySourceRefAccessKind::DirectoryAnnounce,
        source_id,
        directory_id: DidCoreId::new(DIRECTORY_SERVICE_ID.to_owned())?,
        realm_id: event.realm_id.clone(),
        discovery_event_id: event.event_id.clone(),
        source_refs: vec![committed_ref],
        as_of,
        expires_at: as_of + ChronoDuration::minutes(5),
        proof: arkret_wire::PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method,
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at: as_of,
            domain: Some("arkret-event-v1".to_owned()),
            audience: Some(arkret_wire::Audience::Single(
                DIRECTORY_SERVICE_ID.to_owned(),
            )),
            proof_purpose: None,
            jws: "e30..c2ln".to_owned(),
        },
    };
    access.proof.payload_digest = access.payload_digest()?;
    access.proof.jws = sign_jws_ed25519(&access.proof_binding_bytes()?, signing_key)
        .map_err(anyhow::Error::msg)?;
    Ok(access)
}

/// Drive one complete first ingest and prove the resource became servable.
pub(crate) async fn assert_first_ingest_admits_a_did_web_station(
    db: &server::Db,
    service: &Service,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let identity = StationIdentity::new(port)?;
    let realm_id = identity.realm_id().to_string();

    let discovery_event = signed_realm_discovery_event(
        &realm_id,
        realm_discovery_state("did:web First Ingest"),
        identity.verification_method.as_str(),
        &identity.signing_key,
        identity.service_id.as_str(),
    )?;
    let (committed_ref, station) =
        identity.commit(serde_json::from_value(discovery_event.clone())?);
    let access = signed_single_ref_access(
        &station.committed.event,
        committed_ref,
        station.identity.service_id.clone(),
        station.identity.verification_method.clone(),
        &station.identity.signing_key,
    )?;
    let station_id = station.identity.service_id.to_string();

    let station = Arc::new(station);
    let serving = serve_station(listener, Arc::clone(&station));

    // The resource must be unknown beforehand, or this would be a refresh and
    // §8.5 step 4 would never run.
    let mut conn = db.get().await?;
    let before: ResourceCount = diesel::sql_query(
        "SELECT count(*) AS count FROM directory_resources WHERE resource_id = $1",
    )
    .bind::<Text, _>(&realm_id)
    .get_result(&mut conn)
    .await?;
    assert_eq!(
        before.count, 0,
        "this Realm must be unknown so that the announce is a first ingest"
    );
    drop(conn);

    let request = json!({
        "discovery_event": discovery_event,
        "source_ref_access": access,
        "as_of": arkret_sdk::canonical::format_timestamp_canonical(access.as_of),
        "ttl_seconds": 3600,
    });
    let mut response = TestClient::post("http://local/_arkret/find/directory/announce")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_COMMAND_ANNOUNCE_V1,
            true,
        )
        .json(&request)
        .send(service)
        .await;
    let status = response.status_code.unwrap_or(StatusCode::OK);
    if status != StatusCode::OK {
        let body = response.take_string().await.unwrap_or_default();
        serving.abort();
        panic!("first ingest from a did:web Station was refused with {status}: {body}");
    }
    let accepted: JsonValue = response.take_json().await?;
    assert!(
        accepted["announce_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("ak:announce:")),
        "{accepted}"
    );

    // The row is the proof that admission ran to the end: a refusal anywhere
    // in the five steps short-circuits before any write.
    let mut conn = db.get().await?;
    let indexed: IndexedResource = diesel::sql_query(
        "SELECT station_id, public_projection FROM directory_resources WHERE resource_id = $1",
    )
    .bind::<Text, _>(&realm_id)
    .get_result(&mut conn)
    .await?;
    assert_eq!(indexed.station_id, station_id);
    assert_eq!(
        indexed.public_projection["name"], "did:web First Ingest",
        "the stored projection must carry what the Station announced: {}",
        indexed.public_projection
    );
    drop(conn);

    let mut resolved = TestClient::post("http://local/_arkret/find/directory/resolve-realm")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_REALM_V1,
            true,
        )
        .json(&json!({ "realm_id": realm_id }))
        .send(service)
        .await;
    let status = resolved.status_code.unwrap_or(StatusCode::OK);
    if status != StatusCode::OK {
        let body = resolved.take_string().await.unwrap_or_default();
        serving.abort();
        panic!("a first-ingested Realm must resolve, got {status}: {body}");
    }
    let preview: JsonValue = resolved.take_json().await?;
    assert_eq!(preview["realm_preview"]["realm_id"], realm_id);
    assert!(
        preview["realm_preview"]["source_refs"]
            .as_array()
            .is_some_and(|refs| refs
                .iter()
                .any(|reference| reference["event_id"] == discovery_event["event_id"])),
        "the verified carrier ref must be the one the read face serves: {preview}"
    );

    serving.abort();
    Ok(())
}

#[derive(diesel::QueryableByName)]
struct ResourceCount {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    count: i64,
}

#[derive(diesel::QueryableByName)]
struct IndexedResource {
    #[diesel(sql_type = Text)]
    station_id: String,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    public_projection: JsonValue,
}
