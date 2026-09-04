//! Production private-contact-discovery runtime.
//!
//! The public HTTP surface is constructed only after startup verifies the
//! closed SDK configuration, KMS-projected custody, and the complete derived
//! index, then atomically activates that tuple in PostgreSQL.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arkret_sdk::{
    DirectoryPrivateContactDiscoveryOutcome, DirectoryPrivateContactDiscoveryRequestBody,
    InviteConsentHandoffStub, PrivateContactDiscovery, PrivateContactDiscoveryHandoffStubsMode,
    PsiClassBProblemType, PsiDerivedPrefix16, PsiPaddedProblem, PsiResponsePadding,
    PsiResponsePhase, PsiRistretto255Element, PsiVoprfProof,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt as _;
use salvo::http::{HeaderValue, StatusCode, header};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::sleep;
use voprf::{BlindedElement, Group, Ristretto255, VoprfServer};

use crate::Db;
use crate::config::PrivateContactDiscoveryRuntimeConfig;
use crate::pcd_state::{
    BlindAdmissionRequest, DeviceCredentialDigest, MatchAdmissionRequest, OpaqueExactBucketBytes,
    PcdAdmission, PcdConfigSnapshot, PcdError, PcdIndexEntry, PcdOperationalLimits, PcdReject,
    PcdRequestDigest, PostgresPcdStore,
};
use crate::state::AppState;

const DEVICE_TOKEN_PREFIX: &str = "pcd1";

#[derive(Clone)]
pub struct PrivateContactDiscoveryService {
    configuration: PrivateContactDiscovery,
    store: PostgresPcdStore,
    custody: Arc<PrivateContactDiscoveryCustody>,
    device_authentication_key: [u8; 32],
    operational_limits: PcdOperationalLimits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyManifest {
    keys: Vec<CustodyManifestEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodyManifestEntry {
    custody_key_ref: String,
    private_key_file: PathBuf,
}

struct CustodyKey {
    custody_key_ref: String,
    server: VoprfServer<Ristretto255>,
}

struct PrivateContactDiscoveryCustody {
    by_public_key: HashMap<[u8; 32], CustodyKey>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IndexManifest {
    key_epoch: u64,
    generation: String,
    entries: Vec<IndexManifestEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IndexManifestEntry {
    derived_prefix: PsiDerivedPrefix16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    handoff_stub: Option<InviteConsentHandoffStub>,
}

struct PcdHttpResponse {
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
    retry_after_seconds: Option<u64>,
}

impl PrivateContactDiscoveryService {
    pub async fn bootstrap(
        runtime: &PrivateContactDiscoveryRuntimeConfig,
        db: &Db,
    ) -> anyhow::Result<Self> {
        runtime
            .describe
            .validate()
            .map_err(|error| anyhow::anyhow!("PCD Describe configuration rejected: {error}"))?;
        let custody = PrivateContactDiscoveryCustody::load(&runtime.custody_manifest_path)?;
        let public_key = decode_exact::<32>(&runtime.describe.public_key, "PCD public key")?;
        let current_key = custody.by_public_key.get(&public_key).ok_or_else(|| {
            anyhow::anyhow!("PCD KMS manifest does not contain the described key")
        })?;
        if current_key.custody_key_ref != runtime.custody_key_ref {
            anyhow::bail!("PCD custody key reference does not bind the described public key");
        }

        let (manifest, index_entries, index_digest) =
            load_index_manifest(runtime, &runtime.index_manifest_path)?;
        let mut device_authentication_key_bytes =
            std::fs::read(&runtime.device_authentication_key_path).map_err(|error| {
                anyhow::anyhow!(
                    "failed to read PCD device authentication key {}: {error}",
                    runtime.device_authentication_key_path.display()
                )
            })?;
        let device_authentication_key = (|| {
            let encoded_device_key = std::str::from_utf8(&device_authentication_key_bytes)
                .map_err(|_| {
                    anyhow::anyhow!("PCD device authentication key must be base64url text")
                })?
                .trim();
            decode_exact::<32>(encoded_device_key, "PCD device authentication key")
        })();
        device_authentication_key_bytes.fill(0);
        let device_authentication_key = device_authentication_key?;

        let store = PostgresPcdStore::new(db.clone());
        store
            .activate_key_epoch(
                runtime.describe.key_epoch,
                public_key,
                &runtime.custody_key_ref,
                &manifest.generation,
                index_digest,
                &index_entries,
                runtime.key_activated_at,
            )
            .await
            .map_err(|error| anyhow::anyhow!("PCD epoch/index activation failed: {error}"))?;

        Ok(Self {
            configuration: runtime.describe.clone(),
            store,
            custody: Arc::new(custody),
            device_authentication_key,
            operational_limits: PcdOperationalLimits {
                evaluation_lease_seconds: runtime.evaluation_lease_seconds,
            },
        })
    }

    pub fn configuration(&self) -> &PrivateContactDiscovery {
        &self.configuration
    }

    pub async fn garbage_collect(&self) -> Result<(), PcdError> {
        let retained_config = PcdConfigSnapshot::validated(&self.configuration)?;
        self.store
            .garbage_collect(Utc::now(), retained_config.digest())
            .await?;
        Ok(())
    }

    fn authenticate(&self, request: &Request) -> Result<DeviceCredentialDigest, ()> {
        let bearer = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| {
                arkret_server::authorization_credential(
                    value.trim(),
                    arkret_server::AuthorizationScheme::Bearer,
                )
            })
            .ok_or(())?;
        let mut parts = bearer.splitn(3, '.');
        let prefix = parts.next().ok_or(())?;
        let device_id = parts.next().ok_or(())?;
        let tag = parts.next().ok_or(())?;
        if prefix != DEVICE_TOKEN_PREFIX
            || device_id.is_empty()
            || device_id.len() > 128
            || tag.is_empty()
            || tag.len() > 128
        {
            return Err(());
        }
        let tag = URL_SAFE_NO_PAD.decode(tag).map_err(|_| ())?;
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.device_authentication_key)
            .map_err(|_| ())?;
        mac.update(format!("{DEVICE_TOKEN_PREFIX}.{device_id}").as_bytes());
        mac.verify_slice(&tag).map_err(|_| ())?;
        Ok(DeviceCredentialDigest::new(
            Sha256::digest(device_id.as_bytes()).into(),
        ))
    }

    async fn process(
        &self,
        device: DeviceCredentialDigest,
        request: DirectoryPrivateContactDiscoveryRequestBody,
    ) -> Result<PcdHttpResponse, PcdError> {
        let phase = match request {
            DirectoryPrivateContactDiscoveryRequestBody::Blind { .. } => PsiResponsePhase::Blind,
            DirectoryPrivateContactDiscoveryRequestBody::Match { .. } => PsiResponsePhase::Match,
        };
        let request_bytes = arkret_sdk::canonical::canonical_json_bytes(&request)
            .map_err(|error| PcdError::Storage(error.to_string()))?;
        let request_digest =
            PcdRequestDigest::from_closed_body_sha256(Sha256::digest(&request_bytes).into());
        let batch_id = request.batch_id().clone();
        let item_count = u16::try_from(request.item_count())
            .map_err(|_| PcdError::Rejected(PcdReject::FixedBatchCardinality))?;
        let lease_owner = random_lease_owner();

        let response = match &request {
            DirectoryPrivateContactDiscoveryRequestBody::Blind {
                blinded_elements, ..
            } => {
                let admission_request = BlindAdmissionRequest {
                    device_credential_digest: device,
                    batch_id,
                    request_digest,
                    key_epoch: request.key_epoch(),
                    item_count,
                    lease_owner,
                };
                loop {
                    match self
                        .store
                        .admit_blind(
                            &self.configuration,
                            self.operational_limits,
                            Utc::now(),
                            admission_request.clone(),
                        )
                        .await?
                    {
                        PcdAdmission::Cached { outcome, .. } => {
                            break success_response(phase, outcome.as_bytes().to_vec());
                        }
                        PcdAdmission::PendingRetry {
                            retry_after_seconds,
                            ..
                        } => {
                            sleep(Duration::from_secs(retry_after_seconds)).await;
                        }
                        PcdAdmission::Evaluate {
                            pinned_config,
                            lease_version,
                            ..
                        } => {
                            let outcome = self.custody.evaluate_blind(
                                &request,
                                blinded_elements,
                                pinned_config.config(),
                            )?;
                            let bytes =
                                validated_outcome_bytes(outcome, &request, pinned_config.config())?;
                            let stored = OpaqueExactBucketBytes::for_advertised_bucket(
                                bytes.clone(),
                                pinned_config.config().blind_response_bucket_bytes,
                            )?;
                            self.store
                                .record_blind_outcome(
                                    Utc::now(),
                                    &admission_request,
                                    lease_version,
                                    stored,
                                )
                                .await?;
                            break success_response(phase, bytes);
                        }
                    }
                }
            }
            DirectoryPrivateContactDiscoveryRequestBody::Match {
                derived_prefixes, ..
            } => {
                let admission_request = MatchAdmissionRequest {
                    device_credential_digest: device,
                    batch_id,
                    request_digest,
                    key_epoch: request.key_epoch(),
                    item_count,
                    lease_owner,
                };
                loop {
                    match self
                        .store
                        .admit_match(
                            self.operational_limits,
                            Utc::now(),
                            admission_request.clone(),
                        )
                        .await?
                    {
                        PcdAdmission::Cached { outcome, .. } => {
                            break success_response(phase, outcome.as_bytes().to_vec());
                        }
                        PcdAdmission::PendingRetry {
                            retry_after_seconds,
                            ..
                        } => {
                            sleep(Duration::from_secs(retry_after_seconds)).await;
                        }
                        PcdAdmission::Evaluate {
                            pinned_config,
                            lease_version,
                            ..
                        } => {
                            let prefixes = derived_prefixes
                                .iter()
                                .map(|prefix| {
                                    decode_exact::<16>(prefix.as_str(), "PSI derived prefix")
                                        .map_err(|error| PcdError::Storage(error.to_string()))
                                })
                                .collect::<Result<Vec<_>, _>>()?;
                            let matches = self
                                .store
                                .match_index(request.key_epoch(), &prefixes)
                                .await?;
                            let hit_bitmap = matches.iter().map(|entry| entry.hit).collect();
                            let handoff_stubs = match pinned_config.config().handoff_stubs_mode {
                                PrivateContactDiscoveryHandoffStubsMode::Always => Some(
                                    matches
                                        .into_iter()
                                        .map(|entry| {
                                            if entry.hit {
                                                entry.handoff_stub.ok_or_else(|| {
                                                    PcdError::Storage(
                                                        "ready PCD index hit lost its handoff stub"
                                                            .to_owned(),
                                                    )
                                                })
                                            } else {
                                                Ok(InviteConsentHandoffStub::dummy())
                                            }
                                        })
                                        .collect::<Result<Vec<_>, _>>()?,
                                ),
                                PrivateContactDiscoveryHandoffStubsMode::Never => None,
                            };
                            let outcome = DirectoryPrivateContactDiscoveryOutcome::Match {
                                profile: request.profile(),
                                batch_id: request.batch_id().clone(),
                                key_epoch: request.key_epoch(),
                                hit_bitmap,
                                handoff_stubs,
                                padding: PsiResponsePadding::default(),
                            };
                            let bytes =
                                validated_outcome_bytes(outcome, &request, pinned_config.config())?;
                            let stored = OpaqueExactBucketBytes::for_advertised_bucket(
                                bytes.clone(),
                                pinned_config.config().match_response_bucket_bytes,
                            )?;
                            self.store
                                .record_match_outcome(
                                    Utc::now(),
                                    &admission_request,
                                    lease_version,
                                    stored,
                                )
                                .await?;
                            break success_response(phase, bytes);
                        }
                    }
                }
            }
        };
        Ok(response)
    }

    fn padded_problem(
        &self,
        phase: PsiResponsePhase,
        problem_type: PsiClassBProblemType,
        detail: &'static str,
        retry_after_seconds: Option<u64>,
    ) -> Result<PcdHttpResponse, PcdError> {
        let problem = PsiPaddedProblem::new(
            problem_type,
            detail,
            arkret_sdk::new_prefixed_uuid7("ak:request:"),
        )
        .and_then(|problem| problem.pad_to_advertised_bucket(phase, &self.configuration))
        .map_err(|error| PcdError::Storage(error.to_string()))?;
        problem
            .validate_for_phase_and_bucket(phase, &self.configuration)
            .map_err(|error| PcdError::Storage(error.to_string()))?;
        let body = arkret_sdk::canonical::canonical_json_bytes(&problem)
            .map_err(|error| PcdError::Storage(error.to_string()))?;
        Ok(PcdHttpResponse {
            status: StatusCode::from_u16(problem_type.status())
                .map_err(|error| PcdError::Storage(error.to_string()))?,
            content_type: "application/problem+json",
            body,
            retry_after_seconds,
        })
    }

    fn rejected_response(
        &self,
        phase: PsiResponsePhase,
        rejection: PcdReject,
    ) -> Result<Option<PcdHttpResponse>, PcdError> {
        let response = match rejection {
            PcdReject::QuotaExhausted {
                retry_after_seconds,
            } => self.padded_problem(
                PsiResponsePhase::Blind,
                PsiClassBProblemType::PsiQuotaExhausted,
                "psi quota exhausted for this device in the current quota window",
                Some(retry_after_seconds),
            )?,
            PcdReject::DuplicateConflict => self.padded_problem(
                phase,
                PsiClassBProblemType::DuplicateConflict,
                "batch id is already bound to a different canonical request",
                None,
            )?,
            PcdReject::BatchUnavailable => self.padded_problem(
                PsiResponsePhase::Match,
                PsiClassBProblemType::PsiBatchUnavailable,
                "private contact discovery batch is unavailable",
                None,
            )?,
            PcdReject::EpochUnavailable => self.padded_problem(
                phase,
                PsiClassBProblemType::PolicyDenied,
                "private contact discovery epoch is not available",
                None,
            )?,
            PcdReject::InvalidConfiguration
            | PcdReject::FixedBatchCardinality
            | PcdReject::PinnedEpochMismatch
            | PcdReject::BlindOutcomePending
            | PcdReject::InvalidOutcome => return Ok(None),
            PcdReject::OutcomeConflict | PcdReject::LeaseLost => {
                return Err(PcdError::Rejected(rejection));
            }
        };
        Ok(Some(response))
    }
}

impl PrivateContactDiscoveryCustody {
    fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)
            .map_err(|error| anyhow::anyhow!("failed to read PCD KMS manifest: {error}"))?;
        let manifest: CustodyManifest = serde_json::from_slice(&bytes)
            .map_err(|error| anyhow::anyhow!("invalid PCD KMS manifest: {error}"))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        let mut by_public_key = HashMap::new();
        for entry in manifest.keys {
            if !entry.custody_key_ref.starts_with("kms://") || entry.custody_key_ref.len() > 512 {
                anyhow::bail!("invalid PCD KMS custody_key_ref");
            }
            let key_path = if entry.private_key_file.is_absolute() {
                entry.private_key_file
            } else {
                base.join(entry.private_key_file)
            };
            let mut encoded = std::fs::read(&key_path).map_err(|error| {
                anyhow::anyhow!(
                    "failed to read KMS-projected PCD key {}: {error}",
                    key_path.display()
                )
            })?;
            let encoded_str = std::str::from_utf8(&encoded)
                .map_err(|_| anyhow::anyhow!("KMS-projected PCD key must be base64url text"))?
                .trim();
            let mut private_key =
                arkret_sdk::canonical::base64url_decode(encoded_str).map_err(|_| {
                    anyhow::anyhow!("KMS-projected PCD key must be canonical base64url")
                })?;
            if private_key.len() != 32
                || arkret_sdk::canonical::base64url_encode(&private_key) != encoded_str
            {
                private_key.fill(0);
                encoded.fill(0);
                anyhow::bail!("KMS-projected PCD key must encode exactly 32 bytes");
            }
            let server = VoprfServer::<Ristretto255>::new_with_key(&private_key);
            private_key.fill(0);
            encoded.fill(0);
            let server = server
                .map_err(|error| anyhow::anyhow!("invalid KMS-projected PCD scalar: {error}"))?;
            let public_key: [u8; 32] = Ristretto255::serialize_elem(server.get_public_key())
                .as_slice()
                .try_into()
                .expect("ristretto255 public key is 32 bytes");
            if by_public_key
                .insert(
                    public_key,
                    CustodyKey {
                        custody_key_ref: entry.custody_key_ref,
                        server,
                    },
                )
                .is_some()
            {
                anyhow::bail!("PCD KMS manifest repeats a public key");
            }
        }
        if by_public_key.is_empty() {
            anyhow::bail!("PCD KMS manifest must contain at least one retained key");
        }
        Ok(Self { by_public_key })
    }

    fn evaluate_blind(
        &self,
        request: &DirectoryPrivateContactDiscoveryRequestBody,
        elements: &[PsiRistretto255Element],
        configuration: &PrivateContactDiscovery,
    ) -> Result<DirectoryPrivateContactDiscoveryOutcome, PcdError> {
        let public_key = decode_exact::<32>(&configuration.public_key, "PCD public key")
            .map_err(|error| PcdError::Storage(error.to_string()))?;
        let server = self
            .by_public_key
            .get(&public_key)
            .ok_or(PcdReject::EpochUnavailable)?;
        let blinded = elements
            .iter()
            .map(|element| {
                let bytes = decode_exact::<32>(element.as_str(), "PSI blinded element")
                    .map_err(|error| PcdError::Storage(error.to_string()))?;
                BlindedElement::<Ristretto255>::deserialize(&bytes)
                    .map_err(|error| PcdError::Storage(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let evaluated = server
            .server
            // voprf 0.6.0-pre.1 still implements the rand_core 0.9 traits.
            .batch_blind_evaluate(&mut rand_09::rng(), &blinded)
            .map_err(|error| PcdError::Storage(error.to_string()))?;
        let evaluated_elements = evaluated
            .messages
            .iter()
            .map(|element| {
                PsiRistretto255Element::new(URL_SAFE_NO_PAD.encode(element.serialize()))
                    .map_err(|error| PcdError::Storage(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let proof = PsiVoprfProof::new(URL_SAFE_NO_PAD.encode(evaluated.proof.serialize()))
            .map_err(|error| PcdError::Storage(error.to_string()))?;
        Ok(DirectoryPrivateContactDiscoveryOutcome::Blind {
            profile: request.profile(),
            batch_id: request.batch_id().clone(),
            ciphersuite: arkret_sdk::PrivateContactDiscovery::CIPHERSUITE,
            key_epoch: configuration.key_epoch,
            evaluated_elements,
            evaluation_proofs: [proof],
            derived_prefix_bytes: arkret_sdk::PrivateContactDiscovery::DERIVED_PREFIX_BYTES,
            padding: PsiResponsePadding::default(),
        })
    }
}

fn load_index_manifest(
    runtime: &PrivateContactDiscoveryRuntimeConfig,
    path: &Path,
) -> anyhow::Result<(IndexManifest, Vec<PcdIndexEntry>, [u8; 32])> {
    let bytes = std::fs::read(path)
        .map_err(|error| anyhow::anyhow!("failed to read PCD index manifest: {error}"))?;
    let manifest: IndexManifest = serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid PCD index manifest: {error}"))?;
    if manifest.key_epoch != runtime.describe.key_epoch
        || manifest.generation.is_empty()
        || manifest.generation.len() > 256
    {
        anyhow::bail!("PCD index manifest epoch/generation does not match the described epoch");
    }
    let mut seen = HashSet::new();
    let entries = manifest
        .entries
        .iter()
        .map(|entry| {
            let derived_prefix =
                decode_exact::<16>(entry.derived_prefix.as_str(), "PCD index derived prefix")?;
            if !seen.insert(derived_prefix) {
                anyhow::bail!("PCD index manifest contains a duplicate derived prefix");
            }
            match runtime.describe.handoff_stubs_mode {
                PrivateContactDiscoveryHandoffStubsMode::Always if entry.handoff_stub.is_none() => {
                    anyhow::bail!(
                        "PCD handoff_stubs_mode=always requires a stub for every index entry"
                    );
                }
                PrivateContactDiscoveryHandoffStubsMode::Never if entry.handoff_stub.is_some() => {
                    anyhow::bail!("PCD handoff_stubs_mode=never forbids index handoff stubs");
                }
                _ => {}
            }
            Ok(PcdIndexEntry {
                derived_prefix,
                handoff_stub: entry.handoff_stub.clone(),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let canonical = arkret_sdk::canonical::canonical_json_bytes(&manifest)
        .map_err(|error| anyhow::anyhow!("cannot canonicalize PCD index manifest: {error}"))?;
    let digest = Sha256::digest(canonical).into();
    Ok((manifest, entries, digest))
}

fn validated_outcome_bytes(
    outcome: DirectoryPrivateContactDiscoveryOutcome,
    request: &DirectoryPrivateContactDiscoveryRequestBody,
    configuration: &PrivateContactDiscovery,
) -> Result<Vec<u8>, PcdError> {
    let outcome = outcome
        .pad_to_advertised_bucket(configuration)
        .map_err(|error| PcdError::Storage(error.to_string()))?;
    outcome
        .validate_against_request(request, configuration)
        .map_err(|error| PcdError::Storage(error.to_string()))?;
    arkret_sdk::canonical::canonical_json_bytes(&outcome)
        .map_err(|error| PcdError::Storage(error.to_string()))
}

fn success_response(phase: PsiResponsePhase, body: Vec<u8>) -> PcdHttpResponse {
    let _ = phase;
    PcdHttpResponse {
        status: StatusCode::OK,
        content_type: "application/json",
        body,
        retry_after_seconds: None,
    }
}

fn decode_exact<const N: usize>(value: &str, label: &str) -> anyhow::Result<[u8; N]> {
    let decoded = arkret_sdk::canonical::base64url_decode(value)
        .map_err(|_| anyhow::anyhow!("{label} must be canonical base64url"))?;
    if decoded.len() != N || arkret_sdk::canonical::base64url_encode(&decoded) != value {
        anyhow::bail!("{label} must encode exactly {N} bytes");
    }
    Ok(decoded.try_into().expect("decoded length checked"))
}

fn random_lease_owner() -> [u8; 32] {
    let mut owner = [0_u8; 32];
    rand::rng().fill(&mut owner);
    owner
}

fn response_phase(request: &DirectoryPrivateContactDiscoveryRequestBody) -> PsiResponsePhase {
    match request {
        DirectoryPrivateContactDiscoveryRequestBody::Blind { .. } => PsiResponsePhase::Blind,
        DirectoryPrivateContactDiscoveryRequestBody::Match { .. } => PsiResponsePhase::Match,
    }
}

async fn apply_anti_enumeration_delay(
    configuration: &PrivateContactDiscovery,
    started_at: tokio::time::Instant,
) {
    let jitter = rand::rng().random_range(0..=configuration.anti_enumeration_delay.jitter_ms);
    let target = Duration::from_millis(u64::from(
        configuration.anti_enumeration_delay.minimum_ms + jitter,
    ));
    if let Some(remaining) = target.checked_sub(started_at.elapsed()) {
        sleep(remaining).await;
    }
}

fn render_pcd_response(response: PcdHttpResponse, res: &mut Response) {
    res.status_code(response.status);
    let headers = res.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(response.content_type),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-transform"),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&response.body.len().to_string())
            .expect("response bucket length is a valid header"),
    );
    headers.remove(header::CONTENT_ENCODING);
    if let Some(seconds) = response.retry_after_seconds {
        headers.insert(
            header::RETRY_AFTER,
            HeaderValue::from_str(&seconds.to_string()).expect("retry-after is an integer"),
        );
    }
    res.body(response.body);
}

#[handler]
pub async fn private_contact_discovery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = match depot.get_typed::<AppState>() {
        Ok(state) => state.clone(),
        Err(_) => {
            crate::error::ApiErrorCode::InternalError.render(res, "AppState missing");
            return;
        }
    };
    let Some(service) = state.private_contact_discovery() else {
        crate::error::ApiErrorCode::UnsupportedFeature
            .render(res, "private contact discovery is not active");
        return;
    };
    let device = match service.authenticate(req) {
        Ok(device) => device,
        Err(()) => {
            crate::error::ApiErrorCode::Unauthenticated
                .render(res, "authenticated device credential required");
            return;
        }
    };
    let request: DirectoryPrivateContactDiscoveryRequestBody = match req.parse_json().await {
        Ok(request) => request,
        Err(_) => {
            crate::error::ApiErrorCode::JsonInvalid.render(res, "invalid closed PCD JSON body");
            return;
        }
    };
    let phase = response_phase(&request);
    let started_at = tokio::time::Instant::now();
    let response = match service.process(device, request).await {
        Ok(response) => response,
        Err(PcdError::Rejected(rejection)) => match service.rejected_response(phase, rejection) {
            Ok(Some(response)) => response,
            Ok(None) => {
                crate::error::ApiErrorCode::SchemaViolation
                    .render(res, "PCD request does not match the pinned configuration");
                return;
            }
            Err(error) => {
                tracing::error!(%error, "failed to construct padded PCD rejection");
                crate::error::ApiErrorCode::InternalError.render(res, "PCD response failed");
                return;
            }
        },
        Err(error) => {
            tracing::error!(%error, "PCD request failed");
            crate::error::ApiErrorCode::InternalError.render(res, "PCD request failed");
            return;
        }
    };
    apply_anti_enumeration_delay(service.configuration(), started_at).await;
    render_pcd_response(response, res);
}
