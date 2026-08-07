//! Process-wide shared state injected via salvo affix-state.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arkret_rate_limit::{FixedWindowConfig, MemoryFixedWindowRateLimiter};
use chrono::{DateTime, Utc};

use crate::config::AppConfig;
use crate::db::Db;
use crate::did_binding::DidBindingDirectory;
use crate::did_resolver::SharedDidResolver;
use crate::observability::Metrics;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    config: AppConfig,
    db: Db,
    /// DID-P0-C01 — the one DID resolver for this process. Built here at
    /// startup from the `AppConfig` snapshot; request paths borrow it and
    /// never rebuild a resolver or a `reqwest::Client`.
    did_resolver: Arc<SharedDidResolver>,
    /// DID-P0-C02/C03 — the zero-network acceptance directory, shared with (and
    /// written by) `did_resolver`. This is what the query / filter face gets:
    /// it owns no resolver, so a query handler cannot express a network
    /// resolution at all.
    did_bindings: Arc<DidBindingDirectory>,
    cursor_authority: arkret_server::MemoryCursorAuthority,
    rate_limiter: RateLimiter,
    announce_replay_cache: AnnounceReplayCache,
    metrics: Metrics,
    workers: WorkerRuntime,
}

impl AppState {
    /// Build the process state.
    ///
    /// Returns `Err` when the DID resolver chain cannot be constructed (bad
    /// TLS/DNS setup, unusable egress policy). This is deliberately a
    /// **startup** failure surfaced to `main::run`: the alternative designs
    /// (store a `Result`/`OnceLock` in `Inner` and fail at the first request)
    /// would turn a misconfigured deployment into a service that boots green,
    /// answers `/readyz`, and then rejects every signed ingest with a 500. A
    /// resolver that cannot be built is a configuration error, and
    /// configuration errors belong at boot.
    pub fn new(config: AppConfig, db: Db) -> anyhow::Result<Self> {
        let workers = WorkerRuntime::from_config(&config);
        // Built before the resolver so the DID counters land on the same
        // `Metrics` instance `/metrics` renders.
        let metrics = Metrics::default();
        // The egress decision is taken once, here, from the config snapshot —
        // never recomputed per request and never widened by a caller.
        let did_resolver = SharedDidResolver::with_metrics(
            &config.accepted_did_methods,
            config.development_mode,
            &config.service_id,
            metrics.clone(),
        )
        .map_err(|error| anyhow::anyhow!("DID resolver init failed: {error}"))?;
        let did_bindings = Arc::clone(did_resolver.bindings());
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                db,
                did_resolver: Arc::new(did_resolver),
                did_bindings,
                cursor_authority: arkret_server::MemoryCursorAuthority::default(),
                rate_limiter: RateLimiter::default(),
                announce_replay_cache: AnnounceReplayCache::default(),
                metrics,
                workers,
            }),
        })
    }

    pub fn config(&self) -> &AppConfig {
        &self.inner.config
    }

    /// The shared DID **authority** handle. Only the ingest face and the RFC
    /// 9421 HTTP-signature middleware may hold it: those are the two surfaces
    /// that can name a `did-usage-and-verification.md` §4 trigger row.
    ///
    /// Even so, this handle exposes no resolver — see
    /// [`crate::did_resolver::SharedDidResolver`].
    pub fn did_resolver(&self) -> &Arc<SharedDidResolver> {
        &self.inner.did_resolver
    }

    /// The zero-network accepted-binding directory — the handle every
    /// directory **query** / filter path gets.
    ///
    /// DID-P0-C03: `DidBindingDirectory` has no resolver field and no resolver
    /// accessor, so "this query handler resolved a DID online" is not
    /// expressible from here. Unknown issuers fail closed and collapse into the
    /// existing blinded `not_found`, which is also what keeps the
    /// anti-enumeration behaviour unchanged.
    pub fn did_bindings(&self) -> &Arc<DidBindingDirectory> {
        &self.inner.did_bindings
    }

    pub fn db(&self) -> &Db {
        &self.inner.db
    }

    pub fn cursor_authority(&self) -> &arkret_server::MemoryCursorAuthority {
        &self.inner.cursor_authority
    }

    pub fn metrics(&self) -> &Metrics {
        &self.inner.metrics
    }

    pub fn check_rate_limit(&self, key: impl Into<String>, max_requests: u32) -> RateLimitOutcome {
        self.inner
            .rate_limiter
            .check(key.into(), max_requests, Duration::from_secs(60))
    }

    /// Round R2/R3 T14 — look up the federation idempotency cache by the
    /// extended four-field key. `digest` is SHA-256 over `(request_digest
    /// || source_service_id || verification_method ||
    /// service_binding_ref || origin_key_state_digest)`.
    pub fn cached_federation_replay(&self, key: &[u8]) -> Option<CachedDirectoryAnnounceOutcome> {
        self.inner.announce_replay_cache.get(key)
    }

    pub fn remember_federation_replay(
        &self,
        key: Vec<u8>,
        response: CachedDirectoryAnnounceOutcome,
    ) {
        self.inner.announce_replay_cache.put(key, response);
    }

    pub fn worker_started(&self, worker: BackgroundWorker, period: Duration) {
        self.inner.workers.started(worker, period);
    }

    pub fn worker_heartbeat(&self, worker: BackgroundWorker) {
        self.inner.workers.heartbeat(worker);
    }

    pub fn worker_readiness(&self, worker: BackgroundWorker) -> WorkerReadiness {
        self.inner.workers.readiness(worker)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackgroundWorker {
    Divergence,
}

#[derive(Debug, Clone, Copy)]
pub struct WorkerReadiness {
    pub enabled: bool,
    pub ready: bool,
    pub last_seen_ms_ago: Option<u128>,
    pub stale_after_ms: Option<u128>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitOutcome {
    Allowed,
    Limited { retry_after: Duration },
}

struct RateLimiter {
    inner: MemoryFixedWindowRateLimiter<String>,
}

#[derive(Debug, Clone)]
pub struct CachedDirectoryAnnounceOutcome {
    pub announce_id: String,
    pub indexed_at: DateTime<Utc>,
    pub effective_ttl_seconds: i64,
    pub next_revalidation_after: DateTime<Utc>,
}

#[derive(Default)]
struct AnnounceReplayCache {
    rows: Mutex<HashMap<Vec<u8>, CachedAnnounceCacheRow>>,
}

struct CachedAnnounceCacheRow {
    response: CachedDirectoryAnnounceOutcome,
    inserted_at: Instant,
}

struct WorkerRuntime {
    divergence: Mutex<WorkerSlot>,
}

#[derive(Clone, Copy, Debug)]
struct WorkerSlot {
    enabled: bool,
    period: Option<Duration>,
    last_seen: Option<Instant>,
}

impl WorkerRuntime {
    fn from_config(config: &AppConfig) -> Self {
        Self {
            divergence: Mutex::new(WorkerSlot {
                enabled: config.divergence_interval.is_some(),
                period: config.divergence_interval,
                last_seen: None,
            }),
        }
    }

    fn started(&self, worker: BackgroundWorker, period: Duration) {
        let mut slot = self
            .slot(worker)
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        slot.enabled = true;
        slot.period = Some(period);
        slot.last_seen = Some(Instant::now());
    }

    fn heartbeat(&self, worker: BackgroundWorker) {
        let mut slot = self
            .slot(worker)
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot.enabled {
            slot.last_seen = Some(Instant::now());
        }
    }

    fn readiness(&self, worker: BackgroundWorker) -> WorkerReadiness {
        let slot = *self
            .slot(worker)
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !slot.enabled {
            return WorkerReadiness {
                enabled: false,
                ready: true,
                last_seen_ms_ago: None,
                stale_after_ms: None,
            };
        }

        let stale_after = stale_after_for(slot.period);
        let last_seen_ms_ago = slot
            .last_seen
            .map(|last_seen| last_seen.elapsed().as_millis());
        let ready = slot
            .last_seen
            .map(|last_seen| last_seen.elapsed() <= stale_after)
            .unwrap_or(false);
        WorkerReadiness {
            enabled: true,
            ready,
            last_seen_ms_ago,
            stale_after_ms: Some(stale_after.as_millis()),
        }
    }

    fn slot(&self, worker: BackgroundWorker) -> &Mutex<WorkerSlot> {
        match worker {
            BackgroundWorker::Divergence => &self.divergence,
        }
    }
}

fn stale_after_for(period: Option<Duration>) -> Duration {
    period
        .unwrap_or_else(|| Duration::from_secs(30))
        .saturating_mul(3)
        + Duration::from_secs(30)
}

impl AnnounceReplayCache {
    const MAX_ROWS: usize = 8192;
    const TTL: Duration = Duration::from_secs(600);

    fn get(&self, digest: &[u8]) -> Option<CachedDirectoryAnnounceOutcome> {
        let mut rows = self
            .rows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        match rows.get(digest) {
            Some(row) if now.duration_since(row.inserted_at) < Self::TTL => {
                Some(row.response.clone())
            }
            Some(_) => {
                rows.remove(digest);
                None
            }
            None => None,
        }
    }

    fn put(&self, digest: Vec<u8>, response: CachedDirectoryAnnounceOutcome) {
        let mut rows = self
            .rows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if rows.len() >= Self::MAX_ROWS {
            let now = Instant::now();
            rows.retain(|_, row| now.duration_since(row.inserted_at) < Self::TTL);
            while rows.len() >= Self::MAX_ROWS {
                let Some(oldest) = rows
                    .iter()
                    .min_by_key(|(_, row)| row.inserted_at)
                    .map(|(digest, _)| digest.clone())
                else {
                    break;
                };
                rows.remove(&oldest);
            }
        }
        rows.insert(
            digest,
            CachedAnnounceCacheRow {
                response,
                inserted_at: Instant::now(),
            },
        );
    }
}

impl RateLimiter {
    const MAX_BUCKETS: usize = 16_384;

    fn check(&self, key: String, max_requests: u32, window: Duration) -> RateLimitOutcome {
        match self.inner.check_with_config(
            key,
            FixedWindowConfig::new(u64::from(max_requests), window, Self::MAX_BUCKETS),
        ) {
            Ok(()) => RateLimitOutcome::Allowed,
            Err(rejection) => RateLimitOutcome::Limited {
                retry_after: rejection.retry_after,
            },
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            inner: MemoryFixedWindowRateLimiter::new(FixedWindowConfig::new(
                1,
                Duration::from_secs(60),
                Self::MAX_BUCKETS,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_reports_retry_for_exhausted_window() {
        let limiter = RateLimiter::default();
        assert_eq!(
            limiter.check("first".to_owned(), 1, Duration::from_secs(60)),
            RateLimitOutcome::Allowed
        );
        assert!(matches!(
            limiter.check("first".to_owned(), 1, Duration::from_secs(60)),
            RateLimitOutcome::Limited { retry_after } if retry_after > Duration::ZERO
        ));
    }
}
