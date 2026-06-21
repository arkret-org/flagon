//! Process-wide shared state injected via salvo affix-state.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use crate::config::AppConfig;
use crate::db::Db;
use crate::observability::Metrics;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    config: AppConfig,
    db: Db,
    rate_limiter: RateLimiter,
    announce_replay_cache: AnnounceReplayCache,
    metrics: Metrics,
    workers: WorkerRuntime,
}

impl AppState {
    pub fn new(config: AppConfig, db: Db) -> Self {
        let workers = WorkerRuntime::from_config(&config);
        Self {
            inner: Arc::new(Inner {
                config,
                db,
                rate_limiter: RateLimiter::default(),
                announce_replay_cache: AnnounceReplayCache::default(),
                metrics: Metrics::default(),
                workers,
            }),
        }
    }

    pub fn config(&self) -> &AppConfig {
        &self.inner.config
    }

    pub fn db(&self) -> &Db {
        &self.inner.db
    }

    pub fn metrics(&self) -> &Metrics {
        &self.inner.metrics
    }

    pub fn check_rate_limit(&self, key: impl Into<String>, max_requests: u32) -> RateLimitOutcome {
        self.inner
            .rate_limiter
            .check(key.into(), max_requests, Duration::from_secs(60))
    }

    /// Rate-limit check with a caller-supplied window. Used by the PSI
    /// anti-enumeration quota (spec §6.4), whose `quota window` is a fixed
    /// 24h roll (decoupled from the OPRF key epoch) rather than the 60s
    /// query-face window.
    pub fn check_rate_limit_window(
        &self,
        key: impl Into<String>,
        max_requests: u32,
        window: Duration,
    ) -> RateLimitOutcome {
        self.inner
            .rate_limiter
            .check(key.into(), max_requests, window)
    }

    pub fn cached_announce_replay(&self, digest: &[u8]) -> Option<CachedDirectoryAnnounceOutcome> {
        self.inner.announce_replay_cache.get(digest)
    }

    pub fn remember_announce_replay(
        &self,
        digest: Vec<u8>,
        response: CachedDirectoryAnnounceOutcome,
    ) {
        self.inner.announce_replay_cache.put(digest, response);
    }

    /// Round R2/R3 T14 — look up the federation idempotency cache by the
    /// extended four-field key. `digest` is SHA-256 over `(request_digest
    /// || source_service_did || verification_method ||
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
    Pull,
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

#[derive(Default)]
struct RateLimiter {
    buckets: Mutex<HashMap<String, RateBucket>>,
}

struct RateBucket {
    count: u32,
    window_start: Instant,
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
    pull: Mutex<WorkerSlot>,
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
            pull: Mutex::new(WorkerSlot {
                enabled: config.pull_interval.is_some(),
                period: config.pull_interval,
                last_seen: None,
            }),
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
            BackgroundWorker::Pull => &self.pull,
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
    fn check(&self, key: String, max_requests: u32, window: Duration) -> RateLimitOutcome {
        if max_requests == 0 {
            return RateLimitOutcome::Limited {
                retry_after: window,
            };
        }

        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();

        match buckets.get_mut(&key) {
            Some(bucket) if now.duration_since(bucket.window_start) < window => {
                if bucket.count >= max_requests {
                    let retry_after = window
                        .checked_sub(now.duration_since(bucket.window_start))
                        .unwrap_or_else(|| Duration::from_secs(1));
                    RateLimitOutcome::Limited { retry_after }
                } else {
                    bucket.count += 1;
                    RateLimitOutcome::Allowed
                }
            }
            _ => {
                buckets.insert(
                    key,
                    RateBucket {
                        count: 1,
                        window_start: now,
                    },
                );
                RateLimitOutcome::Allowed
            }
        }
    }
}
