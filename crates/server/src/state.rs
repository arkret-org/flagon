//! Process-wide shared state injected via salvo affix-state.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use crate::config::AppConfig;
use crate::db::Db;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    config: AppConfig,
    db: Db,
    rate_limiter: RateLimiter,
    announce_replay_cache: AnnounceReplayCache,
}

impl AppState {
    pub fn new(config: AppConfig, db: Db) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                db,
                rate_limiter: RateLimiter::default(),
                announce_replay_cache: AnnounceReplayCache::default(),
            }),
        }
    }

    pub fn config(&self) -> &AppConfig {
        &self.inner.config
    }

    pub fn db(&self) -> &Db {
        &self.inner.db
    }

    pub fn check_rate_limit(&self, key: impl Into<String>, max_requests: u32) -> RateLimitOutcome {
        self.inner
            .rate_limiter
            .check(key.into(), max_requests, Duration::from_secs(60))
    }

    pub fn cached_announce_replay(&self, digest: &[u8]) -> Option<CachedAnnounceResponse> {
        self.inner.announce_replay_cache.get(digest)
    }

    pub fn remember_announce_replay(&self, digest: Vec<u8>, response: CachedAnnounceResponse) {
        self.inner.announce_replay_cache.put(digest, response);
    }

    /// Round R2/R3 T14 — look up the federation idempotency cache by the
    /// extended four-field key. `digest` is SHA-256 over `(request_digest
    /// || source_service_did || verification_method ||
    /// service_binding_ref || origin_key_state_digest)`.
    pub fn cached_federation_replay(&self, key: &[u8]) -> Option<CachedAnnounceResponse> {
        self.inner.announce_replay_cache.get(key)
    }

    pub fn remember_federation_replay(&self, key: Vec<u8>, response: CachedAnnounceResponse) {
        self.inner.announce_replay_cache.put(key, response);
    }
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
pub struct CachedAnnounceResponse {
    pub announce_id: String,
    pub indexed_at: DateTime<Utc>,
    pub effective_ttl_seconds: i64,
    pub next_revalidation_after: DateTime<Utc>,
    /// Round R2/R3 T14 — the cached response was produced by a replay
    /// path. On a subsequent cache hit *after* the underlying service
    /// key was revoked, the announce handler MUST re-do the capability
    /// check and, if it fails, serve this row with `historical_only=true`
    /// and skip side effects.
    #[allow(dead_code)] // populated on the federation replay path; read by handlers.
    pub historical_only: bool,
}

#[derive(Default)]
struct AnnounceReplayCache {
    rows: Mutex<HashMap<Vec<u8>, CachedAnnounceCacheRow>>,
}

struct CachedAnnounceCacheRow {
    response: CachedAnnounceResponse,
    inserted_at: Instant,
}

impl AnnounceReplayCache {
    fn get(&self, digest: &[u8]) -> Option<CachedAnnounceResponse> {
        let mut rows = self.rows.lock().expect("announce replay cache lock");
        let now = Instant::now();
        rows.retain(|_, row| now.duration_since(row.inserted_at) < Duration::from_secs(600));
        rows.get(digest).map(|row| row.response.clone())
    }

    fn put(&self, digest: Vec<u8>, response: CachedAnnounceResponse) {
        let mut rows = self.rows.lock().expect("announce replay cache lock");
        if rows.len() > 8192 {
            let now = Instant::now();
            rows.retain(|_, row| now.duration_since(row.inserted_at) < Duration::from_secs(600));
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

        let mut buckets = self.buckets.lock().expect("rate limiter lock");
        let now = Instant::now();
        buckets.retain(|_, bucket| now.duration_since(bucket.window_start) < window);

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
