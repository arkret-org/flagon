//! Process-wide shared state injected via salvo affix-state.

use std::sync::Arc;
use std::time::Duration;

use arkret_rate_limit::{FixedWindowConfig, MemoryFixedWindowRateLimiter};
use arkret_sdk::DidCoreId;

use crate::config::AppConfig;
use crate::db::Db;
use crate::observability::Metrics;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    config: AppConfig,
    service_core_id: DidCoreId,
    db: Db,
    cursor_authority: arkret_server::MemoryCursorAuthority,
    rate_limiter: RateLimiter,
    metrics: Metrics,
}

impl AppState {
    /// Build the process state.
    ///
    /// The read-only service has no outbound DID resolution or write
    /// admission at startup.
    pub fn new(config: AppConfig, db: Db) -> anyhow::Result<Self> {
        let service_core_id = config.service_id.clone();
        let metrics = Metrics::default();
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                service_core_id,
                db,
                cursor_authority: arkret_server::MemoryCursorAuthority::default(),
                rate_limiter: RateLimiter::default(),
                metrics,
            }),
        })
    }

    pub fn config(&self) -> &AppConfig {
        &self.inner.config
    }

    pub fn service_core_id(&self) -> &DidCoreId {
        &self.inner.service_core_id
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

    pub fn check_rate_limit(
        &self,
        key: impl Into<String>,
        max_request_count: u32,
    ) -> RateLimitOutcome {
        self.inner
            .rate_limiter
            .check(key.into(), max_request_count, Duration::from_secs(60))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitOutcome {
    Allowed,
    Limited { retry_after: Duration },
}

struct RateLimiter {
    inner: MemoryFixedWindowRateLimiter<String>,
}

impl RateLimiter {
    const MAX_BUCKETS: usize = 16_384;

    fn check(&self, key: String, max_request_count: u32, window: Duration) -> RateLimitOutcome {
        match self.inner.check_with_config(
            key,
            FixedWindowConfig::new(u64::from(max_request_count), window, Self::MAX_BUCKETS),
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
