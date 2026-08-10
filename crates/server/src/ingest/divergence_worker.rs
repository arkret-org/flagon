//! Cross-directory divergence detector scaffold.
//!
//! `directory_resources.via_services` contains stable service core ids, never
//! transport locators. Teabay currently has no persisted, independently
//! verified `ServiceResolutionCarrier` for those optional peer directories, so
//! this worker deliberately performs no outbound request. In particular it
//! must not parse a DID/core id as a URL, derive a host from one, or accept a
//! legacy URL stored in `via_services` as authority.
//!
//! Configuration rejects enabling this scaffold until the route input can be
//! a freshly fetched and verified current service-resolution record.

use std::time::Duration;

use tokio::time::interval;
use tracing::{info, warn};

use crate::state::{AppState, BackgroundWorker};

pub struct DivergenceWorker {
    state: AppState,
    period: Duration,
}

impl DivergenceWorker {
    pub fn new(state: AppState, period: Duration) -> Self {
        Self { state, period }
    }

    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            self.state
                .worker_started(BackgroundWorker::Divergence, self.period);
            info!(
                period_seconds = self.period.as_secs(),
                "teabay divergence worker scaffold started"
            );
            let mut tick = interval(self.period);
            loop {
                tick.tick().await;
                self.state.worker_heartbeat(BackgroundWorker::Divergence);
                warn!(
                    "divergence check skipped: no verified peer service-resolution carrier is configured"
                );
            }
        })
    }
}
