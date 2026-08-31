//! Bounded-retention worker for completed and abandoned PCD state.

use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::warn;

use crate::pcd::PrivateContactDiscoveryService;

pub struct PrivateContactDiscoveryGarbageCollector {
    service: PrivateContactDiscoveryService,
    period: Duration,
}

impl PrivateContactDiscoveryGarbageCollector {
    pub fn new(service: PrivateContactDiscoveryService, period: Duration) -> Self {
        Self { service, period }
    }

    pub fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if let Err(error) = self.service.garbage_collect().await {
                    warn!(%error, "PCD bounded-retention sweep failed");
                }
            }
        })
    }
}
