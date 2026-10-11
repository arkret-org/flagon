//! Read-only Realm query metrics. Retired ingest, PCD, and handle-series are
//! not emitted, so the Prometheus surface matches the mounted operations.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const QUERY_OPS: &[&str] = &["search-realms", "resolve-realm"];

#[derive(Clone, Default)]
pub struct Metrics {
    query_latency: Arc<Mutex<BTreeMap<&'static str, QueryLatencyStats>>>,
}

#[derive(Clone, Copy, Default)]
struct QueryLatencyStats {
    last_seconds: f64,
    sum_seconds: f64,
    count: u64,
}

impl Metrics {
    pub fn query_timer(&self, op: &'static str) -> QueryTimer {
        QueryTimer {
            metrics: self.clone(),
            op,
            started_at: Instant::now(),
        }
    }

    fn record_query_latency(&self, op: &'static str, elapsed: Duration) {
        let mut rows = self
            .query_latency
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let stats = rows.entry(op).or_default();
        let seconds = elapsed.as_secs_f64();
        stats.last_seconds = seconds;
        stats.sum_seconds += seconds;
        stats.count += 1;
    }

    pub fn render_prometheus(&self) -> String {
        let rows = self
            .query_latency
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut out = String::from(
            "# HELP flagon_query_latency_seconds Last observed Realm query latency by operation.\n\
             # TYPE flagon_query_latency_seconds gauge\n",
        );
        for op in QUERY_OPS {
            let stats = rows.get(op).copied().unwrap_or_default();
            out.push_str(&format!(
                "flagon_query_latency_seconds{{op=\"{op}\"}} {:.6}\n\
                 flagon_query_latency_seconds_count{{op=\"{op}\"}} {}\n\
                 flagon_query_latency_seconds_sum{{op=\"{op}\"}} {:.6}\n",
                stats.last_seconds, stats.count, stats.sum_seconds,
            ));
        }
        out
    }
}

pub struct QueryTimer {
    metrics: Metrics,
    op: &'static str,
    started_at: Instant,
}

impl Drop for QueryTimer {
    fn drop(&mut self) {
        self.metrics
            .record_query_latency(self.op, self.started_at.elapsed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_mounted_realm_queries_are_exposed() {
        let metrics = Metrics::default();
        {
            let _timer = metrics.query_timer("search-realms");
        }
        let body = metrics.render_prometheus();
        assert!(body.contains("op=\"search-realms\""));
        assert!(body.contains("op=\"resolve-realm\""));
        assert!(!body.contains("resolve-handle"));
        assert!(!body.contains("flagon_ingest_total"));
    }
}
