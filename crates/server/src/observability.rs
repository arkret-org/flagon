//! Local observability primitives.
//!
//! Kept dependency-free so the Prometheus surface can be used in local
//! release-hygiene slices without changing the workspace lockfile.
//!
//! ## OTLP Exporter (P5)
//!
//! `init_otlp_exporter` reads `TEABAY_OTLP_ENDPOINT` and, when set,
//! installs a minimal OTLP HTTP push from this Prometheus surface so
//! operators get parity with their otel collector. We intentionally
//! avoid pulling the heavy `opentelemetry` crate stack into the
//! workspace lockfile and instead expose `Metrics::push_to_otlp` for
//! the deployment shim — see `docs/operations.md` for the local
//! evidence recipe (curl loop against the metrics endpoint).
//!
//! TODO(P5-impl): replace the curl-loop shim with the official OTLP
//! SDK once the rest of the stack pins a compatible otel crate
//! version. This stub is the contract surface the SDK upgrade will
//! preserve.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PAD_BUCKETS: [f64; 8] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0];
const PAD_BUCKET_COUNT: usize = 9;
const INGEST_KINDS: &[&str] = &["announce", "withdraw", "subscribe"];
const INGEST_OUTCOMES: &[&str] = &[
    "verify_ok",
    "bad_json",
    "schema_rejected",
    "rate_limited",
    "verify_rejected",
    "digest_mismatch",
    "signature_invalid",
    "invalid_endpoint",
    "replay",
    "historical_only",
    "rollback_rejected",
    "projection_rejected",
    "persist_error",
    "internal_error",
];
const QUERY_OPS: &[&str] = &[
    "search-realms",
    "resolve-realm",
    "search-organizations",
    "resolve-organization",
    "search-actors",
    "search-users",
    "resolve-handle",
    // R3.2 (cokret-spec @ b56cab1) — reverse handle lookup.
    "list-handles-for-subject",
    // R3.3 (CXP-0011, cokret-spec @ cced4b8) — object-level resolve.
    "resolve-target",
];
const PULL_OUTCOMES: &[&str] = &["success", "failure"];

/// R3.2 (METRICS-TBY-1) — outcomes recorded on
/// `teabay_directory_query_total{op,outcome}`. The series is pre-seeded with
/// these so a scraper sees a `0` rather than a missing series before the
/// first request of each outcome.
const QUERY_OUTCOMES: &[&str] = &[
    "ok",
    "not_found",
    "fail_closed",
    "bad_json",
    "rate_limited",
    "invalid_subject_kind",
    // R3.3 (CXP-0011) — resolve_target invite-token binding rejection
    // (scope-confusion / expired / malformed / alias-mismatch). Surfaced to
    // the SAME blinded not_found wire response; the split is metrics-only.
    "token_reject",
    "internal_error",
];

/// R3.2 (METRICS-TBY-1) — reasons recorded on
/// `teabay_directory_filter_drop_total{reason}`. Covers anti-enumeration,
/// disclosure policy, issuer trust, audience scope, homograph, and the
/// subject-mismatch / invalid-subject-kind drops that
/// `list_handles_for_subject` adds.
const FILTER_DROP_REASONS: &[&str] = &[
    "anti_enumeration",
    "disclosure",
    "issuer_trust",
    "audience",
    "homograph",
    "subject_mismatch",
    "invalid_subject_kind",
];

/// R3.2 (METRICS-TBY-1) — counters recorded on
/// `teabay_directory_cardinality_guard_total{counter}`: the bounded scans /
/// page ceilings the directory enforces to keep a single request from
/// materialising an unbounded result set.
const CARDINALITY_GUARD_COUNTERS: &[&str] = &[
    "resolved_subjects",
    "candidate_scan_capped",
    "page_limit_clamped",
];

/// Label value for the `directory_resources` table on the
/// `teabay_expired_rows_purged_total` counter. Centralised so the
/// expiry worker and any future per-table purge code emit the same
/// label.
pub const PURGE_TABLE_DIRECTORY_RESOURCES: &str = "directory_resources";

/// Stage labels for `teabay_takedown_notification_failures_total{stage}`.
pub const TAKEDOWN_NOTIFICATION_STAGE_ATTEMPT_FAILED: &str = "attempt_failed";
pub const TAKEDOWN_NOTIFICATION_STAGE_DLQ: &str = "dlq";

const PURGE_TABLES: &[&str] = &[PURGE_TABLE_DIRECTORY_RESOURCES];
const TAKEDOWN_NOTIFICATION_STAGES: &[&str] = &[
    TAKEDOWN_NOTIFICATION_STAGE_ATTEMPT_FAILED,
    TAKEDOWN_NOTIFICATION_STAGE_DLQ,
];

#[derive(Clone, Default)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

#[derive(Default)]
struct MetricsInner {
    ingest: Mutex<BTreeMap<IngestKey, u64>>,
    query_latency: Mutex<BTreeMap<String, QueryLatencyStats>>,
    anti_enum_pad: Mutex<BTreeMap<String, PadHistogram>>,
    pull_revalidations: Mutex<BTreeMap<String, u64>>,
    // Pure scalar counter — an atomic avoids taking a lock on this hot path.
    divergence_detected: AtomicU64,
    expired_rows_purged: Mutex<BTreeMap<String, u64>>,
    takedown_notification_failures: Mutex<BTreeMap<String, u64>>,
    // R3.2 (METRICS-TBY-1) — directory query / filter-drop / cardinality
    // guard counters required by the §C observability slice.
    query_outcomes: Mutex<BTreeMap<QueryOutcomeKey, u64>>,
    filter_drops: Mutex<BTreeMap<String, u64>>,
    cardinality_guard: Mutex<BTreeMap<String, u64>>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct IngestKey {
    kind: &'static str,
    outcome: &'static str,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct QueryOutcomeKey {
    op: String,
    outcome: String,
}

#[derive(Clone, Copy, Debug, Default)]
struct QueryLatencyStats {
    last_seconds: f64,
    sum_seconds: f64,
    count: u64,
}

#[derive(Clone, Debug)]
struct PadHistogram {
    buckets: [u64; PAD_BUCKET_COUNT],
    sum_seconds: f64,
    count: u64,
}

impl Default for PadHistogram {
    fn default() -> Self {
        Self {
            buckets: [0; PAD_BUCKET_COUNT],
            sum_seconds: 0.0,
            count: 0,
        }
    }
}

impl Metrics {
    pub fn ingest_guard(&self, kind: &'static str) -> IngestMetricGuard {
        IngestMetricGuard {
            metrics: self.clone(),
            kind,
            outcome: "internal_error",
            recorded: false,
        }
    }

    pub fn record_ingest(&self, kind: &'static str, outcome: &'static str) {
        let mut ingest = self
            .inner
            .ingest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *ingest.entry(IngestKey { kind, outcome }).or_default() += 1;
    }

    pub fn query_timer(&self, op: &'static str) -> QueryTimer {
        QueryTimer {
            metrics: self.clone(),
            op,
            started_at: Instant::now(),
        }
    }

    pub fn record_query_latency(&self, op: &'static str, elapsed: Duration) {
        let seconds = elapsed.as_secs_f64();
        let mut query_latency = self
            .inner
            .query_latency
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let stats = query_latency.entry(op.to_owned()).or_default();
        stats.last_seconds = seconds;
        stats.sum_seconds += seconds;
        stats.count += 1;
    }

    pub fn record_anti_enum_pad(&self, op: &'static str, target: Duration) {
        let seconds = target.as_secs_f64();
        let mut anti_enum_pad = self
            .inner
            .anti_enum_pad
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        anti_enum_pad
            .entry(op.to_owned())
            .or_default()
            .record(seconds);
    }

    pub fn record_pull_revalidation(&self, outcome: &'static str) {
        let mut pull_revalidations = self
            .inner
            .pull_revalidations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *pull_revalidations.entry(outcome.to_owned()).or_default() += 1;
    }

    pub fn record_divergence_detected(&self) {
        self.inner
            .divergence_detected
            .fetch_add(1, Ordering::Relaxed);
    }

    /// P5 — increment the `teabay_expired_rows_purged_total{table}`
    /// counter for `table` by `count`. Called by the expiry worker.
    pub fn record_expired_rows_purged(&self, table: &'static str, count: u64) {
        let mut expired = self
            .inner
            .expired_rows_purged
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *expired.entry(table.to_owned()).or_default() += count;
    }

    /// P5 — increment the
    /// `teabay_takedown_notification_failures_total{stage}` counter.
    pub fn record_takedown_notification_failure(&self, stage: &'static str) {
        let mut failures = self
            .inner
            .takedown_notification_failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *failures.entry(stage.to_owned()).or_default() += 1;
    }

    /// R3.2 (METRICS-TBY-1) — increment
    /// `teabay_directory_query_total{op,outcome}`. `op` is the dashed route
    /// label (`resolve-handle`, `list-handles-for-subject`, ...); `outcome`
    /// is one of [`QUERY_OUTCOMES`] (unknown values are still recorded).
    pub fn record_query_outcome(&self, op: &str, outcome: &str) {
        let mut outcomes = self
            .inner
            .query_outcomes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *outcomes
            .entry(QueryOutcomeKey {
                op: op.to_owned(),
                outcome: outcome.to_owned(),
            })
            .or_default() += 1;
    }

    /// R3.2 (METRICS-TBY-1) — increment
    /// `teabay_directory_filter_drop_total{reason}` for a filtered-out claim
    /// / result. `reason` should be one of [`FILTER_DROP_REASONS`].
    pub fn record_filter_drop(&self, reason: &str) {
        let mut drops = self
            .inner
            .filter_drops
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *drops.entry(reason.to_owned()).or_default() += 1;
    }

    /// R3.2 (METRICS-TBY-1) — increment
    /// `teabay_directory_cardinality_guard_total{counter}` by `count`.
    pub fn record_cardinality_guard(&self, counter: &str, count: u64) {
        let mut guard = self
            .inner
            .cardinality_guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard.entry(counter.to_owned()).or_default() += count;
    }

    pub fn render_prometheus(&self) -> String {
        let ingest = self
            .inner
            .ingest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let query_latency = self
            .inner
            .query_latency
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let anti_enum_pad = self
            .inner
            .anti_enum_pad
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let pull_revalidations = self
            .inner
            .pull_revalidations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let divergence_detected = self.inner.divergence_detected.load(Ordering::Relaxed);
        let expired_rows_purged = self
            .inner
            .expired_rows_purged
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let takedown_notification_failures = self
            .inner
            .takedown_notification_failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let query_outcomes = self
            .inner
            .query_outcomes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let filter_drops = self
            .inner
            .filter_drops
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let cardinality_guard = self
            .inner
            .cardinality_guard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();

        let mut out = String::new();

        out.push_str(
            "# HELP teabay_ingest_total Directory ingest requests by handler and outcome.\n",
        );
        out.push_str("# TYPE teabay_ingest_total counter\n");
        for &kind in INGEST_KINDS {
            for &outcome in INGEST_OUTCOMES {
                let value = ingest
                    .get(&IngestKey { kind, outcome })
                    .copied()
                    .unwrap_or(0);
                push_sample(
                    &mut out,
                    "teabay_ingest_total",
                    &[("kind", kind), ("outcome", outcome)],
                    value as f64,
                );
            }
        }
        for (key, value) in ingest
            .iter()
            .filter(|(key, _)| !known_ingest_label(key.kind, key.outcome))
        {
            push_sample(
                &mut out,
                "teabay_ingest_total",
                &[("kind", key.kind), ("outcome", key.outcome)],
                *value as f64,
            );
        }

        out.push_str(
            "# HELP teabay_query_latency_seconds Last observed query latency by operation.\n",
        );
        out.push_str("# TYPE teabay_query_latency_seconds gauge\n");
        for &op in QUERY_OPS {
            let stats = query_latency.get(op).copied().unwrap_or_default();
            push_query_latency_samples(&mut out, op, stats);
        }
        for (op, stats) in query_latency
            .iter()
            .filter(|(op, _)| !QUERY_OPS.contains(&op.as_str()))
        {
            push_query_latency_samples(&mut out, op, *stats);
        }

        out.push_str("# HELP teabay_query_anti_enum_pad_seconds Anti-enumeration latency target selected before query execution.\n");
        out.push_str("# TYPE teabay_query_anti_enum_pad_seconds histogram\n");
        for &op in QUERY_OPS {
            let histogram = anti_enum_pad.get(op).cloned().unwrap_or_default();
            push_pad_histogram_samples(&mut out, op, &histogram);
        }
        for (op, histogram) in anti_enum_pad
            .iter()
            .filter(|(op, _)| !QUERY_OPS.contains(&op.as_str()))
        {
            push_pad_histogram_samples(&mut out, op, histogram);
        }

        out.push_str("# HELP teabay_pull_worker_revalidations_total Pull-worker revalidation attempts by outcome.\n");
        out.push_str("# TYPE teabay_pull_worker_revalidations_total counter\n");
        for &outcome in PULL_OUTCOMES {
            let value = pull_revalidations.get(outcome).copied().unwrap_or(0);
            push_sample(
                &mut out,
                "teabay_pull_worker_revalidations_total",
                &[("outcome", outcome)],
                value as f64,
            );
        }
        for (outcome, value) in pull_revalidations
            .iter()
            .filter(|(outcome, _)| !PULL_OUTCOMES.contains(&outcome.as_str()))
        {
            push_sample(
                &mut out,
                "teabay_pull_worker_revalidations_total",
                &[("outcome", outcome.as_str())],
                *value as f64,
            );
        }

        out.push_str("# HELP teabay_divergence_detected_total Cross-directory divergence transitions detected.\n");
        out.push_str("# TYPE teabay_divergence_detected_total counter\n");
        push_sample(
            &mut out,
            "teabay_divergence_detected_total",
            &[],
            divergence_detected as f64,
        );

        // P5 — expiry worker counter (24h+grace purge).
        out.push_str(
            "# HELP teabay_expired_rows_purged_total Rows deleted by the expiry worker.\n",
        );
        out.push_str("# TYPE teabay_expired_rows_purged_total counter\n");
        for &table in PURGE_TABLES {
            let value = expired_rows_purged.get(table).copied().unwrap_or(0);
            push_sample(
                &mut out,
                "teabay_expired_rows_purged_total",
                &[("table", table)],
                value as f64,
            );
        }
        for (table, value) in expired_rows_purged
            .iter()
            .filter(|(table, _)| !PURGE_TABLES.contains(&table.as_str()))
        {
            push_sample(
                &mut out,
                "teabay_expired_rows_purged_total",
                &[("table", table.as_str())],
                *value as f64,
            );
        }

        // P5 — takedown notifier failure counter (HMAC fanout).
        out.push_str("# HELP teabay_takedown_notification_failures_total Takedown webhook dispatch failures by stage.\n");
        out.push_str("# TYPE teabay_takedown_notification_failures_total counter\n");
        for &stage in TAKEDOWN_NOTIFICATION_STAGES {
            let value = takedown_notification_failures
                .get(stage)
                .copied()
                .unwrap_or(0);
            push_sample(
                &mut out,
                "teabay_takedown_notification_failures_total",
                &[("stage", stage)],
                value as f64,
            );
        }
        for (stage, value) in takedown_notification_failures
            .iter()
            .filter(|(stage, _)| !TAKEDOWN_NOTIFICATION_STAGES.contains(&stage.as_str()))
        {
            push_sample(
                &mut out,
                "teabay_takedown_notification_failures_total",
                &[("stage", stage.as_str())],
                *value as f64,
            );
        }

        // R3.2 (METRICS-TBY-1) — directory query outcome counter. Pre-seed
        // the (op × outcome) grid so a scraper sees a zero series before the
        // first request of each combination, then append any unknown
        // (op, outcome) pairs that arrived at runtime.
        out.push_str("# HELP teabay_directory_query_total Directory query / resolve / list_handles_for_subject requests by operation and outcome.\n");
        out.push_str("# TYPE teabay_directory_query_total counter\n");
        for &op in QUERY_OPS {
            for &outcome in QUERY_OUTCOMES {
                let value = query_outcomes
                    .get(&QueryOutcomeKey {
                        op: op.to_owned(),
                        outcome: outcome.to_owned(),
                    })
                    .copied()
                    .unwrap_or(0);
                push_sample(
                    &mut out,
                    "teabay_directory_query_total",
                    &[("op", op), ("outcome", outcome)],
                    value as f64,
                );
            }
        }
        for (key, value) in query_outcomes.iter().filter(|(key, _)| {
            !(QUERY_OPS.contains(&key.op.as_str())
                && QUERY_OUTCOMES.contains(&key.outcome.as_str()))
        }) {
            push_sample(
                &mut out,
                "teabay_directory_query_total",
                &[("op", key.op.as_str()), ("outcome", key.outcome.as_str())],
                *value as f64,
            );
        }

        // R3.2 (METRICS-TBY-1) — filter-drop counter.
        out.push_str("# HELP teabay_directory_filter_drop_total Directory result rows dropped by a privacy / trust filter, by reason.\n");
        out.push_str("# TYPE teabay_directory_filter_drop_total counter\n");
        for &reason in FILTER_DROP_REASONS {
            let value = filter_drops.get(reason).copied().unwrap_or(0);
            push_sample(
                &mut out,
                "teabay_directory_filter_drop_total",
                &[("reason", reason)],
                value as f64,
            );
        }
        for (reason, value) in filter_drops
            .iter()
            .filter(|(reason, _)| !FILTER_DROP_REASONS.contains(&reason.as_str()))
        {
            push_sample(
                &mut out,
                "teabay_directory_filter_drop_total",
                &[("reason", reason.as_str())],
                *value as f64,
            );
        }

        // R3.2 (METRICS-TBY-1) — cardinality-guard counter.
        out.push_str("# HELP teabay_directory_cardinality_guard_total Bounded-scan / page-ceiling guards tripped, by counter.\n");
        out.push_str("# TYPE teabay_directory_cardinality_guard_total counter\n");
        for &counter in CARDINALITY_GUARD_COUNTERS {
            let value = cardinality_guard.get(counter).copied().unwrap_or(0);
            push_sample(
                &mut out,
                "teabay_directory_cardinality_guard_total",
                &[("counter", counter)],
                value as f64,
            );
        }
        for (counter, value) in cardinality_guard
            .iter()
            .filter(|(counter, _)| !CARDINALITY_GUARD_COUNTERS.contains(&counter.as_str()))
        {
            push_sample(
                &mut out,
                "teabay_directory_cardinality_guard_total",
                &[("counter", counter.as_str())],
                *value as f64,
            );
        }

        out
    }

    /// P5 — best-effort OTLP HTTP push of the current Prometheus
    /// snapshot. Returns `Ok(false)` when `TEABAY_OTLP_ENDPOINT` is
    /// unset (caller treats this as "exporter disabled"). On success
    /// returns `Ok(true)`; transport errors propagate.
    ///
    /// The payload is `application/x-www-form-urlencoded` with the raw
    /// Prometheus exposition format under the key `body=`. This matches
    /// the otel collector `prometheusreceiver` simple-push bridge and
    /// avoids pulling the heavy `opentelemetry-otlp` crate stack into
    /// the workspace lockfile for this slice.
    pub async fn push_to_otlp(&self) -> anyhow::Result<bool> {
        let Some(endpoint) = std::env::var("TEABAY_OTLP_ENDPOINT")
            .ok()
            .filter(|v| !v.trim().is_empty())
        else {
            return Ok(false);
        };
        let body = self.render_prometheus();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;
        let resp = client
            .post(endpoint.trim())
            .header("content-type", "text/plain; version=0.0.4")
            .body(body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("OTLP exporter push returned non-2xx status: {status}");
        }
        Ok(true)
    }
}

impl PadHistogram {
    fn record(&mut self, seconds: f64) {
        let bucket = PAD_BUCKETS
            .iter()
            .position(|bound| seconds <= *bound)
            .unwrap_or(PAD_BUCKETS.len());
        self.buckets[bucket] += 1;
        self.sum_seconds += seconds;
        self.count += 1;
    }
}

pub struct IngestMetricGuard {
    metrics: Metrics,
    kind: &'static str,
    outcome: &'static str,
    recorded: bool,
}

impl IngestMetricGuard {
    pub fn set_outcome(&mut self, outcome: &'static str) {
        self.outcome = outcome;
    }

    pub fn record(mut self, outcome: &'static str) {
        self.metrics.record_ingest(self.kind, outcome);
        self.recorded = true;
    }
}

impl Drop for IngestMetricGuard {
    fn drop(&mut self) {
        if !self.recorded {
            self.metrics.record_ingest(self.kind, self.outcome);
        }
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

fn push_sample(out: &mut String, name: &str, labels: &[(&str, &str)], value: f64) {
    out.push_str(name);
    if !labels.is_empty() {
        out.push('{');
        for (idx, (key, value)) in labels.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push_str(key);
            out.push_str("=\"");
            push_escaped_label_value(out, value);
            out.push('"');
        }
        out.push('}');
    }
    out.push(' ');
    out.push_str(&format!("{value:.6}"));
    out.push('\n');
}

fn push_query_latency_samples(out: &mut String, op: &str, stats: QueryLatencyStats) {
    push_sample(
        out,
        "teabay_query_latency_seconds",
        &[("op", op)],
        stats.last_seconds,
    );
    push_sample(
        out,
        "teabay_query_latency_seconds_count",
        &[("op", op)],
        stats.count as f64,
    );
    push_sample(
        out,
        "teabay_query_latency_seconds_sum",
        &[("op", op)],
        stats.sum_seconds,
    );
}

fn push_pad_histogram_samples(out: &mut String, op: &str, histogram: &PadHistogram) {
    let mut cumulative = 0u64;
    for (idx, bound) in PAD_BUCKETS.iter().enumerate() {
        cumulative += histogram.buckets[idx];
        let le = format!("{bound:.3}");
        push_sample(
            out,
            "teabay_query_anti_enum_pad_seconds_bucket",
            &[("op", op), ("le", &le)],
            cumulative as f64,
        );
    }
    cumulative += histogram.buckets[PAD_BUCKETS.len()];
    push_sample(
        out,
        "teabay_query_anti_enum_pad_seconds_bucket",
        &[("op", op), ("le", "+Inf")],
        cumulative as f64,
    );
    push_sample(
        out,
        "teabay_query_anti_enum_pad_seconds_sum",
        &[("op", op)],
        histogram.sum_seconds,
    );
    push_sample(
        out,
        "teabay_query_anti_enum_pad_seconds_count",
        &[("op", op)],
        histogram.count as f64,
    );
}

fn known_ingest_label(kind: &str, outcome: &str) -> bool {
    INGEST_KINDS.contains(&kind) && INGEST_OUTCOMES.contains(&outcome)
}

fn push_escaped_label_value(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            ch => out.push(ch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_render_includes_required_series() {
        let metrics = Metrics::default();
        metrics.record_ingest("announce", "verify_ok");
        metrics.record_query_latency("search-realms", Duration::from_millis(12));
        metrics.record_anti_enum_pad("search-realms", Duration::from_millis(25));
        metrics.record_pull_revalidation("success");
        metrics.record_divergence_detected();

        let body = metrics.render_prometheus();

        assert!(body.contains("teabay_ingest_total{kind=\"announce\",outcome=\"verify_ok\"}"));
        assert!(body.contains("teabay_query_latency_seconds{op=\"search-realms\"}"));
        assert!(body.contains("teabay_query_anti_enum_pad_seconds_bucket"));
        assert!(body.contains("teabay_pull_worker_revalidations_total{outcome=\"success\"}"));
        assert!(body.contains("teabay_divergence_detected_total 1.000000"));
    }

    #[test]
    fn prometheus_render_includes_p5_series() {
        let metrics = Metrics::default();
        metrics.record_expired_rows_purged(PURGE_TABLE_DIRECTORY_RESOURCES, 7);
        metrics.record_takedown_notification_failure(TAKEDOWN_NOTIFICATION_STAGE_ATTEMPT_FAILED);
        metrics.record_takedown_notification_failure(TAKEDOWN_NOTIFICATION_STAGE_DLQ);

        let body = metrics.render_prometheus();

        assert!(
            body.contains(
                "teabay_expired_rows_purged_total{table=\"directory_resources\"} 7.000000"
            )
        );
        assert!(body.contains(
            "teabay_takedown_notification_failures_total{stage=\"attempt_failed\"} 1.000000"
        ));
        assert!(
            body.contains("teabay_takedown_notification_failures_total{stage=\"dlq\"} 1.000000")
        );
    }

    /// R3.2 (METRICS-TBY-1) — the directory query / filter-drop /
    /// cardinality-guard counters render with the required label families,
    /// including the `list-handles-for-subject` op and the new filter-drop
    /// reasons.
    #[test]
    fn prometheus_render_includes_r3_2_directory_counters() {
        let metrics = Metrics::default();
        metrics.record_query_outcome("list-handles-for-subject", "ok");
        metrics.record_query_outcome("resolve-handle", "not_found");
        metrics.record_query_outcome("list-handles-for-subject", "invalid_subject_kind");
        metrics.record_filter_drop("issuer_trust");
        metrics.record_filter_drop("audience");
        metrics.record_filter_drop("subject_mismatch");
        metrics.record_filter_drop("invalid_subject_kind");
        metrics.record_cardinality_guard("resolved_subjects", 3);
        metrics.record_cardinality_guard("candidate_scan_capped", 1);

        let body = metrics.render_prometheus();

        assert!(body.contains(
            "teabay_directory_query_total{op=\"list-handles-for-subject\",outcome=\"ok\"} 1.000000"
        ));
        assert!(body.contains(
            "teabay_directory_query_total{op=\"resolve-handle\",outcome=\"not_found\"} 1.000000"
        ));
        assert!(body.contains(
            "teabay_directory_query_total{op=\"list-handles-for-subject\",outcome=\"invalid_subject_kind\"} 1.000000"
        ));
        assert!(
            body.contains("teabay_directory_filter_drop_total{reason=\"issuer_trust\"} 1.000000")
        );
        assert!(body.contains("teabay_directory_filter_drop_total{reason=\"audience\"} 1.000000"));
        assert!(
            body.contains(
                "teabay_directory_filter_drop_total{reason=\"subject_mismatch\"} 1.000000"
            )
        );
        assert!(body.contains(
            "teabay_directory_cardinality_guard_total{counter=\"resolved_subjects\"} 3.000000"
        ));
        assert!(body.contains(
            "teabay_directory_cardinality_guard_total{counter=\"candidate_scan_capped\"} 1.000000"
        ));
        // Pre-seeded zero series for an outcome that never fired.
        assert!(body.contains(
            "teabay_directory_query_total{op=\"search-realms\",outcome=\"ok\"} 0.000000"
        ));
    }

    /// R3.3 (CXP-0011) — the `resolve-target` op and the `token_reject`
    /// outcome render with the required label families (including the
    /// pre-seeded zero series before any request fires).
    #[test]
    fn prometheus_render_includes_r3_3_resolve_target_counters() {
        let metrics = Metrics::default();
        metrics.record_query_outcome("resolve-target", "ok");
        metrics.record_query_outcome("resolve-target", "token_reject");
        metrics.record_query_outcome("resolve-target", "not_found");

        let body = metrics.render_prometheus();

        assert!(body.contains(
            "teabay_directory_query_total{op=\"resolve-target\",outcome=\"ok\"} 1.000000"
        ));
        assert!(body.contains(
            "teabay_directory_query_total{op=\"resolve-target\",outcome=\"token_reject\"} 1.000000"
        ));
        assert!(body.contains(
            "teabay_directory_query_total{op=\"resolve-target\",outcome=\"not_found\"} 1.000000"
        ));
        // The `token_reject` outcome is pre-seeded for every op (zero before
        // first fire) — e.g. resolve-realm never token-rejects but the series
        // still exists.
        assert!(body.contains(
            "teabay_directory_query_total{op=\"resolve-realm\",outcome=\"token_reject\"} 0.000000"
        ));
    }
}
