//! Anti-enumeration helpers (spec §3.x `member_count_mode` + §10).
//!
//! ## Circle directory invariant (CKP-0007)
//!
//! The bucket grid below is a **Realm-level** projection only. It is
//! computed from the Realm's announced membership, never from any
//! Circle's membership: Circle (`ck:circle:`) is an intra-Realm
//! sub-boundary whose member list and raw counts MUST NEVER reach the
//! directory. The [`crate::filter::circle_isolation`] guard admits only
//! exact Circle directory entry ids in announce preview containers, and
//! [`crate::filter::circle_directory`] collapses those subtrees before
//! anything in this module emits public projection state. The bucket emitter
//! here can trust that top-level `member_count` reflects Realm-scoped totals.
//! See `docs/anti-enumeration.md` for the wider non-leak surface.

use std::time::Duration;

use sha2::{Digest, Sha256};

/// Spec §3.x normative member-count bucket grid. Implementations MUST emit
/// exactly one of these strings; clients MUST treat any other value as
/// `invalid_response` and discard the result.
pub const MEMBER_COUNT_BUCKETS: &[&str] =
    &["1-10", "11-50", "51-100", "101-500", "501-2000", "2000+"];

#[derive(Clone, Copy, Debug)]
struct MemberCountBucketRange {
    label: &'static str,
    max: Option<i64>,
    finite_span: i64,
}

const MEMBER_COUNT_BUCKET_RANGES: &[MemberCountBucketRange] = &[
    MemberCountBucketRange {
        label: "1-10",
        max: Some(10),
        finite_span: 10,
    },
    MemberCountBucketRange {
        label: "11-50",
        max: Some(50),
        finite_span: 40,
    },
    MemberCountBucketRange {
        label: "51-100",
        max: Some(100),
        finite_span: 50,
    },
    MemberCountBucketRange {
        label: "101-500",
        max: Some(500),
        finite_span: 400,
    },
    MemberCountBucketRange {
        label: "501-2000",
        max: Some(2_000),
        finite_span: 1_500,
    },
    MemberCountBucketRange {
        label: "2000+",
        max: None,
        finite_span: 1_500,
    },
];

/// Map an exact member count to its §3.x bucket. Returns `None` for a count of
/// zero or below: the lowest grid bucket is `1-10` ("1 to 10 members"), so a
/// zero/negative count has no valid bucket. Folding it into `1-10` would
/// falsely advertise members and silently mask an upstream counting bug — the
/// caller MUST omit `member_count_bucket` instead.
pub fn bucket_member_count(count: i64) -> Option<&'static str> {
    match count {
        i64::MIN..=0 => None,
        1..=10 => Some("1-10"),
        11..=50 => Some("11-50"),
        51..=100 => Some("51-100"),
        101..=500 => Some("101-500"),
        501..=2000 => Some("501-2000"),
        _ => Some("2000+"),
    }
}

pub fn is_valid_member_count_bucket(bucket: &str) -> bool {
    MEMBER_COUNT_BUCKETS.contains(&bucket)
}

fn member_count_bucket_index(bucket: &str) -> Option<usize> {
    MEMBER_COUNT_BUCKET_RANGES
        .iter()
        .position(|range| range.label == bucket)
}

fn default_member_count_hysteresis_width_for_boundary(lower_bucket_index: usize) -> Option<i64> {
    let lower = MEMBER_COUNT_BUCKET_RANGES.get(lower_bucket_index)?;
    let upper = MEMBER_COUNT_BUCKET_RANGES.get(lower_bucket_index + 1)?;
    let upper_reference_span = if upper.max.is_some() {
        upper.finite_span
    } else {
        lower.finite_span
    };
    let reference_span = lower.finite_span.min(upper_reference_span);
    Some(((reference_span + 9) / 10).max(2))
}

fn real_count_exceeds_default_hysteresis(
    locked_bucket: &str,
    real_bucket: &str,
    real_count: Option<i64>,
) -> bool {
    let Some(locked_index) = member_count_bucket_index(locked_bucket) else {
        return true;
    };
    let Some(real_index) = member_count_bucket_index(real_bucket) else {
        return false;
    };
    if locked_index == real_index {
        return true;
    }

    let Some(count) = real_count else {
        return locked_index.abs_diff(real_index) > 1;
    };
    if bucket_member_count(count) != Some(real_bucket) {
        return false;
    }

    if real_index > locked_index {
        let Some(boundary) = MEMBER_COUNT_BUCKET_RANGES
            .get(locked_index)
            .and_then(|range| range.max)
        else {
            return false;
        };
        let Some(width) = default_member_count_hysteresis_width_for_boundary(locked_index) else {
            return false;
        };
        count >= boundary.saturating_add(width)
    } else {
        let boundary_index = locked_index.saturating_sub(1);
        let Some(boundary) = MEMBER_COUNT_BUCKET_RANGES
            .get(boundary_index)
            .and_then(|range| range.max)
        else {
            return false;
        };
        let Some(width) = default_member_count_hysteresis_width_for_boundary(boundary_index) else {
            return false;
        };
        count <= boundary.saturating_add(1).saturating_sub(width)
    }
}

/// Prior member-count residency state read from `directory_resources`
/// (`member_count_*` columns). `None` for a brand-new row.
#[derive(Clone, Debug)]
pub struct MemberCountResidencyPrior {
    /// Currently-emitted (locked) bucket, mirrored into
    /// `public_projection->>'member_count_bucket'`.
    pub locked_bucket: Option<String>,
    /// When `locked_bucket` last changed.
    pub locked_since: Option<chrono::DateTime<chrono::Utc>>,
}

/// Outcome of applying the §3 hysteresis / minimum-residency rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberCountResidencyDecision {
    /// Bucket to emit publicly this round (pin or switch). `None` when the
    /// projection carries no member-count bucket at all.
    pub emitted_bucket: Option<String>,
    /// Persisted as `member_count_bucket_since` — advances only when the
    /// emitted bucket actually switches.
    pub locked_since: Option<chrono::DateTime<chrono::Utc>>,
}

/// Spec §3 `bucketed` normative anti-oscillation rule.
///
/// The *real* bucket (`real_bucket`, derived from the announced count) can
/// flip on every refresh when the true count hovers at a grid boundary.
/// Emitting it verbatim is an enumeration side channel. This function pins
/// the publicly-emitted bucket for a minimum residency window after it
/// changes, and only switches after the exact count has crossed the default
/// hysteresis band for the adjacent boundary. Until both conditions hold, the
/// previously locked bucket is re-emitted.
///
/// `residency` is the policy minimum-residency window; callers pass the
/// entry's effective refresh TTL (spec: default SHOULD ≥ refresh TTL),
/// clamped to a floor by the caller if an observable refresh interval is
/// larger.
pub fn apply_member_count_residency(
    real_bucket: Option<&str>,
    real_count: Option<i64>,
    prior: &MemberCountResidencyPrior,
    residency: Duration,
    now: chrono::DateTime<chrono::Utc>,
) -> MemberCountResidencyDecision {
    let Some(real) = real_bucket else {
        // No member-count signal in this projection; nothing to pin.
        return MemberCountResidencyDecision {
            emitted_bucket: None,
            locked_since: None,
        };
    };

    match (&prior.locked_bucket, prior.locked_since) {
        // First time we see a bucket for this resource: lock it now.
        (None, _) | (_, None) => MemberCountResidencyDecision {
            emitted_bucket: Some(real.to_string()),
            locked_since: Some(now),
        },
        (Some(locked), Some(since)) => {
            if locked == real {
                // Real bucket unchanged — keep the existing lock window.
                MemberCountResidencyDecision {
                    emitted_bucket: Some(locked.clone()),
                    locked_since: Some(since),
                }
            } else {
                let elapsed = now.signed_duration_since(since);
                let residency = chrono::Duration::from_std(residency)
                    .unwrap_or_else(|_| chrono::Duration::seconds(0));
                if elapsed >= residency
                    && real_count_exceeds_default_hysteresis(locked, real, real_count)
                {
                    // Residency and hysteresis are satisfied: switch and
                    // re-pin the emitted bucket.
                    MemberCountResidencyDecision {
                        emitted_bucket: Some(real.to_string()),
                        locked_since: Some(now),
                    }
                } else {
                    // Still inside the residency window: re-emit the locked
                    // bucket so boundary oscillation is not observable.
                    MemberCountResidencyDecision {
                        emitted_bucket: Some(locked.clone()),
                        locked_since: Some(since),
                    }
                }
            }
        }
    }
}

/// Floor for query / resolve latency. We pad responses up to this floor to
/// reduce the side channel between "not found" and "found-but-hidden".
///
/// The exact value is operator-tunable; spec §10 / §3 only requires that
/// "不存在" and "未授权访问的隐藏资源" responses have **the same status,
/// same latency tier, and same response shape." 25 ms is a conservative
/// default for a Postgres-backed implementation.
pub const MIN_RESPONSE_LATENCY: Duration = Duration::from_millis(25);
pub const DEFAULT_RESPONSE_JITTER: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug)]
pub struct LatencyBudget {
    pub floor: Duration,
    pub jitter: Duration,
}

impl LatencyBudget {
    pub fn new(floor: Duration, jitter: Duration) -> Self {
        Self { floor, jitter }
    }

    pub fn target_for(&self, route: &str, privacy_key: &str) -> Duration {
        self.floor + deterministic_jitter(self.jitter, route, privacy_key)
    }
}

/// Wrap a future in a duration floor so its real completion time leaks no
/// information about the query's hit/miss state. Returns the future's value
/// unchanged but never resolves earlier than `floor`.
pub async fn pad_to<T, F>(floor: Duration, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let timer = tokio::time::sleep(floor);
    let (out, _) = tokio::join!(fut, timer);
    out
}

/// Pad a query/resolve route to a deterministic per-request latency tier.
///
/// The route + request key, rather than the hit/miss result, picks the jitter
/// offset. This keeps repeated probes in the same visible latency tier while
/// avoiding a single global response time that is too easy to fingerprint.
pub async fn pad_to_budget<T, F>(
    budget: LatencyBudget,
    route: &'static str,
    privacy_key: &str,
    fut: F,
) -> T
where
    F: std::future::Future<Output = T>,
{
    pad_to(budget.target_for(route, privacy_key), fut).await
}

pub async fn pad_to_budget_observed<T, F, O>(
    budget: LatencyBudget,
    route: &'static str,
    privacy_key: &str,
    observe_target: O,
    fut: F,
) -> T
where
    F: std::future::Future<Output = T>,
    O: FnOnce(Duration),
{
    let target = budget.target_for(route, privacy_key);
    observe_target(target);
    pad_to(target, fut).await
}

fn deterministic_jitter(jitter: Duration, route: &str, privacy_key: &str) -> Duration {
    let max_micros = jitter.as_micros();
    if max_micros == 0 {
        return Duration::ZERO;
    }

    let mut h = Sha256::new();
    h.update(route.as_bytes());
    h.update([0]);
    h.update(privacy_key.as_bytes());
    let digest = h.finalize();

    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    let offset = (u64::from_be_bytes(bytes) as u128) % (max_micros + 1);
    Duration::from_micros(offset.min(u64::MAX as u128) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_cover_normative_grid() {
        assert_eq!(bucket_member_count(0), None);
        assert_eq!(bucket_member_count(-5), None);
        assert_eq!(bucket_member_count(1), Some("1-10"));
        assert_eq!(bucket_member_count(10), Some("1-10"));
        assert_eq!(bucket_member_count(11), Some("11-50"));
        assert_eq!(bucket_member_count(50), Some("11-50"));
        assert_eq!(bucket_member_count(51), Some("51-100"));
        assert_eq!(bucket_member_count(101), Some("101-500"));
        assert_eq!(bucket_member_count(501), Some("501-2000"));
        assert_eq!(bucket_member_count(2_000), Some("501-2000"));
        assert_eq!(bucket_member_count(2_001), Some("2000+"));
        assert_eq!(bucket_member_count(1_000_000), Some("2000+"));
    }

    #[test]
    fn validates_bucket_grid_only() {
        assert!(is_valid_member_count_bucket("1-10"));
        assert!(is_valid_member_count_bucket("2000+"));
        assert!(!is_valid_member_count_bucket("2001+"));
        assert!(!is_valid_member_count_bucket("42"));
    }

    #[test]
    fn default_hysteresis_widths_follow_spec_boundaries() {
        assert_eq!(
            default_member_count_hysteresis_width_for_boundary(0),
            Some(2)
        );
        assert_eq!(
            default_member_count_hysteresis_width_for_boundary(1),
            Some(4)
        );
        assert_eq!(
            default_member_count_hysteresis_width_for_boundary(2),
            Some(5)
        );
        assert_eq!(
            default_member_count_hysteresis_width_for_boundary(3),
            Some(40)
        );
        assert_eq!(
            default_member_count_hysteresis_width_for_boundary(4),
            Some(150)
        );
    }

    fn prior(
        locked: Option<&str>,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> MemberCountResidencyPrior {
        MemberCountResidencyPrior {
            locked_bucket: locked.map(str::to_string),
            locked_since: since,
        }
    }

    #[test]
    fn residency_first_observation_locks_immediately() {
        let now = chrono::Utc::now();
        let d = apply_member_count_residency(
            Some("11-50"),
            Some(42),
            &prior(None, None),
            Duration::from_secs(3600),
            now,
        );
        assert_eq!(d.emitted_bucket.as_deref(), Some("11-50"));
        assert_eq!(d.locked_since, Some(now));
    }

    #[test]
    fn residency_pins_bucket_inside_window() {
        let since = chrono::Utc::now();
        let now = since + chrono::Duration::seconds(60); // < 3600 residency
        // Real bucket flipped 11-50 -> 1-10 but residency not elapsed.
        let d = apply_member_count_residency(
            Some("1-10"),
            Some(8),
            &prior(Some("11-50"), Some(since)),
            Duration::from_secs(3600),
            now,
        );
        assert_eq!(d.emitted_bucket.as_deref(), Some("11-50"));
        assert_eq!(d.locked_since, Some(since)); // since not advanced
    }

    #[test]
    fn residency_switches_after_window() {
        let since = chrono::Utc::now();
        let now = since + chrono::Duration::seconds(3600);
        let d = apply_member_count_residency(
            Some("1-10"),
            Some(9),
            &prior(Some("11-50"), Some(since)),
            Duration::from_secs(3600),
            now,
        );
        assert_eq!(d.emitted_bucket.as_deref(), Some("1-10"));
        assert_eq!(d.locked_since, Some(now)); // re-pinned
    }

    #[test]
    fn residency_pins_adjacent_jitter_after_window_until_hysteresis_exceeded() {
        let since = chrono::Utc::now();
        let now = since + chrono::Duration::seconds(3600);
        let d = apply_member_count_residency(
            Some("11-50"),
            Some(11),
            &prior(Some("1-10"), Some(since)),
            Duration::from_secs(3600),
            now,
        );
        assert_eq!(d.emitted_bucket.as_deref(), Some("1-10"));
        assert_eq!(d.locked_since, Some(since));

        let d = apply_member_count_residency(
            Some("11-50"),
            Some(12),
            &prior(Some("1-10"), Some(since)),
            Duration::from_secs(3600),
            now,
        );
        assert_eq!(d.emitted_bucket.as_deref(), Some("11-50"));
        assert_eq!(d.locked_since, Some(now));
    }

    #[test]
    fn residency_without_exact_count_does_not_infer_adjacent_hysteresis_crossing() {
        let since = chrono::Utc::now();
        let now = since + chrono::Duration::seconds(3600);
        let d = apply_member_count_residency(
            Some("11-50"),
            None,
            &prior(Some("1-10"), Some(since)),
            Duration::from_secs(3600),
            now,
        );
        assert_eq!(d.emitted_bucket.as_deref(), Some("1-10"));
        assert_eq!(d.locked_since, Some(since));
    }

    #[test]
    fn residency_uses_1500_reference_for_open_upper_bucket_boundary() {
        let since = chrono::Utc::now();
        let now = since + chrono::Duration::seconds(3600);
        let d = apply_member_count_residency(
            Some("2000+"),
            Some(2_149),
            &prior(Some("501-2000"), Some(since)),
            Duration::from_secs(3600),
            now,
        );
        assert_eq!(d.emitted_bucket.as_deref(), Some("501-2000"));
        assert_eq!(d.locked_since, Some(since));

        let d = apply_member_count_residency(
            Some("2000+"),
            Some(2_150),
            &prior(Some("501-2000"), Some(since)),
            Duration::from_secs(3600),
            now,
        );
        assert_eq!(d.emitted_bucket.as_deref(), Some("2000+"));
        assert_eq!(d.locked_since, Some(now));
    }

    #[test]
    fn residency_unchanged_bucket_keeps_window() {
        let since = chrono::Utc::now();
        let now = since + chrono::Duration::seconds(10_000);
        let d = apply_member_count_residency(
            Some("11-50"),
            Some(42),
            &prior(Some("11-50"), Some(since)),
            Duration::from_secs(3600),
            now,
        );
        assert_eq!(d.emitted_bucket.as_deref(), Some("11-50"));
        assert_eq!(d.locked_since, Some(since)); // window preserved
    }

    #[test]
    fn residency_no_bucket_is_noop() {
        let d = apply_member_count_residency(
            None,
            None,
            &prior(Some("11-50"), Some(chrono::Utc::now())),
            Duration::from_secs(3600),
            chrono::Utc::now(),
        );
        assert_eq!(d.emitted_bucket, None);
        assert_eq!(d.locked_since, None);
    }

    #[test]
    fn latency_budget_is_stable_per_route_and_key() {
        let budget = LatencyBudget::new(Duration::from_millis(25), Duration::from_millis(10));
        let first = budget.target_for("ak.find.directory.query.resolve_realm", "space-a");
        let second = budget.target_for("ak.find.directory.query.resolve_realm", "space-a");
        assert_eq!(first, second);
        assert!(first >= Duration::from_millis(25));
        assert!(first <= Duration::from_millis(35));
    }
}
