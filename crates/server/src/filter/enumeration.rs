//! Anti-enumeration helpers (spec §3.x `member_count_mode` + §10).

use std::time::Duration;

use sha2::{Digest, Sha256};

/// Spec §3.x normative member-count bucket grid. Implementations MUST emit
/// exactly one of these strings; clients MUST treat any other value as
/// `invalid_response` and discard the result.
pub const MEMBER_COUNT_BUCKETS: &[&str] =
    &["1-10", "11-50", "51-100", "101-500", "501-2000", "2000+"];

pub fn bucket_member_count(count: i64) -> &'static str {
    match count {
        i64::MIN..=0 => "1-10", // pre-conditions: callers should not pass 0; bucket lower bound.
        1..=10 => "1-10",
        11..=50 => "11-50",
        51..=100 => "51-100",
        101..=500 => "101-500",
        501..=2000 => "501-2000",
        _ => "2000+",
    }
}

pub fn is_valid_member_count_bucket(bucket: &str) -> bool {
    MEMBER_COUNT_BUCKETS.contains(&bucket)
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
        assert_eq!(bucket_member_count(1), "1-10");
        assert_eq!(bucket_member_count(10), "1-10");
        assert_eq!(bucket_member_count(11), "11-50");
        assert_eq!(bucket_member_count(50), "11-50");
        assert_eq!(bucket_member_count(51), "51-100");
        assert_eq!(bucket_member_count(101), "101-500");
        assert_eq!(bucket_member_count(501), "501-2000");
        assert_eq!(bucket_member_count(2_000), "501-2000");
        assert_eq!(bucket_member_count(2_001), "2000+");
        assert_eq!(bucket_member_count(1_000_000), "2000+");
    }

    #[test]
    fn validates_bucket_grid_only() {
        assert!(is_valid_member_count_bucket("1-10"));
        assert!(is_valid_member_count_bucket("2000+"));
        assert!(!is_valid_member_count_bucket("2001+"));
        assert!(!is_valid_member_count_bucket("42"));
    }

    #[test]
    fn latency_budget_is_stable_per_route_and_key() {
        let budget = LatencyBudget::new(Duration::from_millis(25), Duration::from_millis(10));
        let first = budget.target_for("cx.directory.resolve_space", "space-a");
        let second = budget.target_for("cx.directory.resolve_space", "space-a");
        assert_eq!(first, second);
        assert!(first >= Duration::from_millis(25));
        assert!(first <= Duration::from_millis(35));
    }
}
