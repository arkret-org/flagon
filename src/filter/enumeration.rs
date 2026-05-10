//! Anti-enumeration helpers (spec §3.x `member_count_mode` + §10).

use std::time::Duration;

/// Spec §3.x normative member-count bucket grid. Implementations MUST emit
/// exactly one of these strings; clients MUST treat any other value as
/// `invalid_response` and discard the result.
pub const MEMBER_COUNT_BUCKETS: &[&str] = &[
    "1-10",
    "11-50",
    "51-100",
    "101-500",
    "501-2000",
    "2000+",
];

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

/// Floor for query / resolve latency. We pad responses up to this floor to
/// reduce the side channel between "not found" and "found-but-hidden".
///
/// The exact value is operator-tunable; spec §10 / §3 only requires that
/// "不存在" and "未授权访问的隐藏资源" responses have **the same status,
/// same latency tier, and same response shape." 25 ms is a conservative
/// default for a Postgres-backed implementation.
pub const MIN_RESPONSE_LATENCY: Duration = Duration::from_millis(25);

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
}
