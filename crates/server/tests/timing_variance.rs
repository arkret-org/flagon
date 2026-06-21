//! Deterministic coverage for teabay's anti-enumeration latency budget.
//!
//! The request handler pads found, not_found, and unauthorized branches through
//! the same `LatencyBudget::target_for(route, privacy_key)` primitive. This
//! test intentionally avoids wall-clock timing so it remains stable on shared
//! CI runners.

use std::time::Duration;

use server::filter::enumeration::LatencyBudget;

const FLOOR_MS: u64 = 5;
const JITTER_MS: u64 = 3;
const ROUTE: &str = "ck.find.directory.query.resolve_handle";

#[test]
fn latency_budget_targets_are_branch_independent_and_bounded() {
    let budget = LatencyBudget::new(
        Duration::from_millis(FLOOR_MS),
        Duration::from_millis(JITTER_MS),
    );
    let floor = Duration::from_millis(FLOOR_MS);
    let ceiling = floor + Duration::from_millis(JITTER_MS);

    for privacy_key in [
        "handle=alice.example;branch=found",
        "handle=ghost.example;branch=not_found",
        "handle=alice.example;branch=unauthorized",
    ] {
        let first = budget.target_for(ROUTE, privacy_key);
        let second = budget.target_for(ROUTE, privacy_key);

        assert_eq!(first, second);
        assert!(first >= floor, "target {first:?} fell below {floor:?}");
        assert!(
            first <= ceiling,
            "target {first:?} exceeded ceiling {ceiling:?}"
        );
    }
}

#[test]
fn zero_jitter_budget_collapses_to_exact_floor() {
    let budget = LatencyBudget::new(Duration::from_millis(FLOOR_MS), Duration::ZERO);

    assert_eq!(
        budget.target_for(ROUTE, "handle=alice.example;branch=found"),
        Duration::from_millis(FLOOR_MS)
    );
    assert_eq!(
        budget.target_for(ROUTE, "handle=alice.example;branch=unauthorized"),
        Duration::from_millis(FLOOR_MS)
    );
}
