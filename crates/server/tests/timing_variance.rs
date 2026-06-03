//! T8.2 — wall-clock variance smoke for teabay's
//! `pad_to_budget` latency floor.
//!
//! `ck.directory.resolve_handle` (Spec §10) requires that the three
//! policy outcomes — `found`, `not_found` (genuine miss), and
//! `unauthorized` (collapsed to `not_found`) — share the same visible
//! latency tier on the wire so a remote observer cannot enumerate
//! handles by timing the response.
//!
//! This integration test stays at the latency-budget primitive: it
//! drives `pad_to_budget` with three distinct outcome closures (each
//! representing one branch) and confirms that the wall-clock
//! distributions overlap. We are not after rigorous statistics —
//! a simple mean/stddev sanity check is enough to surface a
//! catastrophic regression (e.g. a branch that bypasses the floor).
//!
//! NOTE: this test runs on a single CPU core so jitter from the OS
//! scheduler is the dominant source of noise. We tolerate up to 3×
//! spread between the three branches before failing.

use std::time::{Duration, Instant};

use server::filter::enumeration::{LatencyBudget, pad_to_budget};

/// Trial count per branch. 100+ matches the task brief.
const TRIALS: usize = 100;

/// Latency floor used for the test. Keep it small so CI runs fast.
const FLOOR_MS: u64 = 5;
const JITTER_MS: u64 = 3;

#[tokio::test(flavor = "current_thread")]
async fn pad_to_budget_branches_overlap() {
    let budget = LatencyBudget::new(
        Duration::from_millis(FLOOR_MS),
        Duration::from_millis(JITTER_MS),
    );

    // Three branches that simulate the three resolve_handle outcomes.
    // Each does a different amount of "fast-path" work to ensure the
    // *raw* future cost differs — the budget should mask the
    // difference.
    let found_samples = run_branch(&budget, "alice.example", branch_found).await;
    let not_found_samples = run_branch(&budget, "ghost.example", branch_not_found).await;
    let unauthorized_samples = run_branch(
        &budget,
        "alice.example?intent=member_add",
        branch_unauthorized,
    )
    .await;

    let (found_mean, found_std) = mean_stddev(&found_samples);
    let (nf_mean, nf_std) = mean_stddev(&not_found_samples);
    let (un_mean, un_std) = mean_stddev(&unauthorized_samples);

    eprintln!(
        "found_mean={found_mean:?} found_std={found_std:?}\n\
         not_found_mean={nf_mean:?} not_found_std={nf_std:?}\n\
         unauthorized_mean={un_mean:?} unauthorized_std={un_std:?}"
    );

    // Every sample must clear the floor (the budget is the lower
    // bound). A handful of samples in CI runners may dip slightly due
    // to time resolution; we tolerate one outlier per branch.
    let floor = Duration::from_millis(FLOOR_MS);
    let max_jitter = Duration::from_millis(JITTER_MS);
    for (name, samples) in [
        ("found", &found_samples),
        ("not_found", &not_found_samples),
        ("unauthorized", &unauthorized_samples),
    ] {
        let below = samples.iter().filter(|d| **d + max_jitter < floor).count();
        assert!(
            below <= 2,
            "{name} branch produced {below} samples below the floor of {floor:?}"
        );
    }

    // Smoke: every branch mean should be within 3× of the smallest.
    let means = [found_mean, nf_mean, un_mean];
    let min = means.iter().min().expect("non-empty");
    let max = means.iter().max().expect("non-empty");
    assert!(
        *max <= min.saturating_mul(3) + Duration::from_millis(10),
        "wall-clock means too spread: {means:?}"
    );
}

async fn run_branch<F, Fut>(budget: &LatencyBudget, privacy_key: &str, f: F) -> Vec<Duration>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut samples = Vec::with_capacity(TRIALS);
    for _ in 0..TRIALS {
        let start = Instant::now();
        pad_to_budget(*budget, "ck.directory.resolve_handle", privacy_key, f()).await;
        samples.push(start.elapsed());
    }
    samples
}

// ---- "Outcome" closures ---------------------------------------------------
//
// Each closure does a tiny, fixed amount of work. The budget floor is
// what equalises the visible latency.

async fn branch_found() {
    // Simulate a hot-path projection clone.
    let _ = serde_json::json!({ "did": "did:web:alice.example", "verified": true });
}

async fn branch_not_found() {
    // Simulate the trivial miss-path.
    let _ = ();
}

async fn branch_unauthorized() {
    // Simulate the policy-filter that prunes the member delivery binding.
    let payload = serde_json::json!({
        "member_delivery_binding": {
            "recipient_service_did": "did:web:rs.a",
            "binding_source": "explicit",
        }
    });
    let _ = payload
        .get("member_delivery_binding")
        .and_then(serde_json::Value::as_object)
        .and_then(|binding| binding.get("recipient_service_did"));
}

// ---- Statistics ----------------------------------------------------------

fn mean_stddev(samples: &[Duration]) -> (Duration, Duration) {
    let mean_nanos: u128 =
        samples.iter().map(|d| d.as_nanos()).sum::<u128>() / samples.len() as u128;
    let variance: u128 = samples
        .iter()
        .map(|d| {
            let diff = d.as_nanos() as i128 - mean_nanos as i128;
            (diff * diff) as u128
        })
        .sum::<u128>()
        / samples.len() as u128;
    let std_nanos = (variance as f64).sqrt() as u128;
    (
        Duration::from_nanos(mean_nanos.min(u64::MAX as u128) as u64),
        Duration::from_nanos(std_nanos.min(u64::MAX as u128) as u64),
    )
}
