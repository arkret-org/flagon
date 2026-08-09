//! Profile self-declaration and anti-drift guard.
//!
//! teabay publishes `ak.profile.directory_service.v1`. To keep the live
//! wire surface honest, we embed the spec baseline JSON at compile time
//! (`include_str!`) and verify on startup that the operations and event
//! kinds the code actually exposes (via `crate::kinds`) match the baseline
//! byte-for-byte. Any drift — added op, removed event kind, reorder —
//! panics at startup rather than allowing a quietly non-conformant
//! Directory Service to come up.
//!
//! Source baseline: `teabay-directory-service-baseline-2026-05-10.json`,
//! synthesized from arkret-spec sync dc01ad7
//! (`conformance-profiles.json#/profiles/ak.profile.directory_service.v1`).

use serde::Deserialize;

use crate::kinds::{DIRECTORY_OPERATIONS, DISCOVERY_EVENT_KINDS, SUPPORTED_OPERATIONS};

/// Embedded copy of the directory-service baseline profile.
///
/// We use `include_str!` so the binary carries the spec contract it was
/// built against — there is no runtime file fetch, and the build fails if
/// the JSON ever goes missing.
pub const BASELINE_PROFILE_JSON: &str =
    include_str!("teabay-directory-service-baseline-2026-05-10.json");

/// Wire shape of the baseline JSON. Only the fields the anti-drift guard
/// needs are deserialized; extra fields are ignored so a future
/// `optional_extensions` change does not require a code change here.
#[derive(Debug, Deserialize)]
pub struct BaselineProfile {
    pub profile: String,
    pub required_endpoints: Vec<String>,
    pub required_event_kinds: Vec<String>,
}

impl BaselineProfile {
    pub fn load() -> Self {
        serde_json::from_str(BASELINE_PROFILE_JSON).expect(
            "teabay baseline profile JSON is invalid; this is a build-time bug because the file is embedded via include_str!",
        )
    }
}

/// Verify that the live wire surface declared in [`crate::kinds`] matches
/// the embedded baseline profile. Panics on any mismatch.
///
/// Call this exactly once during startup, before the server binds.
pub fn verify_or_panic() {
    let baseline = BaselineProfile::load();

    assert_eq!(
        baseline.profile, "ak.profile.directory_service.v1",
        "teabay baseline profile JSON declares profile {:?} but this binary only implements ak.profile.directory_service.v1",
        baseline.profile,
    );

    assert_slices_match(
        "required_endpoints",
        &baseline.required_endpoints,
        DIRECTORY_OPERATIONS,
    );
    assert_event_kinds_match(&baseline.required_event_kinds, DISCOVERY_EVENT_KINDS);

    // The describe overlay advertises `SUPPORTED_OPERATIONS`; every required
    // endpoint MUST be advertised, otherwise describe under-reports the
    // profile's mandatory surface.
    for required in DIRECTORY_OPERATIONS {
        assert!(
            SUPPORTED_OPERATIONS.contains(required),
            "directory service profile drift: required endpoint {required:?} \
             is missing from kinds::SUPPORTED_OPERATIONS (the describe overlay) — \
             describe must advertise every required_endpoint.",
        );
    }

    tracing::info!(
        profile = %baseline.profile,
        operations = DIRECTORY_OPERATIONS.len(),
        event_kinds = DISCOVERY_EVENT_KINDS.len(),
        "directory service profile anti-drift guard passed",
    );
}

fn assert_slices_match(field: &str, baseline: &[String], live: &[&str]) {
    if baseline.len() != live.len()
        || baseline
            .iter()
            .zip(live.iter())
            .any(|(b, l)| b.as_str() != *l)
    {
        panic!(
            "directory service profile drift on `{field}`:\n  baseline: {baseline:?}\n  live:     {live:?}\n\
             — update crate::kinds or the embedded baseline JSON so both agree before booting.",
        );
    }
}

fn assert_event_kinds_match(baseline: &[String], live: &[arkret_sdk::EventKind]) {
    if baseline.len() != live.len()
        || baseline
            .iter()
            .zip(live.iter())
            .any(|(expected, actual)| expected.as_str() != actual.as_str())
    {
        panic!(
            "directory service profile drift on `required_event_kinds`:\n  baseline: {baseline:?}\n  live:     {live:?}\n\
             — update crate::kinds or the embedded baseline JSON so both agree before booting.",
        );
    }
}
