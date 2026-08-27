//! Supported Arkret v1 Directory Service event kinds and operations.
//!
//! Values come from generated SDK types. These ordered subsets declare
//! Teabay's actual implementation coverage.

/// Discovery event kinds indexed by this directory service.
///
/// Order matches the baseline profile's `required_event_kinds` array.
pub const DISCOVERY_EVENT_KINDS: &[arkret_sdk::EventKind] = &[
    arkret_sdk::EventKind::RealmDiscovery,
    arkret_sdk::EventKind::OrganizationDiscovery,
    arkret_sdk::EventKind::ActorDiscovery,
    arkret_sdk::EventKind::AppletDiscovery,
    arkret_sdk::EventKind::HandleDiscovery,
];
