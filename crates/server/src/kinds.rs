//! Wire constants for Cokret v1 Directory Service event kinds and operations.
//!
//! These constants are **re-exported from `cokret-sdk`** (which mirrors the
//! canonical `cokret-spec` registry). Teabay does NOT maintain a parallel
//! copy of the strings; this file only adds aliases (`EVENT_KIND_*_DISCOVERY`)
//! and the ordered slices (`DISCOVERY_EVENT_KINDS`, `DIRECTORY_OPERATIONS`)
//! that the profile self-declaration / anti-drift guard
//! (`crate::profile::verify_or_panic`) needs to compare byte-for-byte against
//! `teabay-directory-service-baseline-2026-05-10.json`.
//!
//! Source of truth:
//!   * §3 discovery event kinds → `cokret_sdk::events::{REALM_DISCOVERY, ORGANIZATION_DISCOVERY,
//!     ACTOR_DISCOVERY, APPLET_DISCOVERY, HANDLE_DISCOVERY}`
//!   * §8/§9 directory operations → `cokret_sdk::{OP_DIRECTORY_*}`

// ---- §3 discovery event kinds (wire scope: directory_signed_event) ------

pub const EVENT_KIND_REALM_DISCOVERY: &str = cokret_sdk::events::REALM_DISCOVERY;
pub const EVENT_KIND_ORGANIZATION_DISCOVERY: &str = cokret_sdk::events::ORGANIZATION_DISCOVERY;
pub const EVENT_KIND_ACTOR_DISCOVERY: &str = cokret_sdk::events::ACTOR_DISCOVERY;
pub const EVENT_KIND_APPLET_DISCOVERY: &str = cokret_sdk::events::APPLET_DISCOVERY;
pub const EVENT_KIND_HANDLE_DISCOVERY: &str = cokret_sdk::events::HANDLE_DISCOVERY;

/// All discovery event kinds this directory service indexes.
///
/// Order is significant: it matches the baseline profile's
/// `required_event_kinds` array byte-for-byte so the anti-drift guard can
/// detect rearrangement.
pub const DISCOVERY_EVENT_KINDS: &[&str] = &[
    EVENT_KIND_REALM_DISCOVERY,
    EVENT_KIND_ORGANIZATION_DISCOVERY,
    EVENT_KIND_ACTOR_DISCOVERY,
    EVENT_KIND_APPLET_DISCOVERY,
    EVENT_KIND_HANDLE_DISCOVERY,
];

// ---- §8 ingest operations -----------------------------------------------

pub const OP_DIRECTORY_ANNOUNCE: &str = cokret_sdk::OP_DIRECTORY_ANNOUNCE;
pub const OP_DIRECTORY_WITHDRAW: &str = cokret_sdk::OP_DIRECTORY_WITHDRAW;
pub const OP_DIRECTORY_SUBSCRIBE: &str = cokret_sdk::OP_DIRECTORY_SUBSCRIBE;

// ---- §9 query operations (declared for profile self-check) --------------

pub const OP_DIRECTORY_DESCRIBE: &str = cokret_sdk::OP_DIRECTORY_DESCRIBE;
pub const OP_DIRECTORY_SEARCH_REALMS: &str = cokret_sdk::OP_DIRECTORY_SEARCH_REALMS;
pub const OP_DIRECTORY_RESOLVE_REALM: &str = cokret_sdk::OP_DIRECTORY_RESOLVE_REALM;
pub const OP_DIRECTORY_SEARCH_ORGANIZATIONS: &str = cokret_sdk::OP_DIRECTORY_SEARCH_ORGANIZATIONS;
pub const OP_DIRECTORY_RESOLVE_ORGANIZATION: &str = cokret_sdk::OP_DIRECTORY_RESOLVE_ORGANIZATION;
pub const OP_DIRECTORY_SEARCH_ACTORS: &str = cokret_sdk::OP_DIRECTORY_SEARCH_ACTORS;
pub const OP_DIRECTORY_SEARCH_USERS: &str = cokret_sdk::OP_DIRECTORY_SEARCH_USERS;
pub const OP_DIRECTORY_RESOLVE_HANDLE: &str = cokret_sdk::OP_DIRECTORY_RESOLVE_HANDLE;
/// Generalized target resolution (`cx.directory.resolve_target`). Not part of
/// the profile's `required_endpoints`, but published by teabay and advertised
/// in [`SUPPORTED_OPERATIONS`].
pub const OP_DIRECTORY_RESOLVE_TARGET: &str = cokret_sdk::OP_DIRECTORY_RESOLVE_TARGET;
/// R3.2 (cokret-spec @ b56cab1) — reverse handle lookup
/// (`cx.directory.list_handles_for_subject`). Given a holder/principal
/// DID + context, returns the subject's currently-visible handle claims.
pub const OP_DIRECTORY_LIST_HANDLES_FOR_SUBJECT: &str =
    cokret_sdk::OP_DIRECTORY_LIST_HANDLES_FOR_SUBJECT;

/// The profile's **required** operations, in the same order as
/// `cx.profile.directory_service.v1#/required_endpoints`. Guarded byte-for-byte
/// against the embedded baseline JSON by [`crate::profile::verify_or_panic`].
pub const DIRECTORY_OPERATIONS: &[&str] = &[
    OP_DIRECTORY_DESCRIBE,
    OP_DIRECTORY_SEARCH_REALMS,
    OP_DIRECTORY_RESOLVE_REALM,
    OP_DIRECTORY_SEARCH_ORGANIZATIONS,
    OP_DIRECTORY_RESOLVE_ORGANIZATION,
    OP_DIRECTORY_SEARCH_ACTORS,
    OP_DIRECTORY_SEARCH_USERS,
    OP_DIRECTORY_RESOLVE_HANDLE,
    OP_DIRECTORY_ANNOUNCE,
    OP_DIRECTORY_WITHDRAW,
    OP_DIRECTORY_SUBSCRIBE,
];

/// Every operation `cx.directory.describe` advertises, in wire order. This is
/// the single source of truth for the describe overlay's `supported_operations`
/// (the conditional `private_contact_discovery` op is appended at runtime when
/// enabled). It is a superset of [`DIRECTORY_OPERATIONS`] — the required
/// endpoints plus the two non-required operations teabay also exposes
/// (`resolve_target`, `list_handles_for_subject`). The superset relationship is
/// enforced at startup by [`crate::profile::verify_or_panic`].
pub const SUPPORTED_OPERATIONS: &[&str] = &[
    OP_DIRECTORY_DESCRIBE,
    OP_DIRECTORY_SEARCH_REALMS,
    OP_DIRECTORY_RESOLVE_REALM,
    OP_DIRECTORY_RESOLVE_TARGET,
    OP_DIRECTORY_SEARCH_ORGANIZATIONS,
    OP_DIRECTORY_RESOLVE_ORGANIZATION,
    OP_DIRECTORY_SEARCH_ACTORS,
    OP_DIRECTORY_SEARCH_USERS,
    OP_DIRECTORY_RESOLVE_HANDLE,
    OP_DIRECTORY_LIST_HANDLES_FOR_SUBJECT,
    OP_DIRECTORY_ANNOUNCE,
    OP_DIRECTORY_WITHDRAW,
    OP_DIRECTORY_SUBSCRIBE,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_kinds_match_sdk() {
        assert_eq!(EVENT_KIND_REALM_DISCOVERY, "cx.realm.discovery");
        assert_eq!(
            EVENT_KIND_ORGANIZATION_DISCOVERY,
            "cx.organization.discovery"
        );
        assert_eq!(EVENT_KIND_ACTOR_DISCOVERY, "cx.actor.discovery");
        assert_eq!(EVENT_KIND_APPLET_DISCOVERY, "cx.applet.discovery");
        assert_eq!(EVENT_KIND_HANDLE_DISCOVERY, "cx.handle.discovery");
    }

    #[test]
    fn directory_ops_match_sdk() {
        assert_eq!(OP_DIRECTORY_ANNOUNCE, "cx.directory.announce");
        assert_eq!(OP_DIRECTORY_WITHDRAW, "cx.directory.withdraw");
        assert_eq!(OP_DIRECTORY_SUBSCRIBE, "cx.directory.push.register");
        assert_eq!(OP_DIRECTORY_DESCRIBE, "cx.directory.describe");
        assert_eq!(OP_DIRECTORY_SEARCH_REALMS, "cx.directory.search_realms");
        assert_eq!(OP_DIRECTORY_RESOLVE_REALM, "cx.directory.resolve_realm");
        assert_eq!(OP_DIRECTORY_RESOLVE_HANDLE, "cx.directory.resolve_handle");
        assert_eq!(
            OP_DIRECTORY_LIST_HANDLES_FOR_SUBJECT,
            "cx.directory.list_handles_for_subject"
        );
    }
}
