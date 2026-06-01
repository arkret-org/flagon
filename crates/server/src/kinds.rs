//! Wire constants for Contrix v1 Directory Service event kinds and operations.
//!
//! These constants are **re-exported from `contrix-sdk`** (which mirrors the
//! canonical `contrix-spec` registry). Teabay does NOT maintain a parallel
//! copy of the strings; this file only adds aliases (`EVENT_KIND_*_DISCOVERY`)
//! and the ordered slices (`DISCOVERY_EVENT_KINDS`, `DIRECTORY_OPERATIONS`)
//! that the profile self-declaration / anti-drift guard
//! (`crate::profile::verify_or_panic`) needs to compare byte-for-byte against
//! `teabay-directory-service-baseline-2026-05-10.json`.
//!
//! Source of truth:
//!   * §3 discovery event kinds → `contrix_sdk::events::{REALM_DISCOVERY, ORGANIZATION_DISCOVERY,
//!     ACTOR_DISCOVERY, APPLET_DISCOVERY, HANDLE_DISCOVERY}`
//!   * §8/§9 directory operations → `contrix_sdk::{OP_DIRECTORY_*}`

// ---- §3 discovery event kinds (wire scope: directory_signed_event) ------

pub const EVENT_KIND_REALM_DISCOVERY: &str = contrix_sdk::events::REALM_DISCOVERY;
pub const EVENT_KIND_ORGANIZATION_DISCOVERY: &str = contrix_sdk::events::ORGANIZATION_DISCOVERY;
pub const EVENT_KIND_ACTOR_DISCOVERY: &str = contrix_sdk::events::ACTOR_DISCOVERY;
pub const EVENT_KIND_APPLET_DISCOVERY: &str = contrix_sdk::events::APPLET_DISCOVERY;
pub const EVENT_KIND_HANDLE_DISCOVERY: &str = contrix_sdk::events::HANDLE_DISCOVERY;

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

pub const OP_DIRECTORY_ANNOUNCE: &str = contrix_sdk::OP_DIRECTORY_ANNOUNCE;
pub const OP_DIRECTORY_WITHDRAW: &str = contrix_sdk::OP_DIRECTORY_WITHDRAW;
pub const OP_DIRECTORY_SUBSCRIBE: &str = contrix_sdk::OP_DIRECTORY_SUBSCRIBE;

// ---- §9 query operations (declared for profile self-check) --------------

pub const OP_DIRECTORY_DESCRIBE: &str = contrix_sdk::OP_DIRECTORY_DESCRIBE;
pub const OP_DIRECTORY_SEARCH_REALMS: &str = contrix_sdk::OP_DIRECTORY_SEARCH_REALMS;
pub const OP_DIRECTORY_RESOLVE_REALM: &str = contrix_sdk::OP_DIRECTORY_RESOLVE_REALM;
pub const OP_DIRECTORY_SEARCH_ORGANIZATIONS: &str = contrix_sdk::OP_DIRECTORY_SEARCH_ORGANIZATIONS;
pub const OP_DIRECTORY_RESOLVE_ORGANIZATION: &str = contrix_sdk::OP_DIRECTORY_RESOLVE_ORGANIZATION;
pub const OP_DIRECTORY_SEARCH_ACTORS: &str = contrix_sdk::OP_DIRECTORY_SEARCH_ACTORS;
pub const OP_DIRECTORY_SEARCH_USERS: &str = contrix_sdk::OP_DIRECTORY_SEARCH_USERS;
pub const OP_DIRECTORY_RESOLVE_HANDLE: &str = contrix_sdk::OP_DIRECTORY_RESOLVE_HANDLE;
/// R3.2 (contrix-spec @ b56cab1) — reverse handle lookup
/// (`cx.directory.list_handles_for_subject`). Given a holder/principal
/// DID + context, returns the subject's currently-visible handle claims.
pub const OP_DIRECTORY_LIST_HANDLES_FOR_SUBJECT: &str =
    contrix_sdk::OP_DIRECTORY_LIST_HANDLES_FOR_SUBJECT;

/// Every operation this directory service publishes, in the same order as
/// `cx.profile.directory_service.v1#/required_endpoints`.
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
