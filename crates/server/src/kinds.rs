//! Wire constants for Arkret v1 Directory Service event kinds and operations.
//!
//! These constants are **re-exported from `arkret-sdk`** (which mirrors the
//! canonical `arkret-spec` registry). Teabay does NOT maintain a parallel
//! copy of the strings; this file only adds aliases (`EVENT_KIND_*_DISCOVERY`)
//! and the ordered slices (`DISCOVERY_EVENT_KINDS`, `DIRECTORY_OPERATIONS`)
//! that the profile self-declaration / anti-drift guard
//! (`crate::profile::verify_or_panic`) needs to compare byte-for-byte against
//! `teabay-directory-service-baseline-2026-05-10.json`.
//!
//! Source of truth:
//!   * §3 discovery event kinds → `arkret_sdk::events::{arkret_sdk::events::EventKind::REALM_DISCOVERY, arkret_sdk::events::EventKind::ORGANIZATION_DISCOVERY,
//!     arkret_sdk::events::EventKind::ACTOR_DISCOVERY, arkret_sdk::events::EventKind::APPLET_DISCOVERY, arkret_sdk::events::EventKind::HANDLE_DISCOVERY}`
//!   * §8/§9 directory operations → `arkret_sdk::{OP_DIRECTORY_*}`

// ---- §3 discovery event kinds (wire scope: directory_signed_event) ------

/// All discovery event kinds this directory service indexes.
///
/// Order is significant: it matches the baseline profile's
/// `required_event_kinds` array byte-for-byte so the anti-drift guard can
/// detect rearrangement.
pub const DISCOVERY_EVENT_KINDS: &[&str] = &[
    arkret_sdk::events::EventKind::REALM_DISCOVERY,
    arkret_sdk::events::EventKind::ORGANIZATION_DISCOVERY,
    arkret_sdk::events::EventKind::ACTOR_DISCOVERY,
    arkret_sdk::events::EventKind::APPLET_DISCOVERY,
    arkret_sdk::events::EventKind::HANDLE_DISCOVERY,
];

// ---- §8 ingest operations -----------------------------------------------

// ---- §9 query operations (declared for profile self-check) --------------

/// Generalized target resolution (`ak.find.directory.query.resolve_target`). Not part of
/// the profile's `required_endpoints`, but published by teabay and advertised
/// in [`SUPPORTED_OPERATIONS`].
/// R3.2 (arkret-spec @ b56cab1) — reverse handle lookup
/// (`ak.find.directory.query.list_handles_for_subject`). Given a holder/principal
/// DID + context, returns the subject's currently-visible handle claims.
/// The profile's **required** operations, in the same order as
/// `ak.profile.directory_service.v1#/required_endpoints`. Guarded byte-for-byte
/// against the embedded baseline JSON by [`crate::profile::verify_or_panic`].
pub const DIRECTORY_OPERATIONS: &[&str] = &[
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_DESCRIBE,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_REALMS,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_REALM,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_ORGANIZATIONS,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_ORGANIZATION,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_ACTORS,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_USERS,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_HANDLE,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_COMMAND_ANNOUNCE,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_COMMAND_WITHDRAW,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_PUSH_COMMAND_REGISTER,
];

/// Every operation `ak.find.directory.query.describe` advertises, in wire order. This is
/// the single source of truth for the describe overlay's `supported_operations`
/// (the conditional `private_contact_discovery` op is appended at runtime when
/// enabled). It is a superset of [`DIRECTORY_OPERATIONS`] — the required
/// endpoints plus the two non-required operations teabay also exposes
/// (`resolve_target`, `list_handles_for_subject`). The superset relationship is
/// enforced at startup by [`crate::profile::verify_or_panic`].
pub const SUPPORTED_OPERATIONS: &[&str] = &[
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_DESCRIBE,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_REALMS,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_REALM,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_TARGET,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_ORGANIZATIONS,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_ORGANIZATION,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_ACTORS,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_USERS,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_HANDLE,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_QUERY_LIST_HANDLES_FOR_SUBJECT,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_COMMAND_ANNOUNCE,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_COMMAND_WITHDRAW,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_PUSH_COMMAND_REGISTER,
    // Implemented but non-required (G-3): broadcast appeal support so
    // capability discovery via describe does not rely on out-of-band knowledge.
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_COMMAND_TAKEDOWN_APPEAL,
];
