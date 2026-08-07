//! Supported Arkret v1 Directory Service event kinds and operations.
//!
//! Values come from generated SDK types. These ordered subsets declare
//! Teabay's implementation coverage for profile and anti-drift checks; they
//! are not parallel copies of the protocol registry.

/// Discovery event kinds indexed by this directory service.
///
/// Order matches the baseline profile's `required_event_kinds` array.
pub const DISCOVERY_EVENT_KINDS: &[&str] = &[
    arkret_sdk::EventKind::REALM_DISCOVERY,
    arkret_sdk::EventKind::ORGANIZATION_DISCOVERY,
    arkret_sdk::EventKind::ACTOR_DISCOVERY,
    arkret_sdk::EventKind::APPLET_DISCOVERY,
    arkret_sdk::EventKind::HANDLE_DISCOVERY,
];

/// Operations required by `ak.profile.directory_service.v1`, in profile order.
pub const DIRECTORY_OPERATIONS: &[&str] = &[
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_DESCRIBE,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_REALMS,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_REALM,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_ORGANIZATIONS,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_ORGANIZATION,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_ACTORS,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_USERS,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_HANDLE,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_COMMAND_ANNOUNCE,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_COMMAND_WITHDRAW,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_PUSH_COMMAND_REGISTER,
];

/// Every operation advertised by `ak.find.directory.read.describe`, in wire order.
///
/// The conditional private-contact-discovery operation is appended at runtime.
/// This is a superset of [`DIRECTORY_OPERATIONS`] and includes implemented,
/// non-required resolution and appeal operations.
pub const SUPPORTED_OPERATIONS: &[&str] = &[
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_DESCRIBE,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_REALMS,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_REALM,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_TARGET,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_ORGANIZATIONS,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_ORGANIZATION,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_ACTORS,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_USERS,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_HANDLE,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_READ_LIST_HANDLES_FOR_SUBJECT,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_COMMAND_ANNOUNCE,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_COMMAND_WITHDRAW,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_PUSH_COMMAND_REGISTER,
    arkret_sdk::ServiceOperationId::FIND_DIRECTORY_COMMAND_TAKEDOWN_APPEAL,
];
