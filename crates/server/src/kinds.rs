//! Wire constants for Contrix v1 Directory Service event kinds and operations.
//!
//! These string constants are the single source of truth used by the
//! profile self-declaration / anti-drift guard (`crate::profile`) and any
//! handler-side code that needs to refer to a wire kind/operation by name.
//!
//! Source: contrix-spec sync dc01ad7
//!   * §8 ingest operations: `cx.directory.announce`, `cx.directory.withdraw`,
//!     `cx.directory.subscribe`
//!   * §3 discovery event kinds: `cx.{realm,organization,actor,applet,handle}.discovery`
//!     (`realm` replaces the legacy `space` term after the Realm/Space
//!     terminology inversion — see `README.md#realm-vs-space`)
//!
//! Anything declared here MUST appear in
//! `cx.profile.directory_service.v1`'s `required_*` arrays (verified at
//! startup by `crate::profile::verify_or_panic`).

// ---- §3 discovery event kinds (wire scope: directory_signed_event) ------

pub const EVENT_KIND_REALM_DISCOVERY: &str = "cx.realm.discovery";
pub const EVENT_KIND_ORGANIZATION_DISCOVERY: &str = "cx.organization.discovery";
pub const EVENT_KIND_ACTOR_DISCOVERY: &str = "cx.actor.discovery";
pub const EVENT_KIND_APPLET_DISCOVERY: &str = "cx.applet.discovery";
pub const EVENT_KIND_HANDLE_DISCOVERY: &str = "cx.handle.discovery";

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

pub const OP_DIRECTORY_ANNOUNCE: &str = "cx.directory.announce";
pub const OP_DIRECTORY_WITHDRAW: &str = "cx.directory.withdraw";
pub const OP_DIRECTORY_SUBSCRIBE: &str = "cx.directory.subscribe";

// ---- §9 query operations (declared for profile self-check) --------------

pub const OP_DIRECTORY_DESCRIBE: &str = "cx.directory.describe";
pub const OP_DIRECTORY_SEARCH_SPACES: &str = "cx.directory.search_spaces";
pub const OP_DIRECTORY_RESOLVE_SPACE: &str = "cx.directory.resolve_space";
pub const OP_DIRECTORY_SEARCH_ORGANIZATIONS: &str = "cx.directory.search_organizations";
pub const OP_DIRECTORY_RESOLVE_ORGANIZATION: &str = "cx.directory.resolve_organization";
pub const OP_DIRECTORY_SEARCH_ACTORS: &str = "cx.directory.search_actors";
pub const OP_DIRECTORY_SEARCH_USERS: &str = "cx.directory.search_users";
pub const OP_DIRECTORY_RESOLVE_HANDLE: &str = "cx.directory.resolve_handle";

/// Every operation this directory service publishes, in the same order as
/// `cx.profile.directory_service.v1#/required_endpoints`.
pub const DIRECTORY_OPERATIONS: &[&str] = &[
    OP_DIRECTORY_DESCRIBE,
    OP_DIRECTORY_SEARCH_SPACES,
    OP_DIRECTORY_RESOLVE_SPACE,
    OP_DIRECTORY_SEARCH_ORGANIZATIONS,
    OP_DIRECTORY_RESOLVE_ORGANIZATION,
    OP_DIRECTORY_SEARCH_ACTORS,
    OP_DIRECTORY_SEARCH_USERS,
    OP_DIRECTORY_RESOLVE_HANDLE,
    OP_DIRECTORY_ANNOUNCE,
    OP_DIRECTORY_WITHDRAW,
    OP_DIRECTORY_SUBSCRIBE,
];
