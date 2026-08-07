//! Reusable teabay conformance fixtures.

pub const DIRECTORY_FIXTURE_SQL: &str = include_str!("fixtures/directory_resources.sql");

/// TBY-ORG-04 — verified `ak.realm.organization` relationship fixtures. Seeded
/// after [`DIRECTORY_FIXTURE_SQL`] (it references those realm rows).
pub const VERIFIED_REALM_ORGANIZATIONS_FIXTURE_SQL: &str =
    include_str!("fixtures/verified_realm_organizations.sql");
