//! Reusable teabay conformance fixtures.

pub const DIRECTORY_FIXTURE_SQL: &str = include_str!("fixtures/directory_resources.sql");

pub const SEEDED_REALM_ID: &str = "cx:realm:tea";
pub const SEEDED_LISTED_REALM_ID: &str = "cx:realm:tea-lab";
pub const SEEDED_RESTRICTED_REALM_ID: &str = "cx:realm:restricted";
pub const SEEDED_SECRET_REALM_ID: &str = "cx:realm:secret";
pub const SEEDED_ORGANIZATION_DID: &str = "did:web:tea-org.example";
pub const SEEDED_ACTOR_DID: &str = "did:web:alice.example";
pub const SEEDED_HANDLE: &str = "alice.example";
