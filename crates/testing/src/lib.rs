//! Reusable teabay conformance fixtures.

pub const DIRECTORY_FIXTURE_SQL: &str = include_str!("fixtures/directory_resources.sql");

pub const SEEDED_SPACE_ID: &str = "cx:space:tea";
pub const SEEDED_LISTED_SPACE_ID: &str = "cx:space:tea-lab";
pub const SEEDED_RESTRICTED_SPACE_ID: &str = "cx:space:restricted";
pub const SEEDED_SECRET_SPACE_ID: &str = "cx:space:secret";
pub const SEEDED_ORGANIZATION_DID: &str = "did:web:tea-org.example";
pub const SEEDED_ACTOR_DID: &str = "did:web:alice.example";
pub const SEEDED_HANDLE: &str = "alice.example";
