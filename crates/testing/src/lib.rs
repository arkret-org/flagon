//! Reusable teabay conformance fixtures.

pub const DIRECTORY_FIXTURE_SQL: &str = include_str!("fixtures/directory_resources.sql");

/// TBY-ORG-04 — verified `ak.realm.organization` relationship fixtures. Seeded
/// after [`DIRECTORY_FIXTURE_SQL`] (it references those realm rows).
pub const VERIFIED_REALM_ORGANIZATIONS_FIXTURE_SQL: &str =
    include_str!("fixtures/verified_realm_organizations.sql");

pub const SEEDED_REALM_ID: &str = "ak:realm:tea";

/// TBY-ORG-04 — Realm declaring an org hint but with NO verified statement.
pub const SEEDED_DECLARED_ONLY_ORG_REALM_ID: &str = "ak:realm:org-declared-only";
/// TBY-ORG-04 — Realm with an active verified owner `ak.realm.organization`.
pub const SEEDED_VERIFIED_ORG_REALM_ID: &str = "ak:realm:org-verified";
pub const SEEDED_LISTED_REALM_ID: &str = "ak:realm:tea-lab";
pub const SEEDED_RESTRICTED_REALM_ID: &str = "ak:realm:restricted";
pub const SEEDED_SECRET_REALM_ID: &str = "ak:realm:secret";
pub const SEEDED_ORGANIZATION_DID: &str = "did:web:tea-org.example";
pub const SEEDED_ACTOR_DID: &str = "did:web:alice.example";
pub const SEEDED_HANDLE: &str = "alice.example";
