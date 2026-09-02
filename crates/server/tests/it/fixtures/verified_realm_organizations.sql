-- TBY-ORG-04 — verified `ak.realm.organization` relationship fixtures.
--
-- These rows simulate the post-verification state of the
-- `verified_realm_organizations` index (the SDK verifier output is exercised
-- by the unit tests in `ingest::organization_statement`). They drive the
-- directory-side acceptance cases:
--   * `ak:realm:AZ0Vyo6cesGriGAh_ea-7SD_Hy3GDnSxDMTrErh0Ki2C`  — active owner w/ official_badge ⇒ badge shown.
--   * `ak:realm:ASsKHIftKaTemZcyvFWmoYnCtQNN_4deE04hdIPA0PPu`           — active sponsor relationship (NOT owner /
--                                governance) ⇒ no official owning organization.
INSERT INTO verified_realm_organizations (
    realm_id,
    organization_id,
    relationship,
    control_scopes,
    statement_id,
    statement_issued_at,
    not_before,
    expires_at,
    realm_frontier_digest,
    stale,
    verified_at,
    source_announce_id
) VALUES
(
    'ak:realm:AZ0Vyo6cesGriGAh_ea-7SD_Hy3GDnSxDMTrErh0Ki2C',
    'ak:did_core:web:tea-org.example',
    'owner',
    ARRAY['official_badge', 'realm_admin'],
    'org-stmt-verified-1',
    now() - interval '1 hour',
    NULL,
    NULL,
    NULL,
    false,
    now(),
    'ak.announce:test-realm-org-verified'
),
(
    -- Sponsor is NOT an owning / governance relationship: it MUST NOT yield an
    -- official owning organization even though it carries official_badge scope.
    'ak:realm:ASsKHIftKaTemZcyvFWmoYnCtQNN_4deE04hdIPA0PPu',
    'ak:did_core:web:tea-org.example',
    'sponsor',
    ARRAY['official_badge'],
    'org-stmt-sponsor-1',
    now() - interval '1 hour',
    NULL,
    NULL,
    NULL,
    false,
    now(),
    'ak.announce:test-realm-sponsor'
);
