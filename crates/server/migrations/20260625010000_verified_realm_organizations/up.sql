-- TBY-ORG-01/02/03 — verified `ak.realm.organization` relationship index.
--
-- The directory MUST NOT treat a bare `organization_did` /
-- `owning_organizations` projection hint as an official organization
-- relationship. An official badge, organization scoping, or
-- directory-certifier relationship is only valid when it derives from an
-- `active`, in-validity-window, scope-covering `ak.realm.organization`
-- statement that passed the SDK verifier
-- (`verify_realm_organization_statement`).
--
-- Each verified statement is keyed by `(realm_id, organization_did,
-- relationship)` — the spec reducer cell subject — so a newer statement for
-- the same triple supersedes (or revokes) the prior one. `statement_issued_at`
-- is the monotonic ordering key used to reject replayed older statements
-- (TBY-ORG-03 replay protection).

CREATE TABLE verified_realm_organizations (
    realm_id            TEXT        NOT NULL,
    organization_did    TEXT        NOT NULL,
    relationship        TEXT        NOT NULL
        CHECK (relationship IN ('owner', 'governance', 'sponsor', 'directory_certifier')),
    -- Verified machine-readable endorsement scopes (e.g. `official_badge`,
    -- `realm_admin`, `directory_listing`). Stored as the canonical snake_case
    -- scope strings the SDK enum serializes to.
    control_scopes      TEXT[]      NOT NULL DEFAULT '{}',
    statement_id        TEXT        NOT NULL,
    -- Statement validity window (from the verified payload). `expires_at`
    -- NULL ⇒ no expiry.
    statement_issued_at TIMESTAMPTZ NOT NULL,
    not_before          TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ,
    -- Realm control frontier digest the organization evaluated, when present.
    -- Used by TBY-ORG-03 staleness detection: when the live Realm frontier has
    -- advanced past this digest the verified relationship is marked stale.
    realm_frontier_digest TEXT,
    -- Whether the relationship is currently considered fresh. A relationship is
    -- marked stale (rather than deleted) when the Realm frontier digest the
    -- organization evaluated has fallen behind, so it stops surfacing as an
    -- effective verified badge without losing the audit trail.
    stale               BOOLEAN     NOT NULL DEFAULT false,
    verified_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_announce_id  TEXT,
    PRIMARY KEY (realm_id, organization_did, relationship)
);

CREATE INDEX verified_realm_organizations_realm_idx
    ON verified_realm_organizations (realm_id)
    WHERE stale = false;

CREATE INDEX verified_realm_organizations_org_idx
    ON verified_realm_organizations (organization_did)
    WHERE stale = false;

CREATE INDEX verified_realm_organizations_expiry_idx
    ON verified_realm_organizations (expires_at)
    WHERE expires_at IS NOT NULL;
