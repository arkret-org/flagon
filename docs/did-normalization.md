# DID Normalization (spec commit `07157a0`)

The DID normalization tightening at spec commit `07157a0` constrains the
identifier shape teabay accepts and stores. This page documents the
post-`07157a0` constraint, the migration SQL that backfills existing
rows, and how history rows (immutable audit log) are handled.

## The Constraint

Every DID stored in teabay tables MUST satisfy:

1. **Method allowlist**: `did:web`, `did:webvh`, or `did:key`. Operators
   may extend via `TEABAY_ACCEPTED_DID_METHODS`.
2. **Lowercase scheme + method**: `did:WEB:foo` → reject.
3. **No percent-encoded ASCII**: percent escapes are decoded before
   storage; `did:web:foo%2Ebar` → `did:web:foo.bar`.
4. **No trailing dot or slash** on `did:web` paths.
5. **No control characters** (U+0000 through U+001F, U+007F).
6. **No path-relative components** (`.` or `..`).

Violations are rejected at the ingest verify layer with
`json_invalid` outcome and an `invalid_did` detail.

## Migration SQL

The constraint backfills via migration
`20260526040000_did_normalization_audit`. The migration:

1. Adds a `NOT VALID` check constraint on every DID column so existing
   non-conforming rows do not block the deploy.
2. Records every offending row in a new `did_normalization_audit` table
   for operator review.
3. Provides a `VALIDATE CONSTRAINT` step the operator runs after the
   audit table is empty.

Sample remediation:

```sql
-- 1. Inspect the offending rows.
SELECT table_name, row_pk, original_did, normalized_did, reason
FROM did_normalization_audit
ORDER BY table_name, row_pk;

-- 2. For each row, either update the live table to the normalized DID
--    or hard-delete the row when the resource no longer exists.
UPDATE directory_resources
SET resource_id = 'did:web:example.com'
WHERE resource_id = 'did:WEB:example.com';

-- 3. Once the audit table is empty, promote the constraint to validated.
ALTER TABLE directory_resources
VALIDATE CONSTRAINT directory_resources_resource_id_normalized;
```

Note: `principal_server_service_id` is **not** covered by these rules. It stores a
stable service core id (`ak:did_core:<method>:<core>`), not a DID, and has its
own core-id shape constraint.

## History-Row Handling

`ingest_announces`, `directory_audit`, and `withdrawals.proof` are immutable
once written. The migration treats them as follows:

- **`ingest_announces`**: the original wire payload is preserved verbatim in
  `discovery_state`. The denormalized `resource_id`, however, is normalized on
  the way in — historical lookups MUST query the `discovery_state` JSON, not
  the column, when bit-for-bit reproducibility matters.
- **`directory_audit`**: rows older than the migration boundary remain in
  their original form. The chained `audit_digest` would otherwise break, so
  the constraint is `NOT VALID FOR EXISTING ROWS` permanently on this
  table.
- **`withdrawals.proof`**: the embedded JWS signs the original payload, so
  rewriting the DID inside would invalidate the signature. The row is left
  untouched; verifiers MUST accept either the original or the normalized
  DID when comparing to the live `directory_resources` row.

## Down Migration

The down migration drops the check constraints and the
`did_normalization_audit` table. It does not unwind any data changes
already applied — operators must restore from backup if a rollback is
required.
