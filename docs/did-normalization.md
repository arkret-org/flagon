# DID Representation Validation

Teabay keeps Arkret stable identities and W3C resolution material in separate
value categories:

- `DidCoreId` values use `ak:did_core:<method>:<core>` and occupy stable
  business-object `id` / `*_id` fields.
- `Did` values use `did:<method>:...` without path, query, or fragment and are
  accepted only where registration, resolution, or method evidence requires a
  resolvable DID.
- `DidUrl` values select a verification method and include a required fragment.

The server parses these values through the SDK types at ingress. It never
widens a stored `DidCoreId` back into a DID string; code that needs resolution
material must obtain the required `Did` from verified resolution evidence.

## DID validation

Every `Did` accepted by teabay must satisfy the SDK's canonical DID profile and
the configured method policy:

1. The method must be present in `TEABAY_ACCEPTED_DID_METHODS`.
2. Scheme and method are lowercase.
3. Percent-encoded ASCII, control characters, path-relative components, and
   trailing dot or slash forms are rejected.
4. Resolution and method-evidence objects carry their DID as a required typed
   value; ordinary directory rows and previews do not add an optional DID.

Violations are rejected at the ingest boundary. Stable service and principal
columns instead enforce the `ak:did_core:` shape.

## Database schema

This repository has no released legacy-data contract. DID representation
constraints live directly in the baseline SQL under
`crates/server/migrations/20260512010000_schema/`. Schema changes update that
baseline in place; teabay does not add rename/backfill migrations, dual-read
paths, or compatibility aliases for retired identifier fields.
