# Circle Isolation Hardening (CXP-0007)

This document captures the operator-visible hard-reject list and audit-log
markers that ship with the CXP-0007 circle-isolation tightening.

## Background

CXP-0007 narrows the cross-circle resolution surface so that a Principal
Server in one circle cannot probe membership of a resource in another
circle without the explicit consent edges spelled out in the Contrix v1
discoverability spec. The previous behavior allowed inferred resolution via
`alsoKnownAs` and `via_services` chains; the hardening removes those paths.

## Hard-Reject List

teabay rejects the following request shapes at the verify layer with an
`isolation_rejected` outcome, before any handler runs:

1. A cross-circle `resolve_*` whose `resource_id` is `secret` or
   `invite_only` and whose proofs do not include a same-circle membership
   credential.
2. An announce envelope whose `via_services` set contains a circle DID the
   announcing server does not have a published membership in.
3. A subscribe request whose `resource_filter` would match across circle
   boundaries unless the subscriber is the resource's own Principal Server.
4. Any `actor.resolve` whose `audience` claim is from a circle the
   resource is `unlisted` in.
5. Any `psi` query whose epoch crosses a circle root rotation; the server
   forces a fresh blinded epoch.

The reject is fail-closed: no row data is returned, no existence signal
leaks, and the standard anti-enumeration latency budget still applies.

## Audit Log Markers

Every isolation reject writes a `directory_audit` row with:

- `kind = "isolation_rejected"`
- `detail.rule = "<rule_number>"` matching the list above
- `detail.requester_circle` and `detail.resource_circle` (both masked to a
  SHA-256 prefix in production log redaction mode)
- `prev_digest` / `audit_digest` chained per A.8.5

Dashboards should filter on `kind = isolation_rejected` and alert on a
sustained per-circle reject rate above the steady-state baseline.

## Test Coverage

- `crates/server/src/middleware/http_sig.rs` — signature-layer rejects.
- `crates/server/src/query/realm.rs` / `handle.rs` / `organization.rs` —
  handler-layer membership checks.
- `crates/server/tests/it/conformance.rs` — end-to-end isolation
  reject smoke under the `TEABAY_RUN_DOCKER_TESTS=1` gate.
