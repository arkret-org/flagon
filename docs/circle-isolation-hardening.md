# Circle Isolation Hardening (CKP-0007)

This document captures the operator-visible hard-reject list and audit-log
markers that ship with the CKP-0007 circle-isolation tightening.

## Background

CKP-0007 narrows the cross-circle resolution surface so that a Principal
Server in one circle cannot probe membership of a resource in another
circle without the explicit consent edges spelled out in the Cokret v1
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

## `circle` selector kind in the ingest filter

R3 introduces a `circle` variant on the `ResourceSelector` enum
(matching SDK `ResourceSelector::Circle(CircleId)`, wire pattern
`^ck:circle:[0-9a-f]{8}-...$`). teabay's ingest filter extends to
accept the new selector kind as a first-class membership scope.

### Behavior table: ingest vs query

| Surface | Pre-R3 behavior | R3 behavior with `circle` selector |
|---|---|---|
| **Ingest accept** — event submitted with `effective_scope = circle(...)` | No such surface (events lacked a circle-scoped form) | Accepted iff submitter is a current member of the named circle; rejected with `isolation_rejected` otherwise. The ingest filter consults `circle_membership` (FSM-backed) at write time and refuses any event whose `effective_scope.circle_id` the submitter is not a member of. |
| **Ingest project** — event projected into the audit/event-log table | N/A | Row stored with `effective_scope_kind = "circle"` and `effective_scope_circle_id = <CircleId>`. The B-Tree index `projection_events_effective_scope_idx` covers this column (see `soland/DEPLOYMENT.md` operational notes for sizing). |
| **Query accept** — caller queries `ck.query.list` with `selector = circle(...)` | N/A | Accepted iff caller is a current member of the named circle. Selector validation matches the canonical `ck:circle:<uuid>` pattern. |
| **Query result** — projection rows returned to the caller | Realm-scoped or organization-scoped only | Filtered to rows where `effective_scope_kind = "circle" AND effective_scope_circle_id = caller's-circle-id`. No realm-scoped or organization-scoped rows leak into a circle query (and vice versa). |
| **Query result** — `prev_digest` / `audit_digest` chain | Realm-/org-scoped chain | Per-circle chain; circles maintain their own independent digest chain to prevent cross-circle digest correlation. |
| **Ingest reject reason** | `isolation_rejected` with `detail.rule = "<rule#>"` | Same scheme; `detail.rule = "circle-member"` for circle-scoped rejects, with `detail.circle_id` masked to SHA-256 prefix in production redaction. |
| **Query reject reason** | `isolation_rejected` | Same; `detail.rule = "circle-member"` |

### Invariants

- A `ResourceSelector::Circle(CircleId)` value at ingest **MUST**
  resolve to a circle that is a member of the resource's owning Realm.
  Cross-realm circle references are hard rejected with
  `isolation_rejected` (rule `circle-cross-realm`).
- The circle membership FSM lives on the durable event log
  (`ck.circle.membership.{add,remove}`). teabay reads from a projection;
  if the projection is behind the durable log (replica lag), the
  ingest filter fails closed: writes against a circle the projection
  doesn't yet show membership for are rejected, not silently accepted.
- Circle membership state on the wire is **never** leaked to non-members
  via teabay's directory or push surfaces. The circle-scoped event log
  is opaque to non-members at every read surface.

### Dashboards

Two new metrics:

- `teabay_circle_ingest_rejected_total{rule}` — counter of ingest-time
  circle rejects, bucketed by rule (`circle-member`, `circle-cross-realm`,
  `circle-projection-stale`).
- `teabay_circle_membership_projection_lag_seconds` — gauge of the lag
  between the durable circle-membership event log and the projection
  teabay reads from. Alert at >5s.
