# Anti-Enumeration Rationale

teabay query handlers are designed so an unauthorized requester cannot reliably
distinguish a missing resource from an existing resource hidden by policy.

## Goals

- Do not expose exact member counts.
- Do not expose hidden resources through different status codes or response
  shapes.
- Reduce timing differences between real misses and policy-hidden hits.
- Preserve useful search and resolve behavior for authorized callers.

## Member Count Buckets

Exact `member_count` values are not exposed. During projection, teabay converts
exact counts into one of the normative buckets:

| Count | Bucket |
| ---: | --- |
| 1-10 | `1-10` |
| 11-50 | `11-50` |
| 51-100 | `51-100` |
| 101-500 | `101-500` |
| 501-2000 | `501-2000` |
| 2001 or more | `2000+` |

If a resource sends `member_count_bucket` directly, teabay validates that it is
inside this grid.

## Hidden Result Shape

Search and resolve handlers apply discoverability and requester policy before
building public results. A resource that exists but is not visible to the
requester must be returned as the same public miss shape used for a resource
that does not exist.

This rule is especially important for:

- invite-only or secret realms
- restricted organizations
- actor and handle lookups scoped to a realm
- member delivery binding disclosure

## Latency Equalization

Each query route uses a latency budget:

- `TEABAY_QUERY_LATENCY_FLOOR_MS`, default `25`
- `TEABAY_QUERY_LATENCY_JITTER_MS`, default `10`

The jitter is deterministic from route plus privacy key and is not selected from
the hit or miss result. This keeps repeated probes for the same key in a stable
latency tier while avoiding a single fixed global response time.

## Public Projection

The ingest path strips proof and directory-service internals before persisting
the public projection used for search. Query handlers then apply resource-kind
specific filtering before returning envelopes.

The current projection layer also normalizes member count data, which prevents a
resource from bypassing count buckets by sending exact counts in discovery
state.

## Private Contact Discovery

The Private Contact Discovery endpoint uses the configured PSI budget and epoch
settings:

- `TEABAY_PRIVATE_CONTACT_DISCOVERY_ENABLED`
- `TEABAY_MAX_PSI_QUERIES_PER_EPOCH`
- `TEABAY_PSI_EPOCH_SECONDS`
- `TEABAY_PSI_KEY_RETENTION_SECONDS`

Operators should keep PSI query budgets conservative because the endpoint is
specifically meant to answer membership-style questions without exposing the
whole directory.

## Operational Tradeoffs

Anti-enumeration adds latency and can hide useful diagnostics from clients. The
operator-facing admin and audit surfaces are the intended place to investigate
why a row was filtered, stale, withdrawn, or marked divergent.
