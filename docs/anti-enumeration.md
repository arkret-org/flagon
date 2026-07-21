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

## Query Rate Limits

The shared query limiter applies two independent budgets before the expensive
parts of search and resolve handlers:

- `TEABAY_QUERY_MAX_QUERIES_PER_IP_PER_MIN`, default `600`, limits total query
  requests per resolved client IP.
- `TEABAY_QUERY_MAX_RESOLVES_PER_RESOURCE_PER_MIN`, default `120`, limits
  repeated exact resolves of the same resource key.

Set either value to `0` only when an upstream gateway enforces an equivalent or
stricter budget. These guards sit alongside the per-resource budget
`TEABAY_RATE_LIMIT_PER_RESOURCE_PER_MIN` and the PSI-specific quota below.

## Public Projection

The ingest path strips proof and directory-service internals before persisting
the public projection used for search. Query handlers then apply resource-kind
specific filtering before returning envelopes.

The current projection layer also normalizes member count data, which prevents a
resource from bypassing count buckets by sending exact counts in discovery
state.

## Private Contact Discovery

The Private Contact Discovery endpoint uses the configured PSI quota and epoch
settings:

- `TEABAY_PRIVATE_CONTACT_DISCOVERY_ENABLED`
- `TEABAY_MAX_PSI_QUERIES_PER_WINDOW`
- `TEABAY_PSI_QUOTA_WINDOW_SECONDS`
- `TEABAY_PSI_EPOCH_SECONDS`
- `TEABAY_PSI_KEY_RETENTION_SECONDS`

Operators should keep PSI query budgets conservative because the endpoint is
specifically meant to answer membership-style questions without exposing the
whole directory.

### Quota is decoupled from the OPRF key epoch (spec §6.4)

The anti-enumeration quota is keyed on `psi-quota:{requester}:{floor(now /
psi_quota_window_seconds)}` — a **fixed wall-clock window** (default 24h) that is
deliberately independent of the OPRF key epoch. This enforces the three §6.4
MUSTs:

- A new OPRF key epoch MUST NOT reset the quota — the quota bucket only rolls
  when the wall-clock window advances.
- The client-supplied `epoch` field MUST NOT participate in the quota key;
  otherwise an attacker could rotate `epoch` per batch to land each batch in a
  fresh bucket and bypass `max_psi_queries_per_window`. `epoch` is used solely
  to select the OPRF key.
- The default window is 24h with `max_psi_queries_per_window = 1`.

The match phase returns a fixed-cardinality bitmap and padding count so response
shape does not reveal how many contacts were indexed or matched.

## Operational Tradeoffs

Anti-enumeration adds latency and can hide useful diagnostics from clients. The
operator-facing admin and audit surfaces are the intended place to investigate
why a row was filtered, stale, withdrawn, or marked divergent.

## `alsoKnownAs` Scope (spec 37ce729, B-E)

Directory MUST NOT use `alsoKnownAs` as a mention index, Directory primary key,
or delivery routing field. `alsoKnownAs` is a holder-side reverse endorsement
claim defined in `identity/identity-handles.md` §4.1; it is advisory display
data only. Resolve and search handlers in this directory (`resolve_handle`,
`resolve_realm`, `resolve_organization`, `search_actors`, `search_users`,
`search_organizations`) consult exclusively the canonical identifiers stored
on each row — `resource_id` (handle DID / realm id / organization DID),
`alias`, `invite_token`, `signed_link` — and never reach into any
`alsoKnownAs` value that may be cached inside `public_projection`. The
verifier-authority vs cache split (identity-handles §6 / §6.0) keeps the
Directory firmly on the cache side: it never asserts authoritative DID
bindings and never lets a holder-side endorsement decide who receives a
delivery.

## Internationalized handle and collision policy

Handle query input is prepared with the SDK RFC 8265-derived human-identifier
profile and UTS #46 domain profile. Chinese, Cyrillic, Greek and reasonable
mixed-script localparts are not rejected merely because they are non-ASCII.
Canonical rows use the prepared Unicode localpart and lowercase A-label domain;
noncanonical announced wire values fail schema validation.

UTS #39 skeletons do not define wire equality and are not query-time
canonicalization. A handle registrar MAY maintain an authority-local skeleton
index and return `handle_homograph_forbidden` when a new registration collides
inside that authority's handle namespace. teabay is a resolver/index cache, not
the issuing registrar, so it preserves the issuer's canonical handle and does
not invent a second cross-authority collision policy.

This separation also avoids a collision-membership oracle: resolve and search
paths do not reveal whether a candidate shares a skeleton with a registered
handle. Registrar-side collision checks remain behind the registrar's normal
authenticated, rate-limited registration boundary. A UTS #39 data upgrade
rebuilds only the registrar's derived collision index and never rewrites teabay
resource IDs, signed claims, or cached proof bytes.
