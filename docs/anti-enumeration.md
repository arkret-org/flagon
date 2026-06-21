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

## Handle homograph reject path (R3 wire-level enforcement)

R3 closes a long-standing side channel by moving NFC and UTS#39
confusable-skeleton enforcement **before** the rate-limit gate at the
wire layer. teabay inherits this enforcement: any handle write or
handle-bearing query against teabay surfaces the
`handle_homograph_forbidden` error from the wire layer before
rate-limit token accounting runs.

Companion documentation:

- [`starid/docs/operations.md` → Handle homograph workflow](../../starid/docs/operations.md#handle-homograph-workflow) for triage and audit.
- [`cokret-rust-sdk/docs/architecture.md`](../../cokret-rust-sdk/docs/architecture.md) for the SDK normalize helper.
- [`yougen/docs/user-manual/r3-error-codes.md` → handle_homograph_forbidden](../../yougen/docs/user-manual/r3-error-codes.md#handle_homograph_forbidden) for the user-facing message.

### Wire-level order vs application-level order

```text
inbound request
      │
      ▼
[1. transport / signature verify]
      │
      ▼
[2. handle canonicalization]  ← was application-level, post-rate-limit
      │     - NFC normalize
      │     - UTS#39 confusable skeleton check
      │     - script-mixing reject
      │     - blocklist / collision check
      ▼
[3. rate-limit token-bucket]
      │
      ▼
[4. application handler]
```

Pre-R3 step (2) ran inside step (4), which produced a side channel: an
attacker could probe whether a candidate handle was confusable with a
high-value existing handle by submitting it and observing whether the
rate-limiter responded (no collision) or the application-layer reject
fired (collision). The attacker's token budget was the only enumeration
budget; even modest rate-limit allowances let an attacker enumerate the
confusable skeleton space.

By moving step (2) ahead of step (3), R3 collapses the side channel:

1. **Constant-time-from-the-attacker reject ordering.** Any
   canonicalization reject fires from the same wire-layer code path
   regardless of token-bucket state.
2. **Rate-limit budget is unaffected by confusable probes.** A
   confusable submission is rejected at the wire layer; the rate
   limiter is never consulted, so the attacker cannot use the
   rate-limit-vs-handler decision boundary to leak collision
   membership.
3. **Metric exposure surfaces enumeration without the rate limiter
   alerting on it.** The metric
   `teabay_handle_homograph_forbidden_total{reason}` rises on every
   wire-layer reject; alerting on a per-realm baseline catches
   enumeration that would otherwise be invisible inside the noise of
   the rate-limit log.

### Rejection categories visible at teabay

When teabay forwards a handle-bearing request and the wire layer
returns `handle_homograph_forbidden`, the response carries one of:

| `reason` | What it means |
|---|---|
| `non_nfc` | Input bytes were not in Unicode NFC form. The canonical form is computable; clients SHOULD pre-normalize. |
| `mixed_script` | The handle mixes incompatible Unicode scripts (e.g. Latin + Cyrillic). |
| `disallowed_codepoint` | A codepoint outside the allowed identifier set was present. |
| `skeleton_collision` | The UTS#39 confusable skeleton collides with an existing handle. |

`mixed_script` and `skeleton_collision` are the two reasons most
relevant to enumeration defense; `non_nfc` and `disallowed_codepoint`
are well-formedness rejects that fire for honest mistakes too.

### Operational note

Operators who watch teabay dashboards for enumeration patterns SHOULD
now alert on `teabay_handle_homograph_forbidden_total{reason="skeleton_collision"}`
crossing a per-realm baseline, NOT on rate-limit metrics alone. Rate-
limit metrics still matter for general abuse signaling, but R3's wire-
level enforcement means rate limits no longer hide the homograph signal.
