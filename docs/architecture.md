# Architecture

teabay is the discovery entry layer for Arkret Directory Service traffic. It
accepts signed discovery state from resource Principal Servers, indexes the
public projection, and serves search and resolve endpoints with the directory
result envelope required by the protocol.

teabay is not the source of truth for a resource. The source Principal Server
remains authoritative for identity, membership, authorization, and event state.

## Runtime Shape

```text
client or SDK
    |
    v
Salvo router
    |
    +-- /_arkret/find/directory/describe
    |
    +-- query face
    |      search-realms
    |      resolve-realm
    |      search-organizations
    |      resolve-organization
    |      search-actors
    |      search-users
    |      resolve-handle
    |
    +-- ingest face
    |      announce
    |      withdraw
    |      push/register
    |
    +-- /_teabay/admin/*
    |
    +-- /health
    |
    +-- /readyz

separate listener (TEABAY_METRICS_BIND)
    |
    +-- /metrics
```

The query face is read-only. The ingest face is protected by the HTTP Message
Signature middleware when `TEABAY_REQUIRE_HTTP_SIG=true`, then each announce or
withdrawal runs the handler-level verification chain.

## Main Components

- `crates/server/src/routing.rs` wires public directory routes, admin routes,
  `/health`, and OpenAPI metadata.
- `crates/server/src/config.rs` reads environment configuration and builds the
  advertised service capabilities used by `/_arkret/find/directory/describe`.
- `crates/server/src/ingest/` handles push announce, withdrawal, webhook
  subscription, verification, and freshness checks.
- `crates/server/src/query/` builds the search and resolve responses from
  indexed `directory_resources` rows.
- `crates/server/src/filter/` contains the shared result envelope and
  anti-enumeration helpers.
- `crates/server/src/observability.rs` holds dependency-free Prometheus metrics
  and local timing counters.
- `crates/admin/` is the Dioxus operator console for resources, allowlist,
  takedown, audit, and review workflows.

## Data Model

PostgreSQL is the system of record for the directory index.

- `directory_resources` stores the effective indexed row for each
  `(resource_kind, resource_id)` pair.
- `ingest_announces` records accepted announce attempts and request digests.
- `withdrawals` records resource and operator withdrawal activity.
- `webhook_subscriptions` tracks push notification fanout registrations.
- `accept_allowlist` stores operator-managed accept-policy entries.
- `directory_audit` is the append-only operator-readable audit feed.

Diesel migrations live in `crates/server/migrations/` and are auto-applied at
server startup by the server crate.

## Request Strand

Push announce:

1. The router authenticates ingest transport with HTTP Message Signatures when
   enforcement is enabled.
2. The announce handler validates request shape, replay/idempotency state, TTL,
   and monotonic `as_of` ordering.
3. The verify chain checks freshness, DID method policy, accept policy, source
   references, and directory-service opt-in.
4. The server derives a public projection, stores the effective resource row,
   records the announce, and writes an audit event.
5. Registered webhooks receive best-effort accepted-ingest fanout.

Query or resolve:

1. The handler loads candidate rows from `directory_resources`.
2. Discoverability, requester, and realm policy filters decide whether the row
   may be surfaced.
3. Hidden and absent resources return the same public miss shape.
4. Returned hits include `as_of`, `source_refs`, `policy_revision`, `stale`,
   `divergent`, and `via_services` when applicable.

## Background Work

Pull ingest is not implemented because v1 does not yet define the required
Directory-specific state-only read operation and DTO. Teabay advertises push
ingest only and never falls back to the forbidden self Events API.

Cross-directory divergence detection is not implemented: peer core ids cannot
be mapped through verified current service-resolution records yet, and Teabay
never derives a URL from an id.

`/readyz` checks PostgreSQL reachability. Metrics
are isolated from public API traffic by binding `/metrics` to
`TEABAY_METRICS_BIND`, defaulting to loopback.

## Current Limitations

- In-process OTLP export via `tracing-opentelemetry` is deferred to a
  dependency-refresh slice; use an OTel Collector to scrape Prometheus and
  collect tracing logs.
- The operator takedown path is audit-backed and webhook fanout is HMAC-signed
  with retry/DLQ status tracking; delivery remains best effort.
- Webhook fanout is best effort and does not use a durable retry queue.
