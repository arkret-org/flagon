# Scaling Guide

teabay is a Rust + Diesel + PostgreSQL service: throughput is bounded
by the Postgres connection pool, the per-resource ingest rate limit,
and the synchronous diesel call path. This guide walks operators
through tuning the connection pool for a given target QPS.

## Connection pool

The pool is configured at boot via env. Defaults shown below come
from `crate::config::DbPoolConfig::default`.

| Env                                         | Default | Effect |
|---------------------------------------------|---------|--------|
| `TEABAY_DB_POOL_MAX_SIZE`                   | 16      | Hard ceiling on concurrent connections. Includes background workers + admin queries. |
| `TEABAY_DB_POOL_CONNECTION_TIMEOUT_SECS`    | 5       | How long `pool.get()` waits before returning a `Timeout`. |

### Sizing rule of thumb

Pick `max_size` so the pool can absorb your **peak concurrent
in-flight diesel calls** without queuing:

```
max_size = (target QPS) × (avg diesel call latency in seconds) × 1.5
```

The `× 1.5` is the safety margin for background workers + admin
queries that share the pool.

Examples:

| Profile         | Target QPS | Avg diesel latency | Suggested `max_size` |
|-----------------|------------|--------------------|----------------------|
| dev laptop      | 5          | 0.01 s             | 1 (floored to 4)     |
| small prod      | 100        | 0.02 s             | 8                    |
| medium prod     | 500        | 0.02 s             | 20                   |
| heavy ingest    | 2000       | 0.03 s             | 96                   |

Always confirm against `pg_stat_activity` — if Postgres's own
`max_connections` is below `instances × max_size`, you'll get
connection-refused errors well before saturating CPU. Reserve at
least 8 connections per instance for diesel migrations, admin
queries, and the pull/divergence workers.

### Per-resource rate limit interplay

`TEABAY_RATE_LIMIT_PER_RESOURCE_PER_MIN` caps how many announces a
single `resource_id` can land per minute. The default of 60 ≈ 1 QPS
per resource. When you raise this for a busy publisher, also raise
`max_size` proportionally: the pool capacity is the second bottleneck
to absorb the burst.

> ⚠️ **Multi-replica caveat (in-process limiters).** The ingest /
> query rate limiters, the per-search-needle limiter, and the announce
> idempotency-replay cache are **in-process** (a `Mutex<HashMap<…>>` per
> replica), unlike the HTTP-signature replay store which is shared in
> Postgres across replicas. When you run N teabay replicas behind a load
> balancer, each replica enforces these limits independently, so the
> effective per-IP / per-resource / per-needle ceiling is **N× the
> configured value**, and announce replay de-duplication is per-replica.
> If you need a hard global ceiling or cross-replica replay dedup, pin
> the rate-limited paths to a single replica, or front them with a shared
> token-bucket (e.g. Redis). This is a deliberate scope limit, not a bug —
> the anti-enumeration latency floor/jitter still applies per request on
> every replica.

### Connection timeout

`TEABAY_DB_POOL_CONNECTION_TIMEOUT_SECS` MUST be ≤ the request
deadline your reverse proxy enforces. Otherwise a saturated pool
returns a `Timeout` to teabay only after the proxy has already
dropped the client, wasting Postgres work.

## Observability

The Prometheus scrape exposes live pool occupancy:

```
teabay_db_pool_connections   {value}  # total connections
teabay_db_pool_idle          {value}  # idle (parked) connections
teabay_db_pool_in_use        {value}  # checked-out connections
teabay_db_pool_max_size      {value}  # max_size at boot
```

Set an alert on `teabay_db_pool_in_use / teabay_db_pool_max_size > 0.8`
sustained for 5 minutes — that's the canary for "needs more
`max_size`" (or "Postgres needs more `max_connections`").

The ingest histogram (`teabay_ingest_total{kind,outcome}`) and the
query latency gauge (`teabay_query_latency_seconds{op}`) are the two
other dials that let you derive the right `max_size` empirically from
production traffic.

## Background workers

- `divergence_worker` is disabled by default. When enabled it adds
  one more long-held connection per cycle.

## Future work

`TODO(circle-rollout-P2E.5)` lands a dedicated expiry worker on the
`expires_at` index from migration `20260526010000_add_freshness`.
That worker will add ~1 more connection of steady-state load.
