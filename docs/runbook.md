# Operator Runbook

Concise day-two runbook for the teabay Directory Service. For background and
deeper procedures see [operations.md](operations.md), [scaling.md](scaling.md),
and [takedown-receipts.md](takedown-receipts.md).

teabay is a salvo + diesel service backed by PostgreSQL. The main HTTP API
listens on `TEABAY_BIND` (default `0.0.0.0:7781`); a separate Prometheus
listener binds `TEABAY_METRICS_BIND` (default `127.0.0.1:9095`).

## Health & Readiness

| Endpoint | Purpose | Healthy response |
| --- | --- | --- |
| `GET /health` (alias `/healthz`) | Process liveness | `200`, `{"ok": true, "service": "teabay", "hardening": {…}}` |
| `GET /readyz` | Readiness (DB + workers) | `200`, `{"ok": true, …}` |

- `/health` is a pure liveness probe — it returns `200` as long as the process
  serves HTTP. The `hardening` block is derived from live config and reports
  `development_mode`, `tls_enabled`, `cors_strict`, `admin_auth_mode`,
  `rate_limit_enabled`, and a `checklist_score`/`checklist_max` pair. This is
  the probe wired into the Docker `HEALTHCHECK` (`wget --spider` on
  `http://127.0.0.1:7781/health`).
- `/readyz` returns `200` only when PostgreSQL answers `SELECT 1` **and** every
  enabled background worker has a recent heartbeat. The body reports
  `database.ok` plus a `workers` map with two workers:
  - `pull` — pull-mode revalidation worker.
  - `divergence` — divergence-detection worker.

  Each worker entry reports `enabled`, `ready`, `last_seen_ms_ago`, and
  `stale_after_ms`. A disabled worker (`enabled=false`) does not block
  readiness. A `503` means DB is down or an enabled worker is stale.

Use `/health` for liveness/restart decisions and `/readyz` for load-balancer
admission. In Kubernetes wire `/health` as the liveness probe and `/readyz` as
the readiness probe.

## Failover / Restart

Durable state lives entirely in **PostgreSQL** (`directory_resources`,
`ingest_announces`, `withdrawals`, `pull_subscriptions`, `directory_audit`).
The teabay process itself is stateless — restarting it loses nothing. The
admin SPA is a separate static image and can be restarted independently.

Safe restart:

1. Drain the instance from the load balancer (it stops passing `/readyz`).
2. Restart the process / pod. Migrations are embedded and run at boot.
3. Wait for `/readyz` to return `200`. On boot the worker heartbeats start
   stale, so allow up to `stale_after_ms` for `pull`/`divergence` to report
   `ready=true`.
4. Confirm `hardening.admin_auth_mode` is `production` and
   `development_mode=false` on `/health` before re-admitting traffic.

PostgreSQL is the single source of truth — fail over the database with your
normal Postgres HA process; teabay reconnects through its r2d2 pool.

## Maintenance

**PostgreSQL.** Back up before any migration or retention change; backups are
sensitive (resource metadata). Routine `VACUUM`/`ANALYZE` on the high-churn
tables (`directory_resources`, `directory_audit`) keeps query latency stable.
Watch `directory_audit` growth and archive per retention policy.

**Takedown audit review.** Export the full takedown audit with
`GET /api/admin/v1/takedowns` (optional `since`/`until`) for legal/ops review,
or browse via `GET /api/admin/v1/audit`. Receipt verification steps are in
[operations.md](operations.md#audit-review) and
[takedown-receipts.md](takedown-receipts.md).

**Ingest debugging.** Ingest (`announce`/`withdraw`/`subscribe`) is hardened by
RFC 9421 HTTP Message Signature middleware keyed by the
`TEABAY_HTTP_SIG_PUBKEYS` allowlist. A rejected announce is almost always a
signature/keyid mismatch or an accept-policy rejection — check the audit feed
and `ingest_announces`. For pull-mode, inspect `pull_subscriptions.last_error`
and `consecutive_failures`.

## Debugging

**Logs.** teabay uses `tracing` to stdout/stderr; set `RUST_LOG` (e.g.
`RUST_LOG=info`, `debug` only for short investigations). In production
(`TEABAY_DEVELOPMENT_MODE=false`) `resource_id` and `service_did` are redacted.

**Metrics.** Scrape `http://<TEABAY_METRICS_BIND>/metrics` (default
`127.0.0.1:9095`). Key series:

- `teabay_ingest_total{kind,outcome}` — ingest accept/reject rates.
- `teabay_query_latency_seconds{op}` — query latency.
- `teabay_pull_worker_revalidations_total{outcome}` — pull worker health.
- `teabay_divergence_detected_total` — divergence worker activity.
- `teabay_db_pool_connections` / `_idle` / `_in_use` / `_max_size` — live r2d2
  pool occupancy.

**Common failure modes.**

- **DB pool exhaustion.** `teabay_db_pool_in_use` pinned at
  `teabay_db_pool_max_size` (set via `TEABAY_DB_POOL_MAX_SIZE`) with `_idle`
  near zero; `/readyz` flips to `503` with `database.ok=false` when checkouts
  time out. Raise the pool size or shed load; check for slow/long-running
  queries holding connections.
- **Stale workers.** `/readyz` returns `503` with a worker showing
  `ready=false` and a large `last_seen_ms_ago` (> `stale_after_ms`). The worker
  loop has stalled or the process is overloaded — inspect logs for that worker
  and restart if it does not recover.
- **Accidental dev-mode deploy.** `/health` `hardening.development_mode=true`
  or `admin_auth_mode` not `production` — log redaction is off and admin auth
  may be open. Treat as an incident; set `TEABAY_DEVELOPMENT_MODE=false` and a
  non-empty `TEABAY_ADMIN_TOKEN`, then restart.
