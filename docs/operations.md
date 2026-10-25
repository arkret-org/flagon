# Operations

`GET /health` reports process liveness; `GET /readyz` checks PostgreSQL
readiness. Prometheus metrics are on the separate `FLAGON_METRICS_BIND`
listener (default `127.0.0.1:9095`) at `/metrics`. Only mounted Realm search
and resolve latency series are emitted. A fresh index is empty until an
operator explicitly confirms and loads public metadata.

## Private index maintenance

`flagon-index` is a deployment-local process using `DATABASE_URL` directly.
It exposes no HTTP listener, SDK operation, ServiceDescribe write capability,
callback, or automatic revalidation/renewal worker. The public protocol still
contains exactly describe, search_realms and resolve_realm.

Start the service once against the current fresh schema to apply its migration.
Give the maintenance PostgreSQL role only schema USAGE, SELECT/INSERT/UPDATE/
DELETE on `directory_public_realm_entries`, SELECT/INSERT on `directory_audit`,
and USAGE on `directory_audit_audit_id_seq`. Do not use the read-service role
or an audit HTTP bearer as a maintenance credential. Keep database credentials
outside command arguments and public/browser environments. OS access to the
binary, configuration and database role is the deployment authorization boundary.

For example (substitute the deployed schema and a provisioned login role):

```sql
GRANT USAGE ON SCHEMA public TO directory_maintenance;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.directory_public_realm_entries TO directory_maintenance;
GRANT SELECT, INSERT ON public.directory_audit TO directory_maintenance;
GRANT USAGE ON SEQUENCE public.directory_audit_audit_id_seq TO directory_maintenance;
```

An operator must verify the Realm's current public status outside the Directory
and prepare a UTF-8 JSON file, at most 16 KiB. This is private deployment input,
not a new Arkret DTO. All fields are required; `public_metadata` uses the SDK's
closed `PublicRealmMetadata` shape. Unknown fields, private discovery states,
source refs, authority/membership/join material and asserted operator DIDs are
rejected. The confirmation is the operator's statement, not a governance proof.

```json
{
  "realm_id": "ak:realm:AXXwKm5bWs7Plj3J5iRyqGeeNU99_oZCMnjtWom6sFeR",
  "public_metadata": {"display_name": "Public Realm", "summary": "Discovery hint"},
  "discoverability": "public",
  "confirmed_at": "2026-10-20T01:00:00.000Z",
  "expires_at": "2026-10-20T02:00:00.000Z",
  "reason": "Operator checked current public status"
}
```

Use actual UTC millisecond timestamps, not the example timestamps.
`confirmed_at <= database now < expires_at`; the deployment maximum is 24 hours
from confirmation. `indexed_at` is assigned by the Directory's database clock.
Loading needs a separate explicit acknowledgement:

```bash
cargo run -p server --bin flagon-index -- load public-realm.json --confirm-public
cargo run -p server --bin flagon-index -- remove 'ak:realm:AXXwKm5bWs7Plj3J5iRyqGeeNU99_oZCMnjtWom6sFeR' --reason 'Public status withdrawn'
cargo run -p server --bin flagon-index -- purge-expired --reason 'Expired local entries'
```

The binary also accepts the normal `--config FILE` and `--no-env-overrides`
configuration-source options. Its command output is JSON. Load returns the
same four-field public Directory entry read by search/resolve. Remove returns
`{"hidden":true}`, including for an unknown Realm. Purge returns its row count.
Failures exit nonzero and commit no index or audit change; retry after correcting
the input or database privileges. The CLI does not apply migrations itself.

A byte-equivalent confirmation retry preserves both `indexed_at` and the absolute
`expires_at`. A newer confirmation can replace an entry; an older confirmation,
or different metadata/expiry under the same confirmation time, is rejected.
To renew, first recheck current public state and create a new confirmation with
fresh timestamps. Do not schedule blind replays or timestamp rewriting.

For a change to listed/restricted/unlisted/invite_only/secret, run `remove`
immediately; attempting to load a nonpublic file is an error and does not perform
the separate removal action. Remove erases metadata and retains a hidden local
Realm/time fence whose expiry covers one confirmation window, preventing delayed
old input from republishing it. An explicit fresh public confirmation after removal
may publish again. Purge removes expired entries/fences and never extends TTL.

Rows without `confirmed_public_at`, removed rows, expired rows and unknown IDs
are hidden from both public reads, including exact resolve. Never copy retired
schema rows into this table or set confirmation fields by raw SQL. The local
confirmation/removal fields, reasons and database identity never enter public
responses. Discovery results remain locator hints; consumers still verify current
governance and authorization at the target Station.

## Atomic operator audit

Every successful mutation and its chained audit append share one PostgreSQL
transaction and a common lock order. A role with index write privileges but
without audit insert/sequence privileges cannot commit an unaudited mutation.
The audit records action, reason, Realm/scope, time, expiry/impact and database
`current_user`, `session_user`, and database name read from that same connection.
Authentication is recorded as `postgresql_role`; `actor_id` is empty. No caller
supplied principal/DID is treated as verified identity. The credential identifier
is a digest of the database identity, never a database password or HTTP token.
Denied database operations remain in deployment/database logs, not in a fabricated
successful audit append. Database owners can bypass application controls; restrict
these privileges and protect the append-only audit table operationally.

For review, use `GET /_flagon/admin/audit` with a valid admin token and
`GET /_flagon/admin/audit/verify` to check the append-only digest chain. The
Glory/Sapid console in `crates/admin` exposes only those two reads. These existing HTTP
credentials authorize audit reads only and cannot invoke the maintenance process.
There is no Directory protocol write admission, allowlist, source callback,
webhook retry, private-contact/PSI batch, or new notification receipt to operate.
