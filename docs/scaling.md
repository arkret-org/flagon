# Read-only query sizing

Flagon performs only public Realm searches/resolves and
operator audit reads. `FLAGON_DB_POOL_MAX_SIZE` sets the PostgreSQL connection
pool size (default 16); `FLAGON_DB_POOL_CONNECTION_TIMEOUT_SECS` controls how
long a request waits for a connection (default 5 seconds). Size the pool to
the database's connection budget and measured concurrent query load, leaving
room for migrations and operator access.

`FLAGON_QUERY_MAX_QUERIES_PER_IP_PER_MIN` and
`FLAGON_QUERY_MAX_RESOLVES_PER_RESOURCE_PER_MIN` cap the read face; zero
disables a limit. Behind a proxy, configure `FLAGON_TRUSTED_PROXY` only for
known proxy IPs so arbitrary clients cannot spoof the rate-limit address.

There is no ingest, revalidation, PCD, or takedown worker to size.
