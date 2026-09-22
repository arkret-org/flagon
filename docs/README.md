# teabay operator notes

These notes describe the current-v1 read-only Realm Directory:

- [Architecture](architecture.md): authority and storage boundaries.
- [Deployment](deployment.md): supported configuration and fresh-install checks.
- [Operations](operations.md): health, metrics, and operator audit.
- [Scaling](scaling.md): query pool and rate-limit knobs.

Old ingest, private-contact, Circle, non-Realm query, webhook, takedown, and
direct-edit runbooks were removed because their endpoints and tables are not
part of current-v1. These notes do not authorize a protocol write route.
