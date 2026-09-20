# teabay operator notes

These notes describe the current D2 read-only Realm Directory candidate:

- [Architecture](architecture.md): authority and storage boundaries.
- [Deployment](deployment.md): supported configuration and fresh-install checks.
- [Operations](operations.md): health, metrics, and operator audit.
- [Scaling](scaling.md): query pool and rate-limit knobs.

Old ingest, private-contact, Circle, non-Realm query, webhook, takedown, and
direct-edit runbooks were removed because their endpoints and tables are not
present in this candidate. The unresolved Station-direct announce
proof/currentness question is tracked in arkret-work spec-open 0350; these
notes do not authorize a write route.
