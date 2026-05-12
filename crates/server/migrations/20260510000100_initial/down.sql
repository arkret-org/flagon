DROP TABLE IF EXISTS directory_audit;
DROP TABLE IF EXISTS accept_allowlist;
DROP TABLE IF EXISTS webhook_subscriptions;
DROP TABLE IF EXISTS pull_subscriptions;
DROP TABLE IF EXISTS withdrawals;
DROP TABLE IF EXISTS ingest_announces;
DROP TABLE IF EXISTS directory_resources;

DROP TYPE IF EXISTS audit_event_kind;
DROP TYPE IF EXISTS withdrawal_kind;
DROP TYPE IF EXISTS accept_policy_kind;
DROP TYPE IF EXISTS ingest_mode;
DROP TYPE IF EXISTS discoverability;
DROP TYPE IF EXISTS resource_kind;
