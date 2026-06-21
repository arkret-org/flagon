-- Revert B.8.8.
DROP TABLE IF EXISTS pending_takedown_webhooks;
DROP TABLE IF EXISTS pending_takedown_approvals;
DROP INDEX IF EXISTS pending_takedowns_notification_due_idx;
DROP INDEX IF EXISTS pending_takedowns_status_idx;
DROP TABLE IF EXISTS pending_takedowns;
