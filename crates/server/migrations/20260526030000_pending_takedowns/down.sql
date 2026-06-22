-- Revert B.8.8.
DROP INDEX IF EXISTS withdrawals_active_takedown_idx;
DROP INDEX IF EXISTS takedown_appeals_status_idx;
DROP INDEX IF EXISTS takedown_appeals_takedown_idx;
DROP TABLE IF EXISTS takedown_appeals;
ALTER TABLE withdrawals
    DROP COLUMN IF EXISTS overturn_receipt,
    DROP COLUMN IF EXISTS overturn_appeal_id,
    DROP COLUMN IF EXISTS overturned_at;
DROP TABLE IF EXISTS pending_takedown_webhooks;
DROP TABLE IF EXISTS pending_takedown_approvals;
DROP INDEX IF EXISTS pending_takedowns_notification_due_idx;
DROP INDEX IF EXISTS pending_takedowns_status_idx;
DROP TABLE IF EXISTS pending_takedowns;
