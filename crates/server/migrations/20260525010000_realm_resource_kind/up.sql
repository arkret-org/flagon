-- Introduce the dedicated Realm directory resource kind. Existing `space`
-- enum values are retained for legacy rows and future container discovery.

ALTER TYPE resource_kind ADD VALUE IF NOT EXISTS 'realm' BEFORE 'space';
