-- Spec §3 `bucketed` member_count anti-enumeration: hysteresis / minimum
-- residency for the publicly-emitted member-count bucket.
--
-- The real (instantaneous) bucket can oscillate across a grid boundary
-- (e.g. 10↔11) on every announce/heartbeat. Emitting it verbatim lets an
-- attacker who polls the directory watch the bucket flip and binary-search
-- the exact member count. §3 therefore requires the emitted bucket to stay
-- pinned for a minimum residency window (default SHOULD ≥ the entry's
-- refresh TTL) after it changes.
--
-- Three bookkeeping columns make the residency stateful:
--   * `member_count_real_bucket`    — bucket of the latest *real* count.
--   * `member_count_bucket_locked`  — bucket currently emitted publicly
--     (mirrored into `public_projection->>'member_count_bucket'`).
--   * `member_count_bucket_since`   — when `member_count_bucket_locked`
--     last changed; residency is measured from here.
--
-- Backfill: legacy rows adopt their current projection bucket as both the
-- real and locked value, pinned since `last_refreshed_at`.

ALTER TABLE directory_resources
    ADD COLUMN member_count_real_bucket   TEXT,
    ADD COLUMN member_count_bucket_locked TEXT,
    ADD COLUMN member_count_bucket_since  TIMESTAMPTZ;

UPDATE directory_resources
   SET member_count_real_bucket   = public_projection->>'member_count_bucket',
       member_count_bucket_locked = public_projection->>'member_count_bucket',
       member_count_bucket_since  = last_refreshed_at
 WHERE public_projection ? 'member_count_bucket';
