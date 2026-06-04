ALTER TABLE directory_resources
    DROP COLUMN IF EXISTS member_count_bucket_since,
    DROP COLUMN IF EXISTS member_count_bucket_locked,
    DROP COLUMN IF EXISTS member_count_real_bucket;
