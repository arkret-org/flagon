CREATE TABLE IF NOT EXISTS http_signature_replays (
    replay_key BYTEA PRIMARY KEY,
    key_id TEXT NOT NULL,
    signature BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS http_signature_replays_expires_at_idx
    ON http_signature_replays (expires_at);
