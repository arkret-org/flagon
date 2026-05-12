CREATE TABLE psi_epoch_keys (
    epoch      TEXT        PRIMARY KEY,
    profile    TEXT        NOT NULL,
    server_key BYTEA       NOT NULL,
    public_key BYTEA       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX psi_epoch_keys_expires_at_idx
    ON psi_epoch_keys (expires_at);
