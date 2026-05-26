-- Phase P2 — revert DID normalization audit CHECK constraints.
ALTER TABLE ingest_announces
    DROP CONSTRAINT IF EXISTS ingest_announces_principal_server_did_shape_chk;
ALTER TABLE ingest_announces
    DROP CONSTRAINT IF EXISTS ingest_announces_resource_id_did_shape_chk;
ALTER TABLE directory_resources
    DROP CONSTRAINT IF EXISTS directory_resources_principal_server_did_shape_chk;
ALTER TABLE directory_resources
    DROP CONSTRAINT IF EXISTS directory_resources_resource_id_did_shape_chk;
