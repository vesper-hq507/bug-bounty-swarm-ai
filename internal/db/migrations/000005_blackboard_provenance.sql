-- 000005_blackboard_provenance.sql
-- Persist per-finding Ed25519 provenance so SecureBoard can verify shared
-- memory across process restarts and Postgres-backed campaigns.

ALTER TABLE swarm_findings
    ADD COLUMN IF NOT EXISTS provenance_public_key BYTEA,
    ADD COLUMN IF NOT EXISTS provenance_signature BYTEA,
    ADD COLUMN IF NOT EXISTS provenance_signed_unix BIGINT;

CREATE INDEX IF NOT EXISTS idx_swarm_findings_provenance_missing
    ON swarm_findings(campaign_id, created_at DESC)
    WHERE provenance_signature IS NULL;
