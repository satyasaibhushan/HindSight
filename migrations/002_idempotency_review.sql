-- Owner-scoped idempotency, review state, and broader outcomes. hindsight_* tables only.
ALTER TABLE hindsight_feedback
  ADD COLUMN request_id text CHECK (request_id ~ '^[A-Za-z0-9._:-]{8,128}$'),
  ADD COLUMN payload_hash text CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
  ADD COLUMN review_state text NOT NULL DEFAULT 'new'
    CHECK (review_state IN ('new', 'triaged', 'actioned', 'dismissed')),
  ADD COLUMN reviewed_at timestamptz;

UPDATE hindsight_feedback SET request_id = 'legacy-' || id::text, payload_hash = repeat('0', 64)
  WHERE request_id IS NULL;
ALTER TABLE hindsight_feedback
  ALTER COLUMN request_id SET NOT NULL,
  ALTER COLUMN payload_hash SET NOT NULL;

-- One logical submission per owner and request_id, regardless of which token retried it.
CREATE UNIQUE INDEX hindsight_feedback_owner_request_uq
  ON hindsight_feedback (owner_email, request_id);
CREATE INDEX hindsight_feedback_owner_state_idx
  ON hindsight_feedback (owner_email, review_state, created_at DESC);

ALTER TABLE hindsight_feedback DROP CONSTRAINT IF EXISTS hindsight_feedback_outcome_check;
ALTER TABLE hindsight_feedback ADD CONSTRAINT hindsight_feedback_outcome_check
  CHECK (outcome IN ('completed', 'recovered', 'workaround', 'failed', 'blocked', 'unresolved'));

CREATE INDEX hindsight_rate_limits_window_idx ON hindsight_rate_limits (window_start);
