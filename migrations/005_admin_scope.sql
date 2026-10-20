-- Admin API keys and review bookkeeping. Additive only; hindsight_* tables only.
-- The scope set widens to a superset, so every existing token stays valid as an ingest key.
ALTER TABLE hindsight_ingestion_tokens DROP CONSTRAINT IF EXISTS hindsight_ingestion_tokens_scope_check;
ALTER TABLE hindsight_ingestion_tokens ADD CONSTRAINT hindsight_ingestion_tokens_scope_check
  CHECK (scope IN ('feedback:submit', 'feedback:admin'));

-- When an item last entered actioned/dismissed (reviewed_at stays "last state change"), plus the
-- owner's private review note. All nullable; existing rows are unchanged.
ALTER TABLE hindsight_feedback
  ADD COLUMN actioned_at timestamptz,
  ADD COLUMN dismissed_at timestamptz,
  ADD COLUMN review_note text CHECK (char_length(review_note) BETWEEN 1 AND 2000);
