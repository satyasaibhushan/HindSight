-- Bounded throttling: one row per token holding only the current window. hindsight_* tables only.
-- Rows still cascade-delete with their token.
DELETE FROM hindsight_rate_limits r
  USING hindsight_rate_limits newer
  WHERE newer.token_id = r.token_id AND newer.window_start > r.window_start;

ALTER TABLE hindsight_rate_limits DROP CONSTRAINT hindsight_rate_limits_pkey;
ALTER TABLE hindsight_rate_limits ADD CONSTRAINT hindsight_rate_limits_pkey PRIMARY KEY (token_id);
DROP INDEX IF EXISTS hindsight_rate_limits_window_idx;
