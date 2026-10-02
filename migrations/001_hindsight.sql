-- HindSight schema. Additive only: touches nothing outside hindsight_* tables.
-- scripts/migrate.js wraps each file in a transaction; do not add BEGIN/COMMIT here.

CREATE TABLE IF NOT EXISTS hindsight_ingestion_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_email text NOT NULL CHECK (char_length(owner_email) BETWEEN 3 AND 320),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
  client text NOT NULL CHECK (char_length(client) BETWEEN 1 AND 80),
  scope text NOT NULL DEFAULT 'feedback:submit' CHECK (scope = 'feedback:submit'),
  token_hash text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  last_used_at timestamptz,
  revoked_at timestamptz,
  CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS hindsight_ingestion_tokens_owner_idx
  ON hindsight_ingestion_tokens (owner_email, created_at DESC);

CREATE TABLE IF NOT EXISTS hindsight_feedback (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_id uuid NOT NULL REFERENCES hindsight_ingestion_tokens (id) ON DELETE RESTRICT,
  owner_email text NOT NULL,
  client text NOT NULL,
  friction text NOT NULL CHECK (char_length(friction) BETWEEN 1 AND 4000),
  improvement text NOT NULL CHECK (char_length(improvement) BETWEEN 1 AND 4000),
  category text NOT NULL CHECK (category IN ('connector','tooling','environment','documentation','workflow','performance','other')),
  task text CHECK (char_length(task) <= 300),
  source text CHECK (char_length(source) <= 300),
  repository text CHECK (char_length(repository) <= 300),
  outcome text CHECK (outcome IN ('recovered','workaround','blocked','unresolved')),
  confidence text CHECK (confidence IN ('low','medium','high')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS hindsight_feedback_owner_idx
  ON hindsight_feedback (owner_email, created_at DESC);

CREATE TABLE IF NOT EXISTS hindsight_rate_limits (
  token_id uuid NOT NULL REFERENCES hindsight_ingestion_tokens (id) ON DELETE CASCADE,
  window_start timestamptz NOT NULL,
  count integer NOT NULL CHECK (count >= 0),
  PRIMARY KEY (token_id, window_start)
);
