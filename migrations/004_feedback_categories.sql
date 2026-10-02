-- Additive category expansion: instructions, skills, codebase, collaboration. hindsight_* tables only.
-- The new allowed set is a superset of the old one, so every existing row stays valid; no data changes.
ALTER TABLE hindsight_feedback DROP CONSTRAINT IF EXISTS hindsight_feedback_category_check;
ALTER TABLE hindsight_feedback ADD CONSTRAINT hindsight_feedback_category_check
  CHECK (category IN ('instructions', 'skills', 'codebase', 'collaboration',
    'connector', 'tooling', 'environment', 'documentation', 'workflow', 'performance', 'other'));
