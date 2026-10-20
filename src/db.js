// All queries are parameterized and scoped to hindsight_* tables plus owner/token.
export const REVIEW_STATES = ['new', 'triaged', 'actioned', 'dismissed'];
// Primary: the user's shared instructions, skills, codebase, and collaboration. The rest are kept for
// compatibility with existing rows and clients. Must match migrations/004_feedback_categories.sql.
export const CATEGORIES = ['instructions', 'skills', 'codebase', 'collaboration',
  'connector', 'tooling', 'environment', 'documentation', 'workflow', 'performance', 'other'];
export const OUTCOMES = ['completed', 'recovered', 'workaround', 'failed', 'blocked', 'unresolved'];
export const PAGE_SIZE = 25;
export const MAX_PAGE = 40;
export const TOKEN_PAGE_SIZE = 50;
const FEEDBACK_COLUMNS = `id, client, request_id, friction, improvement, category, task, source, repository, outcome,
  confidence, review_state, review_note, reviewed_at, actioned_at, dismissed_at, created_at`;
// $S is the requested state (NULL keeps the current one). reviewed_at is the last state change;
// actioned_at/dismissed_at record when the item last entered that state, and are kept afterwards.
const SET_STATE = (S) => `review_state = COALESCE(${S}::text, review_state),
  reviewed_at = CASE WHEN ${S}::text IS NULL THEN reviewed_at ELSE now() END,
  actioned_at = CASE WHEN ${S}::text = 'actioned' AND review_state <> 'actioned' THEN now() ELSE actioned_at END,
  dismissed_at = CASE WHEN ${S}::text = 'dismissed' AND review_state <> 'dismissed' THEN now() ELSE dismissed_at END`;
// Fail before client/Vercel deadlines; the server-side limits stop work in PostgreSQL too.
export const PG_POOL_OPTIONS = Object.freeze({
  max: 3, connectionTimeoutMillis: 5000, lock_timeout: 3000,
  statement_timeout: 10000, query_timeout: 12000,
});

export const MAX_LIST_LIMIT = 100;
export const MAX_BULK = 100;
const toToken = (r) => ({ id: r.id, ownerEmail: r.owner_email, client: r.client, name: r.name, scope: r.scope });

export function createPgStore(pool) {
  const q = (text, values) => pool.query(text, values);
  return {
    // Revocation, expiry, and scope are re-checked on every request.
    async authenticateIngestionToken(tokenHash) {
      const { rows } = await q(
        `SELECT id, owner_email, client, name, scope FROM hindsight_ingestion_tokens
         WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
           AND scope IN ('feedback:submit', 'feedback:admin')`, [tokenHash]);
      return rows[0] ? toToken(rows[0]) : null;
    },
    // Canonical allow-listed owners authenticate, throttle, and record usage in one round trip.
    // Keep the JS trim/lowercase fallback for legacy owners: SQL lower/btrim does not have
    // exactly the same Unicode semantics, and rejected owners must never consume the limit.
    async authenticateAndRateLimit(tokenHash, reviewers, limit) {
      const { rows } = await q(
        `WITH token AS MATERIALIZED (
           SELECT id, owner_email, client, name, scope FROM hindsight_ingestion_tokens
           WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
             AND scope IN ('feedback:submit', 'feedback:admin')
         ), hit AS (
           INSERT INTO hindsight_rate_limits AS r (token_id, window_start, count)
           SELECT id, date_trunc('minute', now()), 1 FROM token WHERE owner_email = ANY($2::text[])
           ON CONFLICT (token_id) DO UPDATE SET
             window_start = GREATEST(r.window_start, EXCLUDED.window_start),
             count = CASE WHEN EXCLUDED.window_start > r.window_start THEN 1
                          ELSE LEAST(r.count + 1, $3::integer + 1) END
           RETURNING token_id, count
         ), used AS (
           UPDATE hindsight_ingestion_tokens SET last_used_at = now()
           WHERE id IN (SELECT token_id FROM hit)
             AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')
           RETURNING id
         ) SELECT t.id, t.owner_email, t.client, t.name, t.scope, h.count AS rate_count
           FROM token t LEFT JOIN hit h ON h.token_id = t.id`, [tokenHash, reviewers, limit]);
      const row = rows[0];
      const owner = typeof row?.owner_email === 'string' ? row.owner_email.trim().toLowerCase() : '';
      if (!row || !reviewers.includes(owner)) return { token: null, allowed: false };
      const token = toToken(row);
      const allowed = row.rate_count === null ? await this.hitRateLimit(row.id, limit) : row.rate_count <= limit;
      return { token, allowed };
    },
    // Bounded durable throttle: exactly one row per token (PK token_id) holding the current minute.
    // The upsert row lock serializes concurrent requests, so at most `limit` succeed per window.
    // Discovery counts too. Track authenticated usage once per minute without another round trip.
    async hitRateLimit(tokenId, limit) {
      const { rows } = await q(
        `WITH hit AS (INSERT INTO hindsight_rate_limits AS r (token_id, window_start, count)
         VALUES ($1, date_trunc('minute', now()), 1)
         ON CONFLICT (token_id) DO UPDATE SET
           window_start = GREATEST(r.window_start, EXCLUDED.window_start),
           count = CASE WHEN EXCLUDED.window_start > r.window_start THEN 1
                        ELSE LEAST(r.count + 1, $2::integer + 1) END
         RETURNING count), used AS (
           UPDATE hindsight_ingestion_tokens SET last_used_at = now()
           WHERE id = $1 AND EXISTS (SELECT 1 FROM hit)
             AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')
           RETURNING id
         ) SELECT count FROM hit`, [tokenId, limit]);
      return rows[0].count <= limit;
    },
    // Atomic idempotency: the unique (owner_email, request_id) index serializes concurrent retries.
    // payloadHash fingerprints the token-bound client plus normalized payload, so a rotated token for
    // the same owner/client replays, while another client reusing the request_id conflicts.
    // Returns { status: 'created' | 'replayed' | 'conflict', id, client } using the persisted row.
    async insertFeedback(token, f, payloadHash) {
      const ins = await q(
        `INSERT INTO hindsight_feedback (token_id, owner_email, client, request_id, payload_hash, friction,
           improvement, category, task, source, repository, outcome, confidence)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
         ON CONFLICT (owner_email, request_id) DO NOTHING RETURNING id, client`,
        [token.id, token.ownerEmail, token.client, f.request_id, payloadHash, f.friction, f.improvement,
          f.category, f.task ?? null, f.source ?? null, f.repository ?? null, f.outcome ?? null, f.confidence ?? null]);
      if (ins.rows[0]) return { status: 'created', id: ins.rows[0].id, client: ins.rows[0].client };
      const { rows } = await q(
        `SELECT id, client, payload_hash FROM hindsight_feedback WHERE owner_email = $1 AND request_id = $2`,
        [token.ownerEmail, f.request_id]);
      if (!rows[0]) throw new Error('idempotency_lookup_failed');
      const same = rows[0].payload_hash === payloadHash && rows[0].client === token.client;
      return { status: same ? 'replayed' : 'conflict', id: rows[0].id, client: rows[0].client };
    },
    // `states` (array) narrows to any of several review states, e.g. the Inbox's Open view (new + triaged);
    // a single `state` is still accepted.
    async listFeedback(ownerEmail, { category, state, states, client, page = 0 } = {}) {
      const { rows } = await q(
        `SELECT ${FEEDBACK_COLUMNS} FROM hindsight_feedback
         WHERE owner_email = $1 AND ($2::text IS NULL OR category = $2)
           AND ($3::text[] IS NULL OR review_state = ANY($3)) AND ($4::text IS NULL OR client = $4)
         ORDER BY created_at DESC, id DESC LIMIT $5 OFFSET $6`,
        [ownerEmail, category ?? null, states ?? (state ? [state] : null), client ?? null, PAGE_SIZE + 1,
          Math.min(Math.max(page, 0), MAX_PAGE) * PAGE_SIZE]);
      return { rows: rows.slice(0, PAGE_SIZE), hasMore: rows.length > PAGE_SIZE };
    },
    // Per-state totals for the owner's Inbox tabs, honouring the category/key filters. Every state is present.
    async countFeedback(ownerEmail, { category, client } = {}) {
      const { rows } = await q(
        `SELECT review_state, count(*)::int AS n FROM hindsight_feedback
         WHERE owner_email = $1 AND ($2::text IS NULL OR category = $2) AND ($3::text IS NULL OR client = $3)
         GROUP BY review_state`, [ownerEmail, category ?? null, client ?? null]);
      return Object.fromEntries(REVIEW_STATES.map((s) => [s, rows.find((r) => r.review_state === s)?.n ?? 0]));
    },
    // Admin listing: keyset pagination, newest first, like listTokens. The cursor (the last id on the
    // previous page) is resolved inside the owner-scoped subquery, so a foreign or unknown id yields no rows.
    async listFeedbackPage(ownerEmail, { category, state, client, before, limit = PAGE_SIZE } = {}) {
      const size = Math.min(Math.max(Number.isInteger(limit) ? limit : PAGE_SIZE, 1), MAX_LIST_LIMIT);
      const { rows } = await q(
        `SELECT ${FEEDBACK_COLUMNS} FROM hindsight_feedback
         WHERE owner_email = $1 AND ($2::text IS NULL OR category = $2)
           AND ($3::text IS NULL OR review_state = $3) AND ($4::text IS NULL OR client = $4)
           AND ($5::uuid IS NULL OR (created_at, id) < (
             SELECT created_at, id FROM hindsight_feedback WHERE id = $5::uuid AND owner_email = $1))
         ORDER BY created_at DESC, id DESC LIMIT $6`,
        [ownerEmail, category ?? null, state ?? null, client ?? null, before ?? null, size + 1]);
      const page = rows.slice(0, size);
      return { rows: page, nextCursor: rows.length > size ? page.at(-1).id : null };
    },
    async getFeedback(ownerEmail, id) {
      const { rows } = await q(
        `SELECT ${FEEDBACK_COLUMNS} FROM hindsight_feedback WHERE id = $1::uuid AND owner_email = $2`, [id, ownerEmail]);
      return rows[0] ?? null;
    },
    // Only review state, its timestamps, and the review note change; submitted evidence/context
    // columns are never updated. `note`: undefined keeps it, null clears it, a string sets it.
    async updateFeedback(ownerEmail, id, { state, note } = {}) {
      const { rows } = await q(
        `UPDATE hindsight_feedback SET ${SET_STATE('$3')},
           review_note = CASE WHEN $4::boolean THEN $5::text ELSE review_note END
         WHERE id = $1::uuid AND owner_email = $2 RETURNING ${FEEDBACK_COLUMNS}`,
        [id, ownerEmail, state ?? null, note !== undefined, note ?? null]);
      return rows[0] ?? null;
    },
    async setReviewState(ownerEmail, id, state) {
      return (await this.updateFeedback(ownerEmail, id, { state })) !== null;
    },
    // One statement, so a bulk change is atomic. Returns the ids actually updated (owner's own only).
    async bulkSetReviewState(ownerEmail, ids, state) {
      if (!Array.isArray(ids) || ids.length > MAX_BULK) throw new Error('bulk_limit');
      const { rows } = await q(
        `UPDATE hindsight_feedback SET ${SET_STATE('$3')}
         WHERE owner_email = $1 AND id = ANY($2::uuid[]) RETURNING id`, [ownerEmail, ids, state]);
      return rows.map((r) => r.id);
    },
    async createToken({ ownerEmail, name, client, tokenHash, expiresAt, scope = 'feedback:submit' }) {
      const { rows } = await q(
        `INSERT INTO hindsight_ingestion_tokens (owner_email, name, client, token_hash, expires_at, scope)
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`, [ownerEmail, name, client, tokenHash, expiresAt, scope]);
      return rows[0].id;
    },
    // Keyset pagination, newest first. The cursor is the id of the last row on the previous page; it is
    // resolved inside the owner-scoped subquery, so another owner's id (or an unknown id) yields no rows.
    // Comparing (created_at, id) in SQL keeps full timestamp precision, so every token is reachable.
    async listTokens(ownerEmail, { before } = {}) {
      const { rows } = await q(
        `SELECT id, name, client, scope, created_at, expires_at, last_used_at, revoked_at
         FROM hindsight_ingestion_tokens
         WHERE owner_email = $1 AND ($2::uuid IS NULL OR (created_at, id) < (
           SELECT created_at, id FROM hindsight_ingestion_tokens WHERE id = $2::uuid AND owner_email = $1))
         ORDER BY created_at DESC, id DESC LIMIT $3`,
        [ownerEmail, before ?? null, TOKEN_PAGE_SIZE + 1]);
      const page = rows.slice(0, TOKEN_PAGE_SIZE);
      return { rows: page, nextCursor: rows.length > TOKEN_PAGE_SIZE ? page.at(-1).id : null };
    },
    async revokeToken(ownerEmail, id) {
      const { rowCount } = await q(
        `UPDATE hindsight_ingestion_tokens SET revoked_at = now()
         WHERE id = $1 AND owner_email = $2 AND revoked_at IS NULL`, [id, ownerEmail]);
      return rowCount === 1;
    },
  };
}
