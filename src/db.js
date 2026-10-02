// All queries are parameterized and scoped to hindsight_* tables plus owner/token.
export const REVIEW_STATES = ['new', 'triaged', 'actioned', 'dismissed'];
export const PAGE_SIZE = 25;
export const MAX_PAGE = 40;
export const TOKEN_PAGE_SIZE = 50;

export function createPgStore(pool) {
  const q = (text, values) => pool.query(text, values);
  return {
    // Revocation, expiry, and scope are re-checked on every request.
    async authenticateIngestionToken(tokenHash) {
      const { rows } = await q(
        `UPDATE hindsight_ingestion_tokens SET last_used_at = now()
         WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now() AND scope = 'feedback:submit'
         RETURNING id, owner_email, client, name`, [tokenHash]);
      return rows[0] ? { id: rows[0].id, ownerEmail: rows[0].owner_email, client: rows[0].client, name: rows[0].name } : null;
    },
    // Bounded durable throttle: exactly one row per token (PK token_id) holding the current minute.
    // The upsert row lock serializes concurrent requests, so at most `limit` succeed per window.
    async hitRateLimit(tokenId, limit) {
      const { rows } = await q(
        `INSERT INTO hindsight_rate_limits AS r (token_id, window_start, count)
         VALUES ($1, date_trunc('minute', now()), 1)
         ON CONFLICT (token_id) DO UPDATE SET
           window_start = GREATEST(r.window_start, EXCLUDED.window_start),
           count = CASE WHEN EXCLUDED.window_start > r.window_start THEN 1
                        ELSE LEAST(r.count + 1, $2::integer + 1) END
         RETURNING count`, [tokenId, limit]);
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
    async listFeedback(ownerEmail, { category, state, client, page = 0 } = {}) {
      const { rows } = await q(
        `SELECT id, client, request_id, friction, improvement, category, task, source, repository, outcome,
           confidence, review_state, reviewed_at, created_at
         FROM hindsight_feedback
         WHERE owner_email = $1 AND ($2::text IS NULL OR category = $2)
           AND ($3::text IS NULL OR review_state = $3) AND ($4::text IS NULL OR client = $4)
         ORDER BY created_at DESC, id DESC LIMIT $5 OFFSET $6`,
        [ownerEmail, category ?? null, state ?? null, client ?? null, PAGE_SIZE + 1,
          Math.min(Math.max(page, 0), MAX_PAGE) * PAGE_SIZE]);
      return { rows: rows.slice(0, PAGE_SIZE), hasMore: rows.length > PAGE_SIZE };
    },
    // Only review_state changes; submitted evidence/context columns are never updated.
    async setReviewState(ownerEmail, id, state) {
      const { rowCount } = await q(
        `UPDATE hindsight_feedback SET review_state = $3, reviewed_at = now()
         WHERE id = $1 AND owner_email = $2`, [id, ownerEmail, state]);
      return rowCount === 1;
    },
    async createToken({ ownerEmail, name, client, tokenHash, expiresAt }) {
      const { rows } = await q(
        `INSERT INTO hindsight_ingestion_tokens (owner_email, name, client, token_hash, expires_at)
         VALUES ($1,$2,$3,$4,$5) RETURNING id`, [ownerEmail, name, client, tokenHash, expiresAt]);
      return rows[0].id;
    },
    // Keyset pagination, newest first. The cursor is the id of the last row on the previous page; it is
    // resolved inside the owner-scoped subquery, so another owner's id (or an unknown id) yields no rows.
    // Comparing (created_at, id) in SQL keeps full timestamp precision, so every token is reachable.
    async listTokens(ownerEmail, { before } = {}) {
      const { rows } = await q(
        `SELECT id, name, client, created_at, expires_at, last_used_at, revoked_at
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
