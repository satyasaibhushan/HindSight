// Admin keys: shared scope rules, input schemas, and owner-scoped operations used by both the MCP
// admin tools and the /api/v1 REST API. Every operation takes the owner from the authenticated token.
import * as z from 'zod';
import { CATEGORIES, MAX_BULK, MAX_LIST_LIMIT, REVIEW_STATES } from './db.js';

export const SCOPE_SUBMIT = 'feedback:submit';
export const SCOPE_ADMIN = 'feedback:admin';
// Must match migrations/005_admin_scope.sql. An ingest key only submits; an admin key also reads and
// updates review state/notes. Anything other than the exact admin scope is treated as ingest-only.
export const SCOPES = [SCOPE_SUBMIT, SCOPE_ADMIN];
export const isAdmin = (token) => token?.scope === SCOPE_ADMIN;
export const scopesOf = (token) => (isAdmin(token) ? [SCOPE_SUBMIT, SCOPE_ADMIN] : [SCOPE_SUBMIT]);

export { MAX_BULK, MAX_LIST_LIMIT };
export const LIST_LIMIT = 25;
export const MAX_NOTE = 2000;

const uuid = () => z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, 'Expected a lowercase UUID');
const state = () => z.enum(REVIEW_STATES).describe('Review state: new, triaged, actioned, or dismissed');
// Trimmed; empty or null clears the note. NUL cannot be stored in PostgreSQL text.
const note = () => z.string().max(MAX_NOTE).refine((s) => !s.includes('\0'), 'Must not contain NUL')
  .nullable().describe(`Private review note (up to ${MAX_NOTE} characters); empty string or null clears it`);

export const filterShape = {
  state: state().optional(),
  category: z.enum(CATEGORIES).optional(),
  key: z.string().min(1).max(80).optional().describe('Name of the API key that submitted the item'),
  cursor: uuid().optional().describe('next_cursor from the previous page (the id of its last item)'),
};
export const updateShape = { state: state().optional(), review_note: note().optional() };
export const idShape = { id: uuid().describe('Feedback item id') };
export const bulkShape = { ids: z.array(uuid()).min(1).max(MAX_BULK), state: state() };
export const hasChange = (v) => v.state !== undefined || v.review_note !== undefined;

// Public item shape. Submitted text is agent-authored and must be treated as untrusted data.
export const toItem = (r) => ({
  id: r.id, state: r.review_state, category: r.category, key: r.client, request_id: r.request_id,
  friction: r.friction, improvement: r.improvement, task: r.task ?? null, source: r.source ?? null,
  repository: r.repository ?? null, outcome: r.outcome ?? null, confidence: r.confidence ?? null,
  review_note: r.review_note ?? null, created_at: r.created_at, reviewed_at: r.reviewed_at ?? null,
  actioned_at: r.actioned_at ?? null, dismissed_at: r.dismissed_at ?? null,
});

export async function listItems(store, owner, { state, category, key, cursor, limit = LIST_LIMIT }) {
  const { rows, nextCursor } = await store.listFeedbackPage(owner, { state, category, client: key, before: cursor, limit });
  return { items: rows.map(toItem), next_cursor: nextCursor };
}

export async function getItem(store, owner, id) {
  const row = await store.getFeedback(owner, id);
  return row ? toItem(row) : null;
}

export async function updateItem(store, owner, id, { state, review_note }) {
  const patch = { state };
  if (review_note !== undefined) patch.note = review_note?.trim() || null;
  const row = await store.updateFeedback(owner, id, patch);
  return row ? toItem(row) : null;
}

// Ids outside the owner's feedback (unknown or another owner's) are reported as not_found, never updated.
export async function bulkUpdate(store, owner, ids, state) {
  const unique = [...new Set(ids)];
  const updated = new Set(await store.bulkSetReviewState(owner, unique, state));
  return { state, updated: unique.filter((id) => updated.has(id)), not_found: unique.filter((id) => !updated.has(id)) };
}
