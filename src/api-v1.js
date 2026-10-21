import express from 'express';
import * as z from 'zod';
import { bulkShape, bulkUpdate, filterShape, getItem, hasChange, idShape, isAdmin, listItems, MAX_LIST_LIMIT, SCOPE_ADMIN,
  updateItem, updateShape } from './admin.js';

// JSON admin API. Mounted behind the shared bearer gate in app.js (canonical origin, setup-required,
// token validity, owner allowlist, rate limit), so req.ingestionToken is always an authenticated key.
// Session cookies are never consulted and there are no CORS headers, so CSRF does not apply.
const listQuery = z.strictObject({
  ...filterShape,
  limit: z.string().regex(/^[1-9][0-9]{0,2}$/).transform(Number).pipe(z.number().max(MAX_LIST_LIMIT)).optional(),
});
const idParam = z.strictObject(idShape);
const patchBody = z.strictObject(updateShape).refine(hasChange, 'Provide state and/or review_note');
const bulkBody = z.strictObject(bulkShape);

const invalid = (res, error) => res.status(400).json({ error: 'invalid_request',
  issues: error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })) });
const notFound = (res) => res.status(404).json({ error: 'not_found' });

export function adminApi(store) {
  const router = express.Router({ caseSensitive: true, strict: true });
  router.use((req, res, next) => {
    if (isAdmin(req.ingestionToken)) return next();
    res.status(403).set('WWW-Authenticate', `Bearer error="insufficient_scope", scope="${SCOPE_ADMIN}"`)
      .json({ error: 'insufficient_scope' });
  });
  // Same normalized owner the bearer gate checked against the reviewer allowlist (and /review uses).
  router.use((req, _res, next) => { req.owner = req.ingestionToken.ownerEmail.trim().toLowerCase(); next(); });
  const body = [(req, res, next) => (req.is('application/json') ? next()
    : res.status(415).json({ error: 'unsupported_media_type' })), express.json({ limit: '16kb', strict: true })];
  // Storage failures fail closed with the same code /api/mcp uses; details are never echoed.
  const handle = (fn) => async (req, res) => {
    try { await fn(req, res); } catch { if (!res.headersSent) res.status(503).json({ error: 'storage_unavailable' }); }
  };

  router.get('/feedback', handle(async (req, res) => {
    const q = listQuery.safeParse(req.query);
    if (!q.success) return invalid(res, q.error);
    res.json(await listItems(store, req.owner, q.data));
  }));
  router.post('/feedback/bulk', body, handle(async (req, res) => {
    const b = bulkBody.safeParse(req.body);
    if (!b.success) return invalid(res, b.error);
    res.json(await bulkUpdate(store, req.owner, b.data.ids, b.data.state));
  }));
  router.get('/feedback/:id', handle(async (req, res) => {
    const p = idParam.safeParse(req.params);
    if (!p.success) return invalid(res, p.error);
    const item = await getItem(store, req.owner, p.data.id);
    return item ? res.json(item) : notFound(res);
  }));
  router.patch('/feedback/:id', body, handle(async (req, res) => {
    const p = idParam.safeParse(req.params);
    if (!p.success) return invalid(res, p.error);
    const b = patchBody.safeParse(req.body);
    if (!b.success) return invalid(res, b.error);
    // Another owner's id matches nothing in the owner-scoped UPDATE, so it is indistinguishable from unknown.
    const item = await updateItem(store, req.owner, p.data.id, b.data);
    return item ? res.json(item) : notFound(res);
  }));
  router.use((_req, res) => notFound(res));
  return router;
}
