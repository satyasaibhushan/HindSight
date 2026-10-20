import { request } from 'node:http';

export const ORIGIN = 'https://hs.test';
export const HOST = 'hs.test';
export const SECRET = 'x'.repeat(40);
// Headers Vercel's HTTPS proxy sends for a request to the canonical domain.
export const CANONICAL = { host: HOST, 'x-forwarded-host': HOST, 'x-forwarded-proto': 'https' };
export const env = {
  DATABASE_URL: 'postgres://synthetic.invalid/hindsight', AUTH_GOOGLE_ID: 'id', AUTH_GOOGLE_SECRET: 's',
  AUTH_SECRET: SECRET, HINDSIGHT_REVIEWER_EMAILS: 'owner@example.com', HINDSIGHT_PUBLIC_ORIGIN: ORIGIN,
};

export async function serve(app, fn) {
  const server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  try {
    return await fn(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.closeAllConnections();
    server.close();
  }
}

// node:http (not fetch) so tests control Host and proxy headers exactly. Undefined values are omitted.
export function call(base, path, { method = 'GET', headers = {}, body, signal } = {}) {
  const merged = Object.fromEntries(Object.entries({ ...CANONICAL, ...headers }).filter(([, v]) => v !== undefined));
  return new Promise((resolve, reject) => {
    const req = request(base + path, { method, headers: merged, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    req.on('error', reject);
    signal?.addEventListener('abort', () => { req.destroy(); reject(signal.reason ?? new Error('aborted')); });
    if (body !== undefined) req.write(body);
    req.end();
  });
}

export const text = (res) => res.body.toString('utf8');

export const modernListen = () => ({
  jsonrpc: '2.0', id: 'listen-1', method: 'subscriptions/listen',
  params: {
    _meta: {
      'io.modelcontextprotocol/protocolVersion': '2026-07-28',
      'io.modelcontextprotocol/clientInfo': { name: 'hindsight-test', version: '1' },
      'io.modelcontextprotocol/clientCapabilities': {},
    },
    notifications: { toolsListChanged: true },
  },
});
export const modernListenHeaders = {
  'content-type': 'application/json', accept: 'application/json, text/event-stream',
  'mcp-protocol-version': '2026-07-28', 'mcp-method': 'subscriptions/listen',
};

export const fid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
// Feedback rows for one owner, newest first by created_at (row n is n minutes old); ids fid(start + i).
export const seedRows = (owner, count, start = 1, extra = (_i) => ({})) => Array.from({ length: count }, (_, i) => ({
  id: fid(start + i), owner_email: owner, client: 'laptop', request_id: `req-seed-${start + i}`, friction: `friction ${start + i}`,
  improvement: 'improve', category: 'skills', created_at: new Date(Date.UTC(2026, 9, 1) - (start + i) * 60000), ...extra(i),
}));

// In-memory mirror of the db.js admin semantics: every lookup is owner-scoped; the keyset cursor is
// resolved among the owner's rows only (unknown or foreign cursor -> empty page); filters apply after it.
export function adminMemory(seed = []) {
  const rows = seed.map((r) => ({ review_state: 'new', review_note: null, reviewed_at: null, actioned_at: null,
    dismissed_at: null, task: null, source: null, repository: null, outcome: null, confidence: null, ...r }));
  const own = (owner) => rows.filter((r) => r.owner_email === owner)
    .sort((a, b) => b.created_at - a.created_at || (a.id < b.id ? 1 : -1));
  const setState = (r, state) => {
    if (state === undefined) return;
    if (state === 'actioned' && r.review_state !== 'actioned') r.actioned_at = new Date();
    if (state === 'dismissed' && r.review_state !== 'dismissed') r.dismissed_at = new Date();
    r.review_state = state;
    r.reviewed_at = new Date();
  };
  return {
    adminRows: rows,
    async listFeedbackPage(owner, { category, state, client, before, limit = 25 } = {}) {
      let list = own(owner);
      if (before !== undefined) {
        const i = list.findIndex((r) => r.id === before);
        if (i < 0) return { rows: [], nextCursor: null };
        list = list.slice(i + 1);
      }
      list = list.filter((r) => (!category || r.category === category) && (!state || r.review_state === state) &&
        (!client || r.client === client));
      const page = list.slice(0, limit);
      return { rows: page, nextCursor: list.length > limit ? page.at(-1).id : null };
    },
    async getFeedback(owner, id) { return own(owner).find((r) => r.id === id) ?? null; },
    async updateFeedback(owner, id, { state, note } = {}) {
      const r = own(owner).find((x) => x.id === id);
      if (!r) return null;
      setState(r, state);
      if (note !== undefined) r.review_note = note;
      return { ...r };
    },
    async bulkSetReviewState(owner, ids, state) {
      const hit = own(owner).filter((r) => ids.includes(r.id));
      for (const r of hit) setState(r, state);
      return hit.map((r) => r.id);
    },
  };
}
