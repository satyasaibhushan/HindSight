import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { csrfToken, hashToken, isAuthorizedReviewer } from '../src/security.js';
import { SCRIPT_HASH } from '../src/ui.js';
import { createHash } from 'node:crypto';
import { ORIGIN, SECRET, adminMemory, call, env, fid, seedRows, serve, text } from './helpers.js';

const TOKEN = 'hs_' + 'A'.repeat(43);
const OWNER = 'owner@example.com';
const ID = '00000000-0000-4000-8000-000000000001';
const bearer = { authorization: 'Bearer ' + TOKEN };
const form = (fields) => ({ 'content-type': 'application/x-www-form-urlencoded', origin: ORIGIN, body: new URLSearchParams(fields).toString() });
const post = (base, path, fields, headers = {}) => {
  const { body, ...h } = form(fields);
  return call(base, path, { method: 'POST', headers: { ...h, ...headers }, body });
};

// Synthetic store; every method call is logged so tests can assert no storage access happened.
function fakeStore({ token = 'active', fail = false, limited = false, hasMore = false, ownsRow = true,
  tokenOwner = OWNER, tokenPage = { rows: [], nextCursor: null }, scope, rows = [] } = {}) {
  const s = { calls: [], created: [], stateUpdates: [], lists: [], tokenLists: [] };
  const rec = (name, fn) => async (...args) => {
    s.calls.push(name);
    if (fail) throw new Error('storage down');
    return fn(...args);
  };
  // Revoked/expired tokens are filtered by the SQL in db.js; the store returns null for them.
  s.authenticateIngestionToken = rec('authenticateIngestionToken', (h) =>
    (h === hashToken(TOKEN) && token === 'active' ? { id: 't1', ownerEmail: tokenOwner, client: 'c' } : null));
  s.hitRateLimit = rec('hitRateLimit', () => !limited);
  s.authenticateAndRateLimit = rec('authenticateAndRateLimit', async (h, reviewers) => {
    if (h !== hashToken(TOKEN) || token !== 'active' || !reviewers.includes(tokenOwner.trim().toLowerCase())) {
      return { token: null, allowed: false };
    }
    return { token: { id: 't1', ownerEmail: tokenOwner, client: 'c', ...(scope ? { scope } : {}) },
      allowed: reviewers.includes(tokenOwner) ? !limited : await s.hitRateLimit('t1') };
  });
  s.listFeedback = rec('listFeedback', (owner, filters) => {
    s.lists.push([owner, filters]);
    return { rows: [{ id: ID, client: 'c<b>', request_id: 'req-00001', friction: '<script>alert(1)</script>',
      improvement: 'i"><img src=x>', category: 'other', review_state: 'new', created_at: new Date() }], hasMore };
  });
  s.setReviewState = rec('setReviewState', (owner, id, state) => { s.stateUpdates.push([owner, id, state]); return ownsRow; });
  s.listTokens = rec('listTokens', (owner, opts) => { s.tokenLists.push([owner, opts]); return tokenPage; });
  s.createToken = rec('createToken', (t) => { s.created.push(t); return 'id'; });
  s.revokeToken = rec('revokeToken', () => true);
  s.insertFeedback = rec('insertFeedback', () => { throw new Error('not expected'); });
  const admin = adminMemory(rows);
  s.adminRows = admin.adminRows;
  s.adminCalls = [];
  for (const k of ['listFeedbackPage', 'getFeedback', 'updateFeedback', 'bulkSetReviewState']) {
    s[k] = rec(k, (...args) => { s.adminCalls.push([k, ...args]); return admin[k](...args); });
  }
  return s;
}

function authSpy() {
  const seen = [];
  const router = (req, res) => {
    seen.push({ protocol: req.protocol, secure: req.secure, host: req.get('host'),
      fwdHost: req.get('x-forwarded-host'), fwdProto: req.get('x-forwarded-proto') });
    res.status(200).send('auth');
  };
  return { seen, router };
}

const reviewer = async () => ({ email: OWNER });
const anonymous = async () => null;
const app = (store, { getReviewer = reviewer, config = loadConfig(env), authRouter = authSpy().router, getAuthCsrf } = {}) =>
  createApp({ config, store, getReviewer, authRouter, getAuthCsrf });

test('empty configuration exposes only the setup-required shell', async () => {
  const config = loadConfig({});
  assert.equal(config.webReady, false);
  assert.equal(config.mcpReady, false);
  await serve(createApp({ config, store: null, getReviewer: reviewer }), async (base) => {
    assert.equal((await call(base, '/review')).status, 503);
    assert.equal((await call(base, '/api/mcp', { method: 'POST', headers: bearer })).status, 503);
    assert.deepEqual(JSON.parse(text(await call(base, '/health'))), { status: 'setup-required', web: false, mcp: false });
  });
});

const MISSING = [
  ['DATABASE_URL', undefined], ['DATABASE_URL', 'mysql://x'],
  ['AUTH_GOOGLE_ID', undefined], ['AUTH_GOOGLE_SECRET', undefined],
  ['AUTH_SECRET', undefined], ['AUTH_SECRET', 'short'],
  ['HINDSIGHT_REVIEWER_EMAILS', undefined], ['HINDSIGHT_REVIEWER_EMAILS', 'not-an-email'],
  ['HINDSIGHT_PUBLIC_ORIGIN', undefined], ['HINDSIGHT_PUBLIC_ORIGIN', 'http://hs.test'],
  ['HINDSIGHT_PUBLIC_ORIGIN', 'https://hs.test/path'],
];
for (const [key, value] of MISSING) {
  test(`MCP and web fail closed without storage access when ${key}=${value ?? '(unset)'}`, async () => {
    const partial = { ...env, [key]: value };
    if (value === undefined) delete partial[key];
    const config = loadConfig(partial);
    assert.equal(config.mcpReady, false);
    assert.equal(config.webReady, false);
    const store = fakeStore();
    const spy = authSpy();
    await serve(app(store, { config, authRouter: spy.router }), async (base) => {
      const mcp = await call(base, '/api/mcp', { method: 'POST',
        headers: { ...bearer, 'content-type': 'application/json' }, body: '{"jsonrpc":"2.0","id":1,"method":"ping"}' });
      assert.equal(mcp.status, 503);
      assert.equal((await call(base, '/review')).status, 503);
      assert.equal((await call(base, '/auth/signin')).status, 503);
      assert.equal(JSON.parse(text(await call(base, '/health'))).status, 'setup-required');
    });
    assert.deepEqual(store.calls, []);
    assert.deepEqual(spy.seen, []);
  });
}

test('legitimate Vercel HTTPS proxy request reaches Auth.js with canonical URL inputs', async () => {
  const spy = authSpy();
  await serve(app(fakeStore(), { authRouter: spy.router }), async (base) => {
    const res = await call(base, '/auth/signin', { headers: {
      host: 'HS.TEST', 'x-forwarded-for': '203.0.113.7', forwarded: 'for=203.0.113.7;host=hs.test;proto=https' } });
    assert.equal(res.status, 200);
    assert.equal((await call(base, '/auth/session', { headers: { 'x-forwarded-port': '443' } })).status, 200);
  });
  assert.equal(spy.seen.length, 2);
  for (const seen of spy.seen) {
    assert.deepEqual(seen, { protocol: 'https', secure: true, host: 'hs.test', fwdHost: 'hs.test', fwdProto: 'https' });
  }
});

const SPOOFS = {
  'foreign Host': { host: 'evil.test' },
  'Host with non-canonical port': { host: 'hs.test:8443' },
  'foreign X-Forwarded-Host': { 'x-forwarded-host': 'evil.test' },
  'X-Forwarded-Host list': { 'x-forwarded-host': 'hs.test, evil.test' },
  'plain-HTTP X-Forwarded-Proto': { 'x-forwarded-proto': 'http' },
  'missing X-Forwarded-Proto': { 'x-forwarded-proto': undefined },
  'X-Forwarded-Proto list': { 'x-forwarded-proto': 'https, http' },
  'non-443 X-Forwarded-Port': { 'x-forwarded-port': '8080' },
  'Forwarded foreign host': { forwarded: 'for=1.2.3.4;host=evil.test;proto=https' },
  'Forwarded plain-HTTP proto': { forwarded: 'for=1.2.3.4;proto=http' },
};
for (const [name, headers] of Object.entries(SPOOFS)) {
  test(`spoofed ${name} is rejected before Auth.js, MCP, or storage`, async () => {
    const store = fakeStore();
    const spy = authSpy();
    await serve(app(store, { authRouter: spy.router }), async (base) => {
      assert.equal((await call(base, '/auth/signin', { headers })).status, 421);
      assert.equal((await call(base, '/auth/callback/google?code=x&state=y', { headers })).status, 421);
      assert.equal((await call(base, '/review', { headers })).status, 421);
      assert.equal((await call(base, '/api/mcp', { method: 'POST', headers: { ...bearer, ...headers } })).status, 421);
    });
    assert.deepEqual(store.calls, []);
    assert.deepEqual(spy.seen, []);
  });
}

test('reviewer authorization requires verified allow-listed email', () => {
  assert.equal(isAuthorizedReviewer({ email: OWNER, email_verified: true }, [OWNER]), true);
  assert.equal(isAuthorizedReviewer({ email: 'Owner@Example.com', email_verified: true }, [OWNER]), true);
  assert.equal(isAuthorizedReviewer({ email: OWNER, email_verified: false }, [OWNER]), false);
  assert.equal(isAuthorizedReviewer({ email: OWNER }, [OWNER]), false);
  assert.equal(isAuthorizedReviewer({ email: 'other@example.com', email_verified: true }, [OWNER]), false);
});

test('unauthenticated review redirects; feedback is escaped with private headers', async () => {
  await serve(app(fakeStore(), { getReviewer: anonymous }), async (base) => {
    const res = await call(base, '/review');
    assert.equal(res.status, 303);
    assert.match(res.headers.location, /^\/auth\/signin\?callbackUrl=%2Freview/);
  });
  await serve(app(fakeStore({ hasMore: true })), async (base) => {
    const res = await call(base, '/review');
    const html = text(res);
    assert.equal(res.status, 200);
    assert.equal(res.headers['cache-control'], 'no-store');
    assert.match(res.headers['content-security-policy'], /default-src 'none'/);
    assert.ok(!html.includes('<script>alert(1)'));
    assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
    assert.ok(!html.includes('<img src=x>'));
    assert.ok(html.includes('c&lt;b&gt;'));
    assert.match(html, /Older/);
  });
});

test('review filters are allow-listed and scoped to the signed-in reviewer', async () => {
  const store = fakeStore();
  await serve(app(store), async (base) => {
    assert.equal((await call(base, '/review?category=connector&state=triaged&client=c&page=2')).status, 200);
    assert.equal((await call(base, '/review?category=bogus&state=deleted&page=-5')).status, 200);
    assert.equal((await call(base, '/review?page=9999')).status, 200);
  });
  assert.deepEqual(store.lists, [
    [OWNER, { category: 'connector', state: 'triaged', client: 'c', page: 2 }],
    [OWNER, { category: undefined, state: undefined, client: undefined, page: 0 }],
    [OWNER, { category: undefined, state: undefined, client: undefined, page: 40 }],
  ]);
});

test('review state changes require CSRF and are owner-isolated', async () => {
  const csrf = csrfToken(SECRET, OWNER);
  const store = fakeStore();
  await serve(app(store), async (base) => {
    assert.equal((await post(base, `/review/${ID}/state`, { state: 'triaged', csrf: 'wrong' })).status, 403);
    assert.equal((await post(base, `/review/${ID}/state`, { state: 'triaged', csrf }, { origin: 'https://evil.test' })).status, 403);
    assert.equal((await post(base, `/review/${ID}/state`, { state: 'deleted', csrf })).status, 400);
    const ok = await post(base, `/review/${ID}/state`, { state: 'triaged', csrf });
    assert.equal(ok.status, 303);
  });
  assert.deepEqual(store.stateUpdates, [[OWNER, ID, 'triaged']]);
  // Another owner's row: the store's owner-scoped UPDATE matches nothing.
  const foreign = fakeStore({ ownsRow: false });
  await serve(app(foreign), async (base) => {
    assert.equal((await post(base, `/review/${ID}/state`, { state: 'dismissed', csrf })).status, 404);
  });
  assert.deepEqual(foreign.stateUpdates, [[OWNER, ID, 'dismissed']]);
});

test('token creation requires same origin and CSRF', async () => {
  const store = fakeStore();
  const csrf = csrfToken(SECRET, OWNER);
  await serve(app(store), async (base) => {
    const fields = { name: 'n', client: 'c', days: '7' };
    assert.equal((await post(base, '/tokens', { ...fields, csrf }, { origin: 'https://evil.test' })).status, 403);
    assert.equal((await post(base, '/tokens', { ...fields, csrf }, { origin: undefined })).status, 403);
    assert.equal((await post(base, '/tokens', { ...fields, csrf: 'wrong' })).status, 403);
    const ok = await post(base, '/tokens', { ...fields, csrf });
    assert.equal(ok.status, 200);
    assert.match(text(ok), /hs_[A-Za-z0-9_-]{43}/);
  });
  assert.equal(store.created.length, 1);
  assert.match(store.created[0].tokenHash, /^[0-9a-f]{64}$/);
  assert.equal(store.created[0].ownerEmail, OWNER);
});

test('MCP rejects missing, malformed, revoked/expired, and cross-origin credentials', async () => {
  const none = fakeStore();
  await serve(app(none), async (base) => {
    const noAuth = await call(base, '/api/mcp', { method: 'POST' });
    assert.equal(noAuth.status, 401);
    assert.match(noAuth.headers['www-authenticate'], /Bearer/);
    assert.equal((await call(base, '/api/mcp', { method: 'POST', headers: { authorization: 'Bearer hs_short' } })).status, 401);
    assert.equal((await call(base, '/api/mcp', { method: 'POST', headers: { ...bearer, origin: 'https://evil.test' } })).status, 403);
  });
  assert.deepEqual(none.calls, []);
  for (const state of ['revoked', 'expired']) {
    const store = fakeStore({ token: state });
    await serve(app(store), async (base) => {
      assert.equal((await call(base, '/api/mcp', { method: 'POST', headers: bearer })).status, 401);
    });
    assert.deepEqual(store.calls, ['authenticateAndRateLimit']);
  }
});

test('MCP rate limiting and storage failure fail closed', async () => {
  const limited = fakeStore({ limited: true });
  await serve(app(limited), async (base) => {
    const res = await call(base, '/api/mcp', { method: 'POST', headers: bearer });
    assert.equal(res.status, 429);
    assert.equal(res.headers['retry-after'], '60');
  });
  assert.ok(!limited.calls.includes('insertFeedback'));
  await serve(app(fakeStore({ fail: true })), async (base) => {
    assert.equal((await call(base, '/api/mcp', { method: 'POST', headers: bearer })).status, 503);
  });
});

test('ingestion token is ingestion-only: no review or token-management access', async () => {
  const store = fakeStore();
  const csrf = csrfToken(SECRET, OWNER);
  await serve(app(store, { getReviewer: anonymous }), async (base) => {
    assert.equal((await call(base, '/review', { headers: bearer })).status, 303);
    assert.equal((await call(base, '/tokens', { headers: bearer })).status, 303);
    assert.equal((await post(base, '/tokens', { name: 'n', client: 'c', days: '7', csrf }, bearer)).status, 303);
    assert.equal((await post(base, `/tokens/${ID}/revoke`, { csrf }, bearer)).status, 303);
    assert.equal((await post(base, `/review/${ID}/state`, { state: 'triaged', csrf }, bearer)).status, 303);
  });
  assert.deepEqual(store.calls, []);
});

const MCP_HEADERS = { ...bearer, 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
const RPC = {
  initialize: { jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } } },
  list: { jsonrpc: '2.0', id: 2, method: 'tools/list' },
  call: { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'submit_feedback', arguments: {
    request_id: 'req-removed-01', friction: 'f', improvement: 'i', category: 'other' } } },
};
const rpc = (base, body) => call(base, '/api/mcp', { method: 'POST', headers: MCP_HEADERS, body: JSON.stringify(body) });

test('token whose owner was removed from reviewers is rejected before throttle or MCP', async () => {
  // OWNER removed; another reviewer remains configured, so MCP is still ready.
  const config = loadConfig({ ...env, HINDSIGHT_REVIEWER_EMAILS: 'other@example.com' });
  assert.equal(config.mcpReady, true);
  const store = fakeStore();
  await serve(app(store, { config }), async (base) => {
    for (const body of Object.values(RPC)) {
      const res = await rpc(base, body);
      assert.equal(res.status, 401);
      assert.match(res.headers['www-authenticate'], /invalid_token/);
      assert.deepEqual(JSON.parse(text(res)), { error: 'invalid_token' }); // no owner-policy detail
    }
  });
  assert.deepEqual(store.calls, Array(3).fill('authenticateAndRateLimit')); // no hitRateLimit/insertFeedback

  // Configured owner (stored with different case/whitespace) still reaches throttle and MCP.
  const ok = fakeStore({ tokenOwner: ' Owner@Example.com ' });
  await serve(app(ok), async (base) => {
    assert.equal((await rpc(base, RPC.initialize)).status, 200);
  });
  assert.deepEqual(ok.calls, ['authenticateAndRateLimit', 'hitRateLimit']);
});

test('only the sign-in page may submit forms to the exact Google authorization origin', async () => {
  const policy = (formAction) =>
    `default-src 'none'; script-src ${SCRIPT_HASH}; style-src 'unsafe-inline'; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`;
  await serve(app(fakeStore()), async (base) => {
    for (const path of ['/auth/signin', '/auth/signin?callbackUrl=%2Freview']) {
      assert.equal((await call(base, path)).headers['content-security-policy'], policy("'self' https://accounts.google.com"));
    }
    for (const path of ['/review', '/tokens', '/auth/signout', '/auth/session', '/auth/error', '/auth/signin/google',
      '/auth/callback/google?code=x&state=y', '/auth/signinx', '/health', '/api/mcp']) {
      const csp = (await call(base, path)).headers['content-security-policy'];
      assert.equal(csp, policy("'self'"), path);
    }
  });
});

test('token list pages by owner-scoped cursor with strict cursor validation', async () => {
  const CURSOR = '00000000-0000-4000-8000-0000000000aa';
  const row = { id: ID, name: 'n', client: 'c', expires_at: new Date(Date.now() + 86400000), revoked_at: null };
  const store = fakeStore({ tokenPage: { rows: [row], nextCursor: CURSOR } });
  await serve(app(store), async (base) => {
    const first = text(await call(base, '/tokens'));
    assert.ok(first.includes(`href="/tokens?before=${CURSOR}">Older</a>`));
    assert.ok(!first.includes('Newest'));
    assert.ok(first.includes(`action="/tokens/${ID}/revoke"`));
    const older = text(await call(base, `/tokens?before=${CURSOR}`));
    assert.ok(older.includes('href="/tokens">Newest</a>'));
    for (const bad of ['bogus', `${CURSOR}'--`, CURSOR.toUpperCase(), '', `${CURSOR}&before=${CURSOR}`]) {
      assert.equal((await call(base, '/tokens?before=' + bad)).status, 400, bad);
    }
  });
  assert.deepEqual(store.tokenLists, [[OWNER, { before: undefined }], [OWNER, { before: CURSOR }]]);
});

test('oversized MCP body is rejected', async () => {
  await serve(app(fakeStore()), async (base) => {
    const res = await call(base, '/api/mcp', { method: 'POST',
      headers: { ...bearer, 'content-type': 'application/json' }, body: 'x'.repeat(40000) });
    assert.equal(res.status, 413);
  });
});

test('long unbroken metadata and key names wrap inside their containers', async () => {
  const repository = 'r'.repeat(300);
  const task = 't'.repeat(300);
  const source = 's'.repeat(300);
  const name = 'N'.repeat(80);
  const client = 'C'.repeat(80);
  const store = fakeStore({ tokenPage: { rows: [{ id: ID, name, client,
    expires_at: new Date(Date.now() + 86400000), revoked_at: null }], nextCursor: null } });
  store.listFeedback = async () => ({ hasMore: false, rows: [{ id: ID, client, request_id: 'req-00001',
    friction: 'f', improvement: 'i', category: 'other', review_state: 'new', created_at: new Date(),
    repository, task, source }] });
  const rule = (css, selector) => css.match(new RegExp(`(?:^|\\n)${selector.replace(/[.>]/g, '\\$&')}\\{([^}]*)\\}`))?.[1] ?? '';
  const styleOf = (html) => html.match(/<style>([\s\S]*?)<\/style>/)[1];
  await serve(app(store), async (base) => {
    const review = text(await call(base, '/review'));
    const tokens = text(await call(base, '/tokens'));
    // Complete values stay rendered (no truncation) in the wrapped containers.
    for (const v of [`<dt>Repository</dt><dd>${repository}</dd>`, `<dt>Task</dt><dd>${task}</dd>`,
      `<dt>Source</dt><dd>${source}</dd>`, `</svg>${client}</span>`]) {
      assert.ok(review.includes(v), v.slice(0, 20));
    }
    assert.ok(tokens.includes(`<b>${name}</b>`));
    for (const css of [styleOf(review), styleOf(tokens)]) {
      for (const selector of ['.ctx dd', '.keys .name b', '.fb-top .src']) {
        const decl = rule(css, selector);
        assert.match(decl, /(?:^|;)min-width:0(?:;|$)/, selector);
        assert.match(decl, /(?:^|;)overflow-wrap:anywhere(?:;|$)/, selector);
        assert.doesNotMatch(decl, /overflow:hidden|text-overflow|white-space:nowrap/, selector);
      }
      assert.match(rule(css, '.ctx'), /flex-wrap:wrap/);
      assert.match(rule(css, '.fb-top'), /flex-wrap:wrap/);
    }
  });
});

const CSRF_COOKIE = '__Host-authjs.csrf-token=abc%7Cdef; Path=/; HttpOnly; Secure; SameSite=Lax';
const authCsrf = async () => ({ csrfToken: 'auth-csrf-"1', cookies: [CSRF_COOKIE] });

test('sign-in screen posts to Auth.js Google sign-in with its CSRF token and no external assets', async () => {
  const spy = authSpy();
  await serve(app(fakeStore(), { getReviewer: anonymous, authRouter: spy.router, getAuthCsrf: authCsrf }), async (base) => {
    const res = await call(base, '/auth/signin?callbackUrl=%2Ftokens');
    const html = text(res);
    assert.equal(res.status, 200);
    assert.deepEqual(res.headers['set-cookie'], [CSRF_COOKIE]);
    assert.match(html, /<form method="post" action="\/auth\/signin\/google">/);
    assert.ok(html.includes('name="csrfToken" value="auth-csrf-&quot;1"'));
    assert.ok(html.includes('name="callbackUrl" value="/tokens"'));
    assert.match(html, /Continue with Google/);
    assert.doesNotMatch(html, /<img|https?:\/\/(?!www\.w3\.org)/); // logo is inline SVG; nothing the CSP would block
    // Unsafe or self-referential callbacks fall back to the inbox; same-origin absolute URLs are reduced.
    for (const [cb, want] of [['%2F%2Fevil.test', '/review'], ['https%3A%2F%2Fevil.test%2Fx', '/review'],
      ['%2Fauth%2Fsignin', '/review'], [encodeURIComponent(ORIGIN + '/tokens?x=1'), '/tokens?x=1']]) {
      assert.ok(text(await call(base, '/auth/signin?callbackUrl=' + cb)).includes(`name="callbackUrl" value="${want}"`), cb);
    }
    const denied = await call(base, '/auth/signin?error=AccessDenied');
    assert.equal(denied.status, 401);
    assert.match(text(denied), /not on the reviewer allow-list/);
    assert.match(text(await call(base, '/auth/signin?error=%3Cscript%3E')), /Sign-in did not complete/);
    assert.match(text(await call(base, '/auth/signin?signedOut=1')), /signed out/);
  });
  assert.deepEqual(spy.seen, []); // GET /auth/signin is ours; Auth.js still handles the POST
  await serve(app(fakeStore(), { getAuthCsrf: authCsrf }), async (base) => {
    const res = await call(base, '/auth/signin?callbackUrl=%2Ftokens');
    assert.equal(res.status, 303);
    assert.equal(res.headers.location, '/tokens');
  });
});

test('sign-out screen confirms with an Auth.js CSRF form', async () => {
  await serve(app(fakeStore(), { getAuthCsrf: authCsrf }), async (base) => {
    const html = text(await call(base, '/auth/signout'));
    assert.match(html, /<form class="solo-actions" method="post" action="\/auth\/signout">/);
    assert.ok(html.includes('name="csrfToken" value="auth-csrf-&quot;1"'));
    assert.ok(html.includes(OWNER));
  });
  await serve(app(fakeStore(), { getReviewer: anonymous, getAuthCsrf: authCsrf }), async (base) => {
    const res = await call(base, '/auth/signout');
    assert.equal(res.status, 303);
    assert.equal(res.headers.location, '/auth/signin?signedOut=1');
  });
});

test('API keys have only a name; it becomes the stored client label', async () => {
  const store = fakeStore();
  const csrf = csrfToken(SECRET, OWNER);
  await serve(app(store), async (base) => {
    const page = text(await call(base, '/tokens'));
    assert.ok(page.includes('name="name"'));
    assert.ok(!page.includes('name="client"'));
    const ok = await post(base, '/tokens', { name: '  Work laptop  ', days: '60', csrf });
    const html = text(ok);
    assert.equal(ok.status, 200);
    const secret = html.match(/<code id="new-secret">(hs_[A-Za-z0-9_-]{43})<\/code>/)[1];
    assert.ok(html.includes('data-copy="new-secret"'));
    assert.ok(html.includes(`export HINDSIGHT_INGEST_TOKEN="${secret}"`));
    assert.equal(store.created[0].tokenHash, hashToken(secret));
    for (const bad of [{ name: '' }, { name: 'x'.repeat(81) }, { name: 'n', days: '91' }, { name: 'n', days: '1.5' }]) {
      assert.equal((await post(base, '/tokens', { days: '7', ...bad, csrf })).status, 400);
    }
    const revoked = await post(base, `/tokens/${ID}/revoke`, { csrf });
    assert.equal(revoked.status, 303);
    assert.equal(revoked.headers.location, '/tokens?revoked=1');
    assert.match(text(await call(base, '/tokens?revoked=1')), /API key revoked/);
  });
  assert.equal(store.created.length, 1);
  assert.equal(store.created[0].name, 'Work laptop');
  assert.equal(store.created[0].client, 'Work laptop');
  assert.equal(Math.round((store.created[0].expiresAt - Date.now()) / 86400000), 60);
});

test('review state change returns to the same filtered view, and only to /review', async () => {
  const csrf = csrfToken(SECRET, OWNER);
  await serve(app(fakeStore()), async (base) => {
    const html = text(await call(base, '/review?state=new&category=skills'));
    assert.ok(html.includes('name="next" value="/review?category=skills&amp;state=new"'));
    assert.ok(html.includes('<button name="state" value="new" aria-pressed="true">'));
    const back = await post(base, `/review/${ID}/state`, { state: 'triaged', csrf, next: '/review?category=skills&state=new' });
    assert.equal(back.headers.location, `/review?category=skills&state=new#fb-${ID}`);
    for (const next of ['https://evil.test/review', '//evil.test', '/tokens', '/review/../tokens', '/review?x=<b>']) {
      const res = await post(base, `/review/${ID}/state`, { state: 'triaged', csrf, next });
      assert.equal(res.headers.location, `/review#fb-${ID}`, next);
    }
  });
});

test('connect screen shows copyable client setup for the canonical endpoint', async () => {
  await serve(app(fakeStore(), { getReviewer: anonymous }), async (base) => {
    assert.equal((await call(base, '/connect')).status, 303);
  });
  await serve(app(fakeStore()), async (base) => {
    const html = text(await call(base, '/connect'));
    assert.ok(html.includes(`<code id="c-url" class="small">${ORIGIN}/api/mcp</code>`));
    for (const id of ['c-claude', 'c-codex', 'c-cursor', 'c-opencode', 'c-env', 'c-url']) assert.ok(html.includes(`data-copy="${id}"`), id);
    assert.ok(html.includes('--header &#39;Authorization: Bearer ${HINDSIGHT_INGEST_TOKEN}&#39;'));
    assert.doesNotMatch(html, /hs_[A-Za-z0-9_-]{43}/);
  });
});

test('the inline script on every page matches the CSP hash', async () => {
  await serve(app(fakeStore(), { getAuthCsrf: authCsrf }), async (base) => {
    for (const path of ['/review', '/tokens', '/connect', '/auth/signout']) {
      const res = await call(base, path);
      const scripts = [...text(res).matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
      assert.equal(scripts.length, 1, path);
      const hash = `'sha256-${createHash('sha256').update(scripts[0]).digest('base64')}'`;
      assert.ok(res.headers['content-security-policy'].includes(`script-src ${hash};`), path);
    }
  });
});

// ---- Admin keys: /api/v1 REST API, scope on /tokens, review notes.
const ADMIN = 'feedback:admin';
const OTHER_ROWS = seedRows('other@example.com', 3, 101);
const adminFake = (opts = {}) => fakeStore({ scope: ADMIN, rows: [...seedRows(OWNER, 30, 1,
  (i) => ({ client: i % 3 ? 'laptop' : 'ci', category: i % 2 ? 'codebase' : 'skills' })), ...OTHER_ROWS], ...opts });
const api = (base, path, { method = 'GET', body, headers = {}, auth = bearer } = {}) => call(base, '/api/v1' + path, {
  method, headers: { ...auth, ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...headers },
  body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body) });
const jsonOf = (res) => JSON.parse(text(res));

test('admin REST API fails closed before storage: setup-required, canonical gate, foreign origin', async () => {
  const store = adminFake();
  await serve(createApp({ config: loadConfig({}), store, getReviewer: reviewer }), async (base) => {
    const res = await api(base, '/feedback');
    assert.equal(res.status, 503);
    assert.deepEqual(jsonOf(res), { error: 'setup_required' });
  });
  const partial = loadConfig({ ...env, AUTH_GOOGLE_ID: '' });
  await serve(app(store, { config: partial }), async (base) => {
    assert.deepEqual(jsonOf(await api(base, '/feedback')), { error: 'setup_required' });
  });
  await serve(app(store), async (base) => {
    assert.equal((await api(base, '/feedback', { headers: { host: 'evil.test' } })).status, 421);
    assert.equal((await api(base, '/feedback', { headers: { 'x-forwarded-proto': 'http' } })).status, 421);
    assert.equal((await api(base, '/feedback', { headers: { origin: 'https://evil.test' } })).status, 403);
  });
  assert.deepEqual(store.calls, []);
});

test('admin REST API requires a bearer admin key; sessions and cookies are never accepted', async () => {
  let sessionLookups = 0;
  const session = async () => { sessionLookups += 1; return { email: OWNER }; };
  const none = adminFake();
  await serve(app(none, { getReviewer: session }), async (base) => {
    for (const [path, method] of [['/feedback', 'GET'], [`/feedback/${fid(1)}`, 'GET'], [`/feedback/${fid(1)}`, 'PATCH'],
      ['/feedback/bulk', 'POST'], ['/nope', 'GET']]) {
      const res = await api(base, path, { method, auth: { cookie: '__Secure-authjs.session-token=abc' },
        body: method === 'GET' ? undefined : { state: 'new' } });
      assert.equal(res.status, 401, path);
      assert.match(res.headers['www-authenticate'], /Bearer error="invalid_token"/);
      assert.deepEqual(jsonOf(res), { error: 'invalid_token' });
    }
    for (const auth of [{ authorization: 'Bearer hs_short' }, { authorization: 'Basic ' + TOKEN }, { authorization: TOKEN }]) {
      assert.equal((await api(base, '/feedback', { auth })).status, 401);
    }
  });
  assert.equal(sessionLookups, 0);
  assert.deepEqual(none.calls, []);

  // An ingest key (no scope or feedback:submit) is authenticated but refused, with no data access.
  for (const scope of [undefined, 'feedback:submit']) {
    const ingest = adminFake({ scope });
    await serve(app(ingest), async (base) => {
      for (const [path, method, body] of [['/feedback', 'GET'], [`/feedback/${fid(1)}`, 'GET'],
        [`/feedback/${fid(1)}`, 'PATCH', { state: 'dismissed' }], ['/feedback/bulk', 'POST', { ids: [fid(1)], state: 'dismissed' }],
        ['/unknown', 'GET']]) {
        const res = await api(base, path, { method, body });
        assert.equal(res.status, 403, `${scope} ${method} ${path}`);
        assert.equal(res.headers['www-authenticate'], 'Bearer error="insufficient_scope", scope="feedback:admin"');
        assert.deepEqual(jsonOf(res), { error: 'insufficient_scope' });
      }
    });
    assert.deepEqual([...new Set(ingest.calls)], ['authenticateAndRateLimit']);
    assert.deepEqual(ingest.adminCalls, []);
  }

  for (const state of ['revoked', 'expired']) {
    const store = adminFake({ token: state });
    await serve(app(store), async (base) => {
      assert.equal((await api(base, '/feedback')).status, 401);
    });
    assert.deepEqual(store.calls, ['authenticateAndRateLimit']);
  }
  // Removed owner: generic 401 before any throttle or data access.
  const removed = adminFake();
  await serve(app(removed, { config: loadConfig({ ...env, HINDSIGHT_REVIEWER_EMAILS: 'other@example.com' }) }), async (base) => {
    const res = await api(base, '/feedback');
    assert.equal(res.status, 401);
    assert.deepEqual(jsonOf(res), { error: 'invalid_token' });
  });
  assert.deepEqual(removed.calls, ['authenticateAndRateLimit']);

  const limited = adminFake({ limited: true });
  await serve(app(limited), async (base) => {
    const res = await api(base, '/feedback');
    assert.equal(res.status, 429);
    assert.equal(res.headers['retry-after'], '60');
  });
  assert.deepEqual(limited.adminCalls, []);
  await serve(app(adminFake({ fail: true })), async (base) => {
    assert.deepEqual(jsonOf(await api(base, '/feedback')), { error: 'storage_unavailable' });
  });
});

test('admin REST list: owner-scoped keyset pages, filters, and strict query validation', async () => {
  const store = adminFake();
  await serve(app(store), async (base) => {
    const first = await api(base, '/feedback');
    assert.equal(first.status, 200);
    assert.equal(first.headers['cache-control'], 'no-store');
    assert.match(first.headers['content-type'], /^application\/json/);
    const page = jsonOf(first);
    assert.equal(page.items.length, 25);
    assert.equal(page.next_cursor, fid(25));
    assert.equal(page.items[0].key, 'ci');
    const seen = [];
    let cursor = null;
    do {
      const next = jsonOf(await api(base, '/feedback?limit=9' + (cursor ? '&cursor=' + cursor : '')));
      seen.push(...next.items.map((i) => i.id));
      cursor = next.next_cursor;
    } while (cursor);
    assert.deepEqual(seen, Array.from({ length: 30 }, (_, i) => fid(i + 1)));
    assert.equal(jsonOf(await api(base, '/feedback?key=ci&category=codebase&limit=100')).items.length, 5);
    assert.deepEqual(jsonOf(await api(base, '/feedback?state=actioned')), { items: [], next_cursor: null });
    assert.deepEqual(jsonOf(await api(base, `/feedback?cursor=${fid(101)}`)), { items: [], next_cursor: null });
    for (const q of ['state=deleted', 'category=bogus', 'limit=0', 'limit=101', 'limit=abc', 'limit=1.5', 'limit=-1', 'limit=007',
      'cursor=nope', `cursor=${fid(1)}x`, 'key=', `key=${'k'.repeat(81)}`, 'status=new', 'state=new&state=triaged', 'page=2']) {
      const res = await api(base, '/feedback?' + q);
      assert.equal(res.status, 400, q);
      const err = jsonOf(res);
      assert.equal(err.error, 'invalid_request', q);
      assert.ok(Array.isArray(err.issues) && err.issues.length > 0, q);
    }
  });
  assert.ok(store.adminCalls.every(([, owner]) => owner === OWNER));
  assert.deepEqual(store.adminCalls[0], ['listFeedbackPage', OWNER,
    { state: undefined, category: undefined, client: undefined, before: undefined, limit: 25 }]);
});

test('admin REST get, patch, and bulk: status codes and owner isolation', async () => {
  const store = adminFake();
  await serve(app(store), async (base) => {
    const got = await api(base, `/feedback/${fid(4)}`);
    assert.equal(got.status, 200);
    assert.deepEqual(Object.keys(jsonOf(got)).sort(), ['actioned_at', 'category', 'confidence', 'created_at', 'dismissed_at',
      'friction', 'id', 'improvement', 'key', 'outcome', 'repository', 'request_id', 'review_note', 'reviewed_at', 'source',
      'state', 'task']);
    assert.equal((await api(base, `/feedback/${fid(101)}`)).status, 404); // another owner's id
    assert.deepEqual(jsonOf(await api(base, `/feedback/${fid(999)}`)), { error: 'not_found' });
    assert.equal((await api(base, '/feedback/not-a-uuid')).status, 400);
    assert.equal((await api(base, `/feedback/${fid(4).toUpperCase().replace('0000000', 'ABCDEF0')}`)).status, 400);

    const patched = await api(base, `/feedback/${fid(4)}`, { method: 'PATCH', body: { state: 'actioned' } });
    assert.equal(patched.status, 200);
    assert.equal(jsonOf(patched).state, 'actioned');
    assert.ok(jsonOf(patched).actioned_at);
    const noted = jsonOf(await api(base, `/feedback/${fid(4)}`, { method: 'PATCH', body: { review_note: ' Moved to backlog ' } }));
    assert.deepEqual([noted.state, noted.review_note], ['actioned', 'Moved to backlog']);
    assert.equal(jsonOf(await api(base, `/feedback/${fid(4)}`, { method: 'PATCH', body: { review_note: null } })).review_note, null);
    assert.equal(jsonOf(await api(base, `/feedback/${fid(4)}`, { method: 'PATCH', body: { review_note: '   ' } })).review_note, null);
    assert.equal((await api(base, `/feedback/${fid(101)}`, { method: 'PATCH', body: { state: 'dismissed' } })).status, 404);
    for (const body of [{}, { state: 'deleted' }, { status: 'actioned' }, { state: 'new', friction: 'rewrite' },
      { review_note: 'x'.repeat(2001) }, { review_note: 7 }, [], 'null', '"actioned"']) {
      const res = await api(base, `/feedback/${fid(4)}`, { method: 'PATCH', body });
      assert.equal(res.status, 400, JSON.stringify(body));
    }
    assert.deepEqual(jsonOf(await api(base, `/feedback/${fid(4)}`, { method: 'PATCH', body: '{"state":' })), { error: 'bad_request' });
    const plain = await api(base, `/feedback/${fid(4)}`, { method: 'PATCH', body: JSON.stringify({ state: 'new' }),
      headers: { 'content-type': 'text/plain' } });
    assert.equal(plain.status, 415);
    const form = await api(base, `/feedback/${fid(4)}`, { method: 'PATCH', body: 'state=new',
      headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    assert.equal(form.status, 415);
    const big = await api(base, `/feedback/${fid(4)}`, { method: 'PATCH', body: { review_note: 'x'.repeat(20000) } });
    assert.equal(big.status, 413);

    const bulk = await api(base, '/feedback/bulk', { method: 'POST',
      body: { ids: [fid(1), fid(2), fid(2), fid(101), fid(999)], state: 'dismissed' } });
    assert.equal(bulk.status, 200);
    assert.deepEqual(jsonOf(bulk), { state: 'dismissed', updated: [fid(1), fid(2)], not_found: [fid(101), fid(999)] });
    for (const body of [{ ids: [], state: 'new' }, { ids: [fid(1)] }, { ids: [fid(1)], state: 'gone' }, { ids: ['x'], state: 'new' },
      { ids: Array.from({ length: 101 }, (_, i) => fid(i + 1)), state: 'new' }, { ids: [fid(1)], state: 'new', review_note: 'n' }]) {
      assert.equal((await api(base, '/feedback/bulk', { method: 'POST', body })).status, 400, JSON.stringify(body).slice(0, 40));
    }
    assert.equal((await api(base, '/feedback', { method: 'DELETE' })).status, 404);
    assert.equal((await api(base, `/feedback/${fid(1)}`, { method: 'DELETE' })).status, 404);
    assert.equal((await api(base, '/tokens')).status, 404);
  });
  const rows = Object.fromEntries(store.adminRows.map((r) => [r.id, r]));
  assert.equal(rows[fid(2)].review_state, 'dismissed');
  assert.ok(OTHER_ROWS.every((r) => rows[r.id].review_state === 'new' && rows[r.id].reviewed_at === null));
  assert.ok(store.adminCalls.every(([, owner]) => owner === OWNER));
});

test('admin REST storage failures return 503 without details', async () => {
  const store = adminFake();
  store.getFeedback = async () => { throw new Error('db host 10.0.0.1 down'); };
  store.bulkSetReviewState = store.getFeedback;
  await serve(app(store), async (base) => {
    for (const res of [await api(base, `/feedback/${fid(1)}`),
      await api(base, '/feedback/bulk', { method: 'POST', body: { ids: [fid(1)], state: 'new' } })]) {
      assert.equal(res.status, 503);
      assert.deepEqual(jsonOf(res), { error: 'storage_unavailable' });
    }
  });
});

test('API keys page: choose ingest or admin scope; scope is stored, listed, and revealed', async () => {
  const csrf = csrfToken(SECRET, OWNER);
  const future = new Date(Date.now() + 86400000);
  const store = fakeStore({ tokenPage: { nextCursor: null, rows: [
    { id: fid(1), name: 'ops', client: 'ops', scope: ADMIN, expires_at: future, revoked_at: null },
    { id: fid(2), name: 'laptop', client: 'laptop', scope: 'feedback:submit', expires_at: future, revoked_at: null },
  ] } });
  await serve(app(store), async (base) => {
    const page = text(await call(base, '/tokens'));
    assert.ok(page.includes('<select name="scope"><option value="feedback:submit" selected>Ingest (submit only)</option>'));
    assert.ok(page.includes('<option value="feedback:admin">Admin (read &amp; manage tasks)</option>'));
    assert.match(page, /<b>ops<\/b>\n<span class="pill cat" title="Scope feedback:admin">Admin<\/span>/);
    assert.match(page, /<b>laptop<\/b>\n<span class="pill" title="Scope feedback:submit">Ingest<\/span>/);

    const created = text(await post(base, '/tokens', { name: 'Ops bot', days: '7', scope: ADMIN, csrf }));
    const secret = created.match(/<code id="new-secret">(hs_[A-Za-z0-9_-]{43})<\/code>/)[1];
    assert.ok(created.includes('Admin API key “Ops bot” created'));
    assert.ok(created.includes('Scope <code>feedback:admin</code>'));
    assert.ok(created.includes(`export HINDSIGHT_ADMIN_TOKEN="${secret}"`));
    assert.ok(!created.includes('HINDSIGHT_INGEST_TOKEN="'));
    const ingest = text(await post(base, '/tokens', { name: 'Laptop', days: '7', scope: 'feedback:submit', csrf }));
    assert.ok(ingest.includes('Ingest API key “Laptop” created'));
    assert.ok(ingest.includes('Scope <code>feedback:submit</code>'));
    assert.match(ingest, /export HINDSIGHT_INGEST_TOKEN="hs_/);
    await post(base, '/tokens', { name: 'Default', days: '7', csrf }); // no scope field: ingest
    for (const scope of ['feedback:all', 'admin', '', 'FEEDBACK:ADMIN']) {
      assert.equal((await post(base, '/tokens', { name: 'n', days: '7', scope, csrf })).status, 400, scope);
    }
    assert.equal((await post(base, '/tokens', { name: 'n', days: '7', scope: ADMIN, csrf: 'wrong' })).status, 403);
  });
  assert.deepEqual(store.created.map((t) => [t.name, t.scope]),
    [['Ops bot', ADMIN], ['Laptop', 'feedback:submit'], ['Default', 'feedback:submit']]);
});

test('review note: CSRF-protected, owner-scoped, bounded, cleared when empty, rendered escaped', async () => {
  const csrf = csrfToken(SECRET, OWNER);
  const store = fakeStore({ rows: [...seedRows(OWNER, 1), ...OTHER_ROWS] });
  store.listFeedback = async () => ({ hasMore: false, rows: [{ ...store.adminRows[0], review_note: '<b>note</b>' }] });
  await serve(app(store), async (base) => {
    const html = text(await call(base, '/review?state=new'));
    assert.ok(html.includes(`<form method="post" action="/review/${fid(1)}/note">`));
    assert.ok(html.includes('&lt;b&gt;note&lt;/b&gt;</textarea>'));
    assert.ok(!html.includes('<b>note</b>'));
    assert.match(html, /<details style="width:100%" open>/);
    const path = `/review/${fid(1)}/note`;
    assert.equal((await post(base, path, { note: 'x', csrf: 'wrong' })).status, 403);
    assert.equal((await post(base, path, { note: 'x', csrf }, { origin: 'https://evil.test' })).status, 403);
    const ok = await post(base, path, { note: '  Follow up Friday  ', csrf, next: '/review?state=new' });
    assert.equal(ok.status, 303);
    assert.equal(ok.headers.location, `/review?state=new#fb-${fid(1)}`);
    assert.equal(store.adminRows[0].review_note, 'Follow up Friday');
    assert.equal(store.adminRows[0].review_state, 'new'); // a note alone does not change state
    assert.equal((await post(base, path, { note: 'é'.repeat(2000), csrf })).status, 303); // ~18 KB encoded
    assert.equal((await post(base, path, { note: 'x'.repeat(2001), csrf })).status, 400);
    assert.equal((await post(base, path, { csrf })).status, 400);
    assert.equal((await post(base, `/review/${fid(101)}/note`, { note: 'mine now', csrf })).status, 404);
    assert.equal((await post(base, '/review/not-a-uuid/note', { note: 'x', csrf })).status, 400);
    assert.equal((await post(base, path, { note: '   ', csrf })).status, 303);
  });
  assert.equal(store.adminRows[0].review_note, null);
  assert.equal(store.adminRows.find((r) => r.id === fid(101)).review_note, null);
  await serve(app(store, { getReviewer: anonymous }), async (base) => {
    assert.equal((await post(base, `/review/${fid(1)}/note`, { note: 'x', csrf }, bearer)).status, 303); // to sign-in
  });
});
