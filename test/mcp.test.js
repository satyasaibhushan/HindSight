import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { handleMcp, payloadHash } from '../src/mcp.js';
import { hashToken } from '../src/security.js';
import { REVIEW_STATES } from '../src/db.js';
import { CATEGORIES } from '../src/mcp.js';
import { ORIGIN, adminMemory, call, env, fid, modernListen, modernListenHeaders, seedRows, serve } from './helpers.js';

const OWNER = 'owner@example.com';
const tokenA = { id: 't-a1', ownerEmail: OWNER, client: 'claude-code', name: 'laptop' };
const tokenRotated = { id: 't-a2', ownerEmail: OWNER, client: 'claude-code', name: 'laptop (rotated)' };
const tokenOtherClient = { id: 't-b', ownerEmail: OWNER, client: 'other-agent', name: 'ci' };
const tokenOtherOwner = { id: 't-o', ownerEmail: 'other@example.com', client: 'claude-code', name: 'x' };

const base = { request_id: 'req-0001-abcd', friction: 'Connector timed out twice', improvement: 'Add retry with backoff', category: 'connector' };

// Synthetic storage mirroring db.js semantics: unique (owner, request_id); replay only when the
// persisted fingerprint and client match; attribution comes from the persisted row.
function memoryStore() {
  const s = { rows: new Map(), inserts: 0, fail: false };
  s.insertFeedback = async (token, f, hash) => {
    s.inserts += 1;
    if (s.fail) throw new Error('storage down');
    const key = token.ownerEmail + '\0' + f.request_id;
    const row = s.rows.get(key);
    if (!row) {
      const created = { id: `fb-${s.rows.size + 1}`, client: token.client, tokenId: token.id, hash, f };
      s.rows.set(key, created);
      return { status: 'created', id: created.id, client: created.client };
    }
    const same = row.hash === hash && row.client === token.client;
    return { status: same ? 'replayed' : 'conflict', id: row.id, client: row.client };
  };
  return s;
}

async function withClient(fetchImpl, fn, options) {
  const client = new Client({ name: 'hindsight-test', version: '0.0.0' }, options);
  await client.connect(new StreamableHTTPClientTransport(new URL(ORIGIN + '/api/mcp'), { fetch: fetchImpl }));
  try { return await fn(client); } finally { await client.close(); }
}
const direct = (store, token) => (url, init) => handleMcp(store, token, new Request(url, init));
const submit = (client, args) => client.callTool({ name: 'submit_feedback', arguments: args });
const out = (r) => r.content[0].text;
// Protocol-level errors may surface as a thrown McpError or an isError result depending on the error class.
async function failure(promise) {
  try {
    const r = await promise;
    return r.isError ? out(r) : null;
  } catch (err) {
    return String(err.message);
  }
}

test('payload fingerprint binds client and normalized payload, not token id', () => {
  assert.equal(payloadHash(base, 'claude-code'), payloadHash({ ...base, task: undefined }, 'claude-code'));
  assert.equal(payloadHash({ ...base, friction: 'Café ' }, 'c'), payloadHash({ ...base, friction: 'Café' }, 'c'));
  assert.notEqual(payloadHash(base, 'claude-code'), payloadHash(base, 'other-agent'));
  assert.notEqual(payloadHash(base, 'c'), payloadHash({ ...base, improvement: 'other' }, 'c'));
  assert.equal(payloadHash({ ...base, request_id: 'different-id' }, 'c'), payloadHash(base, 'c'));
});

test('official client initializes and lists exactly one submit_feedback tool', async () => {
  await withClient(direct(memoryStore(), tokenA), async (client) => {
    assert.equal(client.getServerVersion()?.name, 'hindsight');
    assert.equal(client.getServerCapabilities().tools.listChanged, false);
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((t) => t.name), ['submit_feedback']);
    for (const field of ['request_id', 'friction', 'improvement', 'category']) {
      assert.ok(tools[0].inputSchema.required.includes(field), field);
    }
  });
});

test('a modern static-catalog subscription acknowledges no changes and completes', async () => {
  const request = new Request(ORIGIN + '/api/mcp', {
    method: 'POST', headers: modernListenHeaders, body: JSON.stringify(modernListen()),
    signal: AbortSignal.timeout(1000),
  });
  const response = await handleMcp(memoryStore(), tokenA, request);
  assert.equal(response.status, 200);
  const body = await response.text();
  assert.match(body, /notifications\/subscriptions\/acknowledged/);
  assert.match(body, /"notifications":\{\}/);
  assert.match(body, /"resultType":"complete"/);
});

test('normal retry replays the persisted row', async () => {
  const store = memoryStore();
  await withClient(direct(store, tokenA), async (client) => {
    assert.equal(out(await submit(client, base)), 'Recorded feedback fb-1 for claude-code.');
  });
  await withClient(direct(store, tokenA), async (client) => {
    const retry = await submit(client, base);
    assert.equal(retry.isError, false);
    assert.equal(out(retry), 'Already recorded feedback fb-1 for claude-code.');
  });
  assert.equal(store.rows.size, 1);
});

test('same request_id with a different payload conflicts and changes nothing', async () => {
  const store = memoryStore();
  await withClient(direct(store, tokenA), async (client) => {
    await submit(client, base);
    const res = await submit(client, { ...base, improvement: 'Something else entirely' });
    assert.equal(res.isError, true);
    assert.match(out(res), /Conflict \(409\)/);
  });
  assert.equal(store.rows.size, 1);
  assert.equal([...store.rows.values()][0].f.improvement, base.improvement);
});

test('cross-client reuse of an owner request_id conflicts', async () => {
  const store = memoryStore();
  await withClient(direct(store, tokenA), (client) => submit(client, base));
  await withClient(direct(store, tokenOtherClient), async (client) => {
    const res = await submit(client, base);
    assert.equal(res.isError, true);
    assert.match(out(res), /Conflict \(409\)/);
    assert.ok(!out(res).includes('fb-1'));
  });
  assert.equal(store.rows.size, 1);
});

test('token rotation for the same owner/client replays with persisted attribution', async () => {
  const store = memoryStore();
  await withClient(direct(store, tokenA), (client) => submit(client, base));
  await withClient(direct(store, tokenRotated), async (client) => {
    assert.equal(out(await submit(client, base)), 'Already recorded feedback fb-1 for claude-code.');
  });
  assert.equal([...store.rows.values()][0].tokenId, tokenA.id);
});

test('owners are isolated: same request_id under another owner is a new row', async () => {
  const store = memoryStore();
  await withClient(direct(store, tokenA), (client) => submit(client, base));
  await withClient(direct(store, tokenOtherOwner), async (client) => {
    assert.equal(out(await submit(client, base)), 'Recorded feedback fb-2 for claude-code.');
  });
});

test('schema advertises and accepts each new category and a retained old one', async () => {
  const store = memoryStore();
  const categories = ['instructions', 'skills', 'codebase', 'collaboration', 'tooling'];
  await withClient(direct(store, tokenA), async (client) => {
    const { tools } = await client.listTools();
    const advertised = tools[0].inputSchema.properties.category.enum;
    for (const c of [...categories, 'connector', 'other']) assert.ok(advertised.includes(c), c);
    for (const [i, category] of categories.entries()) {
      const res = await submit(client, { ...base, request_id: `req-cat-000${i}`, category });
      assert.equal(res.isError, false, category);
      assert.equal(out(res), `Recorded feedback fb-${i + 1} for claude-code.`);
    }
    assert.ok(await failure(submit(client, { ...base, request_id: 'req-cat-bogus', category: 'bogus' })));
  });
  assert.deepEqual([...store.rows.values()].map((r) => r.f.category), categories);
});

test('tool errors: no-op, secrets, invalid input, unknown tool, storage failure', async () => {
  const store = memoryStore();
  await withClient(direct(store, tokenA), async (client) => {
    assert.match(await failure(submit(client, { ...base, friction: 'n/a' })), /no-op/);
    assert.match(await failure(submit(client, { ...base, improvement: 'use ghp_' + 'a'.repeat(30) })), /secret/);
    assert.ok(await failure(submit(client, { ...base, category: 'bogus' })));
    assert.ok(await failure(submit(client, { ...base, request_id: 'short' })));
    assert.ok(await failure(client.callTool({ name: 'read_feedback', arguments: {} })));
    assert.equal(store.inserts, 0);
    store.fail = true;
    assert.match(await failure(submit(client, base)), /NOT recorded/);
  });
  assert.equal(store.rows.size, 0);
});

// Real app behind the canonical/bearer gate; `token` is what the synthetic store authenticates.
function gatedApp(store, token, TOKEN) {
  store.throttled = 0;
  store.authenticateIngestionToken = async (h) => (h === hashToken(TOKEN) ? token : null);
  store.hitRateLimit = async () => { store.throttled += 1; return true; };
  store.authenticateAndRateLimit = async (h, reviewers) => {
    const allowed = h === hashToken(TOKEN) && reviewers.includes(token.ownerEmail.trim().toLowerCase());
    if (allowed) store.throttled += 1;
    return { token: allowed ? token : null, allowed };
  };
  return createApp({ config: loadConfig(env), store, getReviewer: async () => null,
    authRouter: (_req, res) => res.status(404).end() });
}
// Bridges the official client's fetch to the served app over node:http with the bearer header.
const viaApp = (baseUrl, TOKEN) => async (url, init = {}) => {
  const u = new URL(url);
  const headers = { ...Object.fromEntries(new Headers(init.headers)), authorization: 'Bearer ' + TOKEN };
  const res = await call(baseUrl, u.pathname + u.search,
    { method: init.method || 'GET', headers, body: init.body ?? undefined, signal: init.signal });
  const h = new Headers();
  for (const [k, v] of Object.entries(res.headers)) h.set(k, Array.isArray(v) ? v.join(', ') : v);
  return new Response([204, 205, 304].includes(res.status) ? null : res.body, { status: res.status, headers: h });
};

test('official client works end to end through the gated /api/mcp route', async () => {
  const TOKEN = 'hs_' + 'B'.repeat(43);
  const store = memoryStore();
  await serve(gatedApp(store, tokenA, TOKEN), async (baseUrl) => {
    await withClient(viaApp(baseUrl, TOKEN), async (client) => {
      const { tools } = await client.listTools();
      assert.equal(tools.length, 1);
      assert.equal(out(await submit(client, base)), 'Recorded feedback fb-1 for claude-code.');
      assert.equal(out(await submit(client, base)), 'Already recorded feedback fb-1 for claude-code.');
    });
  });
  assert.ok(store.throttled > 0);
});

test('modern official client discovers and submits through the gated route', async () => {
  const TOKEN = 'hs_' + 'D'.repeat(43);
  const store = memoryStore();
  await serve(gatedApp(store, tokenA, TOKEN), async (baseUrl) => {
    await withClient(viaApp(baseUrl, TOKEN), async (client) => {
      assert.equal(client.getServerCapabilities().tools.listChanged, false);
      assert.deepEqual((await client.listTools()).tools.map((tool) => tool.name), ['submit_feedback']);
      assert.equal(out(await submit(client, base)), 'Recorded feedback fb-1 for claude-code.');
    }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
  });
});

test('official client cannot connect with a token whose owner is not a configured reviewer', async () => {
  const TOKEN = 'hs_' + 'C'.repeat(43);
  const store = memoryStore();
  // tokenOtherOwner's owner is absent from env's HINDSIGHT_REVIEWER_EMAILS.
  await serve(gatedApp(store, tokenOtherOwner, TOKEN), async (baseUrl) => {
    await assert.rejects(withClient(viaApp(baseUrl, TOKEN), (client) => client.listTools()));
  });
  assert.equal(store.throttled, 0);
  assert.equal(store.inserts, 0);
  assert.equal(store.rows.size, 0);
});

// ---- Admin keys: extra tools, owner-scoped reads and updates.
const OTHER = 'other@example.com';
const tokenAdmin = { id: 't-adm', ownerEmail: OWNER, client: 'ops', name: 'ops', scope: 'feedback:admin' };
const ADMIN_TOOLS = ['list_feedback', 'get_feedback', 'update_feedback_state', 'bulk_update_feedback_state'];
// 30 rows for OWNER (fid 1..30, every third from key "ci", odd rows category codebase), 5 for OTHER (fid 101..105).
function adminStore() {
  const s = memoryStore();
  Object.assign(s, adminMemory([
    ...seedRows(OWNER, 30, 1, (i) => ({ client: i % 3 ? 'laptop' : 'ci', category: i % 2 ? 'codebase' : 'skills' })),
    ...seedRows(OTHER, 5, 101),
  ]));
  return s;
}
const call_ = (client, name, args) => client.callTool({ name, arguments: args });
const data = (r) => JSON.parse(out(r));

test('ingest keys keep exactly one tool; admin keys also list the admin tools with consistent schemas', async () => {
  for (const token of [tokenA, { ...tokenA, scope: 'feedback:submit' }, { ...tokenA, scope: 'feedback:ADMIN' }, { ...tokenA, scope: 'admin' }]) {
    await withClient(direct(adminStore(), token), async (client) => {
      assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['submit_feedback'], String(token.scope));
    });
  }
  await withClient(direct(adminStore(), tokenAdmin), async (client) => {
    assert.equal(client.getServerCapabilities().tools.listChanged, false);
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((t) => t.name), ['submit_feedback', ...ADMIN_TOOLS]);
    const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
    const list = byName.list_feedback.inputSchema;
    assert.deepEqual(Object.keys(list.properties).sort(), ['category', 'cursor', 'key', 'limit', 'state']);
    assert.deepEqual(list.properties.state.enum, REVIEW_STATES);
    assert.deepEqual(list.properties.category.enum, CATEGORIES);
    assert.equal(list.properties.limit.maximum, 100);
    assert.deepEqual(list.required ?? [], []);
    assert.deepEqual(byName.get_feedback.inputSchema.required, ['id']);
    assert.deepEqual(byName.update_feedback_state.inputSchema.required.sort(), ['id', 'state']);
    assert.deepEqual(byName.bulk_update_feedback_state.inputSchema.required.sort(), ['ids', 'state']);
    assert.equal(byName.bulk_update_feedback_state.inputSchema.properties.ids.maxItems, 100);
    assert.equal(byName.list_feedback.annotations.readOnlyHint, true);
    assert.equal(byName.get_feedback.annotations.readOnlyHint, true);
    assert.equal(byName.update_feedback_state.annotations.destructiveHint, false);
    assert.match(byName.list_feedback.description, /untrusted/);
  });
});

test('an ingest key is refused every admin tool and nothing is read or changed', async () => {
  const store = adminStore();
  const before = JSON.stringify(store.adminRows);
  let reads = 0;
  for (const k of ['listFeedbackPage', 'getFeedback', 'updateFeedback', 'bulkSetReviewState']) {
    const fn = store[k];
    store[k] = async (...a) => { reads += 1; return fn(...a); };
  }
  await withClient(direct(store, tokenA), async (client) => {
    const args = { list_feedback: {}, get_feedback: { id: fid(1) }, update_feedback_state: { id: fid(1), state: 'dismissed' },
      bulk_update_feedback_state: { ids: [fid(1)], state: 'dismissed' } };
    for (const name of ADMIN_TOOLS) {
      const message = await failure(call_(client, name, args[name]));
      assert.match(message, /not found|unknown/i, name);
      assert.doesNotMatch(message, /friction 1/);
    }
  });
  assert.equal(reads, 0);
  assert.equal(JSON.stringify(store.adminRows), before);
});

test('list_feedback pages by keyset cursor, filters, and sees only the owner\'s items', async () => {
  const store = adminStore();
  await withClient(direct(store, tokenAdmin), async (client) => {
    const first = data(await call_(client, 'list_feedback', {}));
    assert.equal(first.items.length, 25); // default page
    assert.equal(first.next_cursor, fid(25));
    const seen = [];
    let cursor;
    do {
      const page = data(await call_(client, 'list_feedback', { limit: 7, ...(cursor ? { cursor } : {}) }));
      assert.ok(page.items.length <= 7);
      seen.push(...page.items.map((i) => i.id));
      cursor = page.next_cursor;
    } while (cursor);
    assert.deepEqual(seen, Array.from({ length: 30 }, (_, i) => fid(i + 1)));
    const item = data(await call_(client, 'list_feedback', { limit: 1 })).items[0];
    assert.deepEqual(Object.keys(item).sort(), ['actioned_at', 'category', 'confidence', 'created_at', 'dismissed_at', 'friction',
      'id', 'improvement', 'key', 'outcome', 'repository', 'request_id', 'review_note', 'reviewed_at', 'source', 'state', 'task'].sort());
    assert.equal(data(await call_(client, 'list_feedback', { key: 'ci', limit: 100 })).items.length, 10);
    assert.equal(data(await call_(client, 'list_feedback', { category: 'codebase', limit: 100 })).items.length, 15);
    assert.equal(data(await call_(client, 'list_feedback', { state: 'triaged' })).items.length, 0);
    // Another owner's id as cursor yields an empty page, never their rows.
    assert.deepEqual(data(await call_(client, 'list_feedback', { cursor: fid(101) })), { items: [], next_cursor: null });
    for (const bad of [{ limit: 0 }, { limit: 101 }, { limit: 1.5 }, { state: 'deleted' }, { category: 'bogus' }, { cursor: 'nope' },
      { cursor: '0000000A-0000-4000-8000-00000000000B' }, { key: '' }, { key: 'k'.repeat(81) }]) {
      assert.ok(await failure(call_(client, 'list_feedback', bad)), JSON.stringify(bad));
    }
  });
});

test('get, update, and bulk update are owner-scoped with clear errors', async () => {
  const store = adminStore();
  await withClient(direct(store, tokenAdmin), async (client) => {
    assert.equal(data(await call_(client, 'get_feedback', { id: fid(3) })).friction, 'friction 3');
    assert.match(await failure(call_(client, 'get_feedback', { id: fid(101) })), /Not found/);
    assert.ok(await failure(call_(client, 'get_feedback', { id: 'x' })));
    const updated = data(await call_(client, 'update_feedback_state', { id: fid(3), state: 'actioned', review_note: '  Shipped  ' }));
    assert.deepEqual([updated.state, updated.review_note], ['actioned', 'Shipped']);
    assert.ok(updated.actioned_at && updated.reviewed_at);
    assert.equal(data(await call_(client, 'update_feedback_state', { id: fid(3), state: 'triaged', review_note: '' })).review_note, null);
    assert.equal(data(await call_(client, 'update_feedback_state', { id: fid(3), state: 'triaged' })).state, 'triaged');
    assert.match(await failure(call_(client, 'update_feedback_state', { id: fid(101), state: 'dismissed' })), /Not found/);
    for (const bad of [{ id: fid(3) }, { id: fid(3), state: 'deleted' }, { id: fid(3), state: 'new', review_note: 'x'.repeat(2001) },
      { id: fid(3), state: 'new', review_note: 'a\0b' }]) {
      assert.ok(await failure(call_(client, 'update_feedback_state', bad)), JSON.stringify(bad).slice(0, 40));
    }
    const bulk = data(await call_(client, 'bulk_update_feedback_state', { ids: [fid(1), fid(2), fid(2), fid(101), fid(999)], state: 'dismissed' }));
    assert.deepEqual(bulk, { state: 'dismissed', updated: [fid(1), fid(2)], not_found: [fid(101), fid(999)] });
    for (const bad of [{ ids: [], state: 'new' }, { ids: Array.from({ length: 101 }, (_, i) => fid(i + 1)), state: 'new' }, { ids: [fid(1)] }]) {
      assert.ok(await failure(call_(client, 'bulk_update_feedback_state', bad)));
    }
  });
  const byId = Object.fromEntries(store.adminRows.map((r) => [r.id, r]));
  assert.equal(byId[fid(1)].review_state, 'dismissed');
  assert.ok(byId[fid(1)].dismissed_at);
  assert.ok(store.adminRows.filter((r) => r.owner_email === OTHER).every((r) => r.review_state === 'new' && !r.reviewed_at));
});

test('admin tools fail closed on storage errors without details', async () => {
  const store = adminStore();
  store.listFeedbackPage = async () => { throw new Error('connection refused at 10.0.0.1'); };
  store.updateFeedback = store.listFeedbackPage;
  await withClient(direct(store, tokenAdmin), async (client) => {
    for (const [name, args] of [['list_feedback', {}], ['update_feedback_state', { id: fid(1), state: 'new' }]]) {
      const message = await failure(call_(client, name, args));
      assert.match(message, /Storage unavailable/);
      assert.doesNotMatch(message, /10\.0\.0\.1/);
    }
  });
});

test('admin key submits and manages through the gated route; owner is the normalized allow-listed email', async () => {
  const TOKEN = 'hs_' + 'E'.repeat(43);
  const store = adminStore();
  const legacy = { ...tokenAdmin, ownerEmail: ' Owner@Example.com ' };
  await serve(gatedApp(store, legacy, TOKEN), async (baseUrl) => {
    await withClient(viaApp(baseUrl, TOKEN), async (client) => {
      assert.deepEqual((await client.listTools()).tools.map((t) => t.name), ['submit_feedback', ...ADMIN_TOOLS]);
      assert.equal(out(await submit(client, base)), 'Recorded feedback fb-1 for ops.');
      const page = data(await call_(client, 'list_feedback', { limit: 100 }));
      assert.equal(page.items.length, 30);
      assert.ok(page.items.every((i) => !i.id.startsWith('00000000-0000-4000-8000-0000000001')));
    });
  });
  assert.ok(store.throttled > 0);
});
