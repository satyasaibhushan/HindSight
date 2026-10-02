import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { handleMcp, payloadHash } from '../src/mcp.js';
import { hashToken } from '../src/security.js';
import { ORIGIN, call, env, serve } from './helpers.js';

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

async function withClient(fetchImpl, fn) {
  const client = new Client({ name: 'hindsight-test', version: '0.0.0' });
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
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((t) => t.name), ['submit_feedback']);
    for (const field of ['request_id', 'friction', 'improvement', 'category']) {
      assert.ok(tools[0].inputSchema.required.includes(field), field);
    }
  });
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
