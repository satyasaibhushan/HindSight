// Durable-storage integration tests. Uses ONLY HINDSIGHT_TEST_DATABASE_URL (never DATABASE_URL).
// Every test works inside a freshly created, uniquely named schema `hindsight_test_<random>` and drops
// only schemas it created. Without a test URL these tests are reported as SKIPPED, not passed;
// set HINDSIGHT_REQUIRE_DB_TESTS=1 (npm run test:db) to make a missing URL a failure.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, before, describe, test } from 'node:test';
import { assertScoped, loadMigrations, planMigrations, runMigrations } from '../scripts/migrate.js';
import { createPgStore, MAX_BULK, PG_POOL_OPTIONS, TOKEN_PAGE_SIZE } from '../src/db.js';
import { SCOPES } from '../src/admin.js';
import { CATEGORIES, payloadHash } from '../src/mcp.js';
import { generateToken, hashToken } from '../src/security.js';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { call, env, serve } from './helpers.js';

// The five authored migration files; every ledger assertion below derives from this list.
const EXPECTED = [['001', 'hindsight'], ['002', 'idempotency_review'], ['003', 'bounded_rate_limits'],
  ['004', 'feedback_categories'], ['005', 'admin_scope']];
const VERSIONS = EXPECTED.map(([v]) => v);
const NEW_CATEGORIES = ['instructions', 'skills', 'codebase', 'collaboration'];

// Returns { url } or { skip }; throws (fails the run) on unsafe configuration.
export function resolveTestDatabase(env = process.env) {
  const url = env.HINDSIGHT_TEST_DATABASE_URL || '';
  if (!url) {
    if (env.HINDSIGHT_REQUIRE_DB_TESTS === '1') throw new Error('HINDSIGHT_REQUIRE_DB_TESTS=1 but HINDSIGHT_TEST_DATABASE_URL is unset');
    return { skip: 'HINDSIGHT_TEST_DATABASE_URL not set; durable-storage tests NOT run' };
  }
  const parsed = new URL(url);
  if (!/^postgres(ql)?:$/.test(parsed.protocol)) throw new Error('HINDSIGHT_TEST_DATABASE_URL must be postgres://');
  const db = decodeURIComponent(parsed.pathname.slice(1));
  if (!/(test|disposable|scratch)/i.test(db)) {
    throw new Error('test database name must contain "test", "disposable", or "scratch"');
  }
  if (env.DATABASE_URL) {
    const prod = new URL(env.DATABASE_URL);
    const same = prod.hostname === parsed.hostname && (prod.port || '5432') === (parsed.port || '5432') &&
      decodeURIComponent(prod.pathname.slice(1)) === db;
    if (same) throw new Error('HINDSIGHT_TEST_DATABASE_URL points at the same database as DATABASE_URL');
  }
  return { url };
}

test('migration scope guard rejects non-hindsight objects and transaction control', () => {
  assert.throws(() => assertScoped('x', 'ALTER TABLE users ADD COLUMN a int;'), /non-hindsight/);
  assert.throws(() => assertScoped('x', 'CREATE INDEX hindsight_i ON public.accounts (id);'), /non-hindsight/);
  assert.throws(() => assertScoped('x', 'BEGIN; CREATE TABLE hindsight_a (id int);'), /forbidden/);
  assert.throws(() => assertScoped('x', 'DROP SCHEMA hindsight_s CASCADE;'), /forbidden/);
  assert.doesNotThrow(() => loadMigrations());
  assert.deepEqual(loadMigrations().map((m) => [m.version, m.name]), EXPECTED);
  assert.ok(loadMigrations().every((m) => /^[0-9a-f]{64}$/.test(m.checksum)));
});

test('004 category constraint matches CATEGORIES and keeps every old value', () => {
  const sql = loadMigrations().find((m) => m.version === '004').sql;
  const allowed = [...sql.match(/CHECK \(category IN \(([^)]*)\)\)/)[1].matchAll(/'([a-z]+)'/g)].map((x) => x[1]);
  assert.deepEqual(allowed, CATEGORIES);
  for (const c of [...NEW_CATEGORIES, 'connector', 'tooling', 'environment', 'documentation', 'workflow',
    'performance', 'other']) assert.ok(allowed.includes(c), c);
});

test('005 scope constraint matches SCOPES and keeps feedback:submit', () => {
  const sql = loadMigrations().find((m) => m.version === '005').sql;
  const allowed = [...sql.match(/CHECK \(scope IN \(([^)]*)\)\)/)[1].matchAll(/'([a-z:]+)'/g)].map((x) => x[1]);
  assert.deepEqual(allowed, SCOPES);
  assert.deepEqual(SCOPES, ['feedback:submit', 'feedback:admin']);
});

const target = resolveTestDatabase();
const { default: pg } = target.url ? await import('pg') : { default: null };

describe('durable storage (isolated test schema)', { skip: target.skip }, () => {
  const created = [];
  const pools = [];
  const admin = () => new pg.Client({ connectionString: target.url, application_name: 'hindsight-test' });

  async function newSchema() {
    const name = 'hindsight_test_' + randomBytes(6).toString('hex');
    const c = admin();
    await c.connect();
    try { await c.query(`CREATE SCHEMA ${name}`); } finally { await c.end(); } // fails if it already exists
    created.push(name);
    return name;
  }
  // search_path is the test schema only, so unqualified hindsight_* names can never reach other schemas.
  async function schemaClient(schema) {
    const c = admin();
    await c.connect();
    await c.query(`SET search_path TO ${schema}`);
    return c;
  }
  function schemaPool(schema) {
    const pool = new pg.Pool({ connectionString: target.url, max: 6, application_name: 'hindsight-test' });
    pool.on('connect', (c) => { c.query(`SET search_path TO ${schema}`).catch(() => {}); });
    pools.push(pool);
    return pool;
  }
  async function migrated(opts) {
    const schema = await newSchema();
    const c = await schemaClient(schema);
    try { await runMigrations(c, opts); } finally { await c.end(); }
    return schema;
  }

  after(async () => {
    await Promise.all(pools.map((p) => p.end().catch(() => {})));
    const c = admin();
    await c.connect();
    try {
      for (const name of created) {
        if (/^hindsight_test_[0-9a-f]{12}$/.test(name)) await c.query(`DROP SCHEMA IF EXISTS ${name} CASCADE`);
      }
    } finally { await c.end(); }
  });

  describe('migrations', () => {
    test('apply once, rerun skips, ledger records checksums', async () => {
      const schema = await newSchema();
      const c = await schemaClient(schema);
      try {
        assert.deepEqual(await runMigrations(c), { applied: VERSIONS, skipped: [] });
        assert.deepEqual(await runMigrations(c), { applied: [], skipped: VERSIONS });
        assert.deepEqual(await planMigrations(c), { applied: VERSIONS, pending: [] });
        const { rows } = await c.query('SELECT version, name, checksum FROM hindsight_schema_migrations ORDER BY version');
        assert.deepEqual(rows.map((r) => [r.version, r.name]), EXPECTED);
        assert.deepEqual(rows.map((r) => r.checksum), loadMigrations().map((m) => m.checksum));
        const { rows: tables } = await c.query(
          `SELECT table_name FROM information_schema.tables WHERE table_schema = $1 ORDER BY 1`, [schema]);
        assert.ok(tables.every((t) => t.table_name.startsWith('hindsight_')));
      } finally { await c.end(); }
    });

    test('concurrent runners serialize on the advisory lock', async () => {
      const schema = await newSchema();
      const [a, b] = await Promise.all([schemaClient(schema), schemaClient(schema)]);
      try {
        const results = await Promise.all([runMigrations(a), runMigrations(b)]);
        assert.deepEqual(results.flatMap((r) => r.applied).sort(), VERSIONS);
        assert.deepEqual(results.flatMap((r) => r.skipped).sort(), VERSIONS);
        const { rows } = await a.query('SELECT count(*)::int AS n FROM hindsight_schema_migrations');
        assert.equal(rows[0].n, VERSIONS.length);
      } finally { await Promise.all([a.end(), b.end()]); }
    });

    test('checksum drift or missing applied file refuses to run', async () => {
      const schema = await migrated();
      const c = await schemaClient(schema);
      try {
        const files = loadMigrations();
        const edited = files.map((m) => (m.version === '002' ? { ...m, checksum: 'f'.repeat(64) } : m));
        await assert.rejects(runMigrations(c, { migrations: edited }), /checksum mismatch.*002/);
        await assert.rejects(runMigrations(c, { migrations: files.slice(0, 2) }), /missing/);
        await assert.rejects(planMigrations(c, { migrations: edited }), /checksum mismatch/);
      } finally { await c.end(); }
    });

    test('failed migration rolls back fully and retries cleanly', async () => {
      const schema = await migrated();
      const c = await schemaClient(schema);
      const base = loadMigrations();
      // Fixture version is far beyond the authored files, so it never collides with a real migration.
      const next = '900';
      assert.ok(base.every((m) => m.version < next));
      const bad = { version: next, name: 'bad', checksum: 'a'.repeat(64),
        sql: 'CREATE TABLE hindsight_probe (id int); SELECT 1/0;' };
      const good = { ...bad, checksum: 'b'.repeat(64), sql: 'CREATE TABLE hindsight_probe (id int);' };
      try {
        await assert.rejects(runMigrations(c, { migrations: [...base, bad] }), /900_bad failed and was rolled back/);
        const { rows } = await c.query(`SELECT to_regclass('hindsight_probe') AS t,
          (SELECT count(*)::int FROM hindsight_schema_migrations) AS n`);
        assert.deepEqual(rows[0], { t: null, n: VERSIONS.length });
        assert.deepEqual(await runMigrations(c, { migrations: [...base, good] }),
          { applied: ['900'], skipped: VERSIONS });
      } finally { await c.end(); }
    });

    test('003 collapses per-window rate rows to one row per token', async () => {
      const files = loadMigrations();
      const schema = await migrated({ migrations: files.slice(0, 2) });
      const c = await schemaClient(schema);
      try {
        const { rows: [tok] } = await c.query(`INSERT INTO hindsight_ingestion_tokens
          (owner_email, name, client, token_hash, expires_at) VALUES ('o@example.com','n','c',$1, now() + interval '1 day')
          RETURNING id`, [hashToken(generateToken())]);
        await c.query(`INSERT INTO hindsight_rate_limits (token_id, window_start, count) VALUES
          ($1, '2026-01-01T00:00Z', 5), ($1, '2026-01-01T00:01Z', 2), ($1, '2026-01-01T00:02Z', 7)`, [tok.id]);
        assert.deepEqual((await runMigrations(c, { migrations: files })).applied, VERSIONS.slice(2));
        const { rows } = await c.query('SELECT window_start, count FROM hindsight_rate_limits');
        assert.equal(rows.length, 1);
        assert.equal(rows[0].window_start.toISOString(), '2026-01-01T00:02:00.000Z');
        assert.equal(rows[0].count, 7);
        await assert.rejects(c.query(`INSERT INTO hindsight_rate_limits VALUES ($1, now(), 1)`, [tok.id]), /duplicate key/);
      } finally { await c.end(); }
    });

    test('005 keeps existing tokens and feedback valid, adds admin scope and review columns', async () => {
      const files = loadMigrations();
      const schema = await migrated({ migrations: files.filter((m) => m.version < '005') });
      const c = await schemaClient(schema);
      try {
        const plaintext = generateToken();
        const { rows: [tok] } = await c.query(`INSERT INTO hindsight_ingestion_tokens
          (owner_email, name, client, token_hash, expires_at) VALUES ('o@example.com','n','c',$1, now() + interval '1 day')
          RETURNING id`, [hashToken(plaintext)]);
        await c.query(`INSERT INTO hindsight_feedback (token_id, owner_email, client, request_id, payload_hash, friction,
          improvement, category, review_state, reviewed_at) VALUES ($1,'o@example.com','c','pre-005-0001',$2,'f','i','skills','actioned',now())`,
        [tok.id, '0'.repeat(64)]);
        await assert.rejects(c.query(`UPDATE hindsight_ingestion_tokens SET scope = 'feedback:admin'`), /check constraint/);
        assert.deepEqual((await runMigrations(c, { migrations: files })).applied, ['005']);
        const { rows: [t] } = await c.query('SELECT scope FROM hindsight_ingestion_tokens WHERE id = $1', [tok.id]);
        assert.equal(t.scope, 'feedback:submit');
        const { rows: [f] } = await c.query('SELECT review_state, review_note, actioned_at, dismissed_at FROM hindsight_feedback');
        assert.deepEqual(f, { review_state: 'actioned', review_note: null, actioned_at: null, dismissed_at: null });
        await c.query(`UPDATE hindsight_ingestion_tokens SET scope = 'feedback:admin'`);
        await assert.rejects(c.query(`UPDATE hindsight_ingestion_tokens SET scope = 'feedback:all'`), /check constraint/);
        await assert.rejects(c.query(`UPDATE hindsight_feedback SET review_note = ''`), /check constraint/);
        await assert.rejects(c.query(`UPDATE hindsight_feedback SET review_note = repeat('x', 2001)`), /check constraint/);
        await c.query(`UPDATE hindsight_feedback SET review_note = repeat('é', 2000)`);
      } finally { await c.end(); }
    });
  });

  describe('store', () => {
    let schema;
    let store;
    before(async () => {
      schema = await migrated();
      store = createPgStore(schemaPool(schema));
    });

    const day = () => new Date(Date.now() + 86400000);
    async function token(s, ownerEmail, client = 'claude-code', scope) {
      const plaintext = generateToken();
      const id = await s.createToken({ ownerEmail, name: 'test', client, tokenHash: hashToken(plaintext), expiresAt: day(), scope });
      return { id, plaintext, auth: await s.authenticateIngestionToken(hashToken(plaintext)) };
    }
    const feedback = (requestId, extra = {}) => ({
      request_id: requestId, friction: 'Tool schema rejected a valid path', improvement: 'Accept relative paths',
      category: 'tooling', ...extra,
    });
    const submit = (s, tok, f) => s.insertFeedback(tok, f, payloadHash(f, tok.client));

    test('authentication reads current validity without writing; usage updates at most once per minute', async () => {
      const t = await token(store, 'usage@example.com');
      const pool = schemaPool(schema);
      const usage = async () => (await pool.query(
        'SELECT last_used_at, xmin::text AS version FROM hindsight_ingestion_tokens WHERE id = $1', [t.id])).rows[0];
      const unused = await usage();
      assert.equal(unused.last_used_at, null);
      await store.authenticateIngestionToken(hashToken(t.plaintext));
      assert.deepEqual(await usage(), unused);
      assert.equal(await store.hitRateLimit(t.id, 2), true);
      const first = await usage();
      assert.ok(first.last_used_at);
      assert.equal(await store.hitRateLimit(t.id, 2), true);
      assert.equal(await store.hitRateLimit(t.id, 2), false);
      assert.deepEqual(await usage(), first); // includes rate-limited attempts, without repeated token writes
      await pool.query(`UPDATE hindsight_ingestion_tokens SET last_used_at = now() - interval '2 minutes' WHERE id = $1`, [t.id]);
      await store.hitRateLimit(t.id, 2);
      assert.ok((await usage()).last_used_at > first.last_used_at);
      await store.revokeToken('usage@example.com', t.id);
      assert.equal(await store.authenticateIngestionToken(hashToken(t.plaintext)), null);
    });

    test('canonical MCP discovery authenticates and throttles in one round trip', async () => {
      const t = await token(store, 'owner@example.com');
      const pool = schemaPool(schema);
      let queries = 0;
      const counted = createPgStore({ query: (...args) => { queries++; return pool.query(...args); } });
      const oldToken = await counted.authenticateIngestionToken(hashToken(t.plaintext));
      await counted.hitRateLimit(oldToken.id, 20);
      assert.equal(queries, 2); // The previous authenticate-then-throttle path.
      const app = createApp({ config: loadConfig(env), store: counted, getReviewer: async () => null,
        authRouter: (_req, res) => res.status(404).end() });
      await serve(app, async (base) => {
        for (let i = 0; i < 3; i++) {
          const before = queries;
          const response = await call(base, '/api/mcp', { method: 'POST', headers: {
            authorization: 'Bearer ' + t.plaintext, 'content-type': 'application/json',
            accept: 'application/json, text/event-stream',
          }, body: JSON.stringify({ jsonrpc: '2.0', id: i, method: 'tools/list' }) });
          assert.equal(response.status, 200);
          assert.equal(queries - before, 1);
          assert.match(response.body.toString(), /submit_feedback/);
        }
      });
      const usage = (await pool.query('SELECT last_used_at FROM hindsight_ingestion_tokens WHERE id=$1', [t.id])).rows[0];
      assert.ok(usage.last_used_at);
    });

    test('combined authentication durably caps concurrent hits and writes usage once per minute', async () => {
      const owner = 'combined-race@example.com', t = await token(store, owner);
      const pool = schemaPool(schema), other = createPgStore(pool);
      // Pin the fixture window so the burst cannot straddle a wall-clock minute rollover.
      await pool.query(`INSERT INTO hindsight_rate_limits (token_id,window_start,count)
        VALUES ($1,date_trunc('minute',now())+interval '1 hour',0)`, [t.id]);
      const authenticate = () => other.authenticateAndRateLimit(hashToken(t.plaintext), [owner], 5);
      const usage = async () => (await pool.query(
        'SELECT last_used_at,xmin::text AS version FROM hindsight_ingestion_tokens WHERE id=$1', [t.id])).rows[0];
      assert.equal((await usage()).last_used_at, null);
      assert.equal((await authenticate()).allowed, true);
      const first = await usage();
      const results = await Promise.all(Array.from({ length: 20 }, authenticate));
      assert.equal(results.filter((r) => r.allowed).length, 4);
      assert.ok(results.every((r) => r.token.id === t.id));
      assert.deepEqual(await usage(), first);
      const rate = (await pool.query('SELECT count FROM hindsight_rate_limits WHERE token_id=$1', [t.id])).rows[0];
      assert.equal(rate.count, 6);
      await pool.query("UPDATE hindsight_rate_limits SET window_start=now()-interval '2 minutes' WHERE token_id=$1", [t.id]);
      await pool.query("UPDATE hindsight_ingestion_tokens SET last_used_at=now()-interval '2 minutes' WHERE id=$1", [t.id]);
      assert.equal((await authenticate()).allowed, true);
      assert.ok((await usage()).last_used_at > first.last_used_at);
    });

    test('combined authentication checks revocation, expiry and current owner allowlist before writes', async () => {
      const owner = 'combined-validity@example.com', t = await token(store, owner);
      const pool = schemaPool(schema);
      assert.equal((await store.authenticateAndRateLimit(hashToken(t.plaintext), [owner], 20)).allowed, true);
      const before = (await pool.query('SELECT count FROM hindsight_rate_limits WHERE token_id=$1', [t.id])).rows[0].count;
      const denied = { token: null, allowed: false };
      assert.deepEqual(await store.authenticateAndRateLimit(hashToken(t.plaintext), ['other@example.com'], 20), denied);
      await store.revokeToken(owner, t.id);
      assert.deepEqual(await store.authenticateAndRateLimit(hashToken(t.plaintext), [owner], 20), denied);
      assert.equal((await pool.query('SELECT count FROM hindsight_rate_limits WHERE token_id=$1', [t.id])).rows[0].count, before);
      const expired = await token(store, owner);
      await pool.query("UPDATE hindsight_ingestion_tokens SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' WHERE id=$1", [expired.id]);
      assert.deepEqual(await store.authenticateAndRateLimit(hashToken(expired.plaintext), [owner], 20), denied);
      assert.deepEqual(await store.authenticateAndRateLimit(hashToken(generateToken()), [owner], 20), denied);
      assert.equal((await pool.query('SELECT count(*)::int AS n FROM hindsight_rate_limits WHERE token_id=$1', [expired.id])).rows[0].n, 0);
    });

    test('legacy mixed-case and Unicode whitespace owners retain JS normalization fallback', async () => {
      const pool = schemaPool(schema);
      let queries = 0;
      const counted = createPgStore({ query: (...args) => { queries++; return pool.query(...args); } });
      for (const owner of [' Owner@Example.com ', '\u00a0Owner@Example.com\uFEFF']) {
        const t = await token(store, owner);
        queries = 0;
        const first = await counted.authenticateAndRateLimit(hashToken(t.plaintext), ['owner@example.com'], 1);
        assert.equal(queries, 2);
        assert.equal(first.allowed, true);
        assert.equal(first.token.ownerEmail, owner);
        assert.equal((await counted.authenticateAndRateLimit(hashToken(t.plaintext), ['owner@example.com'], 1)).allowed, false);
        const before = (await pool.query('SELECT count FROM hindsight_rate_limits WHERE token_id=$1', [t.id])).rows[0].count;
        assert.deepEqual(await counted.authenticateAndRateLimit(hashToken(t.plaintext), ['removed@example.com'], 1), { token: null, allowed: false });
        assert.equal((await pool.query('SELECT count FROM hindsight_rate_limits WHERE token_id=$1', [t.id])).rows[0].count, before);
      }
    });

    test('combined authentication storage failure rolls back throttle and fails the route closed', async () => {
      const owner = 'combined-failure@example.com', t = await token(store, owner);
      const pool = schemaPool(schema);
      await pool.query(`CREATE FUNCTION hindsight_fail_usage() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.owner_email='combined-failure@example.com' THEN RAISE EXCEPTION 'synthetic usage failure'; END IF;
        RETURN NEW; END $$`);
      await pool.query(`CREATE TRIGGER hindsight_fail_usage BEFORE UPDATE OF last_used_at
        ON hindsight_ingestion_tokens FOR EACH ROW EXECUTE FUNCTION hindsight_fail_usage()`);
      try {
        const app = createApp({ config: loadConfig({ ...env, HINDSIGHT_REVIEWER_EMAILS: owner }), store,
          getReviewer: async () => null, authRouter: (_req, res) => res.status(404).end() });
        await serve(app, async (base) => {
          const response = await call(base, '/api/mcp', { method: 'POST', headers: { authorization: 'Bearer ' + t.plaintext } });
          assert.equal(response.status, 503);
          assert.deepEqual(JSON.parse(response.body), { error: 'storage_unavailable' });
        });
        assert.equal((await pool.query('SELECT count(*)::int AS n FROM hindsight_rate_limits WHERE token_id=$1', [t.id])).rows[0].n, 0);
        assert.equal((await pool.query('SELECT last_used_at FROM hindsight_ingestion_tokens WHERE id=$1', [t.id])).rows[0].last_used_at, null);
      } finally {
        await pool.query('DROP TRIGGER hindsight_fail_usage ON hindsight_ingestion_tokens');
        await pool.query('DROP FUNCTION hindsight_fail_usage()');
      }
      assert.equal((await store.authenticateAndRateLimit(hashToken(t.plaintext), [owner], 20)).allowed, true);
    });

    test('production pool limits bound statements and lock waits and recover after cancellation', { timeout: 20000 }, async () => {
      const pool = new pg.Pool({ connectionString: target.url, ...PG_POOL_OPTIONS,
        options: `-c search_path=${schema}`, application_name: 'hindsight-timeout-test' });
      pools.push(pool);
      assert.equal((await pool.query('SHOW statement_timeout')).rows[0].statement_timeout, '10s');
      assert.equal((await pool.query('SHOW lock_timeout')).rows[0].lock_timeout, '3s');
      await assert.rejects(pool.query('SELECT pg_sleep(11)'), (error) => error.code === '57014');
      assert.equal((await pool.query('SELECT 1 AS n')).rows[0].n, 1);
      const t = await token(store, 'locked@example.com');
      const locked = await pool.connect();
      try {
        await locked.query('BEGIN');
        await locked.query('SELECT id FROM hindsight_ingestion_tokens WHERE id = $1 FOR UPDATE', [t.id]);
        const other = createPgStore(pool);
        await assert.rejects(other.hitRateLimit(t.id, 20), (error) => error.code === '55P03');
        await locked.query('ROLLBACK');
        assert.equal(await other.hitRateLimit(t.id, 20), true);
      } finally { await locked.query('ROLLBACK'); locked.release(); }
    });

    test('production pool bounds acquisition when all connections are busy', { timeout: 10000 }, async () => {
      const pool = new pg.Pool({ connectionString: target.url, ...PG_POOL_OPTIONS,
        application_name: 'hindsight-acquisition-test' });
      pools.push(pool);
      const clients = await Promise.all(Array.from({ length: PG_POOL_OPTIONS.max }, () => pool.connect()));
      try { await assert.rejects(pool.query('SELECT 1'), /timeout exceeded when trying to connect/); }
      finally { for (const client of clients) client.release(); }
      assert.equal((await pool.query('SELECT 1 AS n')).rows[0].n, 1);
    });

    test('persists across store instances and pools', async () => {
      const t = await token(store, 'persist@example.com');
      const first = await submit(store, t.auth, feedback('persist-0001'));
      const other = createPgStore(schemaPool(schema));
      const again = await other.authenticateIngestionToken(hashToken(t.plaintext));
      assert.equal(again.id, t.id);
      const { rows } = await other.listFeedback('persist@example.com');
      assert.deepEqual(rows.map((r) => r.id), [first.id]);
      assert.equal(rows[0].review_state, 'new');
    });

    test('each new category and a retained old one persist and filter; unknown category rejected by the schema', async () => {
      const owner = 'cat@example.com';
      const t = await token(store, owner);
      const ids = {};
      for (const category of [...NEW_CATEGORIES, 'tooling']) {
        const r = await submit(store, t.auth, feedback(`cat-${category}-0001`, { category }));
        assert.equal(r.status, 'created', category);
        ids[category] = r.id;
      }
      const all = (await createPgStore(schemaPool(schema)).listFeedback(owner)).rows;
      assert.equal(all.length, 5);
      for (const category of Object.keys(ids)) {
        const { rows } = await store.listFeedback(owner, { category });
        assert.deepEqual(rows.map((r) => [r.id, r.category]), [[ids[category], category]], category);
      }
      assert.equal((await store.listFeedback(owner, { category: 'connector' })).rows.length, 0);
      await assert.rejects(submit(store, t.auth, feedback('cat-bogus-0001', { category: 'bogus' })), /check constraint/);
      assert.equal((await store.listFeedback(owner)).rows.length, 5);
    });

    test('owner isolation for feedback, review state, and tokens', async () => {
      const a = await token(store, 'a@example.com');
      const b = await token(store, 'b@example.com');
      const fa = await submit(store, a.auth, feedback('iso-00000001'));
      const fb = await submit(store, b.auth, feedback('iso-00000001'));
      assert.equal(fa.status, 'created');
      assert.equal(fb.status, 'created'); // request_id is owner-scoped
      assert.deepEqual((await store.listFeedback('a@example.com')).rows.map((r) => r.id), [fa.id]);
      assert.equal(await store.setReviewState('b@example.com', fa.id, 'triaged'), false);
      assert.equal(await store.setReviewState('a@example.com', fa.id, 'triaged'), true);
      assert.equal((await store.listFeedback('a@example.com', { state: 'triaged' })).rows.length, 1);
      assert.equal(await store.revokeToken('b@example.com', a.id), false);
      const listed = await store.listTokens('a@example.com');
      assert.deepEqual(listed.rows.map((t) => t.id), [a.id]);
      assert.equal(listed.nextCursor, null);
    });

    test('token keyset paging reaches and revokes the oldest of >100 tokens; cursors are owner-scoped', async () => {
      const owner = 'page@example.com';
      const intruder = 'intruder@example.com';
      const pool = schemaPool(schema);
      const oldest = await token(store, owner);
      const ids = [oldest.id];
      for (let i = 0; i < 120; i += 1) {
        ids.push(await store.createToken({ ownerEmail: owner, name: `t${i}`, client: 'c',
          tokenHash: hashToken(generateToken()), expiresAt: day() }));
      }
      // Every token but the oldest shares one created_at, so page boundaries rely on the id tiebreak.
      await pool.query(`UPDATE hindsight_ingestion_tokens SET created_at = CASE WHEN id = $2
        THEN now() - interval '2 days' ELSE now() - interval '1 day' END WHERE owner_email = $1`, [owner, oldest.id]);
      const other = await token(store, intruder);

      const seen = [];
      const cursors = [];
      let cursor;
      do {
        const { rows, nextCursor } = await store.listTokens(owner, { before: cursor });
        assert.ok(rows.length > 0 && rows.length <= TOKEN_PAGE_SIZE);
        seen.push(...rows.map((r) => r.id));
        if (nextCursor) {
          assert.equal(nextCursor, rows.at(-1).id);
          cursors.push(nextCursor);
        }
        cursor = nextCursor;
        assert.ok(cursors.length <= 10, 'pagination must terminate');
      } while (cursor);
      assert.equal(cursors.length, Math.ceil(ids.length / TOKEN_PAGE_SIZE) - 1);
      assert.equal(new Set(seen).size, ids.length); // no duplicates, nothing skipped
      assert.deepEqual([...seen].sort(), [...ids].sort());
      assert.equal(seen.at(-1), oldest.id);

      // Another owner cannot page through these tokens with their cursors, nor revoke the oldest.
      assert.deepEqual((await store.listTokens(intruder)).rows.map((r) => r.id), [other.id]);
      for (const c of cursors) assert.deepEqual(await store.listTokens(intruder, { before: c }), { rows: [], nextCursor: null });
      assert.deepEqual(await store.listTokens(owner, { before: other.id }), { rows: [], nextCursor: null });
      assert.deepEqual(await store.listTokens(owner, { before: '00000000-0000-4000-8000-000000000000' }),
        { rows: [], nextCursor: null }); // unknown cursor
      await assert.rejects(store.listTokens(owner, { before: 'not-a-uuid' })); // invalid cursor never ignored
      assert.equal(await store.revokeToken(intruder, oldest.id), false);
      assert.ok(await store.authenticateIngestionToken(hashToken(oldest.plaintext)));

      assert.equal(await store.revokeToken(owner, oldest.id), true);
      assert.equal(await store.authenticateIngestionToken(hashToken(oldest.plaintext)), null);
      const last = await store.listTokens(owner, { before: cursors.at(-1) });
      assert.equal(last.rows.at(-1).id, oldest.id);
      assert.ok(last.rows.at(-1).revoked_at);
      assert.equal(last.nextCursor, null);
    });

    test('expired, revoked, and unknown tokens do not authenticate', async () => {
      const t = await token(store, 'exp@example.com');
      assert.ok(t.auth);
      const pool = schemaPool(schema);
      await pool.query(`UPDATE hindsight_ingestion_tokens SET created_at = now() - interval '2 hours',
        expires_at = now() - interval '1 hour' WHERE id = $1`, [t.id]);
      assert.equal(await store.authenticateIngestionToken(hashToken(t.plaintext)), null);
      const r = await token(store, 'exp@example.com');
      assert.equal(await store.revokeToken('exp@example.com', r.id), true);
      assert.equal(await store.revokeToken('exp@example.com', r.id), false);
      assert.equal(await store.authenticateIngestionToken(hashToken(r.plaintext)), null);
      assert.equal(await store.authenticateIngestionToken(hashToken(generateToken())), null);
    });

    test('request_id retries, payload conflicts, cross-client conflicts, token rotation', async () => {
      const owner = 'idem@example.com';
      const t1 = await token(store, owner, 'codex');
      const f = feedback('idem-00000001');
      const created = await submit(store, t1.auth, f);
      assert.equal(created.status, 'created');
      assert.deepEqual(await submit(store, t1.auth, { ...f, friction: `  ${f.friction} ` }),
        { status: 'replayed', id: created.id, client: 'codex' }); // normalized identical payload
      assert.equal((await submit(store, t1.auth, { ...f, improvement: 'Something else' })).status, 'conflict');
      const other = await token(store, owner, 'cursor');
      assert.equal((await submit(store, other.auth, f)).status, 'conflict');
      await store.revokeToken(owner, t1.id);
      const rotated = await token(store, owner, 'codex');
      assert.deepEqual(await submit(store, rotated.auth, f), { status: 'replayed', id: created.id, client: 'codex' });
      assert.equal((await store.listFeedback(owner)).rows.length, 1);
    });

    test('concurrent identical inserts create exactly one row', async () => {
      const owner = 'race@example.com';
      const t = await token(store, owner);
      const f = feedback('race-00000001');
      const results = await Promise.all(Array.from({ length: 12 }, () => submit(store, t.auth, f)));
      assert.equal(results.filter((r) => r.status === 'created').length, 1);
      assert.equal(results.filter((r) => r.status === 'replayed').length, 11);
      assert.equal(new Set(results.map((r) => r.id)).size, 1);
      assert.equal((await store.listFeedback(owner)).rows.length, 1);
    });

    test('admin and ingest tokens authenticate with their scope', async () => {
      const owner = 'scope@example.com';
      const ingest = await token(store, owner);
      const admin = await token(store, owner, 'ops', 'feedback:admin');
      assert.equal(ingest.auth.scope, 'feedback:submit');
      assert.equal(admin.auth.scope, 'feedback:admin');
      const combined = await store.authenticateAndRateLimit(hashToken(admin.plaintext), [owner], 20);
      assert.equal(combined.allowed, true);
      assert.equal(combined.token.scope, 'feedback:admin');
      assert.deepEqual((await store.listTokens(owner)).rows.map((t) => t.scope).sort(), ['feedback:admin', 'feedback:submit']);
      await assert.rejects(store.createToken({ ownerEmail: owner, name: 'x', client: 'x', tokenHash: hashToken(generateToken()),
        expiresAt: day(), scope: 'feedback:all' }), /check constraint/);
      await store.revokeToken(owner, admin.id);
      assert.deepEqual(await store.authenticateAndRateLimit(hashToken(admin.plaintext), [owner], 20), { token: null, allowed: false });
    });

    test('admin feedback listing pages by owner-scoped keyset cursor and filters', async () => {
      const owner = 'admin-page@example.com';
      const intruder = 'admin-intruder@example.com';
      const pool = schemaPool(schema);
      const a = await token(store, owner, 'laptop');
      const b = await token(store, owner, 'ci');
      const ids = [];
      for (let i = 0; i < 60; i += 1) {
        const r = await submit(store, i % 3 ? a.auth : b.auth, feedback(`page-${String(i).padStart(4, '0')}`,
          { category: i % 2 ? 'skills' : 'codebase' }));
        ids.push(r.id);
      }
      // All but the oldest share created_at, so page boundaries rely on the id tiebreak.
      await pool.query(`UPDATE hindsight_feedback SET created_at = CASE WHEN id = $2
        THEN now() - interval '2 days' ELSE now() - interval '1 day' END WHERE owner_email = $1`, [owner, ids[0]]);
      const theirs = await submit(store, (await token(store, intruder)).auth, feedback('page-intruder'));

      const walk = async (filters, limit) => {
        const seen = [];
        const cursors = [];
        let before;
        do {
          const { rows, nextCursor } = await store.listFeedbackPage(owner, { ...filters, before, limit });
          assert.ok(rows.length <= limit);
          seen.push(...rows.map((r) => r.id));
          if (nextCursor) { assert.equal(nextCursor, rows.at(-1).id); cursors.push(nextCursor); }
          before = nextCursor;
          assert.ok(cursors.length <= 70, 'pagination must terminate');
        } while (before);
        return { seen, cursors };
      };
      const all = await walk({}, 7);
      assert.equal(all.seen.length, 60);
      assert.deepEqual([...all.seen].sort(), [...ids].sort());
      assert.equal(all.seen.at(-1), ids[0]);
      assert.equal(all.cursors.length, Math.ceil(60 / 7) - 1);

      assert.equal((await walk({ client: 'ci' }, 25)).seen.length, 20);
      assert.equal((await walk({ category: 'skills' }, 25)).seen.length, 30);
      assert.equal((await walk({ category: 'skills', client: 'ci' }, 25)).seen.length, 10);
      assert.equal(await store.bulkSetReviewState(owner, ids.slice(0, 5), 'triaged').then((r) => r.length), 5);
      assert.deepEqual((await walk({ state: 'triaged' }, 2)).seen.sort(), ids.slice(0, 5).sort());

      // Limits are clamped in storage too.
      assert.equal((await store.listFeedbackPage(owner, { limit: 1000 })).rows.length, 60);
      assert.equal((await store.listFeedbackPage(owner, { limit: 0 })).rows.length, 1);
      // Cursors are owner-scoped: another owner's or an unknown id yields an empty page.
      for (const c of all.cursors.slice(0, 3)) {
        assert.deepEqual(await store.listFeedbackPage(intruder, { before: c }), { rows: [], nextCursor: null });
      }
      assert.deepEqual((await store.listFeedbackPage(intruder)).rows.map((r) => r.id), [theirs.id]);
      assert.deepEqual(await store.listFeedbackPage(owner, { before: theirs.id }), { rows: [], nextCursor: null });
      assert.deepEqual(await store.listFeedbackPage(owner, { before: '00000000-0000-4000-8000-000000000000' }),
        { rows: [], nextCursor: null });
      await assert.rejects(store.listFeedbackPage(owner, { before: 'not-a-uuid' }));
    });

    test('admin get, update, and bulk are owner-isolated; state timestamps and notes', async () => {
      const owner = 'admin-update@example.com';
      const other = 'admin-other@example.com';
      const pool = schemaPool(schema);
      const mine = await submit(store, (await token(store, owner)).auth, feedback('upd-00000001'));
      const mine2 = await submit(store, (await token(store, owner)).auth, feedback('upd-00000002'));
      const theirs = await submit(store, (await token(store, other)).auth, feedback('upd-00000001'));
      const raw = async (id) => (await pool.query('SELECT * FROM hindsight_feedback WHERE id = $1', [id])).rows[0];

      assert.equal((await store.getFeedback(owner, mine.id)).id, mine.id);
      assert.equal(await store.getFeedback(owner, theirs.id), null);
      assert.equal(await store.getFeedback(owner, '00000000-0000-4000-8000-000000000000'), null);
      assert.equal(await store.updateFeedback(owner, theirs.id, { state: 'dismissed', note: 'x' }), null);
      const untouched = await raw(theirs.id);
      assert.deepEqual([untouched.review_state, untouched.review_note, untouched.reviewed_at], ['new', null, null]);

      const actioned = await store.updateFeedback(owner, mine.id, { state: 'actioned' });
      assert.equal(actioned.review_state, 'actioned');
      assert.ok(actioned.reviewed_at && actioned.actioned_at);
      assert.equal(actioned.dismissed_at, null);
      await pool.query(`UPDATE hindsight_feedback SET actioned_at = now() - interval '1 hour',
        reviewed_at = now() - interval '1 hour' WHERE id = $1`, [mine.id]);
      const before = await raw(mine.id);
      const again = await store.updateFeedback(owner, mine.id, { state: 'actioned' });
      assert.equal(again.actioned_at.getTime(), before.actioned_at.getTime()); // re-setting keeps entry time
      assert.ok(again.reviewed_at > before.reviewed_at);
      const triaged = await store.updateFeedback(owner, mine.id, { state: 'triaged', note: 'Fixed in skills repo' });
      assert.equal(triaged.actioned_at.getTime(), before.actioned_at.getTime()); // history kept
      assert.equal(triaged.review_note, 'Fixed in skills repo');
      const noteOnly = await store.updateFeedback(owner, mine.id, { note: 'Second thoughts' });
      assert.deepEqual([noteOnly.review_state, noteOnly.review_note], ['triaged', 'Second thoughts']);
      assert.equal(noteOnly.reviewed_at.getTime(), triaged.reviewed_at.getTime()); // note alone is not a state change
      assert.equal((await store.updateFeedback(owner, mine.id, { state: 'new' })).review_note, 'Second thoughts');
      assert.equal((await store.updateFeedback(owner, mine.id, { note: null })).review_note, null);
      assert.equal(await store.setReviewState(owner, mine.id, 'dismissed'), true);
      assert.ok((await raw(mine.id)).dismissed_at);
      assert.equal(await store.setReviewState(other, mine.id, 'new'), false);
      // Submitted evidence is never changed by review updates.
      assert.equal((await raw(mine.id)).friction, feedback('x').friction);

      const unknown = '00000000-0000-4000-8000-000000000000';
      const updated = await store.bulkSetReviewState(owner, [mine.id, mine2.id, theirs.id, unknown], 'actioned');
      assert.deepEqual(updated.sort(), [mine.id, mine2.id].sort());
      assert.equal((await raw(theirs.id)).review_state, 'new');
      assert.ok((await raw(mine2.id)).actioned_at);
      assert.deepEqual(await store.bulkSetReviewState(other, [mine.id], 'new'), []);
      assert.equal((await raw(mine.id)).review_state, 'actioned');
      await assert.rejects(store.bulkSetReviewState(owner, Array(MAX_BULK + 1).fill(mine.id), 'new'), /bulk_limit/);
      await assert.rejects(store.bulkSetReviewState(owner, [mine.id], 'deleted'), /check constraint/);
    });

    test('REST and MCP admin surfaces over real storage: scope, isolation, revocation, removed owner', async () => {
      const owner = 'owner@example.com';
      const pool = schemaPool(schema);
      const admin = await token(store, owner, 'ops', 'feedback:admin');
      const ingest = await token(store, owner, 'laptop');
      const mine = await submit(store, ingest.auth, feedback('rest-00000001'));
      const theirs = await submit(store, (await token(store, 'stranger@example.com')).auth, feedback('rest-00000001'));
      await pool.query('UPDATE hindsight_ingestion_tokens SET name = client'); // UI-created keys: name == client
      const config = loadConfig({ ...env, HINDSIGHT_RATE_LIMIT_PER_MINUTE: '600' });
      const app = createApp({ config, store, getReviewer: async () => null, authRouter: (_req, res) => res.status(404).end() });
      const auth = (t) => ({ authorization: 'Bearer ' + t.plaintext });
      const json = { 'content-type': 'application/json' };
      const rpc = (t, body) => call(base, '/api/mcp', { method: 'POST', headers: { ...auth(t), ...json,
        accept: 'application/json, text/event-stream' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, ...body }) });
      let base;
      await serve(app, async (b) => {
        base = b;
        const list = await call(base, '/api/v1/feedback?key=laptop', { headers: auth(admin) });
        assert.equal(list.status, 200);
        const page = JSON.parse(list.body);
        assert.deepEqual(page.items.map((i) => i.id), [mine.id]);
        assert.equal(page.items[0].key, 'laptop');
        assert.equal(page.next_cursor, null);
        assert.equal((await call(base, `/api/v1/feedback/${theirs.id}`, { headers: auth(admin) })).status, 404);
        const patched = await call(base, `/api/v1/feedback/${mine.id}`, { method: 'PATCH', headers: { ...auth(admin), ...json },
          body: JSON.stringify({ state: 'actioned', review_note: '  done  ' }) });
        assert.equal(patched.status, 200);
        const item = JSON.parse(patched.body);
        assert.deepEqual([item.state, item.review_note], ['actioned', 'done']);
        assert.ok(item.actioned_at);
        const foreign = await call(base, `/api/v1/feedback/${theirs.id}`, { method: 'PATCH', headers: { ...auth(admin), ...json },
          body: JSON.stringify({ state: 'dismissed' }) });
        assert.equal(foreign.status, 404);
        const bulk = await call(base, '/api/v1/feedback/bulk', { method: 'POST', headers: { ...auth(admin), ...json },
          body: JSON.stringify({ ids: [mine.id, theirs.id], state: 'triaged' }) });
        assert.deepEqual(JSON.parse(bulk.body), { state: 'triaged', updated: [mine.id], not_found: [theirs.id] });
        assert.equal((await pool.query('SELECT review_state FROM hindsight_feedback WHERE id = $1', [theirs.id])).rows[0].review_state, 'new');

        // An ingest key is refused on every admin endpoint and keeps exactly one MCP tool.
        assert.equal((await call(base, '/api/v1/feedback', { headers: auth(ingest) })).status, 403);
        assert.equal((await call(base, `/api/v1/feedback/${mine.id}`, { method: 'PATCH', headers: { ...auth(ingest), ...json },
          body: JSON.stringify({ state: 'new' }) })).status, 403);
        const ingestTools = await rpc(ingest, { method: 'tools/list' });
        assert.deepEqual([...ingestTools.body.toString().matchAll(/"name":"([a-z_]+)"/g)].map((m) => m[1]), ['submit_feedback']);
        const adminTools = await rpc(admin, { method: 'tools/list' });
        for (const name of ['submit_feedback', 'list_feedback', 'get_feedback', 'update_feedback_state', 'bulk_update_feedback_state']) {
          assert.ok(adminTools.body.toString().includes(`"name":"${name}"`), name);
        }
        const got = await rpc(admin, { method: 'tools/call', params: { name: 'get_feedback', arguments: { id: mine.id } } });
        assert.match(got.body.toString(), /triaged/);
        const refused = await rpc(ingest, { method: 'tools/call', params: { name: 'get_feedback', arguments: { id: mine.id } } });
        assert.doesNotMatch(refused.body.toString(), /triaged|Accept relative paths/);
        // An admin key can also submit.
        const sub = await rpc(admin, { method: 'tools/call', params: { name: 'submit_feedback', arguments: feedback('rest-00000002') } });
        assert.match(sub.body.toString(), /Recorded feedback [0-9a-f-]{36} for ops/);

        await store.revokeToken(owner, admin.id);
        const revoked = await call(base, '/api/v1/feedback', { headers: auth(admin) });
        assert.equal(revoked.status, 401);
        assert.deepEqual(JSON.parse(revoked.body), { error: 'invalid_token' });
      });
      // A removed owner's admin key gets the same 401, before any throttle write.
      const second = await token(store, owner, 'ops2', 'feedback:admin');
      const removed = createApp({ config: loadConfig({ ...env, HINDSIGHT_REVIEWER_EMAILS: 'other@example.com' }), store,
        getReviewer: async () => null, authRouter: (_req, res) => res.status(404).end() });
      await serve(removed, async (b) => {
        assert.equal((await call(b, '/api/v1/feedback', { headers: auth(second) })).status, 401);
        assert.equal((await call(b, '/api/mcp', { method: 'POST', headers: auth(second) })).status, 401);
      });
      assert.equal((await pool.query('SELECT count(*)::int AS n FROM hindsight_rate_limits WHERE token_id = $1', [second.id])).rows[0].n, 0);
    });

    test('per-token bounded throttling across windows and concurrent requests', async () => {
      const limit = 3;
      const t = await token(store, 'rate@example.com');
      const u = await token(store, 'rate@example.com');
      const pool = schemaPool(schema);
      // Fixture: pin both windows an hour ahead so the burst cannot straddle a wall-clock minute rollover.
      // GREATEST keeps the pinned window, so every hit counts against it; production SQL is unchanged.
      await pool.query(`INSERT INTO hindsight_rate_limits (token_id, window_start, count)
        SELECT unnest($1::uuid[]), date_trunc('minute', now()) + interval '1 hour', 0`, [[t.id, u.id]]);
      const hits = await Promise.all(Array.from({ length: 10 }, () => store.hitRateLimit(t.id, limit)));
      assert.equal(hits.filter(Boolean).length, limit);
      assert.equal(await store.hitRateLimit(u.id, limit), true); // other token unaffected
      const rowsFor = async (id) => (await pool.query(
        'SELECT window_start, count FROM hindsight_rate_limits WHERE token_id = $1', [id])).rows;
      let rows = await rowsFor(t.id);
      assert.equal(rows.length, 1);
      assert.equal(rows[0].count, limit + 1); // capped, not unbounded
      await pool.query(`UPDATE hindsight_rate_limits SET window_start = date_trunc('minute', now()) - interval '1 hour'
        WHERE token_id = $1`, [t.id]);
      assert.equal(await store.hitRateLimit(t.id, limit), true); // new window resets
      rows = await rowsFor(t.id);
      assert.equal(rows.length, 1);
      assert.equal(rows[0].count, 1);
      const { rows: [{ n }] } = await pool.query(
        'SELECT count(*)::int AS n FROM hindsight_rate_limits WHERE token_id = ANY($1::uuid[])', [[t.id, u.id]]);
      assert.equal(n, 2); // storage stays one row per token regardless of request volume
    });
  });
});
