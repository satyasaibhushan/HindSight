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
