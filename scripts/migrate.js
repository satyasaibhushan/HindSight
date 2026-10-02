// Explicit HindSight migration runner. Never invoked by web startup.
//   node scripts/migrate.js --verify-files   offline: parse, checksum, and scope-check migration files
//   node scripts/migrate.js                  read-only plan against DATABASE_URL
//   node scripts/migrate.js --apply          apply pending migrations against DATABASE_URL
// Importing this module has no side effects; tests use runMigrations/planMigrations directly.
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'migrations');
export const LEDGER = 'hindsight_schema_migrations';
const FILE_RE = /^(\d{3})_([a-z0-9_]+)\.sql$/;

const stripComments = (sql) => sql.replace(/--[^\n]*/g, '').replace(/'(?:[^']|'')*'/g, "''");
const FORBIDDEN = /\b(?:(?:CREATE|DROP|ALTER)\s+(?:EXTENSION|SCHEMA|ROLE|USER|DATABASE|FUNCTION|PROCEDURE|TRIGGER|POLICY)|GRANT|REVOKE|TRUNCATE|BEGIN|COMMIT|ROLLBACK|SET\s+(?:search_path|ROLE|SESSION))\b/i;
const NAMED = /\b(?:TABLE|INDEX|CONSTRAINT|REFERENCES|UPDATE|INTO|FROM|USING)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?([A-Za-z_"][\w."]*)/gi;
const ON_NAMED = /\bON\s+(?!DELETE\b|UPDATE\b|CONFLICT\b)([A-Za-z_"][\w."]*)/gi;

// Best-effort static guard: every object a migration names must be an unqualified hindsight_* name,
// and transaction/role/schema/extension statements are refused (the runner owns the transaction).
export function assertScoped(name, sql) {
  const body = stripComments(sql);
  const bad = FORBIDDEN.exec(body);
  if (bad) throw new Error(`${name}: forbidden statement "${bad[0]}"`);
  for (const re of [NAMED, ON_NAMED]) {
    for (const [, ident] of body.matchAll(re)) {
      if (!/^hindsight_[a-z0-9_]+$/.test(ident)) throw new Error(`${name}: non-hindsight object "${ident}"`);
    }
  }
}

// Line endings are normalized so checkouts with CRLF produce the same checksum.
export function loadMigrations(dir = MIGRATIONS_DIR) {
  const files = readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();
  const seen = new Set();
  return files.map((file) => {
    const m = FILE_RE.exec(file);
    if (!m) throw new Error(`unexpected migration file name: ${file}`);
    if (seen.has(m[1])) throw new Error(`duplicate migration version: ${m[1]}`);
    seen.add(m[1]);
    const sql = readFileSync(join(dir, file), 'utf8').replace(/\r\n/g, '\n');
    assertScoped(file, sql);
    return { version: m[1], name: m[2], sql, checksum: createHash('sha256').update(sql).digest('hex') };
  });
}

function assertSingleConnection(client) {
  // Session advisory locks need one connection; a pg.Pool would spread statements across sessions.
  if (!client || typeof client.query !== 'function' || 'totalCount' in client) {
    throw new Error('runMigrations requires a single pg.Client (or one checked-out pool client), not a Pool');
  }
}

async function readLedger(client) {
  const { rows: [{ exists }] } = await client.query(`SELECT to_regclass($1) IS NOT NULL AS exists`, [LEDGER]);
  if (!exists) return new Map();
  const { rows } = await client.query(`SELECT version, name, checksum FROM ${LEDGER} ORDER BY version`);
  return new Map(rows.map((r) => [r.version, r]));
}

// Refuses to continue when an applied migration changed or disappeared; nothing is applied then.
function compare(migrations, ledger) {
  const known = new Map(migrations.map((m) => [m.version, m]));
  for (const [version, row] of ledger) {
    const m = known.get(version);
    if (!m) throw new Error(`applied migration ${version}_${row.name} is missing from the migrations directory`);
    if (m.checksum !== row.checksum) throw new Error(`checksum mismatch for applied migration ${version}_${m.name}`);
  }
  return {
    applied: migrations.filter((m) => ledger.has(m.version)).map((m) => m.version),
    pending: migrations.filter((m) => !ledger.has(m.version)),
  };
}

export async function planMigrations(client, { migrations = loadMigrations() } = {}) {
  assertSingleConnection(client);
  const { applied, pending } = compare(migrations, await readLedger(client));
  return { applied, pending: pending.map((m) => m.version) };
}

// Serialized per database + current schema by a session advisory lock. Each migration and its ledger
// row commit in one transaction, so a failure rolls back cleanly and a rerun retries only that file.
export async function runMigrations(client, { migrations = loadMigrations(), lockTimeoutMs = 60000, log = () => {} } = {}) {
  assertSingleConnection(client);
  await client.query(`SELECT set_config('lock_timeout', $1, false)`, [`${lockTimeoutMs}ms`]);
  const { rows: [{ schema }] } = await client.query(`SELECT current_schema() AS schema`);
  if (!schema) throw new Error('no existing schema on search_path; refusing to migrate');
  await client.query(`SELECT pg_advisory_lock(hashtext('hindsight_migrations'), hashtext($1))`, [schema]);
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS ${LEDGER} (
      version text PRIMARY KEY CHECK (version ~ '^[0-9]{3}$'),
      name text NOT NULL,
      checksum text NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
      applied_at timestamptz NOT NULL DEFAULT now())`);
    const { applied, pending } = compare(migrations, await readLedger(client));
    const done = [];
    for (const m of pending) {
      await client.query('BEGIN');
      try {
        await client.query(m.sql);
        await client.query(`INSERT INTO ${LEDGER} (version, name, checksum) VALUES ($1, $2, $3)`,
          [m.version, m.name, m.checksum]);
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw new Error(`migration ${m.version}_${m.name} failed and was rolled back: ${err.message}`, { cause: err });
      }
      done.push(m.version);
      log(`applied ${m.version}_${m.name}`);
    }
    return { applied: done, skipped: applied };
  } finally {
    // If the connection broke, the server releases the session lock anyway.
    await client.query(`SELECT pg_advisory_unlock(hashtext('hindsight_migrations'), hashtext($1))`, [schema])
      .catch(() => {});
  }
}

async function main(argv, env) {
  const migrations = loadMigrations();
  if (argv.includes('--verify-files')) {
    for (const m of migrations) console.log(`ok ${m.version}_${m.name} ${m.checksum.slice(0, 12)}`);
    return;
  }
  const url = env.DATABASE_URL || '';
  if (!/^postgres(ql)?:\/\/\S+$/.test(url)) throw new Error('DATABASE_URL is not set to a postgres:// URL');
  const { default: pg } = await import('pg');
  const client = new pg.Client({ connectionString: url, application_name: 'hindsight-migrate' });
  await client.connect();
  try {
    if (!argv.includes('--apply')) {
      const plan = await planMigrations(client, { migrations });
      console.log(`applied: ${plan.applied.join(', ') || 'none'}; pending: ${plan.pending.join(', ') || 'none'}`);
      if (plan.pending.length) console.log('Read-only plan. Re-run with --apply to apply pending migrations.');
      return;
    }
    const result = await runMigrations(client, { migrations, log: (msg) => console.log(msg) });
    console.log(`done: applied ${result.applied.length}, already applied ${result.skipped.length}`);
  } finally {
    await client.end();
  }
}

const invokedDirectly = (() => {
  try { return Boolean(process.argv[1]) && pathToFileURL(realpathSync(process.argv[1])).href === import.meta.url; }
  catch { return false; }
})();
if (invokedDirectly) {
  main(process.argv.slice(2), process.env).catch((err) => {
    // Error messages never include the connection string.
    console.error(`migrate: ${err.message}`);
    process.exitCode = 1;
  });
}
