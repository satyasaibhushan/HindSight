// Shared demo harness for scripts/screenshots.js and scripts/demo.js: boots the real app (createApp) on the
// in-memory test store with synthetic config, a fixed signed-in reviewer, and seeded fictional data.
// Dev-only; never touches a database. Every name, email, repository, and request id here is invented.
import { createServer } from 'node:http';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { hashToken } from '../src/security.js';
import { HOST, ORIGIN, adminMemory, env } from '../test/helpers.js';

export const OWNER = 'alex.morgan@example.com';
export const NOW = Date.now();
const ago = (min) => new Date(NOW - min * 60000);
const at = (daysAgo, hh, mm = 0) => { const d = new Date(NOW); d.setUTCDate(d.getUTCDate() - daysAgo); d.setUTCHours(hh, mm, 0, 0); return d; };
const id = (n) => `5f1c0000-0000-4000-8000-${String(n).padStart(12, '0')}`;
export const LAPTOP = 'Work laptop — Claude Code';
export const CODEX = 'Codex on build box';
export const CURSOR = 'Cursor — home desktop';

// Mirrors the mockup's sample inbox: open, planned, done, and won't-do items over several days.
const ITEMS = [
  [ago(14), LAPTOP, 'instructions', 'new', 'Add a line to CLAUDE.md: “Run npm run test:db when touching src/db.js or migrations; a skipped DB suite is not a pass.”',
    'CLAUDE.md says to run `npm test` before committing, but the DB suite silently skips without HINDSIGHT_TEST_DATABASE_URL, so “all green” was misleading. I committed a migration that failed in CI.',
    { repository: 'acme/hindsight', task: 'Add keyset pagination to tokens', outcome: 'recovered', confidence: 'high', source: 'CI failure' }],
  [ago(185), CODEX, 'tooling', 'new', 'Pin the pnpm version in .tool-versions and mention it in the README setup section, so `pnpm install` on a fresh box produces the same lockfile.',
    'Lockfile churn on every CI run because the build box has pnpm 8 and the lockfile was written with pnpm 9.', { repository: 'acme/web', outcome: 'workaround' }],
  [ago(300), CODEX, 'skills', 'triaged', 'Make the release skill check for `gh` first and fall back to printing the PR URL with a prefilled title and body.',
    'The release skill assumes `gh` is installed; on the build box it is not, so the skill failed at the PR step.', { task: 'Cut release 2.4.0', outcome: 'blocked' },
    'Doing this with the next skills pass.'],
  [at(1, 16, 12), CURSOR, 'collaboration', 'new', 'Link the ticket in the first message, or paste acceptance criteria at the top, so agents can start without a round-trip.',
    'I asked three clarifying questions up front that the ticket already answered further down.', { confidence: 'medium' }],
  [at(1, 11), LAPTOP, 'codebase', 'actioned', 'Consolidate on src/lib/time.ts, delete src/util/date.ts, and add a lint rule banning `new Date().getDate()` in src/.',
    'Two date helpers disagree on UTC vs local time; tests passed but the invoice view showed the wrong day.', { repository: 'acme/billing', outcome: 'completed' }],
  [at(1, 8, 30), LAPTOP, 'documentation', 'new', 'Document in docs/dev.md that `make dev` needs Docker running and a free port 5432, and print a friendly error from the Makefile when either is missing. Right now the only signal is a 40-line pg connection stack trace, and the README still points to the old `scripts/start.sh` which no longer exists in the repository.',
    'Spent ten minutes on a connection error before realising Docker was not running.', { repository: 'acme/web', outcome: 'recovered' }],
  [at(4, 14), CODEX, 'connector', 'dismissed', 'Grant the connector read/write on the Platform team, or document which teams it can reach.',
    'The Linear connector returned 403 for issues in the Platform team, so status updates could not be posted.', { outcome: 'failed' }, 'Access is intentional; agents should not post there.'],
  [at(6, 9), LAPTOP, 'environment', 'actioned', 'Add HINDSIGHT_TEST_DATABASE_URL to .env.example with a comment on how to start the test Postgres.',
    'Had to grep the test files to find the variable name.', {}],
  [at(9, 9), CODEX, 'performance', 'new', 'Cache the `node_modules` layer in the CI Docker build; a cold build is 6 minutes and only the last layer changes.',
    'Waited for three full rebuilds while iterating on a one-line change.', { source: 'CI logs', confidence: 'high' }],
];
export const seed = (owner = OWNER) => ITEMS.map(([created_at, client, category, review_state, improvement, friction, ctx, review_note], i) => ({
  id: id(i + 1), owner_email: owner, client, category, review_state, improvement, friction, created_at,
  request_id: `${client.split(' ')[0].toLowerCase()}-${created_at.toISOString().slice(0, 10)}-${(0x7f3a9c + i * 4099).toString(16)}`,
  review_note: review_note ?? null, ...ctx,
}));
// Older filler for the "Show more" shot: 50 more items, one every ~16 hours from day 10 back.
const FILLER = [
  ['codebase', 'Extract the retry loop in src/sync/*.ts into one helper with jittered backoff; three copies have drifted.'],
  ['instructions', 'Say in CLAUDE.md which package manager the repo uses; agents guess between npm and pnpm.'],
  ['skills', 'Give the changelog skill a dry-run mode that prints the entry instead of committing it.'],
  ['tooling', 'Add a `make lint-fix` target so agents do not have to remember the eslint and prettier flags.'],
  ['documentation', 'Document the feature-flag naming convention next to the flags file.'],
  ['collaboration', 'Note in the PR template whether screenshots are expected for UI changes.'],
  ['environment', 'Set TZ=UTC in the test environment; two snapshot tests depend on the machine time zone.'],
  ['workflow', 'Run the slow e2e suite only on PRs labelled `e2e`, and say so in CONTRIBUTING.md.'],
];
export const filler = (owner = OWNER) => Array.from({ length: 50 }, (_, i) => {
  const [category, improvement] = FILLER[i % FILLER.length];
  const client = [LAPTOP, CODEX, CURSOR][i % 3];
  const created_at = ago(10 * 1440 + i * 970);
  return { id: id(300 + i), owner_email: owner, client, category, improvement, created_at,
    review_state: ['new', 'new', 'actioned', 'triaged', 'new', 'dismissed', 'actioned'][i % 7],
    friction: 'Found while working on an unrelated task.', request_id: `filler-${created_at.toISOString().slice(0, 10)}-${i}` };
});
export const TOKENS = [
  ['Work laptop — Claude Code', 'feedback:submit', 3, 12, 26], ['Codex on build box', 'feedback:submit', 9, 300, 51],
  ['Weekly digest script', 'feedback:admin', 32, 8 * 1440, -2], ['Cursor — home desktop', 'feedback:submit', 20, null, 9],
  ['Old CI runner', 'feedback:submit', 60, 40 * 1440, 30, 25],
].map(([name, scope, createdDays, usedMin, expiresDays, revokedDays], i) => ({
  id: id(100 + i), owner_email: OWNER, name, client: name, scope, created_at: ago(createdDays * 1440),
  last_used_at: usedMin === null ? null : ago(usedMin), expires_at: ago(-expiresDays * 1440), revoked_at: revokedDays ? ago(revokedDays * 1440) : null,
}));

// The in-memory test store (test/helpers.js) plus an in-memory token table.
function memoryStore(rows, tokens) {
  const store = adminMemory(rows);
  const list = tokens.map((t) => ({ ...t }));
  return Object.assign(store, {
    async listTokens(owner) {
      return { rows: list.filter((t) => t.owner_email === owner).sort((a, b) => b.created_at - a.created_at), nextCursor: null };
    },
    async createToken({ ownerEmail, name, client, tokenHash, expiresAt, scope }) {
      list.push({ id: id(200 + list.length), owner_email: ownerEmail, name, client, scope, token_hash: tokenHash,
        created_at: new Date(), last_used_at: null, expires_at: expiresAt, revoked_at: null });
      return list.at(-1).id;
    },
    async revokeToken(owner, tid) { const t = list.find((x) => x.id === tid && x.owner_email === owner); if (t) t.revoked_at = new Date(); return Boolean(t); },
  });
}

// The canonical gate expects HTTPS proxy headers for HINDSIGHT_PUBLIC_ORIGIN; a local front door adds them.
export async function start({ rows = seed(), tokens = TOKENS, signedIn = true, configured = true } = {}) {
  const app = createApp({
    config: loadConfig(configured ? { ...env, HINDSIGHT_REVIEWER_EMAILS: OWNER } : {}),
    store: memoryStore(rows, tokens),
    getReviewer: async () => (signedIn ? { email: OWNER } : null),
    authRouter: (_req, res) => res.status(404).end(),
    getAuthCsrf: async () => ({ csrfToken: hashToken('screenshot'), cookies: [] }),
  });
  const server = createServer((req, res) => {
    Object.assign(req.headers, { host: HOST, 'x-forwarded-host': HOST, 'x-forwarded-proto': 'https' });
    if (req.headers.origin) req.headers.origin = ORIGIN;
    if (req.headers.referer) req.headers.referer = ORIGIN + new URL(req.headers.referer).pathname;
    app(req, res);
  }).listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  return { base: `http://127.0.0.1:${server.address().port}`, close: () => { server.closeAllConnections(); server.close(); } };
}

