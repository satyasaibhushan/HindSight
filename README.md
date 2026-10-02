# HindSight

A small Google-protected feedback review app plus submit-only ingestion tokens for MCP clients.

Its purpose: agents submit useful, concrete improvements to the user's editable shared project
instructions, skills, codebase, and collaboration, as well as tools and connectors, so the user can
review and act on them.

Categories (`category`, required): `instructions`, `skills`, `codebase`, `collaboration` (primary),
plus the retained `connector`, `tooling`, `environment`, `documentation`, `workflow`, `performance`,
`other`. The set is additive; existing rows and clients stay valid. Any other value is rejected.

- `/review` — reviewers (Google sign-in, email allowlist) read their own feedback and set review state.
- `/tokens` — reviewers create, list, and revoke ingestion tokens (scope `feedback:submit`, 1–90 day expiry).
  The list is newest first, 50 per page, using a keyset cursor `?before=<token id>` (the last id on the
  previous page). The cursor is resolved only among the signed-in owner's tokens, so every token,
  including the oldest, is reachable and revocable, and a foreign or unknown id yields an empty page.
  A malformed cursor gets `400`.
- `/api/mcp` — Streamable HTTP MCP endpoint with one tool, `submit_feedback`, authenticated by bearer token.
  The token's owner must still be listed in `HINDSIGHT_REVIEWER_EMAILS`. Removing an owner disables
  their tokens at once: requests get the same `401 invalid_token` as an unknown token, before any
  throttle or submission.
- `/health` — reports `ok` or `setup-required`; no secrets.

All pages send `Content-Security-Policy` with `form-action 'self'`. The one exception is the sign-in
page (`/auth/signin`), which also allows `https://accounts.google.com` so its Google redirect can complete.

Feedback is attributable to the owner, token, and client that submitted it. It is **not anonymous**.
Do not submit secrets, transcripts, or provider-private prompts or policies; obvious secret patterns
are rejected. Submit best effort at final handoff, skip generic or no-op notes, and reuse a
`request_id` only to retry the identical submission (see `docs/agent-feedback.md`).

## Status: setup-required

Until Google, database, session, and reviewer configuration are supplied, every route except
`/health` returns `503 setup_required`. That is intentional. Real configuration arrives tomorrow
(see checklist). Real Google sign-in, the four MCP client configurations, and production persistence
have **not** been tested end to end.

## Requirements

- Node.js 24, npm. No build step; ESM JavaScript. Vercel rewrites every path to `api/index.js`.
- The existing approved PostgreSQL resource. HindSight adds only its own dedicated `hindsight_*`
  tables and touches nothing else. Tests run only against a separate disposable test database.

## Install, run, check, test

```sh
npm ci                # after the operator generates package-lock.json (npm install --package-lock-only)
npm run check         # syntax-checks sources, verifies migration files/checksums/scope (no DB)
npm test              # all tests; DB tests are reported SKIPPED unless a test DB is configured
npm start             # http://127.0.0.1:3000, no .env loading
npm run dev           # same, loads an untracked .env if present, restarts on change
```

With empty config, `npm start` serves setup-required pages; `/health` answers `setup-required`.

With full config, the app still enforces the canonical HTTPS boundary: `Host`, `X-Forwarded-Host`,
`X-Forwarded-Proto`, and `Forwarded` must match `HINDSIGHT_PUBLIC_ORIGIN` over HTTPS, otherwise `421`.
Local authenticated use therefore needs an HTTPS reverse proxy or tunnel on that origin in front of
the port. There are no demo users, tokens, or auth-bypass switches.

### Tests and isolated storage

- `test/app.test.js`, `test/mcp.test.js`, and the migration scope-guard test use in-memory stores
  and synthetic `.invalid` config; they need no database.
- `test/db.test.js` (migrations, persistence, category roundtrip and filtering, owner isolation,
  expiry/revocation, idempotency, throttling, token keyset paging over more than 100 tokens) needs `HINDSIGHT_TEST_DATABASE_URL`. It never reads `DATABASE_URL` for connections and
  refuses to run if both point at the same host/port/database, or if the database name does not
  contain `test`, `disposable`, or `scratch`. Each test creates its own `hindsight_test_<random>`
  schema (role needs `CREATE` on the database) and drops only schemas it created.
- Without the URL these tests show as **skipped**, not passed. `npm run test:db` (POSIX shell)
  sets `HINDSIGHT_REQUIRE_DB_TESTS=1` so a missing URL fails instead.

```sh
HINDSIGHT_TEST_DATABASE_URL=postgres://user@localhost:5432/hindsight_test npm run test:db
```

## Configuration

All are server-side; see `.env.example` (empty placeholders only). Never commit values.

| Variable | Meaning |
| --- | --- |
| `DATABASE_URL` | URL of the existing approved PostgreSQL resource. Not connected until all auth config is ready. |
| `AUTH_GOOGLE_ID`, `AUTH_GOOGLE_SECRET` | Google OAuth web client. |
| `AUTH_SECRET` | Session/CSRF secret, ≥ 32 chars (e.g. `openssl rand -base64 48`). |
| `HINDSIGHT_REVIEWER_EMAILS` | Comma-separated allowlist; Google email must be verified. |
| `HINDSIGHT_PUBLIC_ORIGIN` | Canonical bare HTTPS origin, e.g. `https://hindsight.example.com`. |
| `HINDSIGHT_RATE_LIMIT_PER_MINUTE` | Per-token submissions per minute (1–600, default 20). |

Google OAuth redirect URI: `<HINDSIGHT_PUBLIC_ORIGIN>/auth/callback/google`.

## Migrations (explicit, never on startup)

Migrations touch only `hindsight_*` tables. The ledger is `hindsight_schema_migrations`
(version, name, SHA-256 checksum). A session advisory lock on one connection serializes concurrent
runners; each file plus its ledger row commits in one transaction. Already-applied files are skipped;
a changed or missing applied file aborts before applying anything; a failed file rolls back and can
be retried. `003` collapses per-window rate rows to one row per token (primary key `token_id`).
`004` widens the `category` check to the additive set above; no data changes.

```sh
npm run migrate                # read-only plan against DATABASE_URL (from env or .env)
npm run migrate -- --apply     # apply pending migrations
```

The scope guard on migration files is a best-effort static check, not a sandbox; review SQL before
applying. Use a database role limited to the HindSight tables where possible.

## MCP client setup (manual, ingestion-only)

Create a token at `/tokens`, then store the raw token (`hs_…`) in the dedicated environment
variable `HINDSIGHT_INGEST_TOKEN`. Never embed real tokens in checked-in configs; nothing here is
installed automatically. Leave client tool-approval defaults as they are. OAuth onboarding for
machines is deferred. Shapes below follow official docs as of 2026-10-01; they have not been
verified against this server. A rejected configured header fails with 401 rather than falling back to OAuth.

**Claude Code** (user scope stays private across projects; `--scope project` writes `.mcp.json`):

```sh
claude mcp add --transport http --scope user hindsight https://hindsight.example.com/api/mcp \
  --header 'Authorization: Bearer ${HINDSIGHT_INGEST_TOKEN}'
```

Single quotes keep the variable unexpanded in POSIX shells. JSON form:
`{"mcpServers":{"hindsight":{"type":"http","url":"https://hindsight.example.com/api/mcp","headers":{"Authorization":"Bearer ${HINDSIGHT_INGEST_TOKEN}"}}}}`.
Check with `/mcp`.

**Codex CLI** (variable holds the raw token, no `Bearer ` prefix):

```sh
codex mcp add hindsight --url https://hindsight.example.com/api/mcp --bearer-token-env-var HINDSIGHT_INGEST_TOKEN
```

```toml
[mcp_servers.hindsight]
url = "https://hindsight.example.com/api/mcp"
bearer_token_env_var = "HINDSIGHT_INGEST_TOKEN"
```

**Cursor** (`~/.cursor/mcp.json` or project `.cursor/mcp.json`; set the variable in the system/shell
environment, since `envFile` is unsupported for remote servers):

```json
{"mcpServers":{"hindsight":{"url":"https://hindsight.example.com/api/mcp","headers":{"Authorization":"Bearer ${env:HINDSIGHT_INGEST_TOKEN}"}}}}
```

**OpenCode V2** (`opencode.jsonc`, servers under `mcp.servers`):

```json
{"$schema":"https://opencode.ai/config.json","mcp":{"servers":{"hindsight":{"type":"remote","url":"https://hindsight.example.com/api/mcp","oauth":false,"headers":{"Authorization":"Bearer {env:HINDSIGHT_INGEST_TOKEN}"}}}}}
```

**OpenCode V1** (servers directly under `mcp`):

```json
{"mcp":{"hindsight":{"type":"remote","url":"https://hindsight.example.com/api/mcp","oauth":false,"headers":{"Authorization":"Bearer {env:HINDSIGHT_INGEST_TOKEN}"}}}}
```

Z.ai is a model provider, not an MCP client; configure whichever client runs it. Agent guidance for
when and what to submit: [docs/agent-feedback.md](docs/agent-feedback.md).

## Tomorrow's setup checklist

1. Pick the canonical origin; add the custom domain in Vercel and wait for HTTPS. Set `HINDSIGHT_PUBLIC_ORIGIN` exactly (no trailing slash).
2. Create a Google OAuth web client; authorized redirect URI `<origin>/auth/callback/google`. Set `AUTH_GOOGLE_ID`, `AUTH_GOOGLE_SECRET`.
3. Generate `AUTH_SECRET`; set `HINDSIGHT_REVIEWER_EMAILS`.
4. Configure the existing approved PostgreSQL resource: set `DATABASE_URL` in Vercel (with TLS as the provider requires). Do not provision a new database.
5. From a trusted machine: `npm run migrate` (review the plan; it must list only `hindsight_*` migrations), then `npm run migrate -- --apply`.
6. Redeploy; confirm `/health` reports `ok`, and that requests via `*.vercel.app` or other hosts get `421`.
7. Sign in at `/review` with an allowlisted account; confirm a non-listed account is refused.
8. Create a short-lived token, configure one client manually, submit one real note, check it in `/review`; revoke and confirm `401`.
   Then repeat for the remaining clients.
9. Run `npm run test:db` against the disposable test database and record results.
