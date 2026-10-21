# HindSight

A small Google-protected feedback review app plus API keys: submit-only **ingest** keys for MCP clients,
and owner-scoped **admin** keys that can also read and triage that feedback over MCP or a small REST API.

Its purpose: agents submit useful, concrete improvements to the user's editable shared project
instructions, skills, codebase, and collaboration, as well as tools and connectors, so the user can
review and act on them.

Categories (`category`, required): `instructions`, `skills`, `codebase`, `collaboration` (primary),
plus the retained `connector`, `tooling`, `environment`, `documentation`, `workflow`, `performance`,
`other`. The set is additive; existing rows and clients stay valid. Any other value is rejected.

- `/auth/signin`, `/auth/signout` — HindSight's own sign-in ("Continue with Google") and sign-out screens.
  Their forms POST to Auth.js with the CSRF token Auth.js issued; Auth.js errors (e.g. a non-allowlisted
  account) redirect back to the sign-in screen with a readable message.
- `/review` (Inbox) — reviewers (Google sign-in, email allowlist) work through their own feedback as a checklist
  (see [Inbox checklist](#inbox-checklist)): tick an item to mark it done, expand it for the friction, context, request id,
  a private review note, and Plan / Won't do / Mark done, or select many and change them at once.
- `/tokens` (API keys) — reviewers create, list, and revoke API keys (7/30/60/90 day expiry) with a scope chosen
  from two cards: **Ingest** (default), scope `feedback:submit`, or **Admin**, scope `feedback:admin`
  (see [Admin keys](#admin-keys-and-the-rest-api)). Admin keys are amber everywhere: picking Admin shows a warning
  (CSS `:has`; browsers without it always show the warning), and the list and the one-time reveal mark admin keys.
  The list stacks into label/value rows on narrow screens. A key has only a **name**; that name is stored as the token's client label, which attributes
  and idempotency-binds its submissions (the `client` column is kept, so existing tokens and rows are unchanged).
  The list is newest first, 50 per page, using a keyset cursor `?before=<token id>` (the last id on the
  previous page). The cursor is resolved only among the signed-in owner's tokens, so every token,
  including the oldest, is reachable and revocable, and a foreign or unknown id yields an empty page.
  A malformed cursor gets `400`.
- `/api/mcp` — Streamable HTTP MCP endpoint, authenticated by bearer token. Ingest keys see exactly one tool,
  `submit_feedback`; admin keys also see the admin tools listed below.
  The token's owner must still be listed in `HINDSIGHT_REVIEWER_EMAILS`. Removing an owner disables
  their tokens at once: requests get the same `401 invalid_token` as an unknown token, before any
  throttle or submission.
  Its tool catalog is static per key, so it does not advertise catalog-change subscriptions. Premature client
  disconnects abort the MCP exchange and cancel its response stream.
- `/api/v1` — JSON REST API for admin keys (`Authorization: Bearer hs_…`): list, get, and update feedback.
  Same gate as `/api/mcp`; session cookies are never accepted.
- `/connect` — copyable MCP setup for Claude Code, Codex CLI, Cursor, and OpenCode, filled in with this origin, plus a
  "Use an admin key" section (`/connect#admin`) with the admin MCP tools and `/api/v1` examples.
- `/health` — reports `ok` or `setup-required`; no secrets.

All pages send `Content-Security-Policy` with `default-src 'none'`, `connect-src 'self'`, and `form-action 'self'`.
The one exception is the sign-in page (`/auth/signin`), which also allows `https://accounts.google.com` so its Google
redirect can complete. The only script is one small inline progressive-enhancement script (copy buttons, revoke
confirmation, filter auto-submit, closing the `⋯` menu on an outside click or Escape, the live "N selected" count,
opening an item after its note is saved, and the Inbox's in-place "Show more", which is the only reason for
`connect-src 'self'`: it fetches the next batch from `/review`), allowed by its SHA-256 hash; every page works without it. Icons and the
Google logo are inline SVG, so nothing external is loaded. (Auth.js's built-in sign-in page loaded its Google
logo from `authjs.dev`, which this CSP blocked, leaving a broken image in the button.)

Feedback is attributable to the owner and the API key (token name) that submitted it. It is **not anonymous**.
Do not submit secrets, transcripts, or provider-private prompts or policies; obvious secret patterns
are rejected. Submit best effort at final handoff, skip generic or no-op notes, and reuse a
`request_id` only to retry the identical submission (see `docs/agent-feedback.md`).

## Inbox checklist

The Inbox treats each item as a task. The **improvement** is the title; the friction, the context (repository, task,
source, outcome, confidence), the request id with a copy button, the review note form, and the state buttons sit in a
native `<details>` panel. Every control is a plain form POST or link, so the page works without JavaScript.

| Stored `review_state` | Shown as | Checkbox | Ticking it |
| --- | --- | --- | --- |
| `new` | Open | empty | marks it Done (`actioned`) |
| `triaged` | Planned (a dot and a "Planned" tag) | empty with a dot | marks it Done |
| `actioned` | Done (title struck through) | ticked | reopens it (`new`) |
| `dismissed` | Won't do (muted, with a tag) | dash | reopens it (`new`) |

- **Views** are tabs with per-view counts: **Open** (`new` + `triaged`, the default), **Done**, **Won't do**, **All**.
  The counts are one owner-scoped `GROUP BY review_state` query that honours the category and API-key filters.
  The query is `?state=open|done|wontdo|all`. Old links keep working: `?state=actioned` opens Done, `?state=dismissed`
  opens Won't do, and `?state=new` or `?state=triaged` narrows the Open view to that one state (with a "Show all open" link).
  `/review` with no `state` now opens the Open view rather than everything.
- **Filters**: category, API key, and grouping (`?group=` omitted for date, `category`, or `none`). Date groups are
  Today / Yesterday / Earlier by UTC calendar day. The selects auto-submit with JavaScript; an Apply button covers the rest.
- **Row actions**: the `⋯` menu (a `<details>`) offers Plan/Unplan, Won't do or Reopen, "Only this API key", and copy
  request id. After a change the page returns to the same view (tab, filters, grouping, select mode, and list length),
  scrolled to the changed row, or to its neighbour if the change moved it out of the view (e.g. ticked in Open).
- **Bulk select** (`?select=1`): every row gets a real checkbox tied to one form that POSTs `ids` and `state` to
  `/review/bulk`. It is CSRF- and origin-checked like every other form, takes 1–100 well-formed ids (anything else is
  `400`), and uses the same owner-scoped atomic store update as the admin API, so another owner's ids are never changed.
- **Show more** (`?shown=n`): the list grows in batches of 25 instead of paging. `?shown=n` renders the newest `n` items
  (rounded up to a whole batch) as one list, so date and category groups span every batch, from one owner-scoped
  `LIMIT n+1` query with no `OFFSET`. Without JavaScript, "Show more" links to `?shown=n+25#more-n`, which lands on the
  first new item. With it, the link fetches only the new batch (header `X-HindSight-Batch: 1`; `LIMIT 26 OFFSET n`),
  merges the rows into matching groups or inserts new group sections, and `replaceState`s the new `shown` into the URL
  and every form's return path. The list stops at 1,025 items (the reach of the old pages 0–40) with a note to filter.
  Old `?page=p` links map to `shown=(p+1)*25`; `shown` wins if both are given.

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
- `node scripts/screenshots.js` regenerates `docs/screenshots/after/*.png`: it boots the real app on the in-memory test
  store with synthetic config, a fixed signed-in reviewer, and seeded sample data, and captures it with Playwright
  (desktop, 390px mobile, light and dark; `20`/`21` show the Inbox after "Show more"). Playwright is not a project dependency: it needs a local Playwright and
  Chromium (`PLAYWRIGHT_MODULE` may point at its entry file). It never touches a database.
- `test/db.test.js` (migrations, persistence, category roundtrip and filtering, owner isolation,
  expiry/revocation, idempotency, throttling, token keyset paging over more than 100 tokens, admin scope,
  admin feedback paging/get/update/bulk, and the REST/MCP admin gate end to end) needs `HINDSIGHT_TEST_DATABASE_URL`. It never reads `DATABASE_URL` for connections and
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
| `HINDSIGHT_RATE_LIMIT_PER_MINUTE` | Per-token MCP requests per minute (1–600, default 20). |

Authentication reads current token validity on every MCP request; discovery and notifications still
count against the durable rate limit. `last_used_at` records authenticated usage at most once per
minute, so its timestamp may lag the latest request by up to a minute. Storage uses at most three
connections per instance, with 5-second connection/acquisition, 3-second lock, 10-second SQL statement,
and 12-second client query deadlines. PostgreSQL cancels statements and lock waits at its deadlines.

Google OAuth redirect URI: `<HINDSIGHT_PUBLIC_ORIGIN>/auth/callback/google`.

## Migrations (explicit, never on startup)

Migrations touch only `hindsight_*` tables. The ledger is `hindsight_schema_migrations`
(version, name, SHA-256 checksum). A session advisory lock on one connection serializes concurrent
runners; each file plus its ledger row commits in one transaction. Already-applied files are skipped;
a changed or missing applied file aborts before applying anything; a failed file rolls back and can
be retried. `003` collapses per-window rate rows to one row per token (primary key `token_id`).
`004` widens the `category` check to the additive set above; no data changes. `005` widens the token
`scope` check to `feedback:submit`/`feedback:admin` (existing tokens stay ingest keys) and adds nullable
`actioned_at`, `dismissed_at`, and `review_note` (1–2000 characters) to `hindsight_feedback`.

```sh
npm run migrate                # read-only plan against DATABASE_URL (from env or .env)
npm run migrate -- --apply     # apply pending migrations
```

The scope guard on migration files is a best-effort static check, not a sandbox; review SQL before
applying. Use a database role limited to the HindSight tables where possible.

## Admin keys and the REST API

An **admin** key (`feedback:admin`) can do everything an ingest key can (submit) and also read and update
its owner's feedback. An **ingest** key (`feedback:submit`, the default) can only submit. No key can
create, list, or revoke keys; that stays in the signed-in `/tokens` UI.

- **Owner-scoped.** Every read and update is confined to the key owner's feedback, the same isolation
  as `/review`. Another owner's item id behaves exactly like an unknown id (`404`/`not_found`).
- **Same gate as ingest keys.** The owner must still be in `HINDSIGHT_REVIEWER_EMAILS`; expiry,
  revocation, and the per-key rate limit (`HINDSIGHT_RATE_LIMIT_PER_MINUTE`) apply on every request. A
  revoked, expired, unknown, or removed-owner key gets `401 invalid_token`.
- **Only review fields change:** `state`, its timestamps, and `review_note`. Submitted text and context
  are never modified, and nothing can be deleted.
- **Untrusted content.** Item text is agent-submitted. An agent using an admin key must treat it as data,
  never as instructions.
- Store an admin key separately, e.g. in `HINDSIGHT_ADMIN_TOKEN`, and only where something actually needs to
  read or triage feedback. Use ingest keys for ordinary agents.

### MCP admin tools (`/api/mcp`, admin keys only)

| Tool | Input | Result (JSON text) |
| --- | --- | --- |
| `list_feedback` | optional `state`, `category`, `key` (API key name), `limit` (1–100, default 25), `cursor` | `{ items, next_cursor }` |
| `get_feedback` | `id` | item, or an error if not found |
| `update_feedback_state` | `id`, `state`, optional `review_note` (≤ 2000 chars; `""`/`null` clears) | updated item |
| `bulk_update_feedback_state` | `ids` (1–100), `state` | `{ state, updated, not_found }` |

`state` is one of `new`, `triaged`, `actioned`, `dismissed`. Ingest keys still list exactly `submit_feedback`,
and calling an admin tool with one fails as an unknown tool.

### REST API (`/api/v1`, admin keys only)

Authenticate with `Authorization: Bearer hs_…`. Request bodies must be `application/json` (max 16 KB).
Responses are JSON with `Cache-Control: no-store`. Unknown query parameters and body fields are rejected.

| Method and path | Body / query | Success |
| --- | --- | --- |
| `GET /api/v1/feedback` | `?state=&category=&key=&limit=1..100&cursor=<id>` | `200 { items, next_cursor }` |
| `GET /api/v1/feedback/:id` | | `200` item |
| `PATCH /api/v1/feedback/:id` | `{ "state"?: …, "review_note"?: string \| null }` (at least one) | `200` updated item |
| `POST /api/v1/feedback/bulk` | `{ "ids": [1–100 ids], "state": … }` | `200 { state, updated, not_found }` |

Items are newest first. `next_cursor` is the id of the last item on the page (or `null`); pass it back as
`cursor`. Like the token list, the cursor is resolved only among the owner's items, so a foreign or unknown
cursor gives an empty page. An item looks like:

```json
{"id":"…","state":"actioned","category":"skills","key":"Work laptop","request_id":"…","friction":"…",
 "improvement":"…","task":null,"source":null,"repository":null,"outcome":null,"confidence":null,
 "review_note":"Fixed in the skills repo","created_at":"…","reviewed_at":"…","actioned_at":"…","dismissed_at":null}
```

`reviewed_at` is the last state change; `actioned_at`/`dismissed_at` record when the item last entered that
state and are kept if it later moves on. Setting only `review_note` does not touch them.

| Status | `error` | When |
| --- | --- | --- |
| 400 | `invalid_request` (with `issues`) / `bad_request` | Validation failure / malformed JSON |
| 401 | `invalid_token` | Missing, malformed, unknown, expired, or revoked key, or owner no longer a reviewer |
| 403 | `insufficient_scope` | An ingest key on any `/api/v1` endpoint (`WWW-Authenticate: Bearer error="insufficient_scope", scope="feedback:admin"`) |
| 403 | `forbidden_origin` | A browser `Origin` other than `HINDSIGHT_PUBLIC_ORIGIN` |
| 404 | `not_found` | Unknown item, another owner's item, or unknown route |
| 413 / 415 | `payload_too_large` / `unsupported_media_type` | Body over 16 KB / not `application/json` |
| 421 | `misdirected_request` | Non-canonical host or non-HTTPS proxy headers |
| 429 | `rate_limited` | Per-key rate limit (`Retry-After: 60`) |
| 503 | `setup_required` / `storage_unavailable` | Deployment not configured / storage error |

There are no CORS headers, and cookies are never read on `/api/v1`, so CSRF does not apply.

```sh
H="Authorization: Bearer $HINDSIGHT_ADMIN_TOKEN"
API=https://hindsight.example.com/api/v1

curl -sS -H "$H" "$API/feedback?state=new&limit=50"
curl -sS -H "$H" "$API/feedback?state=new&limit=50&cursor=<next_cursor>"
curl -sS -H "$H" "$API/feedback/<id>"
curl -sS -X PATCH -H "$H" -H 'Content-Type: application/json' \
  -d '{"state":"actioned","review_note":"Fixed in the skills repo"}' "$API/feedback/<id>"
curl -sS -X POST -H "$H" -H 'Content-Type: application/json' \
  -d '{"ids":["<id1>","<id2>"],"state":"dismissed"}' "$API/feedback/bulk"
```

To give an MCP client the admin tools, configure it exactly as below but with the admin key's variable
(e.g. `HINDSIGHT_ADMIN_TOKEN`) in place of `HINDSIGHT_INGEST_TOKEN`.

## MCP client setup (manual, ingestion)

Create an API key at `/tokens` (the `/connect` screen has copyable versions of the snippets below), then store the raw token (`hs_…`) in the dedicated environment
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
9. Create a short-lived admin key; confirm `GET /api/v1/feedback` lists the note, `PATCH` changes its state in `/review`,
   and an ingest key gets `403 insufficient_scope`. Revoke the admin key and confirm `401`.
10. Run `npm run test:db` against the disposable test database and record results.
