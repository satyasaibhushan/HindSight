# Authoring status

Scope: a small Google-protected feedback review app plus submit-only ingestion tokens. No summaries,
dashboard, control plane, or extra integrations. All code, tests, config, and docs were authored by
Claude (Opus 5.5). The author ran **no** commands, tests, lints, or installs. Every result below that
says "passed" is an operator-run diagnostic and is labeled that way.

## Implemented

- Review UI (`/review`), token management (`/tokens`), MCP `submit_feedback` at `/api/mcp`, `/health`.
- Fail-closed setup-required mode; canonical HTTPS host/proxy gate; reviewer allowlist; CSRF/origin checks.
- Tokens: hashed at rest, `feedback:submit` scope, expiry, revocation, rechecked on every request.
- Owner-scoped idempotent ingestion (`request_id` + client-bound payload hash); bounded per-token throttle.
- `scripts/migrate.js`: `hindsight_schema_migrations` ledger, checksums, advisory lock, per-file
  transactions, plan/`--apply`/`--verify-files`, import without side effects.
- `scripts/dev.js` local entrypoint; npm `start`/`dev`/`migrate`/`check`/`test`/`test:db` (Node 24).
- `test/db.test.js` against isolated `hindsight_test_*` schemas on `HINDSIGHT_TEST_DATABASE_URL` only.
- README, `.env.example` (empty), `.gitignore`, `docs/agent-feedback.md`.

## Fixed in slice006 (authored; not yet operator-verified)

1. **Token listing reaches every token.** `listTokens` returns `{ rows, nextCursor }`: newest first,
   50 per page, keyset cursor `before` = the last token id on the page. The cursor is resolved only
   among the owner's own tokens, so a foreign or unknown cursor yields an empty page. `/tokens` rejects
   malformed cursors with `400`.
2. **Removed reviewers lose MCP access.** A token whose owner is absent from `HINDSIGHT_REVIEWER_EMAILS`
   gets the generic `401 invalid_token` before any throttle or submission.
3. **Sign-in CSP.** Only `/auth/signin` adds `https://accounts.google.com` to `form-action`. Every
   other route, including the review and token forms, stays `'self'`.

Tests authored for these (run by nobody yet):

- `test/app.test.js`:
  - A removed owner's initialize, tools/list, and tools/call each get `401`, with no `hitRateLimit` or `insertFeedback` call.
  - An exact CSP string is checked per route.
  - The token pager links and cursor validation are checked.
- `test/mcp.test.js`: the official client cannot connect with a removed owner's token, and there is no throttle or insert. The existing exact-one-tool, protocol, and error tests are kept.
- `test/db.test.js`:
  - The owner-isolation case is updated to `{ rows, nextCursor }`.
  - New test with 121 tokens: all but one share a `created_at`, so the id tiebreak is exercised. It walks every page with no duplicates or gaps, reaches and revokes the oldest, and shows another owner's cursors, revoke, and listing get nothing. It also covers unknown and malformed cursors.
  - The throttle test now pins the rate window in a fixture, so a minute rollover can no longer flake it. Production SQL is unchanged.

## Category pass (authored; not yet operator-verified)

Purpose: useful improvements to the user's editable shared project instructions, skills, codebase,
and collaboration, as well as tools and connectors.

- `migrations/004_feedback_categories.sql` widens the `category` check additively. `src/mcp.js`
  `CATEGORIES` adds `instructions`, `skills`, `codebase`, `collaboration` and keeps every old value.
  A modest review-UI pass was also done.
- `test/db.test.js`: migration assertions now cover four files (versions, names, checksums). The
  rollback fixture moved to the unused version `005`. The `003` collapse test now expects `003`
  and `004` applied. A static test checks that the `004` constraint equals `CATEGORIES`. A new
  isolated-PostgreSQL test round-trips each new category plus `tooling`, filters by each one, and
  shows the schema rejects an unknown category.
- `test/mcp.test.js`: the official client sees each new category advertised and accepted, plus
  retained ones. Unknown categories are still rejected.
- README and `docs/agent-feedback.md` describe the purpose and categories. They also say feedback
  must be truthful, never include provider-private prompts or policies, and that a `request_id` is
  reused only for identical retries.

## UI/UX overhaul (authored; tested locally in this session)

- New shared UI module `src/ui.js`: design tokens with light/dark themes, an app shell with Inbox / API keys / Connect
  navigation, inline SVG icons, and one inline script pinned by a CSP `script-src` hash (copy buttons, revoke
  confirmation, filter auto-submit; everything works without it).
- New screens: custom sign-in (fixes the Google button, whose logo the CSP blocked), sign-out confirmation, Connect
  (copyable per-client MCP setup), restyled setup-required and error screens.
- Inbox: state tabs, category and API-key filters, two-column friction/improvement cards, one-click review state that
  returns to the same filtered view, and a copyable request id.
- API keys: name only (no client field; the name is stored as the client label, with no schema change), preset
  expiry, a table with status/created/last used/expiry, a one-time reveal with copy buttons and an env-var snippet,
  and revoke with confirmation plus a flash message.
- `npm run check` and `npm test` (55 tests, DB tests not run) passed locally. A headless Chromium click on "Continue
  with Google" was redirected to `accounts.google.com` with the canonical `redirect_uri`. A real Google round trip is
  still untested.

## Admin keys (authored and run locally in this session; not yet operator-verified)

Branch `revamp/checklist-admin-keys`. Purpose: let the owner read and act on their feedback programmatically.

- **Scopes.** `migrations/005_admin_scope.sql` widens the token `scope` check additively to
  `feedback:submit` (ingest, still the default) and `feedback:admin`. Decision: an admin key can do
  everything (submit, read, update state/note); an ingest key can only submit. Anything other than the
  exact admin scope is treated as ingest in code (`src/admin.js`).
- **Same gate.** `/api/mcp` and the new `/api/v1` share one bearer middleware: setup-required, canonical
  HTTPS host gate, foreign `Origin` refusal, token validity (expiry/revocation), owner allowlist, and the
  durable per-key rate limit. Session cookies are never consulted there. Admin operations use the token's
  normalized, allow-listed owner, so isolation matches `/review`.
- **MCP.** Ingest keys still list exactly `submit_feedback`. Admin keys also get `list_feedback`
  (state/category/key filters, limit ≤ 100, keyset cursor), `get_feedback`, `update_feedback_state`
  (optional `review_note`), and `bulk_update_feedback_state` (≤ 100 ids). Tool descriptions flag item text
  as untrusted. Storage errors return a generic error.
- **REST.** `GET /api/v1/feedback`, `GET`/`PATCH /api/v1/feedback/:id`, `POST /api/v1/feedback/bulk`
  (`src/api-v1.js`), with zod-validated strict query and body handling. Status codes: 401
  `invalid_token`, 403 `insufficient_scope`, 400 `invalid_request`, 404 `not_found` (including another
  owner's id), 413/415, 429, 503.
- **Storage** (`src/db.js`). `listFeedbackPage` (keyset cursor resolved in the owner-scoped subquery),
  `getFeedback`, `updateFeedback`, and `bulkSetReviewState` (one atomic UPDATE). New nullable
  `actioned_at`/`dismissed_at` record when an item last entered that state. `review_note` (1–2000) is
  settable through the API, MCP, and a small CSRF-protected form on `/review` (`POST /review/:id/note`).
  `CATEGORIES`/`OUTCOMES` moved to `db.js` (re-exported from `mcp.js`) to avoid an import cycle.
- **UI** (minimal; the restyle is a separate task). `/tokens` has an Access select (Ingest / Admin), a scope
  pill in the list, and the scope plus `HINDSIGHT_ADMIN_TOKEN` on the reveal. `/review` cards have a
  collapsible note form. CSS: `textarea` joins the input styles, and `.form-row` gains one column.
- **Tests.** In-memory admin store mirror in `test/helpers.js`. `test/mcp.test.js` covers the tool catalog
  and schemas, ingest refusal, paging and filters, isolation, errors, and the gated official client.
  `test/app.test.js` covers the REST gate (setup, canonical, origin, cookies ignored, 401/403/429/503),
  validation, paging, isolation, the token scope UI, and review notes. `test/db.test.js` covers the 005
  migration over pre-existing data, scope auth, keyset paging over 60 items with ties, get/update/bulk
  isolation and timestamps, and REST plus MCP end to end on PostgreSQL, including revoked and
  removed-owner admin keys. The rollback fixture moved from `005` to the unused version `900`.
  `scripts/migrate.js` needed no change: checksums are computed from the files and `--verify-files` lists 005.
- **Run in this session.** `npm run check` passed. `npm test` passed 75/75 without a DB. `npm run test:db`
  passed 29/29 on a local disposable PostgreSQL 16 `hindsight_test`. A manual curl run against a live
  server on PostgreSQL also passed (list, cursor, PATCH, bulk, ingest key `403`, non-canonical `421`).

## Checklist UI revamp (authored and run locally in this session; not yet operator-verified)

Branch `revamp/checklist-admin-keys`, on top of the admin-keys backend. Follows the design spec and mockup
(the Inbox as a to-do list; amber for admin keys).

- **Tokens and shell** (`src/ui.js`): the new light/dark token set (`--ok/--planned/--warn/--danger/--admin…`), a smaller
  topbar, and restyled sign-in, sign-out, setup-required, and error screens. The one inline script gained: close the
  `⋯` menu on an outside click or Escape, a live "N selected" count, and opening an item whose note was just saved. It is
  still interpolation-free and pinned by its SHA-256 hash. A short `ago()` formatter ("14 min ago", "Yesterday") goes with
  the UTC-day groups.
- **Inbox** (`/review`): compact checklist rows. The checkbox is a submit button (`role=checkbox`, `aria-checked`):
  ticking posts `actioned`, and ticking a done or won't-do item posts `new`. The improvement is the title. A native
  `<details>` holds the friction, facts, request id plus copy button, the review note form (moved in from its own
  collapsible), and Plan / Won't do / Mark done. There is a `⋯` overflow menu, Open/Done/Won't do/All tabs with counts,
  category/API key/group filters, date or category group headers, empty states, and Newer/Older paging (unchanged).
  Legacy `?state=` values are mapped (README).
- **Bulk** (`POST /review/bulk`): one form (`id="bulk"`, rows join it via `form=`), with CSRF and origin checks, an
  owner-scoped update via `admin.js` `bulkUpdate` and the existing `bulkSetReviewState`, 1–100 UUIDs, and a valid state.
  Otherwise it returns `400`.
- **Store**: `listFeedback` accepts `states` (array; single `state` still works); new `countFeedback(owner, {category,
  client})` returns every state's count. Both are in `src/db.js` and the in-memory mirror in `test/helpers.js`.
- **API keys**: the two-card radio scope chooser (Ingest default), the admin warning via `:has` (always visible
  without it), an amber create button, an amber admin reveal with `HINDSIGHT_ADMIN_TOKEN` and a link to `/connect#admin`,
  and a key table with a Scope column (stacks on mobile). On a validation error the posted name, scope, and expiry are kept.
- **Connect**: the "Use an admin key" section with the real tool names (`list_feedback`, `get_feedback`,
  `update_feedback_state`, `bulk_update_feedback_state`), `/api/v1` curl examples, and a note that admin keys can also submit.
- **Screenshots**: `scripts/screenshots.js` (new; added to `npm run check`) regenerated `docs/screenshots/after/01–13`
  and added 14–19 (bulk select desktop/mobile, admin key created, connect admin, mobile dark, keys dark).
- **Tests**: `test/app.test.js` assertions on the old markup were updated. New tests cover the checklist rows, tabs,
  owner-scoped counts, and groups; tick/untick/reopen; empty states; bulk (CSRF, origin, owner isolation, the 100 cap,
  invalid state and ids, select-mode markup); the scope chooser; and the connect admin section. `test/db.test.js` adds
  multi-state listing, filtered owner-scoped counts, and bulk isolation on PostgreSQL.
- **Run in this session** (Node 22.22, the only Node available; `engines` says 24): `npm run check` passed, `npm test`
  passed 81/81, and `npm run test:db` passed 30/30 on the local disposable PostgreSQL 16 `hindsight_test`. A headless
  Chromium check at 390px found no horizontal scroll on any page and no CSP console errors, with and without
  JavaScript. The no-JS tick and bulk round trips also worked.

## Inbox "Show more" (authored and run locally in this session; not yet operator-verified)

Branch `fix/inbox-load-more`. Owner bug: Newer/Older swapped the whole list instead of adding to it.

- `/review` pages by `?shown=n` (cumulative, 25-item steps, cap `MAX_SHOWN` = `(MAX_PAGE+1)*PAGE_SIZE` = 1,025) in place
  of `?page=`; the Newer button is gone, and at the cap a note suggests filtering. Old `?page=p` maps to `shown=(p+1)*25`.
- No JS: "Show more" links to `?shown=n+25#more-n` (`id="more-n"` on the first item of each later batch). With JS: the
  inline script fetches only the new batch (`X-HindSight-Batch: 1`), merges rows by `data-group`/`data-order`, skips ids
  already shown, swaps the footer, `replaceState`s `shown`, and rewrites every `next` input and `data-here` link. On any
  failure it falls back to the plain link. CSP gains `connect-src 'self'` (exact-CSP test and README updated).
- Redirects: every form's `next` is the full current URL, so state, note, and bulk changes keep the tab, filters,
  grouping, `shown`, and select mode (bulk used to drop select mode). A state change that moves the item out of the
  view lands on a neighbouring row (`near`) instead of the top of a long list.
- Store: `listFeedback` takes an optional `limit` (default 25, clamped 1–1,025); the default call is unchanged and owner
  scoping is untouched. Full renders use `LIMIT n+1` from offset 0; the script's batch uses `LIMIT 26 OFFSET n`.
- Tests: pager assertions updated; new tests cover cumulative order and groups across batches, the batch fragment,
  the cap and note, old `?page=` mapping, and redirects keeping `shown`, filters, and select mode. `test/db.test.js`
  checks that `limit` equals the batches concatenated, and covers clamping and owner isolation on PostgreSQL.
- Screenshots `20-inbox-show-more` and `21-inbox-show-more-mobile` added; the other screenshots are visually unchanged
  (the sample inbox has fewer than 25 items) and were not regenerated. A headless Chromium run checked the JS append
  with date, category, and no grouping against the server render of the same URL, with no console or CSP errors.
- Run (Node 22.22): `npm run check` passed; `npm test` 85/85; `npm run test:db` 31/31 on local PostgreSQL 16
  `hindsight_test`; `npm test` with the DB URL set 113/113, none skipped.

## Operator-run diagnostics (reported to the author, not run by the author)

- slice004: clean install, syntax check, 41 tests, and `npm audit` (0) passed. Manual checks on isolated
  PostgreSQL for idempotency, throttle, and revocation passed.
- slice005: clean install, syntax, and migration checks passed. 53 of 53 tests passed with zero skips
  on disposable PostgreSQL, and audit passed. Real-HTTP checks also passed: legacy `2025-11-25`
  initialize, plus current `2026-07-28` discovery, tools/list, and submit.
- slice007: clean install, `npm ci`, syntax, and migration checks passed. All 58 tests passed with
  zero skips, including PostgreSQL and the removed-owner official-client test. Audit was 0 and
  source hashes matched. These results came before the category pass.

## Remaining verification

- [ ] Operator: run the category-pass checks (`npm run check`, `npm test`, `npm run test:db` on
      disposable PostgreSQL, none skipped) and do a browser review of the `004`/category/UI changes.
- [ ] Reviewer: finish the slice008 UI/auth regression check, which is in progress.
- [ ] Migration scope guard is a static regex check; review the SQL by hand before `--apply`.
- [ ] Tomorrow: configure the existing approved PostgreSQL resource (dedicated `hindsight_*` tables),
      real Google/session/reviewer config, custom domain, explicit migration (README checklist).
- [ ] Not yet tested: real Google sign-in, any of the four MCP client configs end to end, production persistence.
- [ ] Operator: apply `005` (`npm run migrate` plan must list only it), then run README checklist step 9 (admin key).
- [ ] Reviewer: browser check of the checklist Inbox (tick, reopen, `⋯` menu, bulk select, notes), the `/tokens` scope
      chooser, and `/connect#admin` in Safari and Firefox as well as Chromium (only headless Chromium was used here).
