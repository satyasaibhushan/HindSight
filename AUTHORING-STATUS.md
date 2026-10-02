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
