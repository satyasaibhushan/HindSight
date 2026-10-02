import express from 'express';
import { MAX_PAGE, REVIEW_STATES } from './db.js';
import { CATEGORIES, handleMcp } from './mcp.js';
import { canonicalHeadersOk, checkCsrf, csrfToken, escapeHtml as e, generateToken, hashToken, safeRelativePath, sameOrigin } from './security.js';
import { GOOGLE_G, SCRIPT_HASH, alertBox, copyButton, emptyState, icon, shell, solo, when } from './ui.js';

const setupPage = () => solo('Setup required', `<div style="text-align:left"><p>HindSight collects the improvement notes your agents
submit about your shared instructions, skills, codebase, collaboration, and tools.</p>
<p>This deployment is not ready yet: sign-in, storage, and reviewer access have not all been configured. Until they are,
sign-in, review, and feedback submission stay switched off.</p></div>
<p class="fine">${icon('wrench')} Operators: follow the setup checklist in the project README.</p>`);

// The sign-in page's form POSTs to /auth/signin/google, which 302s to Google's authorization
// endpoint; browsers apply form-action to that redirect. Only that page may target the exact Google
// authorization origin; every other route stays form-action 'self'.
export const GOOGLE_AUTH_ORIGIN = 'https://accounts.google.com';
const SIGNIN_PAGE = /^\/auth\/signin\/?$/;
// The only script allowed is the shared inline one in ui.js, pinned by hash.
export const csp = (formAction) =>
  `default-src 'none'; script-src ${SCRIPT_HASH}; style-src 'unsafe-inline'; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`;

function privateHeaders(req, res, next) {
  res.set({
    'Cache-Control': 'no-store',
    'Content-Security-Policy': csp(SIGNIN_PAGE.test(req.path) ? `'self' ${GOOGLE_AUTH_ORIGIN}` : "'self'"),
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin',
  });
  next();
}

// deps: { config, store, getReviewer(req) -> {email}|null, authRouter,
//         getAuthCsrf(req) -> { csrfToken, cookies: string[] } (Auth.js CSRF token for the sign-in/out forms) }
export function createApp({ config, store, getReviewer, authRouter, getAuthCsrf }) {
  const app = express();
  app.set('trust proxy', false);
  app.disable('x-powered-by');
  app.use(privateHeaders);

  // Canonical gate: runs before Auth.js, MCP, or any store access. Host/proxy headers must match the
  // configured HTTPS origin; they are then normalized so Auth.js derives callback/session URLs and
  // Secure cookies from the canonical origin only.
  const canonicalHost = config.ready.origin ? new URL(config.publicOrigin).host : null;
  app.use((req, res, next) => {
    if (req.path === '/health') return next();
    if (!canonicalHost) {
      return req.path.startsWith('/api/')
        ? res.status(503).json({ error: 'setup_required' })
        : res.status(503).send(setupPage());
    }
    if (!canonicalHeadersOk(req, canonicalHost)) return res.status(421).json({ error: 'misdirected_request' });
    const origin = req.get('origin');
    if (origin !== undefined && origin !== config.publicOrigin) return res.status(403).json({ error: 'forbidden_origin' });
    req.headers.host = canonicalHost;
    req.headers['x-forwarded-host'] = canonicalHost;
    req.headers['x-forwarded-proto'] = 'https';
    Object.defineProperty(req, 'protocol', { value: 'https', configurable: true });
    next();
  });

  app.get('/health', (_req, res) => {
    res.json({ status: config.webReady && config.mcpReady ? 'ok' : 'setup-required', web: config.webReady, mcp: config.mcpReady });
  });

  // ---- MCP: ingestion-only bearer tokens, authenticated before any body parsing or data access.
  app.all('/api/mcp', async (req, res, next) => {
    if (!config.mcpReady) return res.status(503).json({ error: 'setup_required' });
    const match = /^Bearer (hs_[A-Za-z0-9_-]{43})$/.exec(req.get('authorization') || '');
    let token = null;
    try {
      token = match && await store.authenticateIngestionToken(hashToken(match[1]));
      // The owner must still be a configured reviewer. Checked before throttle/MCP; a removed owner gets
      // the same generic invalid_token response as an unknown token.
      const owner = typeof token?.ownerEmail === 'string' ? token.ownerEmail.trim().toLowerCase() : '';
      if (token && !config.reviewers.includes(owner)) token = null;
      if (token && !await store.hitRateLimit(token.id, config.rateLimitPerMinute)) {
        return res.status(429).set('Retry-After', '60').json({ error: 'rate_limited' });
      }
    } catch {
      return res.status(503).json({ error: 'storage_unavailable' });
    }
    if (!token) {
      return res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'invalid_token' });
    }
    req.ingestionToken = token;
    next();
  }, express.raw({ type: () => true, limit: '32kb' }), async (req, res) => {
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') headers.set(k, v);
    const hasBody = !['GET', 'HEAD'].includes(req.method) && Buffer.isBuffer(req.body) && req.body.length > 0;
    const request = new Request(config.publicOrigin + req.originalUrl, {
      method: req.method, headers, body: hasBody ? req.body : undefined,
    });
    const response = await handleMcp(store, req.ingestionToken, request);
    res.status(response.status);
    response.headers.forEach((v, k) => res.setHeader(k, v));
    res.setHeader('Cache-Control', 'no-store');
    if (!response.body) return res.end();
    for await (const chunk of response.body) res.write(chunk);
    res.end();
  });

  // ---- Web: Google-protected review UI. Fail closed until fully configured.
  const setupRequired = (_req, res) => res.status(503).send(setupPage());
  if (!config.webReady) {
    app.use(['/auth', '/review', '/tokens', '/connect'], setupRequired);
  }

  // Sign-in and sign-out screens are rendered here rather than by Auth.js: its built-in page loads the
  // Google logo from authjs.dev, which this CSP blocks. Their forms still POST to Auth.js, carrying the
  // CSRF token Auth.js issued (getAuthCsrf also returns the matching cookie to set).
  const authCsrf = async (req, res) => {
    const { csrfToken: token, cookies = [] } = await getAuthCsrf(req);
    for (const cookie of cookies) res.append('Set-Cookie', cookie);
    return e(token);
  };

  app.get(/^\/auth\/signin\/?$/, async (req, res, next) => {
    if (!getAuthCsrf) return next();
    const callbackUrl = callbackPath(req.query.callbackUrl, config.publicOrigin);
    if (await getReviewer(req)) return res.redirect(303, callbackUrl);
    const error = typeof req.query.error === 'string' ? req.query.error : '';
    const message = !error ? (req.query.signedOut === '1' ? alertBox('ok', 'You have been signed out.') : '')
      : alertBox('err', e(SIGNIN_ERRORS[error] || SIGNIN_ERRORS.Default));
    res.status(error ? 401 : 200).send(solo('Sign in to HindSight', `${message}
<form method="post" action="/auth/signin/google"><input type="hidden" name="csrfToken" value="${await authCsrf(req, res)}">
<input type="hidden" name="callbackUrl" value="${e(callbackUrl)}">
<button class="gbtn" type="submit">${GOOGLE_G}<span>Continue with Google</span></button></form>
<p class="fine">${icon('shield')} Only allow-listed reviewer accounts can sign in.</p>`,
    { sub: 'Review the improvement notes your agents send about your instructions, skills, codebase, and tools.' }));
  });

  app.get(/^\/auth\/signout\/?$/, async (req, res, next) => {
    if (!getAuthCsrf) return next();
    const reviewer = await getReviewer(req);
    if (!reviewer) return res.redirect(303, '/auth/signin?signedOut=1');
    res.send(solo('Sign out?', `<form class="solo-actions" method="post" action="/auth/signout">
<input type="hidden" name="csrfToken" value="${await authCsrf(req, res)}"><input type="hidden" name="callbackUrl" value="/auth/signin?signedOut=1">
<button class="btn btn-block" type="submit">${icon('logout')}Sign out</button><a class="btn btn-ghost btn-block" href="/review">Cancel</a></form>`,
    { sub: `You are signed in as <b>${e(reviewer.email)}</b>.` }));
  });

  if (config.webReady) app.use('/auth', authRouter);

  const requireReviewer = async (req, res, next) => {
    const reviewer = await getReviewer(req);
    if (!reviewer) {
      return res.redirect(303, '/auth/signin?callbackUrl=' + encodeURIComponent(safeRelativePath(req.originalUrl)));
    }
    req.reviewer = reviewer;
    next();
  };
  const problem = (req, res, status, title, text, back = ['/review', 'Back to inbox']) =>
    res.status(status).send(shell(title, `<div class="card card-pad"><p style="margin-top:0">${text}</p>
<a class="btn btn-secondary" href="${back[0]}">${e(back[1])}</a></div>`, { user: req.reviewer }));
  const toTokens = ['/tokens', 'Back to API keys'];
  const requireMutation = (req, res, next) => {
    if (!sameOrigin(req, config.publicOrigin) || !checkCsrf(config.authSecret, req.reviewer.email, req.body?.csrf)) {
      return problem(req, res, 403, 'Forbidden', 'Request origin or CSRF token rejected. Reload the page and try again.');
    }
    next();
  };
  const form = express.urlencoded({ extended: false, limit: '4kb' });
  const ui = (req, current, extra = {}) => ({ user: req.reviewer, current, ...extra });

  app.get('/', (_req, res) => res.redirect(303, '/review'));

  const pick = (v, allowed) => (typeof v === 'string' && allowed.includes(v) ? v : undefined);
  const options = (value, list, any) => (any !== undefined ? `<option value="">${e(any)}</option>` : '') +
    list.map((o) => `<option value="${e(o)}"${o === value ? ' selected' : ''}>${e(o)}</option>`).join('');
  const STATE_LABEL = { new: 'New', triaged: 'Triaged', actioned: 'Actioned', dismissed: 'Dismissed' };

  app.get('/review', requireReviewer, async (req, res) => {
    const filters = {
      category: pick(req.query.category, CATEGORIES),
      state: pick(req.query.state, REVIEW_STATES),
      client: typeof req.query.client === 'string' && /^.{1,80}$/.test(req.query.client) ? req.query.client : undefined,
      page: Math.min(Math.max(Number.parseInt(req.query.page, 10) || 0, 0), MAX_PAGE),
    };
    const [{ rows, hasMore }, keys] = await Promise.all([
      store.listFeedback(req.reviewer.email, filters),
      store.listTokens(req.reviewer.email, {}),
    ]);
    const csrf = e(csrfToken(config.authSecret, req.reviewer.email));
    const qs = (over) => '/review?' + new URLSearchParams(Object.entries({ ...filters, page: String(filters.page), ...over })
      .filter(([, v]) => v !== undefined && v !== '' && v !== '0')).toString();
    const here = qs({});
    const ctx = (label, v) => (v ? `<div><dt>${label}</dt><dd>${e(v)}</dd></div>` : '');
    const items = rows.map((f) => {
      const id = e(f.id);
      const stateButtons = REVIEW_STATES.map((s) => `<button name="state" value="${s}" aria-pressed="${s === f.review_state}">${STATE_LABEL[s]}</button>`).join('');
      const context = ctx('Repository', f.repository) + ctx('Task', f.task) + ctx('Source', f.source) +
        ctx('Outcome', f.outcome) + ctx('Confidence', f.confidence);
      return `<article class="card fb" id="fb-${id}"><div class="fb-top"><span class="pill cat">${e(f.category)}</span>
<span class="pill ${e(f.review_state)}"><span class="dot"></span>${e(STATE_LABEL[f.review_state] || f.review_state)}</span>
<span class="src">${icon('bot')}${e(f.client)}</span>${when(f.created_at)}</div>
<div class="fb-body"><section><h2 class="label">${icon('bolt')}Friction</h2><div class="prose">${e(f.friction)}</div></section>
<section><h2 class="label">${icon('bulb')}Improvement</h2><div class="prose">${e(f.improvement)}</div></section></div>
${context ? `<dl class="ctx">${context}</dl>` : ''}
<div class="fb-foot"><span class="reqid">Request <code id="rq-${id}">${e(f.request_id)}</code>${copyButton('rq-' + f.id, 'Copy', 'btn btn-ghost btn-sm')}</span>
<form method="post" action="/review/${id}/state"><input type="hidden" name="csrf" value="${csrf}">
<input type="hidden" name="next" value="${e(here)}"><div class="seg" role="group" aria-label="Review state">${stateButtons}</div></form></div></article>`;
    }).join('');

    const tabs = [[undefined, 'All'], ...REVIEW_STATES.map((s) => [s, STATE_LABEL[s]])].map(([s, label]) =>
      `<a href="${e(qs({ state: s, page: '0' }))}"${s === filters.state ? ' aria-current="page"' : ''}>${label}</a>`).join('');
    const clients = [...new Set([...keys.rows.map((t) => t.client), ...(filters.client ? [filters.client] : [])])];
    const toolbar = `<div class="toolbar"><nav class="seg" aria-label="Review state">${tabs}</nav>
<form class="filters" method="get" action="/review" role="search" aria-label="Filter feedback">
${filters.state ? `<input type="hidden" name="state" value="${e(filters.state)}">` : ''}
<label class="sr" for="f-cat">Category</label><select id="f-cat" name="category" data-autosubmit>${options(filters.category, CATEGORIES, 'All categories')}</select>
<label class="sr" for="f-key">API key</label><select id="f-key" name="client" data-autosubmit>${options(filters.client, clients, 'All API keys')}</select>
<button class="btn btn-secondary btn-sm apply">Apply</button></form></div>`;
    const filtered = filters.category || filters.state || filters.client;
    const empty = filtered
      ? emptyState('inbox', 'Nothing matches these filters', 'Try another state, category, or API key.', '<a class="btn btn-secondary" href="/review">Clear filters</a>')
      : emptyState('inbox', 'No feedback yet', 'When an agent connected with one of your API keys finishes a task, its improvement notes land here.',
        `<a class="btn" href="/connect">${icon('plug')}Connect a client</a>`);
    const pager = (filters.page > 0 ? `<a class="btn btn-secondary btn-sm" href="${e(qs({ page: String(filters.page - 1) }))}">Newer</a>` : '') +
      (hasMore && filters.page < MAX_PAGE ? `<a class="btn btn-secondary btn-sm" href="${e(qs({ page: String(filters.page + 1) }))}">Older</a>` : '');
    res.send(shell('Inbox', toolbar + (items ? `<div class="feed">${items}</div>` : empty) + (pager ? `<nav class="pager" aria-label="Pages">${pager}</nav>` : ''),
      ui(req, '/review', { sub: 'Improvement notes from your agents. Each one is attributable to the API key that sent it: private to you, not anonymous.' })));
  });

  app.post('/review/:id/state', requireReviewer, form, requireMutation, async (req, res) => {
    const state = pick(req.body.state, REVIEW_STATES);
    if (!/^[0-9a-f-]{36}$/.test(req.params.id) || !state) return problem(req, res, 400, 'Invalid request', 'That review state is not valid.');
    if (!await store.setReviewState(req.reviewer.email, req.params.id, state)) return problem(req, res, 404, 'Not found', 'That feedback item does not exist.');
    // Return to the same filtered view, scrolled to the item.
    const next = typeof req.body.next === 'string' && /^\/review(\?[A-Za-z0-9_.~%&=+-]*)?$/.test(req.body.next) ? req.body.next : '/review';
    res.redirect(303, `${next}#fb-${req.params.id}`);
  });

  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const EXPIRY = [7, 30, 60, 90];
  const tokensPage = async (req, { before, flash = '', created } = {}) => {
    const csrf = e(csrfToken(config.authSecret, req.reviewer.email));
    const { rows, nextCursor } = await store.listTokens(req.reviewer.email, { before });
    const pager = (before ? '<a class="btn btn-secondary btn-sm" href="/tokens">Newest</a>' : '') +
      (nextCursor ? `<a class="btn btn-secondary btn-sm" href="${e('/tokens?before=' + nextCursor)}">Older</a>` : '');
    const list = rows.map((t) => {
      const state = t.revoked_at ? 'revoked' : new Date(t.expires_at) <= new Date() ? 'expired' : 'active';
      const revoke = state === 'active' ? `<form method="post" action="/tokens/${e(t.id)}/revoke" data-confirm="Revoke “${e(t.name)}”? Agents using it will stop submitting immediately.">
<input type="hidden" name="csrf" value="${csrf}"><button class="btn btn-danger btn-sm">Revoke</button></form>` : '';
      return `<li${state === 'active' ? '' : ' class="off"'}><div class="name"><span class="keyico">${icon('key')}</span><b>${e(t.name)}</b>
<span class="pill ${state}"><span class="dot"></span>${state[0].toUpperCase() + state.slice(1)}</span></div>
<div class="cell"><span class="k">Created </span>${t.created_at ? when(t.created_at) : '—'}</div>
<div class="cell"><span class="k">Last used </span>${t.last_used_at ? when(t.last_used_at) : 'Never'}</div>
<div class="cell">${state === 'revoked' ? `Revoked ${t.revoked_at ? when(t.revoked_at) : ''}`
    : `<span class="k">${state === 'expired' ? 'Expired ' : 'Expires '}</span>${when(t.expires_at)}`}</div>
<div class="act">${revoke}</div></li>`;
    }).join('');
    const reveal = created ? `<section class="reveal" aria-labelledby="new-key"><h2 id="new-key">${icon('check')}API key “${e(created.name)}” created</h2>
<p>Copy it now. For your security it will not be shown again.</p>
<div class="secret"><code id="new-secret">${e(created.plaintext)}</code>${copyButton('new-secret', 'Copy key', 'btn btn-sm')}</div>
<p style="margin:14px 0 8px">Then store it in the environment of the machine running your agent:</p>
<div class="code"><pre id="new-env">export HINDSIGHT_INGEST_TOKEN="${e(created.plaintext)}"</pre>${copyButton('new-env')}</div>
<div class="next"><a class="btn btn-secondary" href="/connect">${icon('plug')}Set up a client</a></div></section>` : '';
    const createForm = `<form class="card card-pad" method="post" action="/tokens"><input type="hidden" name="csrf" value="${csrf}">
<h2 style="margin-bottom:12px">Create an API key</h2><div class="form-row">
<label class="field">Name <input name="name" maxlength="80" required placeholder="e.g. Work laptop — Claude Code" autocomplete="off"></label>
<label class="field">Expires after <select name="days">${EXPIRY.map((d) => `<option value="${d}"${d === 30 ? ' selected' : ''}>${d} days</option>`).join('')}</select></label>
<button class="btn" type="submit">${icon('plus')}Create key</button></div>
<p class="small muted" style="margin:10px 0 0">Keys can only submit feedback. They cannot read your inbox or manage other keys.</p></form>`;
    const listCard = list
      ? `<section class="card" aria-label="Your API keys"><ul class="keys"><li class="hd" aria-hidden="true"><span>Name</span><span>Created</span><span>Last used</span><span>Expires / revoked</span><span></span></li>${list}</ul></section>`
      : emptyState('key', 'No API keys yet', 'Create a key above, then use it to connect Claude Code, Codex, Cursor, or OpenCode.');
    return shell('API keys', flash + reveal + `<div class="stack">${createForm}${listCard}</div>` +
      (pager ? `<nav class="pager" aria-label="Pages">${pager}</nav>` : ''),
    ui(req, '/tokens', { sub: 'Submit-only keys that let your agents send feedback to this inbox.' }));
  };

  app.get('/tokens', requireReviewer, async (req, res) => {
    const { before } = req.query;
    if (before !== undefined && (typeof before !== 'string' || !UUID.test(before))) {
      return problem(req, res, 400, 'Invalid request', 'That page link is not valid.', toTokens);
    }
    const flash = req.query.revoked === '1' ? alertBox('ok', 'API key revoked. Agents using it can no longer submit feedback.') : '';
    res.send(await tokensPage(req, { before, flash }));
  });

  app.post('/tokens', requireReviewer, form, requireMutation, async (req, res) => {
    const name = String(req.body.name || '').trim();
    const days = Number(req.body.days || 30);
    if (!name || name.length > 80 || !Number.isInteger(days) || days < 1 || days > 90) {
      return res.status(400).send(await tokensPage(req, { flash: alertBox('err', 'Give the key a name (up to 80 characters) and an expiry of 1–90 days.') }));
    }
    const plaintext = generateToken();
    // A key has just a name. The stored client label, which attributes and idempotency-binds its
    // submissions, is that name.
    await store.createToken({
      ownerEmail: req.reviewer.email, name, client: name, tokenHash: hashToken(plaintext),
      expiresAt: new Date(Date.now() + days * 86400000),
    });
    res.send(await tokensPage(req, { created: { name, plaintext } }));
  });

  app.post('/tokens/:id/revoke', requireReviewer, form, requireMutation, async (req, res) => {
    if (!/^[0-9a-f-]{36}$/.test(req.params.id)) return problem(req, res, 404, 'Not found', 'That API key does not exist.', toTokens);
    await store.revokeToken(req.reviewer.email, req.params.id);
    res.redirect(303, '/tokens?revoked=1');
  });

  app.get('/connect', requireReviewer, (req, res) => {
    const url = config.publicOrigin + '/api/mcp';
    const snippet = (id, code) => `<div class="code"><pre id="${id}">${e(code)}</pre>${copyButton(id)}</div>`;
    const clients = [
      ['Claude Code', snippet('c-claude', `claude mcp add --transport http --scope user hindsight ${url} \\\n  --header 'Authorization: Bearer \${HINDSIGHT_INGEST_TOKEN}'`),
        'Run in a terminal, then check with <code>/mcp</code>. Single quotes keep the variable unexpanded.'],
      ['Codex CLI', snippet('c-codex', `codex mcp add hindsight --url ${url} --bearer-token-env-var HINDSIGHT_INGEST_TOKEN`),
        'Codex reads the raw key from the variable; no <code>Bearer</code> prefix.'],
      ['Cursor', snippet('c-cursor', JSON.stringify({ mcpServers: { hindsight: { url, headers: { Authorization: 'Bearer ${env:HINDSIGHT_INGEST_TOKEN}' } } } }, null, 2)),
        'Add to <code>~/.cursor/mcp.json</code>. Set the variable in your shell or system environment.'],
      ['OpenCode', snippet('c-opencode', JSON.stringify({ $schema: 'https://opencode.ai/config.json', mcp: { servers: { hindsight: { type: 'remote', url, oauth: false,
        headers: { Authorization: 'Bearer {env:HINDSIGHT_INGEST_TOKEN}' } } } } }, null, 2)), 'Add to <code>opencode.jsonc</code>.'],
    ];
    const tabs = `<div class="tabs">${clients.map((_, i) => `<input type="radio" name="client" id="t${i + 1}"${i ? '' : ' checked'}>`).join('')}
<div class="tl" role="presentation">${clients.map(([name], i) => `<label for="t${i + 1}">${name}</label>`).join('')}</div>
${clients.map(([, code, note], i) => `<div class="panel p${i + 1}">${code}<p class="muted">${note}</p></div>`).join('')}</div>`;
    const steps = `<ol class="steps">
<li><h3>Create an API key</h3><p>One key per machine or client makes it easy to see where feedback came from, and to revoke it.</p>
<a class="btn btn-secondary btn-sm" href="/tokens">${icon('key')}Go to API keys</a></li>
<li><h3>Store it in an environment variable</h3><p>Never paste a key into a checked-in config file.</p>${snippet('c-env', 'export HINDSIGHT_INGEST_TOKEN="hs_…"')}</li>
<li><h3>Add HindSight to your client</h3><p>Pick your client and copy the command or config.</p>${tabs}</li>
<li><h3>Done</h3><p>At the end of a task, agents call <code>submit_feedback</code> and the note shows up in your <a href="/review">inbox</a>.</p></li></ol>`;
    const aside = `<aside class="card card-pad"><h2 style="margin-bottom:12px">Server details</h2>
<p class="small muted" style="margin:0 0 6px">MCP endpoint</p><div class="secret" style="margin-bottom:14px"><code id="c-url" class="small">${e(url)}</code>${copyButton('c-url', 'Copy', 'btn btn-ghost btn-sm')}</div>
<dl class="kv"><dt>Transport</dt><dd>Streamable HTTP</dd><dt>Auth</dt><dd>Bearer API key</dd><dt>Tool</dt><dd>submit_feedback</dd><dt>Rate limit</dt><dd>${config.rateLimitPerMinute}/min per key</dd></dl></aside>`;
    res.send(shell('Connect a client', `<div class="grid2"><section class="card card-pad">${steps}</section>${aside}</div>`,
      ui(req, '/connect', { sub: 'Point your coding agents at HindSight so they can send improvement notes when they finish work.' })));
  });

  app.use((err, _req, res, _next) => {
    const status = err.status === 413 || err.type === 'entity.too.large' ? 413 : err.status === 400 ? 400 : 500;
    if (status === 500) console.error('hindsight error', err?.name);
    res.status(status).json({ error: status === 413 ? 'payload_too_large' : status === 400 ? 'bad_request' : 'internal_error' });
  });
  return app;
}

const SIGNIN_ERRORS = {
  AccessDenied: 'This Google account is not on the reviewer allow-list. Try a different account.',
  Verification: 'That sign-in link is no longer valid. Please try again.',
  Configuration: 'Sign-in is not configured correctly on the server. Contact the operator.',
  Default: 'Sign-in did not complete. Please try again.',
};

// Auth.js may hand back an absolute same-origin callbackUrl; reduce it to a safe relative path.
function callbackPath(value, origin) {
  if (typeof value === 'string' && value.startsWith(origin + '/')) value = value.slice(origin.length);
  const path = safeRelativePath(value);
  return /^\/auth\//.test(path) ? '/review' : path;
}
