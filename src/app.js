import express from 'express';
import { fileURLToPath } from 'node:url';
import { MAX_BULK, MAX_NOTE, SCOPE_ADMIN, SCOPE_SUBMIT, SCOPES, bulkUpdate, isAdmin } from './admin.js';
import { adminApi } from './api-v1.js';
import { MAX_PAGE, MAX_SHOWN, PAGE_SIZE, REVIEW_STATES } from './db.js';
import { CATEGORIES, handleMcp } from './mcp.js';
import { forwardMcp } from './mcp-http.js';
import { canonicalHeadersOk, checkCsrf, csrfToken, escapeHtml as e, generateToken, hashToken, safeRelativePath, sameOrigin } from './security.js';
import { GOOGLE_G, SCRIPT_HASH, ago, alertBox, copyButton, dayDiff, emptyState, icon, shell, solo, when } from './ui.js';

const setupPage = () => solo('Setup required', `<div class="prose-left"><p>HindSight collects the improvement notes your agents
submit about your shared instructions, skills, codebase, collaboration, and tools.</p>
<p>This deployment is not ready yet: sign-in, storage, and reviewer access have not all been configured. Until they are,
sign-in, review, and feedback submission stay switched off.</p></div>
<p class="fine">${icon('wrench')} Operators: follow the setup checklist in the project README.</p>`);

// Public product page. The recording is docs/demo (scripts/demo.js); vercel.json bundles that directory into the
// function, and only these three files are served from it.
const DEMO_DIR = fileURLToPath(new URL('../docs/demo/', import.meta.url));
const DEMO_FILES = new Set(['demo.webm', 'demo.mp4', 'poster.png']);
const GITHUB_URL = 'https://github.com/satyasaibhushan/HindSight';
const aboutPage = () => shell('HindSight', `<figure class="card demo"><video autoplay loop muted playsinline poster="/about/poster.png"
aria-label="HindSight demo: an Inbox item expanded and ticked done, the Done view, a new ingest key revealed, and the Connect page">
<source src="/about/demo.webm" type="video/webm"><source src="/about/demo.mp4" type="video/mp4"></video>
<figcaption class="small muted">Recorded from the app with fictional feedback and a fictional reviewer.</figcaption></figure>
<section class="card card-pad stack"><h2>What it does</h2><ul class="prose-left">
<li>Agents call one MCP tool, <code>submit_feedback</code>, with a submit-only ingest key when they finish work.</li>
<li>Each suggestion is a concrete change to instructions, skills, the codebase, collaboration, or tools, with the friction that prompted it.</li>
<li>The owner works through them as an Inbox checklist behind Google sign-in: plan, won't do, mark done, a private note, or bulk changes.</li>
<li>Owner-scoped admin keys read and triage the same feedback over MCP or a small REST API.</li></ul>
<div class="actions"><a class="btn" href="/review">Open the app${icon('arrow')}</a><a class="btn btn-secondary" href="${GITHUB_URL}">GitHub</a></div></section>`,
{ sub: 'A private inbox for the improvements your coding agents suggest, so you can review them and act.' });

// The sign-in page's form POSTs to /auth/signin/google, which 302s to Google's authorization
// endpoint; browsers apply form-action to that redirect. Only that page may target the exact Google
// authorization origin; every other route stays form-action 'self'.
export const GOOGLE_AUTH_ORIGIN = 'https://accounts.google.com';
const SIGNIN_PAGE = /^\/auth\/signin\/?$/;
// The only script allowed is the shared inline one in ui.js, pinned by hash.
// connect-src 'self' lets the Inbox's "Show more" fetch the next batch from /review.
export const csp = (formAction) =>
  `default-src 'none'; script-src ${SCRIPT_HASH}; style-src 'unsafe-inline'; connect-src 'self'; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`;

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

  // ---- Bearer-token API: /api/mcp (any valid key) and /api/v1 (admin keys only). Keys are authenticated
  // before any body parsing or data access; session cookies are never consulted on these routes.
  const bearer = async (req, res, next) => {
    if (!config.mcpReady) return res.status(503).json({ error: 'setup_required' });
    const match = /^Bearer (hs_[A-Za-z0-9_-]{43})$/.exec(req.get('authorization') || '');
    let token = null;
    try {
      const authenticated = match && await store.authenticateAndRateLimit(
        hashToken(match[1]), config.reviewers, config.rateLimitPerMinute);
      token = authenticated?.token;
      // The store throttles only configured owners; retain the middleware allowlist guard too.
      // A removed owner gets the same generic invalid_token response as an unknown token.
      const owner = typeof token?.ownerEmail === 'string' ? token.ownerEmail.trim().toLowerCase() : '';
      if (token && !config.reviewers.includes(owner)) token = null;
      if (token && !authenticated.allowed) {
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
  };
  app.all('/api/mcp', bearer, express.raw({ type: () => true, limit: '32kb' }), async (req, res) => {
    await forwardMcp(req, res, config.publicOrigin, (request) => handleMcp(store, req.ingestionToken, request));
  });
  app.use('/api/v1', bearer, adminApi(store));

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
    { sub: 'Review what your agents suggest you change in your instructions, skills, codebase, and tools.' }));
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
    res.status(status).send(shell(title, `<div class="card card-pad problem">${icon('alert')}<div><p>${text}</p>
<a class="btn btn-secondary btn-sm" href="${e(back[0])}">${e(back[1])}</a></div></div>`, { user: req.reviewer }));
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

  // The only public pages besides /health: no session lookup, store access, or forms. Media is same-origin.
  app.get('/about', (_req, res) => {
    res.set('Content-Security-Policy', `${csp("'self'")}; img-src 'self'; media-src 'self'`).send(aboutPage());
  });
  app.get('/about/:file', (req, res, next) => {
    if (!DEMO_FILES.has(req.params.file)) return next();
    res.set('Cache-Control', 'public, max-age=3600').sendFile(req.params.file, { root: DEMO_DIR, cacheControl: false });
  });

  // Return to the same filtered view, scrolled to the item (or to its note form).
  const NEXT = /^\/review(\?[A-Za-z0-9_.~%&=+-]*)?$/;
  const nextOf = (req) => (typeof req.body.next === 'string' && NEXT.test(req.body.next) ? req.body.next : '/review');
  const backToItem = (req, anchor = 'fb') => `${nextOf(req)}#${anchor}-${req.params.id}`;
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const pick = (v, allowed) => (typeof v === 'string' && allowed.includes(v) ? v : undefined);
  const options = (value, list, any) => (any !== undefined ? `<option value="">${e(any)}</option>` : '') +
    list.map((o) => `<option value="${e(o)}"${o === value ? ' selected' : ''}>${e(o)}</option>`).join('');

  // The Inbox is a checklist. Views map onto DB states: Open = new + triaged (Planned), Done = actioned,
  // Won't do = dismissed. The old ?state=<db state> links still work: actioned/dismissed open their view,
  // new/triaged narrow the Open view to that one state.
  const VIEWS = { open: ['new', 'triaged'], done: ['actioned'], wontdo: ['dismissed'], all: undefined };
  const VIEW_LABEL = { open: 'Open', done: 'Done', wontdo: 'Won’t do', all: 'All' };
  const VIEW_OF = { new: 'open', triaged: 'open', actioned: 'done', dismissed: 'wontdo' };
  const STATE_NAME = { new: 'Open', triaged: 'Planned', actioned: 'Done', dismissed: 'Won’t do' };
  const GROUPS = ['category', 'none'];
  const STATE_PARAMS = [...Object.keys(VIEWS), ...REVIEW_STATES];
  // [state, label, icon, primary] buttons offered for an item in each state.
  const ACTIONS = {
    new: [['triaged', 'Plan', 'target'], ['dismissed', 'Won’t do', 'x'], ['actioned', 'Mark done', 'check', true]],
    triaged: [['new', 'Unplan', 'undo'], ['dismissed', 'Won’t do', 'x'], ['actioned', 'Mark done', 'check', true]],
    actioned: [['new', 'Reopen', 'undo'], ['dismissed', 'Won’t do', 'x']],
    dismissed: [['new', 'Reopen', 'undo'], ['actioned', 'Mark done', 'check']],
  };
  const MENU = { new: ACTIONS.new.slice(0, 2), triaged: ACTIONS.triaged.slice(0, 2), actioned: ACTIONS.actioned, dismissed: ACTIONS.dismissed.slice(0, 1) };
  // ?state= -> the view, an optional single-state narrowing, and the DB states listed (undefined = all).
  const viewOf = (raw) => {
    const state = pick(raw, STATE_PARAMS);
    const view = VIEW_OF[state] ?? state ?? 'open';
    const narrow = state === 'new' || state === 'triaged' ? state : undefined;
    return { state, view, narrow, states: narrow ? [narrow] : VIEWS[view] };
  };
  // "Show more" is cumulative: ?shown=<n> renders the newest n items (PAGE_SIZE steps, up to MAX_SHOWN) as one
  // list. An old ?page=<p> link maps to the same items it used to reach the end of: shown = (p + 1) * PAGE_SIZE.
  const shownOf = (q) => {
    const n = Number.parseInt(q.shown, 10);
    const steps = n > 0 ? Math.ceil(n / PAGE_SIZE) : Math.min(Math.max(Number.parseInt(q.page, 10) || 0, 0), MAX_PAGE) + 1;
    return Math.min(steps * PAGE_SIZE, MAX_SHOWN);
  };
  const BATCH = 'X-HindSight-Batch';

  app.get('/review', requireReviewer, async (req, res) => {
    const { state, view, narrow, states } = viewOf(req.query.state);
    const filters = {
      category: pick(req.query.category, CATEGORIES),
      states,
      client: typeof req.query.client === 'string' && /^.{1,80}$/.test(req.query.client) ? req.query.client : undefined,
    };
    const shown = shownOf(req.query);
    // The inline script asks for just the newest batch (header BATCH) and appends it; otherwise the whole list.
    const batch = req.get(BATCH) === '1';
    const group = pick(req.query.group, GROUPS) ?? 'date';
    const select = req.query.select === '1';
    const owner = req.reviewer.email;
    const [{ rows, hasMore }, counts, keys] = await Promise.all([
      store.listFeedback(owner, batch ? { ...filters, page: shown / PAGE_SIZE - 1, limit: PAGE_SIZE } : { ...filters, limit: shown }),
      store.countFeedback(owner, { category: filters.category, client: filters.client }),
      batch ? { rows: [] } : store.listTokens(owner, {}),
    ]);
    const csrf = e(csrfToken(config.authSecret, owner));
    const params = { state: state === 'open' ? undefined : state, category: filters.category, client: filters.client,
      group: group === 'date' ? undefined : group, select: select ? '1' : undefined, shown: shown === PAGE_SIZE ? undefined : String(shown) };
    const qs = (over) => '/review' + ((q) => (q ? '?' + q : ''))(new URLSearchParams(Object.entries({ ...params, ...over })
      .filter(([, v]) => v !== undefined && v !== '')).toString());
    // Every form returns here: same view, filters, grouping, select mode, and length of list.
    const here = qs({});
    const hidden = (name, value) => `<input type="hidden" name="${name}" value="${e(value)}">`;
    // `near`: the neighbouring row, where the redirect lands if this item leaves the view.
    const stateForm = (id, cls, inner, near) => `<form${cls ? ` class="${cls}"` : ''} method="post" action="/review/${id}/state">${hidden('csrf', csrf)}${hidden('next', here)}${near ? hidden('near', near) : ''}${inner}</form>`;
    const fact = (label, v) => (v ? `<div><dt>${label}</dt><dd>${e(v)}</dd></div>` : '');
    const SEP = '<span class="sep">·</span>';

    const offset = batch ? shown - PAGE_SIZE : 0;
    const index = new Map(rows.map((f, i) => [f.id, offset + i]));
    const row = (f, i, all) => {
      const id = e(f.id);
      const near = (all[i + 1] ?? all[i - 1])?.id;
      // The first item of each later batch is where "Show more" lands without JS.
      const at = index.get(f.id);
      const s = f.review_state;
      const done = s === 'actioned';
      const glyph = s === 'triaged' ? ' planned' : s === 'dismissed' ? ' wontdo' : '';
      const label = done ? 'Reopen' : s === 'dismissed' ? 'Reopen (currently won’t do)' : s === 'triaged' ? 'Mark done (currently planned)' : 'Mark done';
      const box = `<span class="box">${icon('check')}</span>`;
      const lead = select
        ? `<label class="sel"><input type="checkbox" name="ids" value="${id}" form="bulk" aria-label="Select: ${e(f.improvement.slice(0, 80))}">${box}</label>`
        : stateForm(id, 'chk-form', `<button class="chk${glyph}" type="submit" name="state" value="${done || s === 'dismissed' ? 'new' : 'actioned'}" role="checkbox" aria-checked="${done}" aria-label="${label}">${box}</button>`, near);
      const tag = s === 'triaged' ? `<span class="tag planned">Planned</span>${SEP}` : s === 'dismissed' ? `<span class="tag wontdo">Won’t do</span>${SEP}` : '';
      const note = f.review_note ? `${SEP}<span class="tag hasnote">Has note</span>` : '';
      const facts = fact('Repository', f.repository) + fact('Task', f.task) + fact('Source', f.source) + fact('Outcome', f.outcome) + fact('Confidence', f.confidence);
      const buttons = ACTIONS[s] ?? ACTIONS.new;
      const actions = stateForm(id, 'actions', buttons.map(([to, text, ico, primary]) =>
        `<button class="btn${primary ? '' : ' btn-secondary'} btn-sm" name="state" value="${to}">${icon(ico)}${text}</button>`).join(''), near);
      const menu = select ? '<span></span>' : `<details class="menu"><summary aria-label="More actions">${icon('dots')}</summary><div class="menu-panel">
${stateForm(id, '', (MENU[s] ?? MENU.new).map(([to, text, ico]) => `<button name="state" value="${to}">${icon(ico)}${text}</button>`).join(''), near)}<hr>
<a href="${e(qs({ client: f.client, shown: undefined }))}">${icon('key')}Only this API key</a><button type="button" class="copy" data-copy="rq-${id}">${icon('copy')}<span class="copy-label">Copy request id</span></button></div></details>`;
      return `<li class="task is-${{ new: 'open', triaged: 'planned', actioned: 'done', dismissed: 'wontdo' }[s] ?? 'open'}" id="fb-${id}">${lead}
<details class="body"${at && at % PAGE_SIZE === 0 ? ` id="more-${at}"` : ''}><summary><span class="title">${e(f.improvement)}</span>
<span class="meta">${tag}<span class="cat">${e(f.category)}</span>${SEP}<span class="src">${e(f.client)}</span>${SEP}${ago(f.created_at)}${note}<span class="chev"><span>Details</span>${icon('chev')}</span></span></summary>
<div class="detail"><h3>Friction</h3><p class="prose">${e(f.friction)}</p>${facts ? `<dl class="facts">${facts}</dl>` : ''}
<form class="note" id="nt-${id}" method="post" action="/review/${id}/note">${hidden('csrf', csrf)}${hidden('next', here)}
<label for="note-${id}">Review note <span>· private to you</span></label><textarea id="note-${id}" name="note" maxlength="${MAX_NOTE}" rows="${f.review_note ? 3 : 1}" placeholder="Add a note…">${e(f.review_note ?? '')}</textarea>
<button class="btn btn-secondary btn-sm">Save note</button></form>
<div class="detail-foot"><span class="reqid">Request <code id="rq-${id}">${e(f.request_id)}</code>${copyButton('rq-' + f.id, 'Copy', 'btn btn-ghost btn-sm')}</span>${actions}</div></div></details>
${menu}</li>`;
    };

    // Groups over the whole list: by UTC day (Today / Yesterday / Earlier), by category, or none. data-group and
    // data-order let the script merge an appended batch into the matching group or slot a new one in place.
    const DAYS = ['Today', 'Yesterday', 'Earlier'];
    const groups = new Map();
    for (const f of rows) {
      const days = dayDiff(f.created_at);
      const key = group === 'none' ? '' : group === 'category' ? f.category : DAYS[Math.min(Math.max(days, 0), 2)];
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(f);
    }
    const order = group === 'category' ? CATEGORIES.filter((c) => groups.has(c)) : [...groups.keys()];
    const flat = order.flatMap((k) => groups.get(k));
    const pos = new Map(flat.map((f, i) => [f.id, i]));
    const rank = (k) => Math.max((group === 'category' ? CATEGORIES : DAYS).indexOf(k), 0);
    const list = order.map((k) => (k ? `<h2 class="group">${e(k)} <span class="n">${groups.get(k).length}</span></h2>` : '') +
      `<ul class="tasks" data-group="${e(k)}" data-order="${rank(k)}">${groups.get(k).map((f) => row(f, pos.get(f.id), flat)).join('')}</ul>`).join('');

    const n = { open: counts.new + counts.triaged, done: counts.actioned, wontdo: counts.dismissed,
      all: REVIEW_STATES.reduce((t, s) => t + counts[s], 0) };
    const total = narrow ? counts[narrow] : n[view];
    const loaded = offset + rows.length;
    const more = hasMore && shown < MAX_SHOWN
      ? `<nav class="more" aria-label="More items"><span>Showing ${loaded} of ${Math.max(total, loaded + 1)}</span>
<a class="btn btn-secondary btn-sm" href="${e(qs({ shown: String(shown + PAGE_SIZE) }) + '#more-' + shown)}" data-more>Show more</a></nav>`
      : hasMore ? `<p class="more">Showing the newest ${loaded}. Filter by category or API key to reach older items.</p>` : '';
    if (batch) return res.set(BATCH, '1').vary(BATCH).send(list + more);
    res.vary(BATCH);
    const tabs = Object.keys(VIEWS).map((v) => `<a href="${e(qs({ state: v === 'open' ? undefined : v, shown: undefined }))}"${v === view ? ' aria-current="page"' : ''}>${VIEW_LABEL[v]} <span class="n">${n[v]}</span></a>`).join('');
    const clients = [...new Set([...keys.rows.map((t) => t.client), ...(filters.client ? [filters.client] : [])])];
    const toolbar = `<div class="toolbar"><nav class="views" aria-label="View">${tabs}</nav>
${select ? '' : `<a class="btn btn-ghost btn-sm" href="${e(qs({ select: '1' }))}" data-here>${icon('list')}Select</a>`}</div>
<form class="filters" method="get" action="/review" role="search" aria-label="Filter items">
${params.state ? hidden('state', params.state) : ''}${select ? hidden('select', '1') : ''}
<label class="sr" for="f-cat">Category</label><select id="f-cat" name="category" data-autosubmit>${options(filters.category, CATEGORIES, 'Category: all')}</select>
<label class="sr" for="f-key">API key</label><select id="f-key" name="client" data-autosubmit>${options(filters.client, clients, 'API key: all')}</select>
<label class="sr" for="f-grp">Group by</label><select id="f-grp" name="group" data-autosubmit><option value="">Group: date</option>
<option value="category"${group === 'category' ? ' selected' : ''}>Group: category</option><option value="none"${group === 'none' ? ' selected' : ''}>No grouping</option></select>
<button class="btn btn-secondary btn-sm apply">Apply</button></form>
${narrow ? `<p class="narrow">Showing only ${STATE_NAME[narrow]} items.<a href="${e(qs({ state: undefined, shown: undefined }))}">Show all open</a></p>` : ''}`;
    const bulkbar = select ? `<form id="bulk" class="bulkbar" method="post" action="/review/bulk" role="group" aria-label="Bulk actions">
${hidden('csrf', csrf)}${hidden('next', here)}<span class="count" data-count aria-live="polite">Select items</span>
<button class="btn btn-sm" name="state" value="actioned">${icon('check')}Mark done</button>
<button class="btn btn-secondary btn-sm" name="state" value="triaged">${icon('target')}Plan</button>
<button class="btn btn-secondary btn-sm" name="state" value="dismissed">${icon('x')}Won’t do</button><span class="spacer"></span>
<a class="btn btn-ghost btn-sm" href="${e(qs({ select: undefined }))}" data-here>Cancel</a></form>` : '';

    let empty = '';
    if (!rows.length) {
      empty = n.all === 0 && !filters.category && !filters.client
        ? emptyState('inbox', 'No feedback yet', 'When an agent connected with one of your API keys finishes a task, its suggestions land here.',
          `<a class="btn" href="/connect">${icon('plug')}Connect a client</a>`)
        : filters.category || filters.client
          ? emptyState('', 'Nothing matches these filters', 'Try another category or API key.', `<a class="btn btn-secondary btn-sm" href="${e(qs({ category: undefined, client: undefined, shown: undefined }))}">Clear filters</a>`)
          : view === 'open' && !narrow
            ? emptyState('', 'All clear', 'Nothing open. New suggestions land here when an agent finishes a task.', `<a class="btn btn-secondary btn-sm" href="${e(qs({ state: 'done', shown: undefined }))}">See what’s done</a>`)
            : emptyState('', 'Nothing here', 'No items in this view.', `<a class="btn btn-secondary btn-sm" href="${e(qs({ state: 'all', shown: undefined }))}">Show all</a>`);
    }
    res.send(shell('Inbox', toolbar + bulkbar + (list || empty) + more,
      ui(req, '/review', { sub: 'What your agents suggest you change. Tick an item when it is done. Each item is attributable to the API key that sent it.' })));
  });

  app.post('/review/:id/state', requireReviewer, form, requireMutation, async (req, res) => {
    const state = pick(req.body.state, REVIEW_STATES);
    if (!UUID.test(req.params.id) || !state) return problem(req, res, 400, 'Invalid request', 'That review state is not valid.');
    if (!await store.setReviewState(req.reviewer.email, req.params.id, state)) return problem(req, res, 404, 'Not found', 'That feedback item does not exist.');
    // An item that leaves the view (e.g. ticked in Open) is gone after the redirect: land on its neighbour.
    const { states } = viewOf(new URLSearchParams(nextOf(req).split('?')[1] ?? '').get('state'));
    const near = typeof req.body.near === 'string' && UUID.test(req.body.near) ? req.body.near : null;
    res.redirect(303, !states || states.includes(state) || !near ? backToItem(req) : `${nextOf(req)}#fb-${near}`);
  });

  // Bulk select mode: one form, up to MAX_BULK owner-scoped ids, one atomic store update. Ids that are not the
  // owner's (or unknown) are skipped by the owner-scoped UPDATE. Its own parser: 100 ids are ~4.2 KB encoded.
  const bulkForm = express.urlencoded({ extended: false, limit: '16kb', parameterLimit: MAX_BULK + 10 });
  app.post('/review/bulk', requireReviewer, bulkForm, requireMutation, async (req, res) => {
    const state = pick(req.body.state, REVIEW_STATES);
    const ids = [req.body.ids ?? []].flat();
    if (!state || !ids.every((id) => typeof id === 'string' && UUID.test(id))) {
      return problem(req, res, 400, 'Invalid request', 'That bulk change is not valid.');
    }
    if (!ids.length || ids.length > MAX_BULK) {
      const back = /[?&]select=1(&|$)/.test(nextOf(req)) ? nextOf(req) : nextOf(req) + (nextOf(req).includes('?') ? '&' : '?') + 'select=1';
      return problem(req, res, 400, 'Invalid request', `Select between 1 and ${MAX_BULK} items.`, [back, 'Back to selection']);
    }
    await bulkUpdate(store, req.reviewer.email, ids, state);
    res.redirect(303, nextOf(req));
  });

  // The note is private to the owner. Empty clears it. Its own parser: 2000 characters may encode to ~18 KB.
  const noteForm = express.urlencoded({ extended: false, limit: '24kb' });
  app.post('/review/:id/note', requireReviewer, noteForm, requireMutation, async (req, res) => {
    const note = typeof req.body.note === 'string' ? req.body.note.trim() : null;
    if (!UUID.test(req.params.id) || note === null || note.length > MAX_NOTE || note.includes('\0')) {
      return problem(req, res, 400, 'Invalid request', `A review note can be up to ${MAX_NOTE} characters.`);
    }
    if (!await store.updateFeedback(req.reviewer.email, req.params.id, { note: note || null })) {
      return problem(req, res, 404, 'Not found', 'That feedback item does not exist.');
    }
    res.redirect(303, backToItem(req, 'nt'));
  });

  const EXPIRY = [7, 30, 60, 90];
  const tokensPage = async (req, { before, flash = '', created, form: posted = {} } = {}) => {
    const csrf = e(csrfToken(config.authSecret, req.reviewer.email));
    const { rows, nextCursor } = await store.listTokens(req.reviewer.email, { before });
    const pager = (before ? '<a class="btn btn-secondary btn-sm" href="/tokens">Newest</a>' : '') +
      (nextCursor ? `<a class="btn btn-secondary btn-sm" href="${e('/tokens?before=' + nextCursor)}">Older</a>` : '');
    const list = rows.map((t) => {
      const state = t.revoked_at ? 'revoked' : new Date(t.expires_at) <= new Date() ? 'expired' : 'active';
      const admin = isAdmin(t);
      const confirm = admin ? `Revoke “${t.name}”? Anything using it loses access immediately.`
        : `Revoke “${t.name}”? Agents using it will stop submitting immediately.`;
      const revoke = state === 'active' ? `<form method="post" action="/tokens/${e(t.id)}/revoke" data-confirm="${e(confirm)}">
<input type="hidden" name="csrf" value="${csrf}"><button class="btn btn-danger btn-sm" aria-label="Revoke ${e(t.name)}">Revoke</button></form>` : '';
      const cls = [admin && 'is-admin', state !== 'active' && 'off'].filter(Boolean).join(' ');
      return `<li${cls ? ` class="${cls}"` : ''}><div class="name"><span class="keyico${admin ? ' admin' : ''}">${icon(admin ? 'shield' : 'key')}</span><span class="nm"><b>${e(t.name)}</b>
<span class="status ${state}">${state[0].toUpperCase() + state.slice(1)}</span></span></div>
<div class="cell"><span class="scopelbl${admin ? ' admin' : ''}" title="Scope ${e(admin ? SCOPE_ADMIN : SCOPE_SUBMIT)}">${admin ? icon('shield') + 'Admin' : 'Ingest'}</span></div>
<div class="cell"><span class="k">Created </span>${t.created_at ? when(t.created_at) : '—'}</div>
<div class="cell"><span class="k">Last used </span>${t.last_used_at ? when(t.last_used_at) : 'Never'}</div>
<div class="cell">${state === 'revoked' ? `Revoked ${t.revoked_at ? when(t.revoked_at) : ''}`
    : `<span class="k">${state === 'expired' ? 'Expired ' : 'Expires '}</span>${when(t.expires_at)}`}</div>
<div class="act">${revoke}</div></li>`;
    }).join('');
    const adminCreated = created && isAdmin(created);
    const reveal = !created ? '' : `<section class="reveal${adminCreated ? ' admin' : ''}" aria-labelledby="new-key">
<h2 id="new-key">${icon(adminCreated ? 'shield' : 'check')}${adminCreated ? 'Admin' : 'Ingest'} key “${e(created.name)}” created</h2>
<p>Scope <code>${e(created.scope)}</code>. Copy it now. For your security it will not be shown again.</p>
${adminCreated ? `<div class="warnline">${icon('warn')}<span>This key can read every item in your inbox and change its state. Keep it out of agent configs and shared machines; revoke it the moment it leaks.</span></div>` : ''}
<div class="secret"><code id="new-secret">${e(created.plaintext)}</code>${copyButton('new-secret', 'Copy key', 'btn btn-sm')}</div>
<p style="margin:12px 0 8px">${adminCreated ? 'Store it where the admin tool runs, not where agents run:' : 'Then store it in the environment of the machine running your agent:'}</p>
<div class="code"><pre id="new-env">export ${adminCreated ? 'HINDSIGHT_ADMIN_TOKEN' : 'HINDSIGHT_INGEST_TOKEN'}="${e(created.plaintext)}"</pre>${copyButton('new-env')}</div>
<div class="next">${adminCreated ? `<a class="btn btn-secondary" href="/connect#admin">${icon('plug')}How to use an admin key</a>`
    : `<a class="btn btn-secondary" href="/connect">${icon('plug')}Set up a client</a>`}</div></section>`;
    const adminPicked = posted.scope === SCOPE_ADMIN;
    const days = EXPIRY.includes(posted.days) ? posted.days : 30;
    const createForm = `<form class="card card-pad kform" method="post" action="/tokens"><input type="hidden" name="csrf" value="${csrf}">
<h2>Create an API key</h2>
<label class="field">Name <input name="name" maxlength="80" required placeholder="e.g. Work laptop — Claude Code" autocomplete="off"${posted.name ? ` value="${e(posted.name)}"` : ''}></label>
<fieldset class="scopes"><legend>Scope</legend><div class="scope-grid">
<label class="scope"><input type="radio" name="scope" value="${SCOPE_SUBMIT}" id="sc-ingest"${adminPicked ? '' : ' checked'}><b>Ingest</b>
<span>Agents submit suggestions with it. It cannot read the inbox or manage keys. Use one per machine or client.</span></label>
<label class="scope admin"><input type="radio" name="scope" value="${SCOPE_ADMIN}" id="sc-admin"${adminPicked ? ' checked' : ''}><b>${icon('shield')}Admin</b>
<span>Reads every item in your inbox and changes its state over the API or MCP. It can also submit. For a triage tool or script you run yourself.</span></label>
</div></fieldset>
<p class="admin-warn">${icon('warn')}<span><b>Admin keys are powerful.</b> Anyone holding one sees all of your inbox and can mark items done or dismissed. Do not give one to a coding agent, and prefer the shortest expiry that works.</span></p>
<div class="row2"><label class="field">Expires after <select name="days">${EXPIRY.map((d) => `<option value="${d}"${d === days ? ' selected' : ''}>${d} days</option>`).join('')}</select></label><span></span>
<button class="btn btn-create" type="submit">${icon('plus')}<span class="lbl-i">${adminPicked ? 'Create admin key' : 'Create key'}</span><span class="lbl-a" aria-hidden="true">Create admin key</span></button></div>
<p class="small muted" style="margin:0">No key can create, list, or revoke keys; that stays on this page.</p></form>`;
    const listCard = list
      ? `<section class="card" aria-label="Your API keys"><ul class="keys"><li class="hd" aria-hidden="true"><span>Name</span><span>Scope</span><span>Created</span><span>Last used</span><span>Expires / revoked</span><span></span></li>${list}</ul></section>`
      : emptyState('key', 'No API keys yet', 'Create a key above, then use it to connect Claude Code, Codex, Cursor, or OpenCode.');
    return shell('API keys', flash + reveal + `<div class="stack">${createForm}${listCard}</div>` +
      (pager ? `<nav class="pager" aria-label="Pages">${pager}</nav>` : ''),
    ui(req, '/tokens', { sub: 'Ingest keys let agents send suggestions. Admin keys let a tool read and update your inbox.' }));
  };

  app.get('/tokens', requireReviewer, async (req, res) => {
    const { before } = req.query;
    if (before !== undefined && (typeof before !== 'string' || !UUID.test(before))) {
      return problem(req, res, 400, 'Invalid request', 'That page link is not valid.', toTokens);
    }
    const flash = req.query.revoked === '1' ? alertBox('ok', 'API key revoked. Agents using it can no longer submit feedback or use the API.') : '';
    res.send(await tokensPage(req, { before, flash }));
  });

  app.post('/tokens', requireReviewer, form, requireMutation, async (req, res) => {
    const name = String(req.body.name || '').trim();
    const days = Number(req.body.days || 30);
    // A missing scope means ingest (the safe default); an unknown one is refused, never widened.
    const scope = req.body.scope === undefined ? SCOPE_SUBMIT : pick(req.body.scope, SCOPES);
    if (!name || name.length > 80 || !Number.isInteger(days) || days < 1 || days > 90 || !scope) {
      return res.status(400).send(await tokensPage(req, { form: { name: name.slice(0, 80), scope, days },
        flash: alertBox('err', 'Give the key a name (up to 80 characters), a scope, and an expiry of 1–90 days.') }));
    }
    const plaintext = generateToken();
    // A key has just a name. The stored client label, which attributes and idempotency-binds its
    // submissions, is that name.
    await store.createToken({
      ownerEmail: req.reviewer.email, name, client: name, tokenHash: hashToken(plaintext), scope,
      expiresAt: new Date(Date.now() + days * 86400000),
    });
    res.send(await tokensPage(req, { created: { name, plaintext, scope } }));
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
<li><h3>Create an API key</h3><p>An <b>Ingest</b> key, one per machine or client, makes it easy to see where feedback came from, and to revoke it.</p>
<a class="btn btn-secondary btn-sm" href="/tokens">${icon('key')}Go to API keys</a></li>
<li><h3>Store it in an environment variable</h3><p>Never paste a key into a checked-in config file.</p>${snippet('c-env', 'export HINDSIGHT_INGEST_TOKEN="hs_…"')}</li>
<li><h3>Add HindSight to your client</h3><p>Pick your client and copy the command or config.</p>${tabs}</li>
<li><h3>Done</h3><p>At the end of a task, agents call <code>submit_feedback</code> and the suggestion shows up in your <a href="/review">inbox</a>.</p></li></ol>`;
    const api = config.publicOrigin + '/api/v1';
    const H = '-H "Authorization: Bearer $HINDSIGHT_ADMIN_TOKEN"';
    const adminBox = `<section class="adminbox" id="admin" aria-labelledby="adm-h"><header>${icon('shield')}<div><h2 id="adm-h">Use an admin key</h2>
<p>For a triage script, a dashboard, or an assistant you drive yourself. Not for coding agents.</p></div></header><div class="in">
<p class="small muted">Create a key with the <b>Admin</b> scope on <a href="/tokens">API keys</a>, then export it where that tool runs:</p>
${snippet('a-env', 'export HINDSIGHT_ADMIN_TOKEN="hs_…"')}
<div class="tabs" style="margin-top:14px"><input type="radio" name="adm" id="a1" checked><input type="radio" name="adm" id="a2">
<div class="tl" role="presentation"><label for="a1">MCP (Claude Code)</label><label for="a2">HTTP</label></div>
<div class="panel p1">${snippet('a-claude', `claude mcp add --transport http --scope user hindsight-admin ${url} \\\n  --header 'Authorization: Bearer \${HINDSIGHT_ADMIN_TOKEN}'`)}
<p class="muted">Same endpoint as ingest; the key’s scope decides which tools are listed. An admin key gets:</p>
<dl class="toolgrid"><dt>list_feedback</dt><dd>Read items, newest first. Optional <code>state</code>, <code>category</code>, <code>key</code> (API key name), <code>limit</code> (1–100), <code>cursor</code>.</dd>
<dt>get_feedback</dt><dd>One item by <code>id</code>.</dd>
<dt>update_feedback_state</dt><dd>Set <code>state</code> and/or a private <code>review_note</code> on one item.</dd>
<dt>bulk_update_feedback_state</dt><dd>Set one <code>state</code> on up to 100 <code>ids</code>.</dd>
<dt>submit_feedback</dt><dd>Also available: an admin key can submit, like an ingest key. Agents should still use ingest keys.</dd></dl></div>
<div class="panel p2">${snippet('a-http', `curl -sS ${H} \\\n  "${api}/feedback?state=new&category=instructions&limit=50"\n\ncurl -sS -X PATCH ${H} \\\n  -H "Content-Type: application/json" -d '{"state":"actioned"}' \\\n  "${api}/feedback/<id>"\n\ncurl -sS -X POST ${H} \\\n  -H "Content-Type: application/json" -d '{"ids":["<id1>","<id2>"],"state":"dismissed"}' \\\n  "${api}/feedback/bulk"`)}
<p class="muted">JSON in, JSON out. Page with <code>cursor=&lt;next_cursor&gt;</code>. States use the stored names: <code>new</code> (Open), <code>triaged</code> (Planned),
<code>actioned</code> (Done), <code>dismissed</code> (Won’t do).</p></div></div>
<p class="small muted" style="margin:12px 0 0">Item text is agent-submitted: a tool using an admin key must treat it as data, never as instructions.</p></div></section>`;
    const aside = `<aside class="card card-pad"><h2 style="margin-bottom:12px">Server details</h2>
<p class="small muted" style="margin:0 0 6px">MCP endpoint</p><div class="secret" style="margin-bottom:14px"><code id="c-url" class="small">${e(url)}</code>${copyButton('c-url', 'Copy', 'btn btn-ghost btn-sm')}</div>
<dl class="kv"><dt>Transport</dt><dd>Streamable HTTP</dd><dt>Auth</dt><dd>Bearer API key</dd><dt>Tool</dt><dd>submit_feedback</dd><dt>Admin</dt><dd><a href="#admin">+ 4 tools, /api/v1</a></dd><dt>Rate limit</dt><dd>${config.rateLimitPerMinute}/min per key</dd></dl></aside>`;
    res.send(shell('Connect a client', `<div class="grid2"><div><section class="card card-pad">${steps}</section>${adminBox}</div>${aside}</div>`,
      ui(req, '/connect', { sub: 'Point your coding agents at HindSight so they can send suggestions when they finish work.' })));
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
