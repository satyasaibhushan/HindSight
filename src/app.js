import express from 'express';
import { MAX_PAGE, REVIEW_STATES } from './db.js';
import { CATEGORIES, handleMcp } from './mcp.js';
import { canonicalHeadersOk, checkCsrf, csrfToken, escapeHtml as e, generateToken, hashToken, safeRelativePath, sameOrigin } from './security.js';

// Restrained inline styles only (CSP allows inline styles, nothing else): system fonts, wrapping
// nav/forms, and 44px tap targets. No scripts or external assets.
const STYLE = `*{box-sizing:border-box}
body{font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#1f2328;background:#f6f7f9;margin:0}
main{max-width:860px;margin:0 auto;padding:1rem}
header.top{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:.5rem 1rem;margin-bottom:.5rem}
.brand{font-weight:700;font-size:1.1rem;letter-spacing:.01em}
h1{font-size:1.4rem;margin:.5rem 0 1rem}
nav{display:flex;flex-wrap:wrap;gap:.25rem}
nav a{color:#1f2328;text-decoration:none;padding:.6rem .8rem;border-radius:6px;min-height:44px;display:inline-flex;align-items:center}
nav a:hover,nav a:focus-visible{background:#e8eaee}
a{color:#0b57d0}
.note{color:#57606a;font-size:.9rem}
.card{background:#fff;border:1px solid #d8dee4;border-radius:8px;padding:1rem;margin:0 0 1rem}
form.row{display:flex;flex-wrap:wrap;align-items:flex-end;gap:.75rem}
fieldset{border:0;padding:0;margin:0;min-width:0}
legend{font-weight:600;padding:0;margin-bottom:.5rem}
.fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(12rem,1fr));gap:.75rem;margin-bottom:.75rem}
label{display:flex;flex-direction:column;gap:.25rem;font-size:.9rem;font-weight:600}
.hint{font-weight:400;color:#57606a}
input,select,button{font:inherit;min-height:44px;padding:.45rem .6rem;border:1px solid #8c959f;border-radius:6px;background:#fff;color:inherit;max-width:100%}
button{background:#1f2328;color:#fff;border-color:#1f2328;cursor:pointer;padding:.45rem 1rem}
button.secondary{background:#fff;color:#1f2328}
:focus-visible{outline:3px solid #0b57d0;outline-offset:2px}
.meta{display:flex;flex-wrap:wrap;gap:.25rem .75rem;list-style:none;padding:0;margin:0 0 .5rem;color:#57606a;font-size:.9rem}
.meta>li{min-width:0;max-width:100%;overflow-wrap:anywhere}
.meta.foot{margin-top:.75rem}
.tag{background:#eef1f4;color:#1f2328;border-radius:999px;padding:0 .6rem;font-weight:600}
h2{font-size:.95rem;margin:.75rem 0 .25rem}
.prose{white-space:pre-wrap;overflow-wrap:anywhere;margin:0}
.credential{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;background:#eef1f4;padding:.75rem;border-radius:6px;margin:.5rem 0 0}
ul.plain{list-style:none;padding:0;margin:0}
ul.plain li{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:.5rem;padding:.75rem 0;border-top:1px solid #d8dee4}
ul.plain li>div{min-width:0;max-width:100%;overflow-wrap:anywhere}
ul.plain li:first-child{border-top:0}
.pager{display:flex;flex-wrap:wrap;gap:1rem}
.pager a{min-height:44px;display:inline-flex;align-items:center}`;

const page = (title, body, { nav = '' } = {}) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${e(title)} · HindSight</title>
<style>${STYLE}</style>
</head><body><main><header class="top"><span class="brand">HindSight</span>${nav}</header>
<h1>${e(title)}</h1>${body}</main></body></html>`;

// Server-rendered dates are shown in UTC and labeled as such; the machine-readable value stays exact.
const when = (value) => {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return `<time datetime="${e(d.toISOString())}">${e(d.toISOString().slice(0, 16).replace('T', ' '))} UTC</time>`;
};

const SETUP_BODY = `<div class="card"><p>HindSight is a private tool for reviewing feedback that your agents submit about
your shared instructions, skills, codebase, collaboration, and tools.</p>
<p>This deployment is not ready yet: sign-in, storage, and reviewer access have not all been configured.
Until they are, sign-in, review, and feedback submission stay switched off.</p>
<p class="note">If you operate this deployment, follow the setup checklist in the project README.</p></div>`;
const setupPage = () => page('Setup required', SETUP_BODY);

// The Auth.js sign-in page's form POSTs to /auth/signin/google, which 302s to Google's authorization
// endpoint; browsers apply form-action to that redirect. Only that page may target the exact Google
// authorization origin; every other route stays form-action 'self'.
export const GOOGLE_AUTH_ORIGIN = 'https://accounts.google.com';
const SIGNIN_PAGE = /^\/auth\/signin\/?$/;
const csp = (formAction) =>
  `default-src 'none'; style-src 'unsafe-inline'; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`;

function privateHeaders(req, res, next) {
  res.set({
    'Cache-Control': 'no-store',
    'Content-Security-Policy': csp(SIGNIN_PAGE.test(req.path) ? `'self' ${GOOGLE_AUTH_ORIGIN}` : "'self'"),
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin',
  });
  next();
}

// deps: { config, store, getReviewer(req) -> {email}|null, authRouter }
export function createApp({ config, store, getReviewer, authRouter }) {
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
    app.use(['/auth', '/review', '/tokens'], setupRequired);
  } else {
    app.use('/auth', authRouter);
  }

  const requireReviewer = async (req, res, next) => {
    const reviewer = await getReviewer(req);
    if (!reviewer) {
      return res.redirect(303, '/auth/signin?callbackUrl=' + encodeURIComponent(safeRelativePath(req.originalUrl)));
    }
    req.reviewer = reviewer;
    next();
  };
  const requireMutation = (req, res, next) => {
    if (!sameOrigin(req, config.publicOrigin) || !checkCsrf(config.authSecret, req.reviewer.email, req.body?.csrf)) {
      return res.status(403).send(page('Forbidden', '<p>Request origin or CSRF token rejected.</p>' + back));
    }
    next();
  };
  const form = express.urlencoded({ extended: false, limit: '4kb' });
  const nav = '<nav aria-label="Main"><a href="/review">Feedback</a><a href="/tokens">Ingestion tokens</a><a href="/auth/signout">Sign out</a></nav>';
  const withNav = { nav };
  const back = '<p><a href="/review">Back to feedback</a></p>';

  app.get('/', (_req, res) => res.redirect(303, '/review'));

  const pick = (v, allowed) => (typeof v === 'string' && allowed.includes(v) ? v : undefined);
  // `any` adds an empty "any …" choice for filters; omitted for required values.
  const select = (name, value, options, any) => `<select name="${name}">${any ? `<option value="">${e(any)}</option>` : ''}${options
    .map((o) => `<option${o === value ? ' selected' : ''}>${e(o)}</option>`).join('')}</select>`;

  app.get('/review', requireReviewer, async (req, res) => {
    const filters = {
      category: pick(req.query.category, CATEGORIES),
      state: pick(req.query.state, REVIEW_STATES),
      client: typeof req.query.client === 'string' && /^.{1,80}$/.test(req.query.client) ? req.query.client : undefined,
      page: Math.min(Math.max(Number.parseInt(req.query.page, 10) || 0, 0), MAX_PAGE),
    };
    const { rows, hasMore } = await store.listFeedback(req.reviewer.email, filters);
    const csrf = e(csrfToken(config.authSecret, req.reviewer.email));
    const optional = (label, v) => (v ? `<li>${label}: ${e(v)}</li>` : '');
    const items = rows.map((f) => `<article class="card"><ul class="meta"><li class="tag">${e(f.category)}</li>
<li>${e(f.client)}</li><li>${when(f.created_at)}</li>${optional('Repository', f.repository)}${optional('Task', f.task)}${optional('Source', f.source)}</ul>
<h2>Friction</h2><div class="prose">${e(f.friction)}</div><h2>Improvement</h2><div class="prose">${e(f.improvement)}</div>
<ul class="meta foot"><li>Outcome: ${e(f.outcome || '—')}</li><li>Confidence: ${e(f.confidence || '—')}</li><li>Request: ${e(f.request_id)}</li></ul>
<form class="row" method="post" action="/review/${e(f.id)}/state"><input type="hidden" name="csrf" value="${csrf}">
<label>Review state ${select('state', f.review_state, REVIEW_STATES)}</label><button class="secondary">Update</button></form></article>`).join('');
    const qs = (p) => '/review?' + new URLSearchParams(Object.entries({ ...filters, page: String(p) })
      .filter(([, v]) => v !== undefined && v !== '')).toString();
    const pager = (filters.page > 0 ? `<a href="${e(qs(filters.page - 1))}">Newer</a> ` : '') +
      (hasMore && filters.page < MAX_PAGE ? `<a href="${e(qs(filters.page + 1))}">Older</a>` : '');
    const filterForm = `<form class="card row" method="get" action="/review" role="search" aria-label="Filter feedback">
<label>Category ${select('category', filters.category, CATEGORIES, 'Any category')}</label>
<label>Review state ${select('state', filters.state, REVIEW_STATES, 'Any state')}</label>
<label>Client <input name="client" maxlength="80" value="${e(filters.client || '')}"></label>
<button>Filter</button></form>`;
    const notice = '<p class="note">Feedback is attributable to the issuing token and client, private to you, and reviewable here. It is not anonymous. Dates are UTC.</p>';
    res.send(page('Feedback', notice + filterForm + (items || '<p>No feedback yet.</p>') + `<p class="pager">${pager}</p>`, withNav));
  });

  app.post('/review/:id/state', requireReviewer, form, requireMutation, async (req, res) => {
    const state = pick(req.body.state, REVIEW_STATES);
    if (!/^[0-9a-f-]{36}$/.test(req.params.id) || !state) return res.status(400).send(page('Invalid request', back, withNav));
    if (!await store.setReviewState(req.reviewer.email, req.params.id, state)) return res.status(404).send(page('Not found', back, withNav));
    res.redirect(303, '/review');
  });

  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const tokensPage = async (req, extra = '', before = undefined) => {
    const csrf = e(csrfToken(config.authSecret, req.reviewer.email));
    const { rows, nextCursor } = await store.listTokens(req.reviewer.email, { before });
    const pager = (before ? '<a href="/tokens">Newest</a> ' : '') +
      (nextCursor ? `<a href="${e('/tokens?before=' + nextCursor)}">Older</a>` : '');
    const list = rows.map((t) => {
      const state = t.revoked_at ? 'revoked' : new Date(t.expires_at) <= new Date() ? 'expired' : 'active';
      const revoke = state === 'active' ? `<form method="post" action="/tokens/${e(t.id)}/revoke">
<input type="hidden" name="csrf" value="${csrf}"><button class="secondary">Revoke</button></form>` : '';
      return `<li><div><b>${e(t.name)}</b> <span class="note">${e(t.client)}</span><br>
<span class="tag">${state}</span> <span class="note">expires ${when(t.expires_at)}</span></div>${revoke}</li>`;
    }).join('');
    return page('Ingestion tokens', extra + `<form class="card" method="post" action="/tokens">
<input type="hidden" name="csrf" value="${csrf}"><fieldset><legend>New submit-only token</legend><div class="fields">
<label>Name <span class="hint">e.g. work laptop</span><input name="name" maxlength="80" required></label>
<label>Client <span class="hint">e.g. claude-code</span><input name="client" maxlength="80" required></label>
<label>Expires in days <span class="hint">1–90</span><input name="days" type="number" min="1" max="90" value="30"></label>
</div></fieldset><button>Create token</button></form>
<section class="card" aria-label="Your tokens">${list ? `<ul class="plain">${list}</ul>` : '<p>No tokens yet.</p>'}</section>
<p class="pager">${pager}</p>`, withNav);
  };

  app.get('/tokens', requireReviewer, async (req, res) => {
    const { before } = req.query;
    if (before !== undefined && (typeof before !== 'string' || !UUID.test(before))) {
      return res.status(400).send(page('Invalid request', '<p><a href="/tokens">Back to tokens</a></p>', withNav));
    }
    res.send(await tokensPage(req, '', before));
  });

  app.post('/tokens', requireReviewer, form, requireMutation, async (req, res) => {
    const name = String(req.body.name || '').trim();
    const client = String(req.body.client || '').trim();
    const days = Number(req.body.days || 30);
    if (!name || name.length > 80 || !client || client.length > 80 || !Number.isInteger(days) || days < 1 || days > 90) {
      return res.status(400).send(page('Invalid token request', '<p><a href="/tokens">Back to tokens</a></p>', withNav));
    }
    const plaintext = generateToken();
    await store.createToken({
      ownerEmail: req.reviewer.email, name, client, tokenHash: hashToken(plaintext),
      expiresAt: new Date(Date.now() + days * 86400000),
    });
    res.send(await tokensPage(req, `<div class="card" role="status"><b>Copy this token now; it will not be shown again:</b>
<pre class="credential">${e(plaintext)}</pre></div>`));
  });

  app.post('/tokens/:id/revoke', requireReviewer, form, requireMutation, async (req, res) => {
    if (!/^[0-9a-f-]{36}$/.test(req.params.id)) return res.status(404).send(page('Not found', '<p><a href="/tokens">Back to tokens</a></p>', withNav));
    await store.revokeToken(req.reviewer.email, req.params.id);
    res.redirect(303, '/tokens');
  });

  app.use((err, _req, res, _next) => {
    const status = err.status === 413 || err.type === 'entity.too.large' ? 413 : err.status === 400 ? 400 : 500;
    if (status === 500) console.error('hindsight error', err?.name);
    res.status(status).json({ error: status === 413 ? 'payload_too_large' : status === 400 ? 'bad_request' : 'internal_error' });
  });
  return app;
}
