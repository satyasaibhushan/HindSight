import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { isAuthorizedReviewer, safeRelativePath } from '../src/security.js';

let appPromise = null;

async function init() {
  const config = loadConfig();
  let store = null;
  // No database connection until the full production auth configuration is ready.
  if (config.mcpReady) {
    const { default: pg } = await import('pg');
    const { createPgStore } = await import('../src/db.js');
    store = createPgStore(new pg.Pool({ connectionString: config.databaseUrl, max: 3 }));
  }
  const auth = config.webReady ? await buildAuth(config) : { authRouter: null, getReviewer: async () => null };
  return createApp({ config, store, ...auth });
}

export default async function handler(req, res) {
  appPromise ??= init().catch((err) => { appPromise = null; throw err; });
  const app = await appPromise;
  return app(req, res);
}

// Auth.js wiring: the Express router, the session lookup, and the CSRF token for HindSight's own
// sign-in/sign-out screens.
export async function buildAuth(config) {
  const { ExpressAuth, getSession } = await import('@auth/express');
  const { Auth, setEnvDefaults } = await import('@auth/core');
  const { default: Google } = await import('@auth/express/providers/google');
  // trustHost is safe only because createApp's canonical gate rejects spoofed Host/X-Forwarded-*/
  // Forwarded values and normalizes them to the configured HTTPS origin before /auth or getSession.
  const origin = config.publicOrigin;
  const authConfig = {
    secret: config.authSecret,
    trustHost: true,
    useSecureCookies: true,
    basePath: '/auth',
    session: { strategy: 'jwt', maxAge: 8 * 60 * 60 },
    // createApp renders GET /auth/signin itself; Auth.js errors (e.g. AccessDenied) land there too.
    pages: { signIn: '/auth/signin', error: '/auth/signin' },
    providers: [Google({ clientId: config.googleId, clientSecret: config.googleSecret, checks: ['pkce', 'state'] })],
    callbacks: {
      signIn: ({ account, profile }) => account?.provider === 'google' && isAuthorizedReviewer(profile, config.reviewers),
      // Redirects are resolved against the configured origin, never the request-derived baseUrl.
      redirect: ({ url }) => {
        if (url.startsWith('/')) return origin + safeRelativePath(url);
        try { if (new URL(url).origin === origin) return url; } catch {}
        return origin + '/review';
      },
    },
  };
  const authRouter = ExpressAuth(authConfig);
  const getReviewer = async (req) => {
    const email = (await getSession(req, authConfig))?.user?.email?.toLowerCase();
    return email && config.reviewers.includes(email) ? { email } : null;
  };
  // Asks Auth.js for its double-submit CSRF token; returns any cookie it set so the form's POST matches.
  const getAuthCsrf = async (req) => {
    setEnvDefaults(process.env, authConfig);
    const response = await Auth(new Request(origin + '/auth/csrf', { headers: { cookie: req.headers.cookie ?? '' } }), authConfig);
    const { csrfToken } = await response.json();
    return { csrfToken, cookies: response.headers.getSetCookie() };
  };
  return { authRouter, getReviewer, getAuthCsrf };
}
