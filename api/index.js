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
  let authRouter = null;
  let getReviewer = async () => null;
  if (config.webReady) {
    const { ExpressAuth, getSession } = await import('@auth/express');
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
    authRouter = ExpressAuth(authConfig);
    getReviewer = async (req) => {
      const email = (await getSession(req, authConfig))?.user?.email?.toLowerCase();
      return email && config.reviewers.includes(email) ? { email } : null;
    };
  }
  return createApp({ config, store, getReviewer, authRouter });
}

export default async function handler(req, res) {
  appPromise ??= init().catch((err) => { appPromise = null; throw err; });
  const app = await appPromise;
  return app(req, res);
}
