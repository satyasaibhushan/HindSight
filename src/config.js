// Canonical origin must be a bare HTTPS origin (no path, query, credentials, or trailing slash).
export function isCanonicalOrigin(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.origin === value && !url.username && !url.password;
  } catch {
    return false;
  }
}

export function loadConfig(env = process.env) {
  const reviewers = (env.HINDSIGHT_REVIEWER_EMAILS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const limit = Number.parseInt(env.HINDSIGHT_RATE_LIMIT_PER_MINUTE, 10);
  const config = {
    databaseUrl: env.DATABASE_URL || '',
    googleId: env.AUTH_GOOGLE_ID || '',
    googleSecret: env.AUTH_GOOGLE_SECRET || '',
    authSecret: env.AUTH_SECRET || '',
    reviewers,
    publicOrigin: (env.HINDSIGHT_PUBLIC_ORIGIN || '').replace(/\/+$/, ''),
    rateLimitPerMinute: Number.isInteger(limit) && limit >= 1 && limit <= 600 ? limit : 20,
  };
  const ready = {
    database: /^postgres(ql)?:\/\/\S+$/.test(config.databaseUrl),
    google: Boolean(config.googleId.trim() && config.googleSecret.trim()),
    session: config.authSecret.length >= 32,
    reviewers: reviewers.length > 0 && reviewers.every((r) => /^[^@\s,]+@[^@\s,]+$/.test(r)),
    origin: isCanonicalOrigin(config.publicOrigin),
  };
  config.ready = ready;
  config.webReady = Object.values(ready).every(Boolean);
  // MCP accepts credentials and stores submissions only when the full production auth surface
  // (Google, session, reviewers, database, canonical origin) is configured.
  config.mcpReady = config.webReady;
  return config;
}
