import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export const generateToken = () => 'hs_' + randomBytes(32).toString('base64url');
export const hashToken = (token) => createHash('sha256').update(token).digest('hex');

export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

export function safeRelativePath(value, fallback = '/review') {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.includes('\\')) {
    return fallback;
  }
  return value;
}

export function csrfToken(secret, email) {
  return createHmac('sha256', secret).update('csrf:' + email).digest('base64url');
}

export function checkCsrf(secret, email, submitted) {
  const expected = Buffer.from(csrfToken(secret, email));
  const actual = Buffer.from(String(submitted || ''));
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function sameOrigin(req, publicOrigin) {
  let origin = req.get('origin');
  if (!origin && req.get('referer')) {
    try { origin = new URL(req.get('referer')).origin; } catch { return false; }
  }
  return Boolean(origin) && origin === publicOrigin;
}

// Host and proxy headers must all describe the canonical HTTPS origin. Vercel sets Host,
// X-Forwarded-Host, X-Forwarded-Proto (and Forwarded) to the requested domain over HTTPS;
// any disagreement, list value, or plain-HTTP indication is treated as spoofing.
export function canonicalHeadersOk(req, canonicalHost) {
  const lower = (v) => (typeof v === 'string' ? v.toLowerCase() : v);
  if (!req.originalUrl.startsWith('/') || req.originalUrl.startsWith('//')) return false;
  if (lower(req.get('host')) !== canonicalHost) return false;
  const fwdHost = req.get('x-forwarded-host');
  if (fwdHost !== undefined && lower(fwdHost) !== canonicalHost) return false;
  if (lower(req.get('x-forwarded-proto')) !== 'https') return false;
  const fwdPort = req.get('x-forwarded-port');
  if (fwdPort !== undefined && fwdPort !== '443') return false;
  const forwarded = req.get('forwarded');
  if (forwarded !== undefined) {
    for (const pair of forwarded.split(/[,;]/)) {
      const [key, ...rest] = pair.split('=');
      const value = lower(rest.join('=').trim().replace(/^"(.*)"$/, '$1'));
      const name = lower(key.trim());
      if (name === 'host' && value !== canonicalHost) return false;
      if (name === 'proto' && value !== 'https') return false;
    }
  }
  return true;
}

const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\b(?:sk-|ghp_|gho_|github_pat_|xox[abpr]-|AKIA|hs_)[A-Za-z0-9_-]{12,}/,
  /\bBearer\s+[A-Za-z0-9._~+/-]{20,}/i,
];
export const looksSecret = (text) => SECRET_PATTERNS.some((re) => re.test(text));

export function isAuthorizedReviewer(profile, reviewers) {
  const email = typeof profile?.email === 'string' ? profile.email.toLowerCase() : '';
  return profile?.email_verified === true && email !== '' && reviewers.includes(email);
}
