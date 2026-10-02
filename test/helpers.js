import { request } from 'node:http';

export const ORIGIN = 'https://hs.test';
export const HOST = 'hs.test';
export const SECRET = 'x'.repeat(40);
// Headers Vercel's HTTPS proxy sends for a request to the canonical domain.
export const CANONICAL = { host: HOST, 'x-forwarded-host': HOST, 'x-forwarded-proto': 'https' };
export const env = {
  DATABASE_URL: 'postgres://synthetic.invalid/hindsight', AUTH_GOOGLE_ID: 'id', AUTH_GOOGLE_SECRET: 's',
  AUTH_SECRET: SECRET, HINDSIGHT_REVIEWER_EMAILS: 'owner@example.com', HINDSIGHT_PUBLIC_ORIGIN: ORIGIN,
};

export async function serve(app, fn) {
  const server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  try {
    return await fn(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.closeAllConnections();
    server.close();
  }
}

// node:http (not fetch) so tests control Host and proxy headers exactly. Undefined values are omitted.
export function call(base, path, { method = 'GET', headers = {}, body, signal } = {}) {
  const merged = Object.fromEntries(Object.entries({ ...CANONICAL, ...headers }).filter(([, v]) => v !== undefined));
  return new Promise((resolve, reject) => {
    const req = request(base + path, { method, headers: merged, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    req.on('error', reject);
    signal?.addEventListener('abort', () => { req.destroy(); reject(signal.reason ?? new Error('aborted')); });
    if (body !== undefined) req.write(body);
    req.end();
  });
}

export const text = (res) => res.body.toString('utf8');
