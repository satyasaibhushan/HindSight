// Local HTTP entrypoint serving the same handler Vercel runs (api/index.js); no extra switches.
// With empty config every route except /health answers setup-required. With full config the canonical
// gate still requires Host/X-Forwarded-* to match HINDSIGHT_PUBLIC_ORIGIN over HTTPS, so authenticated
// use needs an HTTPS reverse proxy or tunnel on that origin in front of this port.
// Never runs migrations.
import { createServer } from 'node:http';
import handler from '../api/index.js';

const port = Number.parseInt(process.env.PORT || '3000', 10);
const host = process.env.HOST || '127.0.0.1';

const server = createServer((req, res) => {
  handler(req, res).catch((err) => {
    console.error('hindsight startup error', err?.name);
    if (!res.headersSent) res.writeHead(500, { 'content-type': 'application/json' });
    res.end('{"error":"internal_error"}');
  });
});
server.listen(port, host, () => console.log(`HindSight listening on http://${host}:${port} (check /health)`));
for (const sig of ['SIGINT', 'SIGTERM']) process.once(sig, () => server.close(() => process.exit(0)));
