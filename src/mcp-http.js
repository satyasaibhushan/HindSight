import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';

// Tie the web-standard MCP exchange to the real Node response, including premature disconnects.
export async function forwardMcp(req, res, origin, handle) {
  const abort = new AbortController();
  const disconnected = () => abort.abort(new Error('MCP client disconnected'));
  const closed = () => { if (!res.writableFinished) disconnected(); };
  req.once('aborted', disconnected);
  res.once('close', closed);
  let response;
  try {
    if (req.aborted || res.destroyed) disconnected();
    abort.signal.throwIfAborted();
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === 'string') headers.set(k, v);
    const hasBody = !['GET', 'HEAD'].includes(req.method) && Buffer.isBuffer(req.body) && req.body.length > 0;
    const request = new Request(origin + req.originalUrl, {
      method: req.method, headers, body: hasBody ? req.body : undefined, signal: abort.signal,
    });
    response = await handle(request);
    abort.signal.throwIfAborted();
    res.status(response.status);
    response.headers.forEach((v, k) => res.setHeader(k, v));
    res.setHeader('Cache-Control', 'no-store');
    if (!response.body) return res.end();
    // Pipeline cancels the source on disconnect and respects response backpressure.
    await pipeline(Readable.fromWeb(response.body), res, { signal: abort.signal });
  } catch (error) {
    if (!abort.signal.aborted) throw error;
  } finally {
    req.removeListener('aborted', disconnected);
    res.removeListener('close', closed);
    if (response?.body && !response.body.locked) await response.body.cancel().catch(() => {});
  }
}
