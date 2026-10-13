import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';
import express from 'express';
import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import { forwardMcp } from '../src/mcp-http.js';
import { ORIGIN, modernListen, modernListenHeaders, serve } from './helpers.js';

const deferred = () => Promise.withResolvers();
function adapter(handle, finished) {
  const app = express();
  app.use(express.raw({ type: () => true }));
  app.all('/api/mcp', async (req, res) => {
    try { await forwardMcp(req, res, ORIGIN, handle); finished.resolve(); }
    catch (error) { finished.reject(error); res.destroy(); }
  });
  return app;
}

test('disconnect aborts a real SDK subscription and finishes the response pump', { timeout: 3000 }, async () => {
  const finished = deferred();
  let signal;
  const handler = createMcpHandler(() => new McpServer({ name: 'stream-test', version: '1' }, {
    capabilities: { tools: { listChanged: true } },
  }), { keepAliveMs: 10 });
  try {
    await serve(adapter((request) => {
      signal = request.signal;
      return handler.fetch(request);
    }, finished), async (url) => {
      const abort = new AbortController();
      const response = await fetch(url + '/api/mcp', {
        method: 'POST', headers: modernListenHeaders, body: JSON.stringify(modernListen()), signal: abort.signal,
      });
      assert.equal(response.status, 200);
      const reader = response.body.getReader();
      assert.match(new TextDecoder().decode((await reader.read()).value), /acknowledged/);
      abort.abort();
      await reader.cancel().catch(() => {});
      await finished.promise;
      assert.equal(signal.aborted, true);
    });
  } finally { await handler.close(); }
});

test('disconnect cancels an unfinished source and stops its keepalive work', { timeout: 3000 }, async () => {
  const finished = deferred();
  let cancelled = 0;
  let ticks = 0;
  let timer;
  try {
    await serve(adapter(async () => new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(': connected\n\n'));
        timer = setInterval(() => { ticks++; controller.enqueue(new Uint8Array([32])); }, 10);
      },
      cancel() { cancelled++; clearInterval(timer); },
    })), finished), async (url) => {
      const abort = new AbortController();
      const response = await fetch(url + '/api/mcp', { method: 'POST', signal: abort.signal });
      const reader = response.body.getReader();
      await reader.read();
      abort.abort();
      await reader.cancel().catch(() => {});
      await finished.promise;
      const stopped = ticks;
      await delay(40);
      assert.equal(ticks, stopped);
      assert.equal(cancelled, 1);
    });
  } finally { clearInterval(timer); }
});

test('a response arriving after disconnect is cancelled instead of written', { timeout: 3000 }, async () => {
  const finished = deferred();
  const started = deferred();
  const release = deferred();
  let cancelled = 0;
  await serve(adapter(async (request) => {
    started.resolve(request.signal);
    await release.promise;
    return new Response(new ReadableStream({ cancel() { cancelled++; } }));
  }, finished), async (url) => {
    const client = httpRequest(url + '/api/mcp', { method: 'POST' });
    client.on('error', () => {});
    client.end();
    const signal = await started.promise;
    const aborted = new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
    client.destroy();
    await aborted;
    release.resolve();
    await finished.promise;
    assert.equal(cancelled, 1);
  });
});

test('successful concurrent responses finish independently without aborting their requests', async () => {
  const signals = [];
  let completed = 0;
  const finished = deferred();
  await serve(adapter(async (request) => {
    signals.push(request.signal);
    return new Response('complete', { status: 200 });
  }, { resolve() { if (++completed === 2) finished.resolve(); }, reject: finished.reject }), async (url) => {
    const responses = await Promise.all([1, 2].map(async () => {
      const response = await fetch(url + '/api/mcp', { method: 'POST' });
      return response.text();
    }));
    await finished.promise;
    assert.deepEqual(responses, ['complete', 'complete']);
    assert.equal(signals.length, 2);
    assert.ok(signals.every((signal) => !signal.aborted));
  });
});
