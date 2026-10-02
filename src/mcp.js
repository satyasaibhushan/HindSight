import { createHash } from 'node:crypto';
import { McpServer, createMcpHandler } from '@modelcontextprotocol/server';
import * as z from 'zod';
import { looksSecret } from './security.js';

// Primary: the user's shared instructions, skills, codebase, and collaboration. The rest are kept for
// compatibility with existing rows and clients. Must match migrations/004_feedback_categories.sql.
export const CATEGORIES = ['instructions', 'skills', 'codebase', 'collaboration',
  'connector', 'tooling', 'environment', 'documentation', 'workflow', 'performance', 'other'];
export const OUTCOMES = ['completed', 'recovered', 'workaround', 'failed', 'blocked', 'unresolved'];
const text = (max) => z.string().trim().min(1).max(max);

export const feedbackSchema = z.object({
  request_id: z.string().regex(/^[A-Za-z0-9._:-]{8,128}$/)
    .describe('Client-generated idempotency key; reuse it only when retrying the identical submission'),
  friction: text(4000).describe('Observed friction'),
  improvement: text(4000).describe('Concrete proposed improvement'),
  category: z.enum(CATEGORIES).describe('instructions/skills: the user\'s editable shared project instructions or skills; ' +
    'codebase; collaboration: working practices with the user; connector/tooling: tools and connectors'),
  task: text(300).optional(),
  source: text(300).optional(),
  repository: text(300).optional(),
  outcome: z.enum(OUTCOMES).optional(),
  confidence: z.enum(['low', 'medium', 'high']).optional(),
});

const FIELDS = ['friction', 'improvement', 'category', 'task', 'source', 'repository', 'outcome', 'confidence'];
// Versioned fingerprint of the authenticated token-bound client plus normalized fields in fixed order
// (request_id excluded; it is the key). Token id is excluded so rotation replays for the same client.
export function payloadHash(input, client) {
  const norm = (v) => (typeof v === 'string' ? v.trim().normalize('NFC') : v ?? null);
  const canonical = JSON.stringify(['hindsight-feedback-v2', norm(client), ...FIELDS.map((k) => norm(input[k]))]);
  return createHash('sha256').update(canonical).digest('hex');
}

const NO_OP = /^(n\/?a|none|nothing|no issues?|ok|fine|-+|\.+)$/i;
const result = (message, isError = false) => ({ content: [{ type: 'text', text: message }], isError });

// One fresh server per request; the authenticated token is bound in the closure.
export function createServer(store, token) {
  const server = new McpServer({ name: 'hindsight', version: '0.2.0' });
  server.registerTool('submit_feedback', {
    description: 'Record attributable, user-reviewable feedback (not anonymous) on the user\'s shared instructions, ' +
      'skills, codebase, collaboration, or tools/connectors. ' +
      'Submit only concrete friction with a specific improvement. Never include secrets or transcripts.',
    inputSchema: feedbackSchema,
  }, async (input) => {
    if (NO_OP.test(input.friction) || NO_OP.test(input.improvement)) {
      return result('Rejected: empty or no-op feedback is not recorded.', true);
    }
    const values = Object.values(input).filter((v) => typeof v === 'string');
    if (values.some(looksSecret)) return result('Rejected: feedback appears to contain a secret.', true);
    let outcome;
    try {
      outcome = await store.insertFeedback(token, input, payloadHash(input, token.client));
    } catch {
      return result('Storage unavailable; feedback was NOT recorded. Retry later with the same request_id.', true);
    }
    if (outcome.status === 'conflict') {
      return result('Conflict (409): request_id was already used with a different client or payload; nothing recorded.', true);
    }
    const verb = outcome.status === 'replayed' ? 'Already recorded' : 'Recorded';
    return result(`${verb} feedback ${outcome.id} for ${outcome.client}.`);
  });
  return server;
}

export function handleMcp(store, token, request) {
  const handler = createMcpHandler(() => createServer(store, token));
  return handler.fetch(request, {
    authInfo: { token: token.id, clientId: token.client, scopes: ['feedback:submit'], extra: { tokenId: token.id } },
  });
}
