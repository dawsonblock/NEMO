// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import { createCorrectOnceGatewayClient } from '../src/gateway.mjs';

test('Correct-Once client calls the authenticated Effect Fabric tool endpoint', async () => {
  let observed;
  const client = createCorrectOnceGatewayClient({
    baseUrl: 'http://127.0.0.1:8765',
    token: 'gateway-token',
    fetchImpl: async (url, options) => {
      observed = { url: String(url), options, body: JSON.parse(options.body) };
      return new Response(JSON.stringify({ receipt: 'ok' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });
  const result = await client.execute({
    subject: 'alice',
    server: 'filesystem',
    tool: 'delete',
    args: { path: 'x' },
    actionId: 'action-1',
    idempotencyKey: 'idem-1',
    approvalToken: 'coap1.approval',
    grant: 'coap3.grant',
    grantDigest: 'digest',
  });
  assert.deepEqual(result, { receipt: 'ok' });
  assert.equal(observed.url, 'http://127.0.0.1:8765/gateway/tool-call');
  assert.equal(observed.options.headers.authorization, 'Bearer gateway-token');
  assert.equal(observed.body.action_id, 'action-1');
  assert.equal(observed.body.approval_token, 'coap1.approval');
  assert.equal(observed.body.semantic_metadata.nemo_grant, 'coap3.grant');
});

test('transport failure is surfaced as reconciliation required', async () => {
  const client = createCorrectOnceGatewayClient({
    baseUrl: 'http://127.0.0.1:8765',
    token: 'gateway-token',
    fetchImpl: async () => {
      throw new Error('connection reset');
    },
  });
  await assert.rejects(
    () =>
      client.execute({
        subject: 'alice',
        server: 'filesystem',
        tool: 'delete',
        args: {},
        actionId: 'a',
        idempotencyKey: 'i',
        grant: 'coap3.g',
        grantDigest: 'd',
      }),
    (error) => error.code === 'RECONCILIATION_REQUIRED' && error.details.outcome === 'unknown',
  );
});

test('gateway 5xx responses are treated as ambiguous effects', async () => {
  const client = createCorrectOnceGatewayClient({
    baseUrl: 'http://127.0.0.1:8765',
    token: 'gateway-token',
    fetchImpl: async () => new Response(JSON.stringify({ error: 'upstream failed' }), { status: 503 }),
  });
  await assert.rejects(
    () =>
      client.execute({
        subject: 'alice',
        server: 'filesystem',
        tool: 'delete',
        args: {},
        actionId: 'a',
        idempotencyKey: 'i',
        grant: 'coap3.g',
        grantDigest: 'd',
      }),
    (error) => error.code === 'RECONCILIATION_REQUIRED' && error.details.status === 503,
  );
});

test('successful gateway responses must contain a JSON receipt object', async () => {
  const client = createCorrectOnceGatewayClient({
    baseUrl: 'http://127.0.0.1:8765',
    token: 'gateway-token',
    fetchImpl: async () => new Response('not-json', { status: 200 }),
  });
  await assert.rejects(
    () =>
      client.execute({
        subject: 'alice',
        server: 'filesystem',
        tool: 'delete',
        args: {},
        actionId: 'a',
        idempotencyKey: 'i',
        grant: 'coap3.g',
        grantDigest: 'd',
      }),
    /invalid receipt/,
  );
});
