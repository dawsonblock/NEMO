// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import { FunctionHooksBridge } from '../src/function-hooks.mjs';
import { EffectFabricBridge } from '../src/effect-fabric.mjs';
import { createCorrectOnceGatewayClient } from '../src/gateway.mjs';
import { createNemoCorrectOnceRuntime } from '../src/nemo.mjs';
import { CapabilityRegistry } from '../src/registry.mjs';

const secret = '01234567890123456789012345678901';

test('PURE and READ route through Function Hooks and MUTATION through Effect Fabric', async () => {
  const registry = new CapabilityRegistry();
  const pure = registry.register({ id: 'pure.test', capabilityClass: 'pure', operation: 'pure.test' });
  const mutation = registry.register({ id: 'mutation.test', capabilityClass: 'mutation', operation: 'mutation.test' });
  const functionHooks = new FunctionHooksBridge({
    registry,
    signingSecret: secret,
    handlers: new Map([[pure.id, async (args) => ({ echoed: args })]]),
  });
  const effectFabric = new EffectFabricBridge({
    registry,
    signingSecret: secret,
    handlers: new Map([[mutation.id, async () => ({ committed: true })]]),
  });
  const runtime = createNemoCorrectOnceRuntime({
    nemo: {},
    registry,
    functionHooks,
    effectFabric,
    signingSecret: secret,
    subject: 'alice',
  });
  const pureResult = await runtime.execute(pure.id, { value: 1 });
  const mutationResult = await runtime.execute(mutation.id, { value: 2 }, { idempotencyKey: 'mutation-1' });
  assert.equal(pureResult.route, 'function-hooks');
  assert.equal(mutationResult.route, 'effect-fabric');
  assert.deepEqual(mutationResult.result, { committed: true });
  const replay = await runtime.execute(mutation.id, { value: 2 }, { idempotencyKey: 'mutation-1' });
  assert.equal(replay.replayed, true);
});

test('registry revocation invalidates the admission before execution', async () => {
  const registry = new CapabilityRegistry();
  const capability = registry.register({ id: 'read.revoked', capabilityClass: 'read', operation: 'read.revoked' });
  const admission = registry.admit(capability.id);
  registry.revoke(capability.id);
  assert.throws(
    () =>
      registry.verifyAdmission(
        admission.admissionId,
        capability.id,
        capability.registrationDigest,
        admission.policyVersion,
      ),
    /unavailable/,
  );
});

test('critical mutation binds the grant and native approval to the Correct-Once Gateway request', async () => {
  let observed;
  const gateway = createCorrectOnceGatewayClient({
    baseUrl: 'http://127.0.0.1:8765',
    token: 'gateway-token',
    fetchImpl: async (url, options) => {
      observed = { url: String(url), body: JSON.parse(options.body) };
      return new Response(JSON.stringify({ effect: 'committed' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });
  const registry = new CapabilityRegistry();
  const critical = registry.register({
    id: 'mutation.critical',
    capabilityClass: 'mutation',
    executionClass: 'critical',
    operation: 'mutation.critical',
    server: 'local-filesystem',
    tool: 'delete',
  });
  const functionHooks = new FunctionHooksBridge({ registry, signingSecret: secret });
  const effectFabric = new EffectFabricBridge({ registry, signingSecret: secret, criticalGateway: gateway });
  const runtime = createNemoCorrectOnceRuntime({
    nemo: {},
    registry,
    functionHooks,
    effectFabric,
    signingSecret: secret,
    subject: 'alice',
  });
  const result = await runtime.execute(
    critical.id,
    { relativePath: 'nested/value.txt', expectedDigest: 'digest', reason: 'approved test' },
    { approvalToken: 'coap1.approval', actionId: 'action-1', idempotencyKey: 'idem-1' },
  );
  assert.deepEqual(result.result, { effect: 'committed' });
  assert.equal(observed.url, 'http://127.0.0.1:8765/gateway/tool-call');
  assert.equal(observed.body.server, 'local-filesystem');
  assert.equal(observed.body.tool, 'delete');
  assert.equal(observed.body.approval_token, 'coap1.approval');
  assert.match(observed.body.semantic_metadata.nemo_grant, /^coap2\./);
  assert.match(observed.body.semantic_metadata.nemo_grant_digest, /^[0-9a-f]{64}$/);
});

test('NEMO tool installation routes marked calls and rejects marker collisions', async () => {
  const requestInterceptors = new Map();
  const executionInterceptors = new Map();
  const nemo = {
    registerToolRequestIntercept: (name, _priority, _breakChain, callback) => requestInterceptors.set(name, callback),
    deregisterToolRequestIntercept: (name) => requestInterceptors.delete(name),
    registerToolExecutionIntercept: (name, _priority, callback) => executionInterceptors.set(name, callback),
    deregisterToolExecutionIntercept: (name) => executionInterceptors.delete(name),
  };
  const registry = new CapabilityRegistry();
  const capability = registry.register({ id: 'pure.installed', capabilityClass: 'pure', operation: 'pure.installed' });
  const functionHooks = new FunctionHooksBridge({ registry, signingSecret: secret, handlers: new Map() });
  const effectFabric = new EffectFabricBridge({ registry, signingSecret: secret });
  const runtime = createNemoCorrectOnceRuntime({ nemo, registry, functionHooks, effectFabric, signingSecret: secret });
  runtime.installTool({ toolName: 'digest', capabilityId: capability.id });
  const request = [...requestInterceptors.values()][0];
  const execution = [...executionInterceptors.values()][0];
  const marked = request('digest', { value: 1 });
  const result = await execution(marked, async (args) => ({ result: { echoed: args } }));
  assert.deepEqual(result, { result: { echoed: { value: 1 } } });
  assert.throws(() => request('digest', { [runtime.marker]: true }), /reserved capability marker/);
});
