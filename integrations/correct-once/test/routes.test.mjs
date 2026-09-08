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

test('schemas are enforced before grants or handlers run', async () => {
  const registry = new CapabilityRegistry();
  const capability = registry.register({
    id: 'read.schema',
    capabilityClass: 'read',
    operation: 'read.schema',
    schema: { type: 'object', required: ['mustExist'] },
  });
  const functionHooks = new FunctionHooksBridge({
    registry,
    signingSecret: secret,
    handlers: new Map([[capability.id, async () => ({ shouldNotRun: true })]]),
  });
  const effectFabric = new EffectFabricBridge({ registry, signingSecret: secret });
  const runtime = createNemoCorrectOnceRuntime({
    nemo: {},
    registry,
    functionHooks,
    effectFabric,
    signingSecret: secret,
  });
  await assert.rejects(() => runtime.execute(capability.id, {}), /missing required property mustExist/);
});

test('inconsistent capability and execution classes are rejected at registration', () => {
  const registry = new CapabilityRegistry();
  assert.throws(
    () =>
      registry.register({ id: 'pure.critical', capabilityClass: 'pure', executionClass: 'critical', operation: 'x' }),
    /classes are inconsistent/,
  );
});

test('idempotency keys reject conflicting capability or argument reuse', async () => {
  const registry = new CapabilityRegistry();
  const first = registry.register({ id: 'mutation.first', capabilityClass: 'mutation', operation: 'mutation.first' });
  const second = registry.register({
    id: 'mutation.second',
    capabilityClass: 'mutation',
    operation: 'mutation.second',
  });
  let calls = 0;
  const functionHooks = new FunctionHooksBridge({ registry, signingSecret: secret });
  const effectFabric = new EffectFabricBridge({
    registry,
    signingSecret: secret,
    handlers: new Map([
      [
        first.id,
        async () => {
          calls += 1;
          return { from: 'first' };
        },
      ],
      [
        second.id,
        async () => {
          calls += 1;
          return { from: 'second' };
        },
      ],
    ]),
  });
  const runtime = createNemoCorrectOnceRuntime({
    nemo: {},
    registry,
    functionHooks,
    effectFabric,
    signingSecret: secret,
  });
  const result = await runtime.execute(first.id, { value: 1 }, { idempotencyKey: 'shared' });
  const replay = await runtime.execute(first.id, { value: 1 }, { idempotencyKey: 'shared' });
  assert.equal(replay.replayed, true);
  await assert.rejects(
    () => runtime.execute(second.id, { value: 1 }, { idempotencyKey: 'shared' }),
    /idempotency key is bound to a different request/,
  );
  await assert.rejects(
    () => runtime.execute(first.id, { value: 2 }, { idempotencyKey: 'shared' }),
    /idempotency key is bound to a different request/,
  );
  assert.equal(calls, 1);
  assert.equal(result.result.from, 'first');
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
    approvalRequired: true,
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

test('approval-required mutations fail before contacting the gateway without approval', async () => {
  let calls = 0;
  const registry = new CapabilityRegistry();
  const critical = registry.register({
    id: 'mutation.approval-required',
    capabilityClass: 'mutation',
    executionClass: 'critical',
    operation: 'mutation.approval-required',
    approvalRequired: true,
    server: 'local-filesystem',
    tool: 'delete',
  });
  const functionHooks = new FunctionHooksBridge({ registry, signingSecret: secret });
  const effectFabric = new EffectFabricBridge({
    registry,
    signingSecret: secret,
    criticalGateway: {
      execute: async () => {
        calls += 1;
      },
    },
  });
  const runtime = createNemoCorrectOnceRuntime({
    nemo: {},
    registry,
    functionHooks,
    effectFabric,
    signingSecret: secret,
  });
  await assert.rejects(() => runtime.execute(critical.id, { path: 'x' }), /approval token/);
  assert.equal(calls, 0);
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

test('installed mutation tools wrap the real NEMO callback through Effect Fabric', async () => {
  const requestInterceptors = new Map();
  const executionInterceptors = new Map();
  const nemo = {
    registerToolRequestIntercept: (name, _priority, _breakChain, callback) => requestInterceptors.set(name, callback),
    deregisterToolRequestIntercept: (name) => requestInterceptors.delete(name),
    registerToolExecutionIntercept: (name, _priority, callback) => executionInterceptors.set(name, callback),
    deregisterToolExecutionIntercept: (name) => executionInterceptors.delete(name),
  };
  const registry = new CapabilityRegistry();
  const capability = registry.register({
    id: 'mutation.installed',
    capabilityClass: 'mutation',
    operation: 'mutation.installed',
  });
  const functionHooks = new FunctionHooksBridge({ registry, signingSecret: secret });
  const effectFabric = new EffectFabricBridge({ registry, signingSecret: secret });
  const runtime = createNemoCorrectOnceRuntime({ nemo, registry, functionHooks, effectFabric, signingSecret: secret });
  runtime.installTool({ toolName: 'write', capabilityId: capability.id });
  const request = [...requestInterceptors.values()][0];
  const execution = [...executionInterceptors.values()][0];
  const marked = request('write', { value: 1 });
  let nextCalls = 0;
  const result = await execution(marked, async (args) => {
    nextCalls += 1;
    return { result: { accepted: args } };
  });
  assert.equal(result.result.route, 'effect-fabric');
  assert.deepEqual(result.result.result, { result: { accepted: { value: 1 } } });
  assert.equal(nextCalls, 1);
});
