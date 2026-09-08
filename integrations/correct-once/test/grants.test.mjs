// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import { digestArguments } from '../src/canonical.mjs';
import { issueGrant, verifyGrant } from '../src/grants.mjs';
import { CapabilityRegistry } from '../src/registry.mjs';

const secret = '01234567890123456789012345678901';

function setup() {
  const registry = new CapabilityRegistry();
  const capability = registry.register({ id: 'test.read', capabilityClass: 'read', operation: 'read.test' });
  const admission = registry.admit(capability.id, 'policy-v1');
  const input = {
    subject: 'alice',
    capabilityId: capability.id,
    executionClass: capability.executionClass,
    admissionId: admission.admissionId,
    registrationDigest: capability.registrationDigest,
    policyVersion: 'policy-v1',
    operation: capability.operation,
    routeDigest: capability.routeDigest,
    actionId: 'action-1',
    idempotencyKey: 'idem-1',
    issuedAt: 100,
    expiresAt: 200,
    nonce: 'nonce-1',
  };
  const args = { z: 1, a: ['x', true] };
  return { registry, capability, admission, input, args };
}

test('canonical argument digest is independent of object key order', () => {
  assert.equal(digestArguments({ a: 1, b: 2 }), digestArguments({ b: 2, a: 1 }));
  assert.notEqual(digestArguments({ a: 1 }), digestArguments({ a: 2 }));
});

test('grant verifies the exact capability and arguments', () => {
  const { capability, admission, input, args } = setup();
  const issued = issueGrant(input, args, { signingSecret: secret, now: 100 });
  const verified = verifyGrant(issued.token, args, { ...input }, { signingSecret: secret, now: 101 });
  assert.equal(verified.grantDigest, issued.grantDigest);
  assert.throws(
    () => verifyGrant(issued.token, { ...args, z: 2 }, { ...input }, { signingSecret: secret, now: 101 }),
    /arguments do not match/,
  );
  assert.equal(admission.registrationDigest, capability.registrationDigest);
});

test('grant binds the registered execution route', () => {
  const { input, args } = setup();
  const issued = issueGrant(input, args, { signingSecret: secret, now: 100 });
  assert.throws(
    () =>
      verifyGrant(
        issued.token,
        args,
        { ...input, routeDigest: `${input.routeDigest}x` },
        { signingSecret: secret, now: 101 },
      ),
    /grant route does not match/,
  );
});

test('invalid signatures and expired grants fail closed', () => {
  const { input, args } = setup();
  const issued = issueGrant(input, args, { signingSecret: secret, now: 100 });
  assert.throws(() => verifyGrant(issued.token, args, input, { signingSecret: `${secret}x`, now: 101 }), /signature/);
  assert.throws(() => verifyGrant(issued.token, args, input, { signingSecret: secret, now: 200 }), /expired/);
});
