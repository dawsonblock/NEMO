// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { verifyGrant } from './grants.mjs';
import { CapabilityError } from './errors.mjs';

export class FunctionHooksBridge {
  constructor({ registry, signingSecret, handlers = new Map() }) {
    this.registry = registry;
    this.signingSecret = signingSecret;
    this.handlers = handlers;
  }

  async execute(capabilityId, args, context) {
    const capability = this.registry.get(capabilityId);
    if (capability.executionClass !== 'pure' && capability.executionClass !== 'read') {
      throw new CapabilityError('WRONG_ROUTE', 'PURE and READ capabilities must use Function Hooks');
    }
    this.registry.validateArguments(capabilityId, args);
    const admission = this.registry.verifyAdmission(
      context.admissionId,
      capability.id,
      capability.registrationDigest,
      context.policyVersion,
    );
    const grant = verifyGrant(
      context.grant,
      args,
      {
        subject: context.subject,
        capabilityId: capability.id,
        executionClass: capability.executionClass,
        admissionId: admission.admissionId,
        registrationDigest: capability.registrationDigest,
        policyVersion: context.policyVersion,
        operation: capability.operation,
        routeDigest: capability.routeDigest,
        actionId: context.actionId,
        idempotencyKey: context.idempotencyKey,
      },
      { signingSecret: this.signingSecret, now: context.now },
    );
    const handler = context.handler ?? this.handlers.get(capability.id);
    if (typeof handler !== 'function')
      throw new CapabilityError('HANDLER_MISSING', `no Function Hooks handler for ${capability.id}`);
    const result = await handler(args, { capability, grant, subject: context.subject });
    return { result, route: 'function-hooks', grantDigest: grant.grantDigest };
  }
}
