// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// Apache-2.0

import { randomUUID } from 'node:crypto';
import { verifyGrant } from './grants.mjs';
import { CapabilityError } from './errors.mjs';

export class EffectFabricBridge {
  constructor({ registry, signingSecret, handlers = new Map(), criticalGateway = null, journal = null }) {
    this.registry = registry;
    this.signingSecret = signingSecret;
    this.handlers = handlers;
    this.criticalGateway = criticalGateway;
    this.journal = journal;
    this.receipts = new Map();
  }

  async execute(capabilityId, args, context) {
    const capability = this.registry.get(capabilityId);
    if (capability.capabilityClass !== 'mutation')
      throw new CapabilityError('WRONG_ROUTE', 'only MUTATION capabilities use Effect Fabric');
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
        actionId: context.actionId,
        idempotencyKey: context.idempotencyKey,
      },
      { signingSecret: this.signingSecret, now: context.now },
    );
    if (this.receipts.has(context.idempotencyKey)) {
      return { ...this.receipts.get(context.idempotencyKey), replayed: true };
    }
    const transactionId = context.transactionId ?? randomUUID();
    const request = Object.freeze({
      transactionId,
      idempotencyKey: context.idempotencyKey,
      subject: context.subject,
      capabilityId: capability.id,
      operation: capability.operation,
      server: context.server ?? capability.server,
      tool: context.tool ?? capability.tool,
      args,
      grant: context.grant,
      approvalToken: context.approvalToken,
      grantDigest: grant.grantDigest,
    });
    if (capability.executionClass === 'critical' && (!request.server || !request.tool)) {
      throw new CapabilityError(
        'GATEWAY_ROUTE_MISSING',
        'critical capabilities require Correct-Once server and tool bindings',
      );
    }
    if (capability.approvalRequired && typeof request.approvalToken !== 'string') {
      throw new CapabilityError('APPROVAL_REQUIRED', 'this capability requires a Correct-Once approval token');
    }
    await this.journal?.append?.({ state: 'PREPARED', request });
    let result;
    try {
      if (capability.executionClass === 'critical') {
        if (!this.criticalGateway)
          throw new CapabilityError('GATEWAY_REQUIRED', 'critical mutations require Correct-Once Gateway');
        result = await this.criticalGateway.execute(request);
      } else {
        const handler = this.handlers.get(capability.id);
        if (typeof handler !== 'function')
          throw new CapabilityError('HANDLER_MISSING', `no Effect Fabric handler for ${capability.id}`);
        result = await handler(args, { capability, grant, request });
      }
    } catch (error) {
      await this.journal?.append?.({ state: 'FAILED', request, error: String(error) });
      throw error;
    }
    const receipt = Object.freeze({
      route: 'effect-fabric',
      state: 'SUCCEEDED',
      transactionId,
      idempotencyKey: context.idempotencyKey,
      result,
      grantDigest: grant.grantDigest,
    });
    this.receipts.set(context.idempotencyKey, receipt);
    await this.journal?.append?.({ state: 'SUCCEEDED', request, receipt });
    return receipt;
  }
}
