// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// Apache-2.0

import { randomUUID } from 'node:crypto';
import { verifyGrant } from './grants.mjs';
import { CapabilityError } from './errors.mjs';
import { digestArguments, sha256Domain } from './canonical.mjs';

export class EffectFabricBridge {
  constructor({ registry, signingSecret, handlers = new Map(), criticalGateway = null, journal = null }) {
    this.registry = registry;
    this.signingSecret = signingSecret;
    this.handlers = handlers;
    this.criticalGateway = criticalGateway;
    this.journal = journal;
    this.receipts = new Map();
    this.inFlight = new Map();
  }

  async execute(capabilityId, args, context) {
    const capability = this.registry.get(capabilityId);
    if (capability.executionClass !== 'mutation' && capability.executionClass !== 'critical')
      throw new CapabilityError('WRONG_ROUTE', 'only MUTATION capabilities use Effect Fabric');
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
    const transactionId = context.transactionId ?? randomUUID();
    const request = Object.freeze({
      transactionId,
      idempotencyKey: context.idempotencyKey,
      subject: context.subject,
      capabilityId: capability.id,
      operation: capability.operation,
      executionClass: capability.executionClass,
      actionId: context.actionId,
      server: capability.server,
      tool: capability.tool,
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
    const fingerprint = sha256Domain('nemo/idempotency/v1', {
      subject: request.subject,
      capabilityId: request.capabilityId,
      operation: request.operation,
      executionClass: request.executionClass,
      actionId: request.actionId,
      argumentDigest: digestArguments(args),
    });
    const existing = this.receipts.get(context.idempotencyKey);
    if (existing) {
      if (existing.fingerprint !== fingerprint)
        throw new CapabilityError('IDEMPOTENCY_CONFLICT', 'idempotency key is bound to a different request');
      return { ...existing.receipt, replayed: true };
    }
    const pending = this.inFlight.get(context.idempotencyKey);
    if (pending) {
      if (pending.fingerprint !== fingerprint)
        throw new CapabilityError('IDEMPOTENCY_CONFLICT', 'idempotency key is bound to a different request');
      return { ...(await pending.promise), replayed: true };
    }
    const promise = (async () => {
      await this.journal?.append?.({ state: 'PREPARED', request });
      let result;
      try {
        if (capability.executionClass === 'critical') {
          if (!this.criticalGateway)
            throw new CapabilityError('GATEWAY_REQUIRED', 'critical mutations require Correct-Once Gateway');
          result = await this.criticalGateway.execute(request);
        } else {
          const handler = context.handler ?? this.handlers.get(capability.id);
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
      this.receipts.set(context.idempotencyKey, { fingerprint, receipt });
      await this.journal?.append?.({ state: 'SUCCEEDED', request, receipt });
      return receipt;
    })();
    this.inFlight.set(context.idempotencyKey, { fingerprint, promise });
    try {
      return await promise;
    } finally {
      if (this.inFlight.get(context.idempotencyKey)?.promise === promise) this.inFlight.delete(context.idempotencyKey);
    }
  }
}
