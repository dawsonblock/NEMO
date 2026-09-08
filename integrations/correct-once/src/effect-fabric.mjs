// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// Apache-2.0

import { randomUUID } from 'node:crypto';
import { verifyGrant } from './grants.mjs';
import { CapabilityError, classifyEffectError } from './errors.mjs';
import { digestArguments, sha256Domain } from './canonical.mjs';

const JOURNAL_TRANSITIONS = Object.freeze({
  PREPARED: new Set(['DISPATCHING']),
  DISPATCHING: new Set(['COMMITTED', 'FAILED', 'UNKNOWN']),
  UNKNOWN: new Set(['RECONCILING']),
  RECONCILING: new Set(['COMMITTED', 'FAILED']),
});

export class EffectFabricBridge {
  constructor({ registry, signingSecret, handlers = new Map(), criticalGateway = null, journal = null }) {
    this.registry = registry;
    this.signingSecret = signingSecret;
    this.handlers = handlers;
    this.criticalGateway = criticalGateway;
    this.journal = journal;
    this.receipts = new Map();
    this.uncertain = new Map();
    this.inFlight = new Map();
    this.journalState = new Map();
  }

  async appendJournal(actionId, state, entry) {
    const previous = this.journalState.get(actionId);
    if (previous && !JOURNAL_TRANSITIONS[previous]?.has(state)) {
      throw new CapabilityError('INVALID_EFFECT_TRANSITION', `illegal effect transition ${previous} -> ${state}`, {
        previous,
        state,
      });
    }
    await this.journal?.append?.({ ...entry, state });
    this.journalState.set(actionId, state);
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
    const uncertain = this.uncertain.get(context.idempotencyKey);
    if (uncertain) {
      if (uncertain.fingerprint !== fingerprint)
        throw new CapabilityError('IDEMPOTENCY_CONFLICT', 'idempotency key is bound to a different request');
      throw uncertain.error;
    }
    const pending = this.inFlight.get(context.idempotencyKey);
    if (pending) {
      if (pending.fingerprint !== fingerprint)
        throw new CapabilityError('IDEMPOTENCY_CONFLICT', 'idempotency key is bound to a different request');
      return { ...(await pending.promise), replayed: true };
    }
    const promise = (async () => {
      await this.appendJournal(request.actionId, 'PREPARED', { request });
      await this.appendJournal(request.actionId, 'DISPATCHING', { request });
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
        const classification = classifyEffectError(error);
        await this.appendJournal(request.actionId, classification.state, {
          request,
          error: String(error),
          outcome: classification.outcome,
          dispatchState: classification.dispatchState,
          outcomeCertainty: classification.outcomeCertainty,
        });
        if (classification.state === 'UNKNOWN') this.uncertain.set(context.idempotencyKey, { fingerprint, error });
        throw error;
      }
      const receipt = Object.freeze({
        route: 'effect-fabric',
        state: 'COMMITTED',
        transactionId,
        idempotencyKey: context.idempotencyKey,
        result,
        grantDigest: grant.grantDigest,
      });
      try {
        await this.appendJournal(request.actionId, 'COMMITTED', { request, receipt });
      } catch (error) {
        const uncertain = new CapabilityError(
          'RECONCILIATION_REQUIRED',
          'effect succeeded but its committed journal entry could not be persisted',
          {
            outcome: 'unknown',
            retryable: false,
            dispatchState: 'DISPATCH_CONFIRMED',
            outcomeCertainty: 'UNKNOWN',
            cause: String(error),
          },
        );
        this.uncertain.set(context.idempotencyKey, { fingerprint, error: uncertain });
        throw uncertain;
      }
      this.receipts.set(context.idempotencyKey, { fingerprint, receipt });
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
