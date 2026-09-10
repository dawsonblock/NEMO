// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// Apache-2.0

import { randomUUID } from 'node:crypto';
import { issueGrant } from './grants.mjs';
import { CapabilityError } from './errors.mjs';
import { sha256Domain } from './canonical.mjs';

const MARKER = '__nemo_relay_correct_once_v1';

export function createNemoCorrectOnceRuntime({
  nemo,
  registry,
  functionHooks,
  effectFabric,
  signingSecret,
  subject = 'local',
  policyVersion = 'nemo-local-v1',
}) {
  if (!nemo || !registry || !functionHooks || !effectFabric)
    throw new TypeError('nemo, registry, functionHooks, and effectFabric are required');
  if (typeof policyVersion !== 'string' || policyVersion.length === 0)
    throw new TypeError('policyVersion must be a non-empty string');

  async function execute(capabilityId, args, options = {}) {
    if (Object.prototype.hasOwnProperty.call(options, 'subject') && options.subject !== subject) {
      throw new CapabilityError('IDENTITY_OVERRIDE', 'runtime identity is immutable for this execution context');
    }
    if (
      Object.prototype.hasOwnProperty.call(options, 'server') ||
      Object.prototype.hasOwnProperty.call(options, 'tool')
    ) {
      throw new CapabilityError('ROUTE_OVERRIDE', 'execution routes are fixed by the registered capability');
    }
    if (Object.prototype.hasOwnProperty.call(options, 'policyVersion') && options.policyVersion !== policyVersion) {
      throw new CapabilityError('POLICY_OVERRIDE', 'policy version is fixed by the trusted runtime context');
    }
    const capability = registry.get(capabilityId);
    registry.validateArguments(capabilityId, args);
    const admission = registry.admit(capabilityId, policyVersion);
    const finalIdempotencyKey = options.idempotencyKey ?? randomUUID();
    const finalActionId =
      options.actionId ??
      sha256Domain('nemo/action/v1', { subject, capabilityId, idempotencyKey: finalIdempotencyKey });
    const context = {
      ...options,
      subject,
      actionId: finalActionId,
      idempotencyKey: finalIdempotencyKey,
      policyVersion,
      admissionId: admission.admissionId,
      grant:
        options.grant ??
        issueGrant(
          {
            subject,
            capabilityId,
            executionClass: capability.executionClass,
            admissionId: admission.admissionId,
            registrationDigest: capability.registrationDigest,
            policyVersion,
            operation: capability.operation,
            routeDigest: capability.routeDigest,
            actionId: finalActionId,
            idempotencyKey: finalIdempotencyKey,
          },
          args,
          { signingSecret, now: options.now },
        ).token,
      approvalToken: options.approvalToken,
    };
    if (capability.executionClass === 'pure' || capability.executionClass === 'read')
      return functionHooks.execute(capabilityId, args, context);
    return effectFabric.execute(capabilityId, args, context);
  }

  function installTool({
    toolName,
    capabilityId,
    priority = 10000,
    actionId,
    idempotencyKey,
    approvalToken,
    policyVersion: requestedPolicyVersion,
  }) {
    if (typeof toolName !== 'string' || typeof capabilityId !== 'string')
      throw new TypeError('toolName and capabilityId are required');
    if (requestedPolicyVersion !== undefined && requestedPolicyVersion !== policyVersion)
      throw new CapabilityError('POLICY_OVERRIDE', 'policy version is fixed by the trusted runtime context');
    const capability = registry.get(capabilityId);
    const requestName = `correct_once_request_${capabilityId}`;
    const executionName = `correct_once_execution_${capabilityId}`;
    nemo.registerToolRequestIntercept(requestName, priority, false, (name, args) => {
      if (name !== toolName) return args;
      if (Object.prototype.hasOwnProperty.call(args, MARKER))
        throw new CapabilityError('MARKER_COLLISION', 'reserved capability marker is present in tool arguments');
      registry.validateArguments(capabilityId, args);
      const admission = registry.admit(capabilityId, policyVersion);
      const finalActionId = actionId ?? randomUUID();
      const finalIdempotencyKey = idempotencyKey ?? randomUUID();
      const grant = issueGrant(
        {
          subject,
          capabilityId,
          executionClass: capability.executionClass,
          admissionId: admission.admissionId,
          registrationDigest: capability.registrationDigest,
          policyVersion,
          operation: capability.operation,
          routeDigest: capability.routeDigest,
          actionId: finalActionId,
          idempotencyKey: finalIdempotencyKey,
        },
        args,
        { signingSecret },
      );
      return {
        ...args,
        [MARKER]: {
          capabilityId,
          grant: grant.token,
          approvalToken,
          admissionId: admission.admissionId,
          actionId: finalActionId,
          idempotencyKey: finalIdempotencyKey,
          policyVersion,
        },
      };
    });
    nemo.registerToolExecutionIntercept(executionName, priority, async (args, next) => {
      const marker = args?.[MARKER];
      if (!marker || marker.capabilityId !== capabilityId) return next(args);
      const cleanArgs = { ...args };
      delete cleanArgs[MARKER];
      const context = { ...marker, subject, grant: marker.grant };
      if (capability.executionClass === 'pure' || capability.executionClass === 'read') {
        const routed = await functionHooks.execute(capabilityId, cleanArgs, {
          ...context,
          handler: (value) => next(value),
        });
        return routed.result;
      }
      const routed = await effectFabric.execute(capabilityId, cleanArgs, {
        ...context,
        handler: (value) => next(value),
      });
      return { result: routed };
    });
    return () => {
      nemo.deregisterToolRequestIntercept(requestName);
      nemo.deregisterToolExecutionIntercept(executionName);
    };
  }

  return Object.freeze({ execute, installTool, marker: MARKER });
}
