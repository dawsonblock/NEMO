// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

export class CapabilityError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'CapabilityError';
    this.code = code;
    this.details = details;
  }
}

export class EffectExecutionError extends CapabilityError {
  constructor(
    code,
    message,
    {
      dispatchState = DISPATCH_STATES.NOT_DISPATCHED,
      outcomeCertainty = OUTCOME_CERTAINTIES.CONFIRMED_FAILURE,
      providerRequestId = null,
      retryable = false,
      reconciliationRequired = outcomeCertainty === OUTCOME_CERTAINTIES.UNKNOWN,
      ...details
    } = {},
  ) {
    super(code, message, {
      ...details,
      dispatchState,
      outcomeCertainty,
      providerRequestId,
      retryable,
      reconciliationRequired,
    });
    this.dispatchState = dispatchState;
    this.outcomeCertainty = outcomeCertainty;
    this.providerRequestId = providerRequestId;
    this.retryable = retryable;
    this.reconciliationRequired = reconciliationRequired;
  }
}

export function normalizeEffectExecutionError(error, defaults = {}) {
  if (error instanceof EffectExecutionError || error instanceof CapabilityError) return error;
  return new EffectExecutionError('EFFECT_EXECUTION_FAILED', String(error), {
    ...defaults,
    dispatchState: defaults.dispatchState ?? DISPATCH_STATES.DISPATCH_ATTEMPTED,
    outcomeCertainty: defaults.outcomeCertainty ?? OUTCOME_CERTAINTIES.UNKNOWN,
    retryable: defaults.retryable ?? false,
    reconciliationRequired: defaults.reconciliationRequired ?? true,
    cause: String(error),
  });
}

export const DISPATCH_STATES = Object.freeze({
  NOT_DISPATCHED: 'NOT_DISPATCHED',
  DISPATCH_ATTEMPTED: 'DISPATCH_ATTEMPTED',
  DISPATCH_CONFIRMED: 'DISPATCH_CONFIRMED',
});

export const OUTCOME_CERTAINTIES = Object.freeze({
  CONFIRMED_FAILURE: 'CONFIRMED_FAILURE',
  CONFIRMED_SUCCESS: 'CONFIRMED_SUCCESS',
  UNKNOWN: 'UNKNOWN',
});

export const EFFECT_STATES = Object.freeze({
  PROPOSED: 'PROPOSED',
  AUTHORIZED: 'AUTHORIZED',
  PREPARED: 'PREPARED',
  DISPATCHING: 'DISPATCHING',
  COMMITTED: 'COMMITTED',
  FAILED: 'FAILED',
  UNKNOWN: 'UNKNOWN',
  RECONCILING: 'RECONCILING',
  CANCELLED: 'CANCELLED',
});

export function classifyEffectError(error) {
  const dispatchState = error?.details?.dispatchState ?? DISPATCH_STATES.NOT_DISPATCHED;
  const outcomeCertainty =
    error?.details?.outcomeCertainty ??
    (error?.code === 'RECONCILIATION_REQUIRED' ? OUTCOME_CERTAINTIES.UNKNOWN : OUTCOME_CERTAINTIES.CONFIRMED_FAILURE);
  if (dispatchState !== DISPATCH_STATES.NOT_DISPATCHED && outcomeCertainty === OUTCOME_CERTAINTIES.UNKNOWN) {
    return Object.freeze({
      state: 'UNKNOWN',
      outcome: 'unknown',
      dispatchState,
      outcomeCertainty,
    });
  }
  return Object.freeze({
    state: 'FAILED',
    outcome: 'failed',
    dispatchState,
    outcomeCertainty,
  });
}

export function fail(code, message, details) {
  throw new CapabilityError(code, message, details);
}
