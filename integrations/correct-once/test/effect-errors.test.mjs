// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// Apache-2.0

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyEffectError,
  DISPATCH_STATES,
  OUTCOME_CERTAINTIES,
  EffectExecutionError,
  normalizeEffectExecutionError,
} from '../src/errors.mjs';

test('effect classification preserves unknown after any attempted dispatch', () => {
  const cases = [
    [DISPATCH_STATES.NOT_DISPATCHED, OUTCOME_CERTAINTIES.CONFIRMED_FAILURE, 'FAILED'],
    [DISPATCH_STATES.NOT_DISPATCHED, OUTCOME_CERTAINTIES.CONFIRMED_SUCCESS, 'FAILED'],
    [DISPATCH_STATES.NOT_DISPATCHED, OUTCOME_CERTAINTIES.UNKNOWN, 'FAILED'],
    [DISPATCH_STATES.DISPATCH_ATTEMPTED, OUTCOME_CERTAINTIES.CONFIRMED_FAILURE, 'FAILED'],
    [DISPATCH_STATES.DISPATCH_ATTEMPTED, OUTCOME_CERTAINTIES.CONFIRMED_SUCCESS, 'FAILED'],
    [DISPATCH_STATES.DISPATCH_ATTEMPTED, OUTCOME_CERTAINTIES.UNKNOWN, 'UNKNOWN'],
    [DISPATCH_STATES.DISPATCH_CONFIRMED, OUTCOME_CERTAINTIES.CONFIRMED_FAILURE, 'FAILED'],
    [DISPATCH_STATES.DISPATCH_CONFIRMED, OUTCOME_CERTAINTIES.CONFIRMED_SUCCESS, 'FAILED'],
    [DISPATCH_STATES.DISPATCH_CONFIRMED, OUTCOME_CERTAINTIES.UNKNOWN, 'UNKNOWN'],
  ];

  for (const [dispatchState, outcomeCertainty, expectedState] of cases) {
    const result = classifyEffectError(new EffectExecutionError('TEST', 'test', { dispatchState, outcomeCertainty }));
    assert.equal(result.state, expectedState, `${dispatchState} + ${outcomeCertainty}`);
  }
});

test('untyped backend errors normalize to a conservative unknown effect outcome', () => {
  const error = normalizeEffectExecutionError(new Error('provider parser failed'));
  assert.equal(error.code, 'EFFECT_EXECUTION_FAILED');
  assert.equal(error.details.dispatchState, DISPATCH_STATES.DISPATCH_ATTEMPTED);
  assert.equal(error.details.outcomeCertainty, OUTCOME_CERTAINTIES.UNKNOWN);
  assert.equal(error.details.reconciliationRequired, true);
});
