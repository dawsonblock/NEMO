// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// Apache-2.0

import { CapabilityError } from './errors.mjs';

function ambiguousReceipt(message, details = {}) {
  return new CapabilityError('RECONCILIATION_REQUIRED', message, {
    outcome: 'unknown',
    retryable: false,
    dispatchState: 'DISPATCH_ATTEMPTED',
    outcomeCertainty: 'UNKNOWN',
    ...details,
  });
}

export function createCorrectOnceGatewayClient({ baseUrl, token, fetchImpl = globalThis.fetch }) {
  if (!baseUrl || !token || typeof fetchImpl !== 'function')
    throw new TypeError('baseUrl, token, and fetchImpl are required');
  return Object.freeze({
    async execute(request) {
      let response;
      try {
        response = await fetchImpl(new URL('/gateway/tool-call', baseUrl), {
          method: 'POST',
          headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
          body: JSON.stringify({
            subject: request.subject,
            server: request.server,
            tool: request.tool,
            arguments: request.args,
            action_id: request.actionId,
            idempotency_key: request.idempotencyKey,
            approval_token: request.approvalToken,
            semantic_metadata: { nemo_grant: request.grant, nemo_grant_digest: request.grantDigest },
          }),
        });
      } catch (error) {
        throw new CapabilityError(
          'RECONCILIATION_REQUIRED',
          'Correct-Once transport failed after dispatch may have occurred',
          {
            outcome: 'unknown',
            retryable: false,
            dispatchState: 'DISPATCH_ATTEMPTED',
            outcomeCertainty: 'UNKNOWN',
            cause: String(error),
          },
        );
      }
      const body = await response.json().catch(() => null);
      if (!response.ok) {
        if (response.status === 408 || response.status >= 500) {
          throw new CapabilityError(
            'RECONCILIATION_REQUIRED',
            `Correct-Once Gateway response is ambiguous (${response.status})`,
            {
              outcome: 'unknown',
              retryable: false,
              dispatchState: 'DISPATCH_ATTEMPTED',
              outcomeCertainty: 'UNKNOWN',
              status: response.status,
              body,
            },
          );
        }
        throw new CapabilityError(
          response.status === 409 ? 'APPROVAL_REQUIRED' : 'GATEWAY_REJECTED',
          `Correct-Once Gateway rejected the effect (${response.status})`,
          { body },
        );
      }
      if (body === null || typeof body !== 'object' || Array.isArray(body)) {
        throw ambiguousReceipt('Correct-Once Gateway returned an invalid receipt');
      }
      if (typeof body.action_id !== 'string' || typeof body.idempotency_key !== 'string') {
        throw ambiguousReceipt('Correct-Once Gateway receipt must bind action_id and idempotency_key');
      }
      if (body.action_id !== request.actionId) {
        throw ambiguousReceipt('Correct-Once receipt action does not match the request', {
          reason: 'ACTION_ID_MISMATCH',
        });
      }
      if (body.idempotency_key !== request.idempotencyKey) {
        throw ambiguousReceipt('Correct-Once receipt idempotency key does not match the request', {
          reason: 'IDEMPOTENCY_KEY_MISMATCH',
        });
      }
      return body;
    },
  });
}
