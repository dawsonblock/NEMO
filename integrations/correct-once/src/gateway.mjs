// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// Apache-2.0

import { CapabilityError } from './errors.mjs';

export function createCorrectOnceGatewayClient({ baseUrl, token, fetchImpl = globalThis.fetch }) {
  if (!baseUrl || !token || typeof fetchImpl !== 'function')
    throw new TypeError('baseUrl, token, and fetchImpl are required');
  return Object.freeze({
    async execute(request) {
      const response = await fetchImpl(new URL('/gateway/tool-call', baseUrl), {
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
      const body = await response.json().catch(() => null);
      if (!response.ok) {
        throw new CapabilityError(
          response.status === 409 ? 'APPROVAL_REQUIRED' : 'GATEWAY_REJECTED',
          `Correct-Once Gateway rejected the effect (${response.status})`,
          { body },
        );
      }
      return body;
    },
  });
}
