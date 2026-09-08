// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { digestArguments, digestGrantClaims } from './canonical.mjs';
import { CapabilityError } from './errors.mjs';

const VERSION = 'coap3';

function secretBytes(secret) {
  const value = Buffer.isBuffer(secret) ? secret : Buffer.from(String(secret ?? ''), 'utf8');
  if (value.length < 32)
    throw new CapabilityError('INVALID_SIGNING_KEY', 'grant signing key must be at least 32 bytes');
  return value;
}

function encode(value) {
  return Buffer.from(value).toString('base64url');
}

function decode(value) {
  return JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
}

function sign(payload, secret) {
  return createHmac('sha256', secretBytes(secret)).update(payload, 'ascii').digest('base64url');
}

function claimsFor(input, args, now) {
  const issuedAt = input.issuedAt ?? now;
  const expiresAt = input.expiresAt ?? issuedAt + (input.ttlSeconds ?? 300);
  if (!Number.isInteger(issuedAt) || !Number.isInteger(expiresAt) || expiresAt <= issuedAt) {
    throw new CapabilityError('INVALID_GRANT', 'grant timestamps are invalid');
  }
  return {
    v: 3,
    sub: input.subject,
    cap: input.capabilityId,
    cls: input.executionClass,
    adm: input.admissionId,
    reg: input.registrationDigest,
    pol: input.policyVersion,
    op: input.operation,
    route: input.routeDigest,
    act: input.actionId,
    idem: input.idempotencyKey,
    arg: digestArguments(args),
    iat: issuedAt,
    exp: expiresAt,
    nonce: input.nonce ?? randomBytes(18).toString('base64url'),
  };
}

export function issueGrant(input, args, { signingSecret, now = Math.floor(Date.now() / 1000) } = {}) {
  for (const field of [
    'subject',
    'capabilityId',
    'executionClass',
    'admissionId',
    'registrationDigest',
    'policyVersion',
    'operation',
    'routeDigest',
    'actionId',
    'idempotencyKey',
  ]) {
    if (typeof input?.[field] !== 'string' || input[field].length === 0)
      throw new CapabilityError('INVALID_GRANT', `grant ${field} is required`);
  }
  const claims = claimsFor(input, args, now);
  const payload = encode(JSON.stringify(claims));
  const token = `${VERSION}.${payload}.${sign(payload, signingSecret)}`;
  return Object.freeze({ token, claims, grantDigest: digestGrantClaims(claims) });
}

function equal(left, right) {
  return typeof left === 'string' && typeof right === 'string' && left === right;
}

export function verifyGrant(token, args, expected, { signingSecret, now = Math.floor(Date.now() / 1000) } = {}) {
  if (typeof token !== 'string') throw new CapabilityError('GRANT_REQUIRED', 'a capability grant is required');
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== VERSION)
    throw new CapabilityError('INVALID_GRANT', 'unsupported grant format');
  const [prefix, payload, observed] = parts;
  const expectedSignature = sign(payload, signingSecret);
  const observedBytes = Buffer.from(observed);
  const expectedBytes = Buffer.from(expectedSignature);
  if (observedBytes.length !== expectedBytes.length || !timingSafeEqual(observedBytes, expectedBytes)) {
    throw new CapabilityError('INVALID_GRANT', 'grant signature is invalid');
  }
  let claims;
  try {
    claims = decode(payload);
  } catch {
    throw new CapabilityError('INVALID_GRANT', 'grant claims are not valid JSON');
  }
  if (claims?.v !== 3 || claims.exp <= now || claims.iat > now + 30 || claims.exp <= claims.iat) {
    throw new CapabilityError('GRANT_EXPIRED', 'grant is expired or has invalid timestamps');
  }
  const comparisons = {
    sub: expected.subject,
    cap: expected.capabilityId,
    cls: expected.executionClass,
    adm: expected.admissionId,
    reg: expected.registrationDigest,
    pol: expected.policyVersion,
    op: expected.operation,
    route: expected.routeDigest,
    act: expected.actionId,
    idem: expected.idempotencyKey,
  };
  for (const [claim, value] of Object.entries(comparisons)) {
    if (!equal(claims[claim], value))
      throw new CapabilityError('GRANT_SCOPE_MISMATCH', `grant ${claim} does not match`);
  }
  if (!equal(claims.arg, digestArguments(args)))
    throw new CapabilityError('GRANT_ARGUMENT_MISMATCH', 'grant arguments do not match');
  return Object.freeze({ claims, grantDigest: digestGrantClaims(claims) });
}
