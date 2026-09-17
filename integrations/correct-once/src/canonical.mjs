// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';

function encode(value, path = '$') {
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError(`${path}: non-finite numbers are not supported`);
    return JSON.stringify(value === 0 ? 0 : value);
  }
  if (typeof value !== 'object') throw new TypeError(`${path}: unsupported value type`);
  if (Array.isArray(value)) return `[${value.map((item, index) => encode(item, `${path}[${index}]`)).join(',')}]`;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${path}: only plain JSON objects are supported`);
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${encode(value[key], `${path}.${key}`)}`).join(',')}}`;
}

export function canonicalize(value) {
  return encode(value);
}

export function sha256Domain(domain, value) {
  return createHash('sha256')
    .update(`${domain}\0${canonicalize(value)}`, 'utf8')
    .digest('hex');
}

export function digestCapability(value) {
  return sha256Domain('nemo/capability/v1', value);
}

export function digestArguments(value) {
  return sha256Domain('nemo/arguments/v1', value);
}

export function digestRoute(value) {
  return sha256Domain('nemo/route/v1', value);
}

export function digestGrantClaims(value) {
  return sha256Domain('nemo/grant/v1', value);
}
