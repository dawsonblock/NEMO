// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// Apache-2.0

import { CapabilityError } from './errors.mjs';

const TYPES = new Set(['array', 'boolean', 'integer', 'null', 'number', 'object', 'string']);
const SUPPORTED_KEYWORDS = new Set([
  'type',
  'required',
  'properties',
  'additionalProperties',
  'items',
  'enum',
  'pattern',
  'minLength',
  'maxLength',
  'minimum',
  'maximum',
  'minItems',
  'maxItems',
]);

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function matchesType(value, type) {
  switch (type) {
    case 'array':
      return Array.isArray(value);
    case 'boolean':
      return typeof value === 'boolean';
    case 'integer':
      return typeof value === 'number' && Number.isSafeInteger(value);
    case 'null':
      return value === null;
    case 'number':
      return typeof value === 'number' && Number.isFinite(value);
    case 'object':
      return isPlainObject(value);
    case 'string':
      return typeof value === 'string';
    default:
      return false;
  }
}

function schemaFailure(path, message) {
  throw new CapabilityError('SCHEMA_VIOLATION', `${path}: ${message}`);
}

function deepCloneFreeze(value, path = '$') {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value))
      throw new CapabilityError('INVALID_SCHEMA', `${path}: non-finite numbers are not supported`);
    return value;
  }
  if (Array.isArray(value)) {
    const clone = value.map((item, index) => deepCloneFreeze(item, `${path}[${index}]`));
    return Object.freeze(clone);
  }
  if (!isPlainObject(value)) {
    throw new CapabilityError('INVALID_SCHEMA', `${path}: only JSON values are supported`);
  }
  const clone = {};
  for (const [key, child] of Object.entries(value)) clone[key] = deepCloneFreeze(child, `${path}.${key}`);
  return Object.freeze(clone);
}

function equalJson(left, right) {
  if (left === right) return true;
  if (typeof left !== typeof right || left === null || right === null) return false;
  if (Array.isArray(left)) {
    return (
      Array.isArray(right) && left.length === right.length && left.every((item, index) => equalJson(item, right[index]))
    );
  }
  if (typeof left === 'object') {
    if (!isPlainObject(left) || !isPlainObject(right)) return false;
    const leftKeys = Object.keys(left);
    const rightKeys = Object.keys(right);
    return (
      leftKeys.length === rightKeys.length &&
      leftKeys.every((key) => Object.prototype.hasOwnProperty.call(right, key) && equalJson(left[key], right[key]))
    );
  }
  return false;
}

function validateKeywords(schema, path) {
  for (const key of Object.keys(schema)) {
    if (!SUPPORTED_KEYWORDS.has(key)) {
      throw new CapabilityError('INVALID_SCHEMA', `${path}.${key}: unsupported schema keyword`);
    }
  }
}

function compileNode(schema, path) {
  if (schema === true) return () => {};
  if (schema === false) return () => schemaFailure(path, 'value is not permitted');
  if (!isPlainObject(schema)) {
    throw new CapabilityError('INVALID_SCHEMA', `${path}: schema must be an object or boolean`);
  }
  validateKeywords(schema, path);

  const types = schema.type === undefined ? null : Array.isArray(schema.type) ? schema.type : [schema.type];
  if (
    types &&
    (!types.length ||
      types.some((type) => typeof type !== 'string' || !TYPES.has(type)) ||
      new Set(types).size !== types.length)
  ) {
    throw new CapabilityError('INVALID_SCHEMA', `${path}.type contains an unsupported type`);
  }
  const required = schema.required ?? [];
  if (
    !Array.isArray(required) ||
    required.some((name) => typeof name !== 'string') ||
    new Set(required).size !== required.length
  ) {
    throw new CapabilityError('INVALID_SCHEMA', `${path}.required must contain unique property names`);
  }
  const properties = schema.properties ?? {};
  if (!isPlainObject(properties)) throw new CapabilityError('INVALID_SCHEMA', `${path}.properties must be an object`);
  const propertyValidators = new Map(
    Object.entries(properties).map(([name, child]) => [name, compileNode(child, `${path}.properties.${name}`)]),
  );
  const additionalProperties = schema.additionalProperties ?? true;
  if (typeof additionalProperties !== 'boolean' && !isPlainObject(additionalProperties)) {
    throw new CapabilityError('INVALID_SCHEMA', `${path}.additionalProperties is invalid`);
  }
  const additionalValidator =
    typeof additionalProperties === 'boolean'
      ? null
      : compileNode(additionalProperties, `${path}.additionalProperties`);
  const itemsValidator = schema.items === undefined ? null : compileNode(schema.items, `${path}.items`);
  const enumValues = schema.enum;
  if (enumValues !== undefined && (!Array.isArray(enumValues) || enumValues.length === 0)) {
    throw new CapabilityError('INVALID_SCHEMA', `${path}.enum must be a non-empty array`);
  }
  if (schema.pattern !== undefined && typeof schema.pattern !== 'string') {
    throw new CapabilityError('INVALID_SCHEMA', `${path}.pattern must be a string`);
  }
  for (const keyword of ['minLength', 'maxLength', 'minItems', 'maxItems']) {
    if (schema[keyword] !== undefined && (!Number.isSafeInteger(schema[keyword]) || schema[keyword] < 0)) {
      throw new CapabilityError('INVALID_SCHEMA', `${path}.${keyword} must be a non-negative integer`);
    }
  }
  if (schema.minLength !== undefined && schema.maxLength !== undefined && schema.minLength > schema.maxLength) {
    throw new CapabilityError('INVALID_SCHEMA', `${path}.minLength cannot exceed maxLength`);
  }
  if (schema.minItems !== undefined && schema.maxItems !== undefined && schema.minItems > schema.maxItems) {
    throw new CapabilityError('INVALID_SCHEMA', `${path}.minItems cannot exceed maxItems`);
  }
  for (const keyword of ['minimum', 'maximum']) {
    if (schema[keyword] !== undefined && (typeof schema[keyword] !== 'number' || !Number.isFinite(schema[keyword]))) {
      throw new CapabilityError('INVALID_SCHEMA', `${path}.${keyword} must be a finite number`);
    }
  }
  if (schema.minimum !== undefined && schema.maximum !== undefined && schema.minimum > schema.maximum) {
    throw new CapabilityError('INVALID_SCHEMA', `${path}.minimum cannot exceed maximum`);
  }
  let pattern = null;
  if (schema.pattern !== undefined) {
    try {
      pattern = new RegExp(schema.pattern);
    } catch (error) {
      throw new CapabilityError('INVALID_SCHEMA', `${path}.pattern is not a valid regular expression`, {
        cause: String(error),
      });
    }
  }

  return (value, valuePath = '$') => {
    if (types && !types.some((type) => matchesType(value, type))) {
      schemaFailure(valuePath, `expected ${types.join(' or ')}`);
    }
    if (enumValues && !enumValues.some((candidate) => equalJson(candidate, value))) {
      schemaFailure(valuePath, 'value is not in enum');
    }
    if (typeof value === 'string') {
      if (schema.minLength !== undefined && value.length < schema.minLength)
        schemaFailure(valuePath, 'string is too short');
      if (schema.maxLength !== undefined && value.length > schema.maxLength)
        schemaFailure(valuePath, 'string is too long');
      if (pattern && !pattern.test(value)) schemaFailure(valuePath, 'string does not match pattern');
    }
    if (typeof value === 'number') {
      if (schema.minimum !== undefined && value < schema.minimum) schemaFailure(valuePath, 'number is below minimum');
      if (schema.maximum !== undefined && value > schema.maximum) schemaFailure(valuePath, 'number is above maximum');
    }
    if (Array.isArray(value)) {
      if (schema.minItems !== undefined && value.length < schema.minItems)
        schemaFailure(valuePath, 'array is too short');
      if (schema.maxItems !== undefined && value.length > schema.maxItems)
        schemaFailure(valuePath, 'array is too long');
      if (itemsValidator) value.forEach((item, index) => itemsValidator(item, `${valuePath}[${index}]`));
    }
    if (isPlainObject(value)) {
      for (const name of required) {
        if (!Object.prototype.hasOwnProperty.call(value, name))
          schemaFailure(valuePath, `missing required property ${name}`);
      }
      for (const [name, childValidator] of propertyValidators) {
        if (Object.prototype.hasOwnProperty.call(value, name)) childValidator(value[name], `${valuePath}.${name}`);
      }
      for (const [name, childValue] of Object.entries(value)) {
        if (propertyValidators.has(name)) continue;
        if (additionalProperties === false)
          schemaFailure(`${valuePath}.${name}`, 'additional property is not permitted');
        additionalValidator?.(childValue, `${valuePath}.${name}`);
      }
    }
  };
}

export function compileSchema(schema) {
  const immutableSchema = deepCloneFreeze(schema);
  const validate = compileNode(immutableSchema, '$');
  return Object.freeze({
    validate(value) {
      validate(value, '$');
    },
  });
}

export function cloneAndFreezeJson(value) {
  return deepCloneFreeze(value);
}
