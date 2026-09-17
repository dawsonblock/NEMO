// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { digestCapability, digestRoute, sha256Domain } from './canonical.mjs';
import { CapabilityError } from './errors.mjs';
import { cloneAndFreezeJson, compileSchema } from './schema.mjs';

const VALID_CLASSES = new Set(['pure', 'read', 'mutation']);
const VALID_EXECUTION_CLASSES = new Set(['pure', 'read', 'mutation', 'critical']);

export class CapabilityRegistry {
  #entries = new Map();
  #admissions = new Map();
  #revoked = new Set();
  #validators = new Map();

  register(definition) {
    const required = ['id', 'capabilityClass', 'operation'];
    for (const field of required) {
      if (typeof definition?.[field] !== 'string' || definition[field].length === 0) {
        throw new CapabilityError('INVALID_CAPABILITY', `capability ${field} is required`);
      }
    }
    if (!VALID_CLASSES.has(definition.capabilityClass)) {
      throw new CapabilityError('INVALID_CAPABILITY', `unsupported capability class: ${definition.capabilityClass}`);
    }
    if (this.#entries.has(definition.id)) {
      throw new CapabilityError('CAPABILITY_EXISTS', `capability already registered: ${definition.id}`);
    }
    const executionClass = definition.executionClass ?? definition.capabilityClass;
    if (!VALID_EXECUTION_CLASSES.has(executionClass)) {
      throw new CapabilityError('INVALID_CAPABILITY', `unsupported execution class: ${executionClass}`);
    }
    const compatible =
      (definition.capabilityClass === 'pure' && executionClass === 'pure') ||
      (definition.capabilityClass === 'read' && executionClass === 'read') ||
      (definition.capabilityClass === 'mutation' && (executionClass === 'mutation' || executionClass === 'critical'));
    if (!compatible) {
      throw new CapabilityError('INVALID_CAPABILITY', 'capability and execution classes are inconsistent');
    }
    const normalized = {
      id: definition.id,
      capabilityClass: definition.capabilityClass,
      executionClass,
      operation: definition.operation,
      server: definition.server ?? null,
      tool: definition.tool ?? null,
      routeDigest: digestRoute({ server: definition.server ?? null, tool: definition.tool ?? null }),
      description: definition.description ?? '',
      approvalRequired: definition.approvalRequired === true,
      schema: definition.schema ?? { type: 'object' },
      resourceFields: [...(definition.resourceFields ?? [])],
    };
    if (normalized.approvalRequired !== (executionClass === 'critical')) {
      throw new CapabilityError(
        'INVALID_CAPABILITY',
        'approval is reserved for critical capabilities; critical capabilities must require approval',
      );
    }
    if (executionClass === 'critical' && (!normalized.server || !normalized.tool)) {
      throw new CapabilityError('INVALID_CAPABILITY', 'critical capabilities require server and tool bindings');
    }
    const immutable = cloneAndFreezeJson(normalized);
    const validator = compileSchema(immutable.schema);
    const registrationDigest = digestCapability(immutable);
    const entry = Object.freeze({ ...immutable, registrationDigest });
    this.#entries.set(entry.id, entry);
    this.#validators.set(entry.id, validator);
    return entry;
  }

  get(id) {
    const entry = this.#entries.get(id);
    if (!entry || this.#revoked.has(id)) {
      throw new CapabilityError('CAPABILITY_UNAVAILABLE', `capability is not active: ${id}`);
    }
    return entry;
  }

  revoke(id) {
    this.get(id);
    this.#revoked.add(id);
  }

  admit(id, policyVersion = 'nemo-local-v1') {
    const entry = this.get(id);
    const admissionId = sha256Domain('nemo/admission/v1', {
      capabilityId: entry.id,
      registrationDigest: entry.registrationDigest,
      policyVersion,
    });
    const admission = Object.freeze({
      admissionId,
      capabilityId: entry.id,
      registrationDigest: entry.registrationDigest,
      policyVersion,
    });
    this.#admissions.set(admissionId, admission);
    return admission;
  }

  validateArguments(id, args) {
    const entry = this.get(id);
    const validator = this.#validators.get(entry.id);
    if (!validator) throw new CapabilityError('SCHEMA_UNAVAILABLE', `schema validator is unavailable: ${id}`);
    validator.validate(args);
  }

  verifyAdmission(admissionId, capabilityId, registrationDigest, policyVersion) {
    const admission = this.#admissions.get(admissionId);
    if (!admission || this.#revoked.has(capabilityId)) {
      throw new CapabilityError('ADMISSION_REVOKED', 'capability admission is unavailable');
    }
    if (
      admission.capabilityId !== capabilityId ||
      admission.registrationDigest !== registrationDigest ||
      admission.policyVersion !== policyVersion
    ) {
      throw new CapabilityError('ADMISSION_MISMATCH', 'capability admission does not match the request');
    }
    return admission;
  }

  snapshot() {
    return [...this.#entries.values()]
      .filter((entry) => !this.#revoked.has(entry.id))
      .sort((left, right) => left.id.localeCompare(right.id));
  }

  snapshotDigest() {
    return digestCapability(this.snapshot());
  }
}
