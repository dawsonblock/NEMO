// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

export type JsonValue = null | boolean | number | string | JsonValue[] | { readonly [key: string]: JsonValue };
export type CapabilityClass = 'pure' | 'read' | 'mutation';

export interface CapabilityDefinition {
  readonly id: string;
  readonly capabilityClass: CapabilityClass;
  readonly executionClass?: CapabilityClass | 'critical';
  readonly operation: string;
  readonly server?: string;
  readonly tool?: string;
  readonly description?: string;
  readonly approvalRequired?: boolean;
  readonly schema?: JsonValue;
  readonly resourceFields?: readonly string[];
}

export interface CapabilityEntry extends Omit<CapabilityDefinition, 'description' | 'schema' | 'resourceFields' | 'executionClass' | 'server' | 'tool'> {
  readonly executionClass: CapabilityClass | 'critical';
  readonly server: string | null;
  readonly tool: string | null;
  readonly description: string;
  readonly schema: JsonValue;
  readonly resourceFields: readonly string[];
  readonly registrationDigest: string;
}

export interface CapabilityAdmission {
  readonly admissionId: string;
  readonly capabilityId: string;
  readonly registrationDigest: string;
  readonly policyVersion: string;
}

export interface GrantContext {
  readonly subject: string;
  readonly capabilityId: string;
  readonly executionClass: string;
  readonly admissionId: string;
  readonly registrationDigest: string;
  readonly policyVersion: string;
  readonly operation: string;
  readonly actionId: string;
  readonly idempotencyKey: string;
}

export type ExecutionOptions = Omit<Partial<GrantContext>, 'subject' | 'server' | 'tool'> & {
  grant?: string;
  approvalToken?: string;
  now?: number;
};

export interface GrantResult {
  readonly token: string;
  readonly claims: Readonly<Record<string, JsonValue>>;
  readonly grantDigest: string;
}

export function canonicalize(value: JsonValue): string;
export function digestArguments(value: JsonValue): string;
export function digestCapability(value: JsonValue): string;
export function digestGrantClaims(value: JsonValue): string;
export function issueGrant(input: GrantContext, args: JsonValue, options: { signingSecret: string | Uint8Array; now?: number }): GrantResult;
export function verifyGrant(token: string, args: JsonValue, expected: GrantContext, options: { signingSecret: string | Uint8Array; now?: number }): { claims: Readonly<Record<string, JsonValue>>; grantDigest: string };
export class CapabilityError extends Error {
  readonly code: string;
  readonly details: Readonly<Record<string, unknown>>;
  constructor(code: string, message: string, details?: Record<string, unknown>);
}
export function fail(code: string, message: string, details?: Record<string, unknown>): never;
export function compileSchema(schema: JsonValue): { validate(value: JsonValue): void };

export class CapabilityRegistry {
  register(definition: CapabilityDefinition): CapabilityEntry;
  get(id: string): CapabilityEntry;
  revoke(id: string): void;
  admit(id: string, policyVersion?: string): CapabilityAdmission;
  validateArguments(id: string, args: JsonValue): void;
  verifyAdmission(admissionId: string, capabilityId: string, registrationDigest: string, policyVersion: string): CapabilityAdmission;
  snapshot(): readonly CapabilityEntry[];
  snapshotDigest(): string;
}

export class FunctionHooksBridge {
  constructor(options: { registry: CapabilityRegistry; signingSecret: string | Uint8Array; handlers?: ReadonlyMap<string, (args: JsonValue, context: unknown) => unknown> });
  execute(capabilityId: string, args: JsonValue, context: GrantContext & { grant: string; subject: string; now?: number; handler?: (args: JsonValue) => unknown }): Promise<{ result: unknown; route: 'function-hooks'; grantDigest: string }>;
}

export class EffectFabricBridge {
  constructor(options: { registry: CapabilityRegistry; signingSecret: string | Uint8Array; handlers?: ReadonlyMap<string, (args: JsonValue, context: unknown) => unknown>; criticalGateway?: { execute(request: unknown): Promise<unknown> } | null; journal?: { append(entry: unknown): Promise<void> } | null });
  execute(capabilityId: string, args: JsonValue, context: GrantContext & { grant: string; subject: string; transactionId?: string; now?: number; approvalToken?: string; handler?: (args: JsonValue) => unknown }): Promise<unknown>;
}

export const REFERENCE_CAPABILITIES: readonly CapabilityDefinition[];
export function createReferenceHandlers(options: { root: string }): Map<string, (args: JsonValue, context?: unknown) => Promise<unknown>>;
export function createCorrectOnceGatewayClient(options: { baseUrl: string; token: string; fetchImpl?: typeof fetch }): { execute(request: unknown): Promise<unknown> };
export function createNemoCorrectOnceRuntime(options: { nemo: Record<string, (...args: unknown[]) => unknown>; registry: CapabilityRegistry; functionHooks: FunctionHooksBridge; effectFabric: EffectFabricBridge; signingSecret: string | Uint8Array; subject?: string }): { execute(capabilityId: string, args: JsonValue, options?: ExecutionOptions): Promise<unknown>; installTool(options: { toolName: string; capabilityId: string; priority?: number; actionId?: string; idempotencyKey?: string; approvalToken?: string; policyVersion?: string }): () => void; readonly marker: string };
