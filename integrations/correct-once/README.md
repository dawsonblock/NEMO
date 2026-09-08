<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# NEMO Correct-Once integration

This package connects NEMO’s Node runtime to the Correct-Once execution boundary.
`PURE` and `READ` capabilities run through Function Hooks. `MUTATION`
capabilities run through the Effect Fabric bridge. `CRITICAL` mutations require
the authenticated Correct-Once Gateway.

Every call requires a versioned `coap3` grant. The signed grant is bound to the
subject, capability, active registry admission, policy version, operation,
registered route, action ID, idempotency key, and the SHA-256 digest of the
canonical arguments.
Changing any of those values fails closed before a handler or external effect
runs.

Registered JSON schemas are validated before admission grants are issued.
Capability and execution classes are checked for consistency at registration;
`critical` is only valid for an approval-required mutation with an explicit
Correct-Once server/tool route. Idempotency keys are bound to the subject,
capability, action, and argument digest; conflicting reuse returns an explicit
conflict instead of replaying another operation's receipt. Runtime identity is
installed when the integration is created and cannot be overridden per call.
Approval is reserved for `critical` capabilities; an approval flag on an
ordinary mutation is rejected rather than treated as an unverified string.

Capability descriptors and their schemas are deep-cloned and frozen at
registration. The digest and compiled validator therefore describe the same
immutable descriptor, even if the caller later mutates its original object.
Schemas use the package's restricted JSON-schema profile (object/array/string
types, properties, required fields, enums, bounds, patterns, and additional
properties). Unsupported keywords fail registration; they are never silently
ignored. Registered `server` and `tool` routes are execution-bound and cannot be
overridden by per-call options.

## Reference capabilities

The package includes four local capabilities for qualification:

- `nemo.pure.json_digest`
- `nemo.read.file_snapshot`
- `nemo.mutation.file_write_atomic`
- `nemo.mutation.file_delete_approved`

The file capabilities reject path traversal and symlink escapes. Writes use an
atomic replacement. Deletes require a predecessor digest and a scoped critical
grant.

## Direct use

```js
import {
  CapabilityRegistry,
  EffectFabricBridge,
  FunctionHooksBridge,
  REFERENCE_CAPABILITIES,
  createNemoCorrectOnceRuntime,
  createReferenceHandlers,
} from 'nemo-relay-correct-once';

const registry = new CapabilityRegistry();
for (const capability of REFERENCE_CAPABILITIES) registry.register(capability);
const handlers = createReferenceHandlers({ root: '/workspace' });
const signingSecret = process.env.NEMO_GRANT_SECRET;

const hooks = new FunctionHooksBridge({ registry, signingSecret, handlers });
const effects = new EffectFabricBridge({ registry, signingSecret, handlers });
const runtime = createNemoCorrectOnceRuntime({
  nemo: relayNode,
  registry,
  functionHooks: hooks,
  effectFabric: effects,
  signingSecret,
  subject: 'local-agent',
});

const result = await runtime.execute('nemo.pure.json_digest', { document: { ok: true } });
```

`installTool()` connects a named NEMO tool to the same routing boundary. A
reserved argument marker is inserted by the request intercept and removed before
the downstream handler receives the arguments. User-supplied marker collisions
are rejected.

For remote critical effects, configure `createCorrectOnceGatewayClient()` as
the Effect Fabric bridge’s `criticalGateway`. The gateway token belongs only to
the runtime client; the approval signing secret remains with the approval
authority.

The integration carries its deterministic `coap3` capability grant in
`semantic_metadata.nemo_grant` and sends the native Correct-Once `coap1`
approval token separately as `approval_token`. This keeps capability/argument
binding local to NEMO while preserving Correct-Once’s existing approval and
reconciliation contract.

This package provides the routing and grant contract. The current NEMO release
does not claim OS sandboxing, a durable ledger, or exactly-once semantics for
arbitrary external providers. Ambiguous critical effects must be reconciled by
Correct-Once before retry.
