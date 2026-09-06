<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Runtime global-state inventory

This inventory covers mutable state whose lifetime can outlive one scope or
one request. It is part of the `0.9.1-rc.2` lifecycle audit. Static schemas,
constants, and immutable codec descriptors are intentionally omitted except
where they explain ownership; test-only state is listed separately.

The classification is deliberately conservative:

| Class | Meaning |
| --- | --- |
| `PROCESS_IMMUTABLE` | Read-only static data or a once-only initialization that does not retain runtime work. |
| `PROCESS_REGISTRY` | Process-wide mutable registry or worker shared by all Relay instances in one process. Its ownership and reset semantics must be explicit. |
| `RUNTIME_STATE` | Request, scope-stack, task-local, or binding-environment state that must not leak to another runtime. |
| `TEST_ONLY` | State only compiled or used by tests to serialize mutation of a process-wide surface. |

## Core runtime

| State | Class | Owner / purpose | Reset or isolation rule |
| --- | --- | --- | --- |
| `PLUGIN_HANDLERS` | `PROCESS_REGISTRY` | Registered plugin implementations and owner/implementation identity. | Registration uses owner-aware collision checks; deregistration removes the exact registration. |
| `ACTIVE_PLUGIN_CONFIGURATION` | `PROCESS_REGISTRY` | Active static plugin configuration. | Cleared by plugin configuration teardown; two unrelated active static configurations are not silently merged. |
| `LAST_FAILED_RUNTIME_DIAGNOSTICS_REPORT` | `PROCESS_REGISTRY` | Last failed plugin configuration diagnostics. | Replaced on the next validation attempt; diagnostic only. |
| `PLUGIN_MUTATION_OWNER` | `PROCESS_REGISTRY` | Serializes legacy and host-owned plugin mutations. | Returns to `Idle` during normal teardown; incomplete rollback remains fail-closed. |
| `PLUGIN_MUTATION_EXECUTOR` | `PROCESS_REGISTRY` | One bounded (256) host mutation executor. | Process-lifetime worker; capacity returns typed `ResourceExhausted`, never an unbounded future queue. |
| Plugin registration and host-owner counters | `PROCESS_REGISTRY` | Monotonic identity allocation for registrations and dynamic hosts. | Not reset; identifiers are process-local and not a security identity. |
| `GLOBAL_CONTEXT` | `PROCESS_REGISTRY` | Global middleware, subscribers, and callbacks. | Scope-local registrations remain on `ScopeStack` instead; global registrations require explicit deregistration. |
| Conditional middleware guardrail registry | `PROCESS_REGISTRY` | Global conditional-guardrail callbacks. | Deregister by registration identity during teardown. |
| Subscriber `PROCESS_STATE` | `PROCESS_REGISTRY` | Bounded dispatcher, sanitizer runtime, detached-publication executor, and queue metrics. | Process lifetime by design; post-fork state is replaced safely rather than reclaimed under inherited locks. |
| Default logging runtime and active Relay logger | `PROCESS_REGISTRY` | Process-wide logging setup. | `shutdown_default_logging` clears the active default runtime. |
| Runtime owner controller | `PROCESS_REGISTRY` | Prevents incompatible binding/runtime ownership in one process. | Explicit owner release is required before a conflicting host can initialize. |
| Active pricing resolver | `PROCESS_REGISTRY` | Shared model-pricing lookup configuration. | Replaced only through its explicit resolver API. |
| Scope stacks and publication context task/thread locals | `RUNTIME_STATE` | Current scope lineage, runtime identity, event parentage, and nested-publication context. | Captured and restored at thread/task boundaries; child stacks inherit immutable runtime identity. |
| Pending OpenTelemetry Relay IDs | `RUNTIME_STATE` | Per-thread OpenTelemetry correlation during emission. | Cleared after the correlated span/event completes. |

## Adaptive runtime

| State | Class | Owner / purpose | Reset or isolation rule |
| --- | --- | --- | --- |
| Cache write tracker | `PROCESS_REGISTRY` | Counts detached cache writes for `wait_for_cache_idle` and `flush_cache_writes`. | Tracks work only; it does not own cache entries or security identity. |
| Response-cache single-flight maps | `RUNTIME_STATE` | In-flight keys, waiter limits, and provider/model semaphores for one activated cache feature. | Dropped with the feature/runtime; active-key and waiter limits prevent unbounded work. |
| Response-cache sampling RNG | `RUNTIME_STATE` | Per-thread sampling state. | Thread-local; never used as an identity or cache partition. |
| Editor schemas and cache policy maps | `PROCESS_IMMUTABLE` | Configuration metadata and static defaults. | No request or plugin activation data is retained. |

## Language bindings and workers

| State | Class | Owner / purpose | Reset or isolation rule |
| --- | --- | --- | --- |
| Node environment count, lifecycle lock, and stream-channel map | `PROCESS_REGISTRY` | Tracks N-API environment ownership and bounded JS stream bridges. | Environment teardown removes channels; bridge capacity is enforced before queueing chunks. |
| Node callback error state | `PROCESS_REGISTRY` | Last callback error exposed to the JS binding. | Replaced/cleared on the next callback operation; diagnostic only. |
| Python plugin clear state | `PROCESS_REGISTRY` | Coordinates Python plugin configuration teardown. | Replaced by explicit teardown; Python test switches are guarded separately. |
| Python callback test switches | `TEST_ONLY` | Inject binding failures for coverage. | Guarded by a test mutex and never exposed as runtime configuration. |
| Worker task/thread scope context | `RUNTIME_STATE` | Scope context propagated into a worker execution. | Captured from the caller and cleared when worker work completes. |

## Lifecycle invariants

1. A scope or `RelayRuntime` must not acquire authority by mutating a global
   registry; `RuntimeIdentity` remains attached to the scope stack.
2. A failed plugin activation must roll back registrations in reverse order. If
   rollback cannot prove a clean state, later mutation is fail-closed rather
   than treated as a fresh runtime.
3. Process registries may be shared only where their contract says so. Multiple
   simultaneous hosts must either use the same explicitly supported registry or
   be rejected with a deterministic conflict.
4. New mutable statics, `LazyLock`, `OnceLock`, and task/thread locals must be
   classified here and covered by an initialization, teardown, or isolation
   test before they enter a production execution path.

For queue-specific ownership and saturation behavior, see
[Runtime queue inventory](queue-inventory.md). For qualification boundaries,
see [Hardened runtime qualification](reference/hardening.mdx).
