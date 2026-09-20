<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Milestone: native plugin isolation

Almost all of the kernel's `unsafe` is the native plugin path: 280 occurrences
in `crates/core/src/plugin/dynamic/native.rs` and another 315 in
`nemo-relay-plugin`. Together that is roughly 96% of the measured in-process
surface, and `just tcb-report` prints the number this milestone is judged on:

```
kernel-process unsafe tokens: 617
```

Moving the loader into another Rust crate would improve the source layout and
leave that number unchanged, because a memory-corruption bug in the loader would
still corrupt the kernel. The boundary has to be a process.

## Target

```text
                      NEMO Runtime
                           |
                 PluginExecutionClient
                           |
                    process / RPC
                           |
          +----------------+----------------+
          |                                 |
    kernel process                  plugin-host process
                                            |
                                            +- native loader
                                            +- dlopen / libloading
                                            +- FFI and plugin ABI
                                            +- unsafe
```

The kernel owns the interface. The runtime supplies the implementation. Dynamic
loading happens on the far side, so the trusted side never loads a library.

## Increments

Each one leaves the repository buildable, and none of them is the endpoint.

1. **Contract below the implementation.** *(done)*
   `crates/plugin-protocol` (`nemo-relay-plugin-protocol`) defines the
   operations, identities, structured failures, and version handshake, and
   classifies at the `contracts` layer so a kernel interface may depend on it.
   It ships no loader, no transport, and no `unsafe`, and nothing depends on it
   yet — in particular `nemo-relay` does not.

2. **Injected interface.** Core depends on a `PluginExecutionBackend`, not on
   the loader. An in-process backend keeps existing consumers building. That is
   the compatibility bridge, not the destination.

3. **Migrate the consumers.** `node`, `ffi`, `cli`, and the integration tests
   stop importing implementation details from `nemo_relay::plugin::dynamic::*`.
   User-facing API compatibility is preserved by facade re-exports, and the old
   direct-native surface is marked transitional. Afterwards nothing outside the
   compatibility implementation instantiates the native loader.

4. **Process backend.** The unsafe loader moves into a separate process behind a
   versioned framed protocol with hard deadlines and kill/restart semantics. A
   host crash becomes a structured plugin failure instead of a kernel crash.

5. **Delete the in-process production path.** Any in-process backend is kept for
   development and tests only, or removed. The layer gate is tightened so core
   cannot regain a dependency on the native implementation.

## What the boundary actually has to carry

Reconnaissance for increment 2 changed the shape of the work, and it is
recorded here because it determines whether increments 3-5 are migrations or
another redesign.

**The native ABI is bidirectional and callback-based, not request/response.**
`crates/plugin` defines a table of host functions the plugin calls while it
runs (`NemoRelayNativeHostApiV1`, `V3`, `V4`) *and* callbacks the host re-enters
(`NemoRelayNativePluginV1.register`, `validate`, `drop`, plus per-component
callbacks for LLM execution, streaming, middleware, event subscription, and
payload codecs). A protocol that only carries caller-to-plugin requests cannot
express the majority of what native plugins do today.

**Part of the host API is an artefact of the in-process boundary.**
`string_new`, `string_data`, `string_len`, `string_free`, and the thread-local
error accessors exist because raw pointers cross an FFI boundary and someone has
to own and free them. A framed message carries its own bytes, so those have no
counterpart in the contract, and the contract says so rather than importing
them.

**The loader's public surface is narrow; its integration is not.**
`crates/core/src/plugin/dynamic/native.rs` exposes three items —
`NativePluginLoadSpec`, `NativePluginActivation`, and `load_native_plugins` —
and core imports the ABI crate in exactly one place, `native.rs:58`. But
`load_native_plugins` registers an adapter that implements core's own `Plugin`
trait, so a native plugin is currently an in-process Rust object with live
callbacks rather than a remote endpoint. Moving the loader across a process
boundary means replacing that object with an RPC-backed proxy implementing the
same trait, which is a change to plugin semantics, not a file move.

**The compatibility backend cannot be built before that.** The in-process
backend is supposed to live outside core, but a crate implementing a core-owned
trait must depend on core, and core depends on the ABI crate only because its
own loader needs it. The loader therefore has to leave core at the same time the
backend does, and core's plugin system has to reach it through injection rather
than by calling it. Coupling increments 2 and 4 is the honest reading; the
alternative is an in-process backend inside core, which is the thing this
milestone exists to prevent.

**Consumer classification**, before assuming compatibility is possible:

| Consumer | Usage | Compatibility risk |
|---|---|---|
| `crates/node` | `DynamicPluginActivationSpec`, `DynamicPluginKind`, `PluginHostActivation` | Types only, re-exportable |
| `crates/ffi` | `DynamicPluginActivationSpec`, `PluginHostActivation`, plus core's plugin registry API | Types only, re-exportable |
| `crates/cli` | `load_native_plugins`, `load_worker_plugins`, `NativePluginLoadSpec`, `NativePluginActivation` | The only caller of the loader entry point outside core |
| `crates/core/tests` | The same types and entry point | Test-only |

No consumer constrains the loader's internals or pattern-matches on them, so a
facade that re-exports *contract* types without re-exporting implementation
types is viable. `cli` is the one place that has to move to the injected
backend rather than to a re-export, because it is the only external caller of
`load_native_plugins`.

## Acceptance gates

- `nemo-relay` contains no native dynamic-loading implementation.
- The crate graph has no upward edge from the kernel to the plugin
  implementation, and the layer ratchet prevents one from reappearing.
- Production startup selects the process backend, not the compatibility one.
- Killing the host during load, invocation, or response serialization cannot
  kill NEMO; a plugin segfault becomes a bounded failure.
- A hung plugin is terminated at the configured deadline.
- Malformed or oversized responses are rejected, stdout and stderr cannot
  corrupt protocol framing, and an ABI or version mismatch fails closed.
- Node, FFI, CLI, and integration behavior stays covered; native-plugin
  conformance runs against both backends until the in-process one is removed.
- `kernel-process unsafe tokens` falls. The milestone is judged on that number
  in `just tcb-report`, not on the tier total and not on crate relocation.

## Status

Increment 1 is complete. Increment 2 is started and its boundary design is in
place:

- `nemo-relay-plugin-protocol` now carries `PluginExecutionContext` (request
  correlation, protocol version, runtime binding, deadline, response budget),
  `PluginExecutionOutcome` (the result together with `DispatchState` and
  `OutcomeCertainty`, so a plugin failure cannot pass for a definite outcome),
  the `HostCall` direction the plugin uses to call back into the host, and the
  deadline rules below.
- `DispatchState` and `OutcomeCertainty` moved to `nemo-relay-types` and are
  re-exported from `nemo-relay-executor`, because the contract needs that
  vocabulary and a contract crate cannot depend on an adapter. Duplicating a
  classification that decides whether an effect may be retried is how the two
  copies drift apart.

Deadline rules, defined before any implementation so the process backend cannot
invent its own: a deadline that has already passed means the caller does not
invoke the backend at all and reports `DeadlineExceeded`; a deadline that passes
during execution is reported as `DeadlineExceeded`; and a host terminated
*because* the deadline passed is still `DeadlineExceeded`, not `HostCrashed`,
which is reserved for a host that ended on its own.

The seam itself now exists:

- `nemo_relay::plugin::execution` owns `PluginExecutionBackend` and
  `PluginManager`. The trait is asynchronous, is expressed entirely in the
  protocol vocabulary, and names no transport.
- `PluginManager` owns the deadline rule: every operation checks the context's
  deadline *before* the backend is reached, so "an operation that is already out
  of time is never started" holds for every backend rather than being something
  each implementation has to remember. It is constructed from the backend rather
  than reaching for a process-wide one.
- `crates/plugin-host` holds `InProcessPluginBackend`, which implements the seam
  by calling the existing loader and holding each activation as the lifetime
  guard for what it loaded. The kernel does not depend on this crate.
- `crates/plugin-host/src/conformance.rs` is the shared suite: the in-process
  backend passes it today, and the process backend runs the identical suite so
  "implements the contract" is demonstrated rather than asserted.
- `crates/plugin-host/tests/architecture.rs` fails when new native-loading code
  or a new caller of `load_native_plugins` appears outside the grandfather list.
  It found the CLI caller on its first run, which is why that exception is
  written down by crate and path instead of being left implicit.

Two things are deliberately outstanding. The trait covers load, unload, inspect,
and health, but not `invoke`: a loaded plugin registers components into the
runtime's own machinery rather than exposing an endpoint, so there is nothing
honest for an in-process backend to invoke yet, and a method whose only
implementation refuses would be the temporary abstraction this milestone is
supposed to avoid. `invoke` arrives with the process host that has to serve it.
And the CLI called the loader directly — increment 3 removed that, below.

Increment 3 is largely complete:

- The CLI is the only consumer that reached the loader directly, and it now goes
  through `LoadedPlugins`, which holds the backend and therefore the activations
  it loaded. Teardown is unchanged in shape: the activation guard used to
  deregister plugin kinds when it dropped after sessions closed and subscribers
  flushed, and dropping the backend does the same at the same point, so a
  runtime callback still cannot outlive the code behind it.
- `node` and `ffi` needed no change. They import configuration types
  (`DynamicPluginActivationSpec`, `PluginHostActivation`, `DynamicPluginKind`),
  not the loader, so no facade or re-export was needed to preserve their paths.
- The architecture guard's CLI exception is gone, and the guard passes without
  it. That is the check that increment 3 actually happened, rather than a claim
  that it did.
- Core's integration tests still call `load_native_plugins` directly. They are
  the loader's own tests — they exercise the native ABI and the dynamic library
  it loads — so they are the implementation's test surface rather than
  consumers of it, and the guard deliberately scans shipped sources rather than
  tests.

Migrating the CLI also exposed a gap in the contract: `load` returned only a
descriptor, and a caller that wanted to unload later had nothing to name. The
response now carries the handle as well, because only the backend knows the
generation it assigned.

The wire model now lives in `crates/plugin-proto` as a gRPC schema, and the
earlier hand-rolled length-prefixed JSON framing is gone — gRPC frames the
stream, and the limit travels in the handshake instead of in a header. The
schema is authoritative: an architecture test permits `.proto` files and
`include_proto!` in the two wire crates and rejects them everywhere else.

## Boundary closure

The schema was ahead of what the native ABI does, and writing the supervisor
before closing that gap would have forced ad hoc exceptions. Closed:

- **Registration descriptors.** `PluginDescriptor.registrations` carries what a
  proxy needs: registration identity, component kind, class, ordering with
  priority and chain-breaking, execution shape, configuration keys and an
  optional declared digest. A list of kind names could not say how to order two
  registrations, whether one breaks a chain, or whether its callback streams.
- **Wire↔domain conversion.** `plugin_proto::convert` refuses `UNSPECIFIED` and
  unknown enums, missing nested messages, inconsistent failure detail, empty
  identities and generation-zero handles, so the host's looseness cannot become
  domain state the kernel trusts.
- **Session establishment.** `HandshakeResponse` returns the `session_id` every
  later request names; the host owns `host_instance_id` because only it knows
  which process it is, and the kernel supplies the client nonce.
- **Artifact identity.** `LoadRequest` carries a manifest and library digest,
  which is the kernel's statement of what it approved; the host verifies both
  immediately before loading.
- **Local peer authentication.** The handshake carries a session credential the
  supervisor passes to the host out of band, so knowing the socket path is not
  enough to present as the kernel.
- **Vector coverage.** A check parses the `rpc` signatures and requires every
  message they name to be vectored or explicitly pending, asserting first that
  it found at least twenty so it cannot pass by parsing nothing.

- **Approved artifact identity, in the domain and not only the wire.**
  `PluginLoadRequest` carries a `PluginArtifactIdentity`, and
  `plugin_artifact_identity` computes it on the trusted side, so the loader
  confirms what it was told to load instead of deciding what the reference
  points at. Without this the wire promised a guarantee the core request could
  not provide.
- **Validation fixes.** An ABI mismatch carrying frame-size detail is refused
  like the other detailed codes, and a load response whose handle and descriptor
  name different plugins is refused rather than accepted as two valid halves.
  The converter that turned a bare success into `NotDispatched` with
  `ConfirmedSuccess` is replaced by one that takes the outcome, so a
  convenience path cannot invent certainty.

Still open, in the order they need closing:

1. **Structured lifecycle outcomes.** `InvokeOutcome` carries a failure in the
   message, but `LoadResponse`, `UnloadResponse`, `InspectResponse`,
   `HealthResponse` and `HandshakeResponse` do not. A lifecycle failure such as
   `AlreadyLoaded` or `StaleHandle` would therefore have to travel as a gRPC
   status, which conflates a peer that answered coherently with a channel that
   failed.
2. **Registration operation identity.** The six broad classes cannot reconstruct
   a proxy: tool and LLM sanitizers, conditional execution, request and
   execution intercepts and streaming intercepts all collapse into one class
   while needing different installation points.
3. **Complete callback mapping for ABI v4**, especially async continuation and
   the pull-based downstream LLM stream, which cannot be a unary call because
   the plugin controls when to pull and backpressure is explicit.
4. **Conversions for every message the host uses**, and vectors for all of them
   rather than nineteen declared pending.
5. **Migrate Node, Python and FFI** off `PluginHostActivation`, which the
   architecture guard currently grandfathers by crate name.

Until those are closed the process host would still be architecture by
exception, which is why the supervisor is not being written yet.

This increment does not move `kernel-process unsafe tokens`, which is 621. The
number falls when native loading physically crosses the process boundary, and a
reduction achieved by reclassifying crates would not mean anything.
