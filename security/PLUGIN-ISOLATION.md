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
kernel-process unsafe tokens: 621
```

`just tcb-report` checks that figure against the measurement rather than
trusting this paragraph: a revision of this document said 617 here and 621 forty
lines later, which is what a hand-maintained number does.

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
   It ships no loader, no transport, and no `unsafe`, and nothing depended on it
   yet — in particular `nemo-relay` did not, until increment 2.

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
  The coarse class is gone: it is replaced by the attachment point below, and a
  registration the runtime cannot place is worse than a missing one, because a
  proxy would be built and then behave unlike the plugin it stands for.
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
- **Structured lifecycle outcomes.** `Load`, `Unload`, `Inspect`, `Health`,
  `CancelOperation` and `Handshake` answer with a oneof whose arms are the
  success payload and a `PluginFailure`, so `AlreadyLoaded` or `StaleHandle`
  travels as a result rather than as a gRPC status. A message carrying neither
  arm is refused as malformed, because saying nothing is not the same as
  reporting a failure, and the distinction is what stops a lost response from
  being read as a definite negative. The handshake's success arm is a new
  `PluginSessionIdentity`: the session identity was on the wire with no domain
  counterpart, so the kernel had nothing to validate before naming a session,
  and the frame limit the host offers is now checked against this side's own
  rather than adopted.
- **The attachment point of every native registration.** The native ABI has
  fourteen registration hooks, and each installs its callback somewhere
  different; "it registered a guardrail" cannot install a proxy at the right
  place. `PluginRegistrationOperation` names the exact attachment point, the
  loader records it inside the host function that performs the registration —
  the only place it is known — and `InProcessPluginBackend` reports what the
  loader recorded instead of a hard-coded empty list. The ordering fields became
  optional in the same change, because the ABI declares a priority for some
  hooks and a chain answer for fewer still, and a default would be a claim
  nobody made. A gate records one entry per kind it gates and carries the
  registration it decides; a gate the plugin removes through its runtime
  handle is dropped from the record, so the description cannot name a
  registration that no longer runs.

  The ABI v4 callback inventory, each hook mapped to exactly one attachment
  point:

  | Native host callback | Attachment point |
  |---|---|
  | `plugin_context_register_subscriber` | `Subscriber` |
  | `plugin_context_register_async_middleware` (kind 0–14) | the kind's own point: tool and LLM request/response sanitizers, tool and LLM conditional execution, tool and LLM request and execution intercepts, mark and scope sanitizers, event metadata injector |
  | `plugin_context_register_async_stream_middleware` | `LlmStreamExecutionIntercept` |
  | `plugin_context_register_tool_sanitize_request_guardrail` | `ToolSanitizeRequestGuardrail` |
  | `plugin_context_register_tool_sanitize_response_guardrail` | `ToolSanitizeResponseGuardrail` |
  | `plugin_context_register_tool_conditional_execution_guardrail` | `ToolConditionalExecutionGuardrail` |
  | `plugin_context_register_tool_request_intercept` | `ToolRequestIntercept` |
  | `plugin_context_register_tool_execution_intercept` | `ToolExecutionIntercept` |
  | `plugin_context_register_llm_sanitize_request_guardrail` | `LlmSanitizeRequestGuardrail` |
  | `plugin_context_register_llm_sanitize_response_guardrail` | `LlmSanitizeResponseGuardrail` |
  | `plugin_context_register_llm_conditional_execution_guardrail` | `LlmConditionalExecutionGuardrail` |
  | `plugin_context_register_llm_request_intercept` | `LlmRequestIntercept` |
  | `plugin_context_register_llm_execution_intercept` | `LlmExecutionIntercept` |
  | `plugin_context_register_llm_stream_execution_intercept` | `LlmStreamExecutionIntercept` |
  | `plugin_context_register_conditional_middleware_guardrail` (+ `_callback`, and the runtime-handle pair) | one entry per gated kind, with the gated registration named |

  A native fixture registers on every one of those surfaces, and the test
  asserts the recorded set is exactly the sixteen attachment points and nothing
  else.

- **The duplex channel, and what a registered callback needs while it runs.**
  Most calls between the two sides are one request and one answer, and those
  keep one typed representation each. Two families are not. A completion is
  settled *after* the callback that produced it has returned, so its answer
  belongs to no call in flight, and the kernel also has to tell the plugin that
  the awaiting runtime cancelled it. A downstream stream is opened, pulled one
  item at a time by the plugin, and may be cancelled or released while a pull is
  outstanding, so its pace is the plugin's and cancellation travels the other
  way. `RelayRuntime.Session` carries both, with a session id, a call id, an
  operation id and a stream id on the messages that need them, and the
  conversions refuse a message that names no session, no stream, no completion,
  or an empty payload. The chain continuation — a plugin's "run the rest of the
  chain" — is `RelayRuntime.Continue`, a typed request, because it is exactly
  one request and one answer with nothing pushed in between.

  The complete ABI-v4 host callback inventory, each callback classified by how
  it reaches the other side. Nothing here is left unnamed: the operations that
  are not yet on the wire say what they need rather than waiting to be
  rediscovered.

  | Native host callback | Remote representation |
  |---|---|
  | `plugin_context_register_*` (fourteen hooks, above) | registration descriptors with the attachment point |
  | `plugin_runtime_register_conditional_middleware_guardrail` (+ `_callback`), `plugin_context_register_conditional_middleware_guardrail` (+ `_callback`), `plugin_runtime_deregister_conditional_middleware_guardrail` | registration descriptors, one entry per gated kind, dropped when the gate is removed |
  | `async_completion_resolve_json`, `async_completion_reject` | session `CompletionSettle`, answered by `CompletionOutcome` so a settlement that was already cancelled is refused rather than silently dropped |
  | `async_completion_is_cancelled` | session `CompletionCancelled`, pushed by the kernel |
  | `async_next_invoke`, `async_next_invoke_result` | `RelayRuntime.Continue` |
  | `async_next_open_llm_stream` | session `StreamOpen` → `StreamOpened` or `StreamOpenFailed` |
  | `async_llm_stream_pull` | session `StreamPull` → `StreamItem`, `StreamEnd` or `StreamFailed` |
  | `async_llm_stream_cancel`, `async_llm_stream_release` | session `StreamCancel`, `StreamRelease` |
  | `async_stream_push_json`, `async_stream_finish`, `async_stream_reject` | `InvokeStream`'s `StreamChunk` |
  | `async_stream_is_cancelled` | `CancelOperation`, which the host reports to the plugin |
  | `scope_get_current`, `scope_push`, `scope_pop`, `scope_handle_free`, `scope_stack_create`, `scope_stack_free` | `ScopeStack` typed request with a closed `ScopeOperation` (`Current`, `Push`, `Pop`, `CreateIsolated`, `ReleaseIsolated`) — the set the ABI exposes, so a peer cannot manufacture one; a payload is accepted exactly where the operation carries one |
  | `emit_mark`, `emit_mark_v2` | `EmitMark` typed request carrying the whole v2 payload — parent scope, metadata, schema, severity and timestamp included — with the scope named by its canonical UUID and a negative timestamp refused |
  | `llm_request_codec_encode`, `llm_request_codec_decode`, `llm_response_codec_decode`, `async_completion_llm_*_codec_*` | `ResolveCodec` typed request with a closed `CodecOperation` naming one of the three |
  | `async_next_invoke_stream` | session `ContinuationChunk` (kernel → plugin, one-based `sequence`) and `ContinuationChunkDisposition` (plugin → kernel: `Continue`, `Stop`, or a failure). The kernel does not produce chunk N+1 until the disposition for N permits it, which is what the callback's return value means in process |
  | `async_stream_is_backpressured` and the `Backpressured` status | session `OutputCredit`: the kernel grants items, the host reports "the producer may continue" exactly while it holds credit, and a frame sent past the grant is refused |
  | `get_runtime_diagnostics`, `plugin_runtime_list_registrations` | **decided, not yet served**: each is a read capability (`RuntimeDiagnostics`, `RegistrationInventory`) that the kernel grants in the handshake. Requesting one is not being granted it, an unknown capability is refused rather than dropped, and the default grant is empty |
  | `scope_stack_set_thread`, `scope_stack_capture_thread`, `scope_stack_restore_thread`, `with_scope_stack` | host-local: they bind a runtime-issued stack to a thread inside the host process |
  | `string_new`, `string_data`, `string_len`, `string_free`, `last_error_clear`, `last_error_set` | host-local: allocation and the plugin's error channel inside the host process |
  | `async_completion_release`, `async_completion_retain`, `async_next_release`, `async_stream_release`, `plugin_context_runtime`, `plugin_runtime_retain`, `plugin_runtime_release` | host-local: reference counting for handles the host owns |

  Three invariants the inventory implies, stated so they can be checked rather
  than assumed:

  - **Backpressure means the same thing on both sides.** In process, a full
    bounded queue makes the push return `Backpressured` and the plugin retries.
    Remotely, that sentence is only equivalent if the capacity is explicit, so
    it is: `OutputCredit` grants items, the state machine refuses a frame sent
    past the grant, and the kernel grants more as it consumes. Transport flow
    control stops being asked to mean something it does not say.
  - **A settlement is answered.** A plugin that settles a completion learns
    whether the settlement was taken, so a completion that was already
    cancelled cannot leave the callback's owner waiting forever.
  - **A sequence binds an answer to a chunk.** Chunks are one-based and
    per-call, and the kernel produces the next one only after the disposition
    for the current one arrives; an answer naming sequence zero is refused at
    the boundary.

  Conversion is the only legal crossing point, and the manifest in
  `crates/plugin-proto/tests/conversion_coverage.rs` is what enforces that it
  stays exhaustive: every message a service signature or the session envelope
  can carry is listed with the converter that owns it, the vector that records
  its bytes and the tests that refuse a malformed version, and the build fails
  when a message reaches either without an entry. The same file refuses an
  `impl From` for a wire type, so a later `.into()` shortcut cannot compile.

- **The session state machine.** Conversions refuse a message that cannot mean
  what it says; they cannot refuse one that does not fit what came before it.
  `nemo_relay_plugin_host::session` holds the kernel's view of one session and
  the invariants that need memory: a completion settles once and never after it
  was cancelled, a completion identity the kernel never created is refused
  rather than believed, a pull is answered exactly once and only by the call
  that made it, one pull is outstanding per stream, a second pull waits, an item
  after the terminal frame is refused, a cancelled or released stream produces
  nothing, a chunk is produced only when the disposition for the previous one
  arrived and the sequence is exactly the next one — so a replay, a regression
  and an answer to a chunk nobody sent are one rule — and a call identity cannot
  be outstanding twice. Completions carry the operation that owns them so
  `forget_operation` can release everything an operation held, which is what
  keeps a long-lived session from accumulating a record per callback.

  It is deliberately not a transport and not a driver: it takes the domain
  messages the conversions produced and answers whether they fit, so the
  supervisor that owns the socket and the callbacks can stay about those.

## Production cutover: the remaining work, written down

Everything the cutover needs now exists and is tested; what remains is moving code.
The list is here so the next session starts from a checklist rather than from
archaeology, and so the ordering constraints are not rediscovered by breaking them.

**What holds the metric up.** `libloading` reaches the kernel through exactly one
edge, declared in `crates/core/Cargo.toml`. Behind it, `crates/core/src/plugin/dynamic/native.rs`
is 6,455 lines with 280 `unsafe` occurrences, and core depends on
`nemo-relay-plugin` for the ABI structs (252 more). Those two are 595 of the 621,
so the number falls by the loader leaving rather than by any reclassification.

**Why it cannot be done in pieces.** The loader calls core's runtime APIs to
serve plugin callbacks — marks, scopes, codecs — and registers into core's
registries, so it cannot be lifted into another crate while staying where it is.
The move has to happen together with the composition change.

**Step one: the ABI and the loader become their own crates.** The ABI types move
out of `nemo-relay-plugin` into a crate both the SDK and the loader depend on;
the loader and its host adapter move into a crate depending on core. Core then
declares neither `libloading` nor `nemo-relay-plugin`. Wide but mechanical: the
SDK, the two native fixtures, the Rust example, and the loader's own tests all
name these types.

**Step two: core's activation path moves behind a facade in `plugin-host`.**
`crates/core/src/plugin/dynamic/` has to split into the kernel's interface and
the implementation: `host.rs` (11 public items), `manifest.rs` (45), `native.rs`
(23) and `registry.rs` (16). `load_native_plugins`, `NativePluginActivation` and
`plugin_artifact_identity` are named from three core test files, `plugin-host`,
and — through `PluginHostActivation` — the CLI, FFI, Node and Python. The facade
is what those consumers call instead, and a crate implementing a core-owned trait
has to depend on core, which is why this cannot be folded into step one.

**Step three: production selects the process backend.** The CLI stops composing
`LoadedPlugins` and the three bindings stop calling
`activate_with_discovered_config`. This is the step the metric waits on: until
shipped runtimes stop linking the loader, moving it changes a crate diagram and
not an attack surface. It is also the step with three language test suites
attached, and the one the cross-process tool call now qualifies.

**Step four: re-measure and record.** Remove the moved crates from
`[in_process]`, update `security/tcb.toml` and `security/BASELINE.md` with the
new surface, and expect the number to land near 26 — the loader's 280 and the
ABI's 252 having left, rather than having been renamed.

Still open, in the order they need closing:

1. **Serving the read capabilities.** Diagnostics and registration reads are
   negotiated in the handshake but nothing serves them yet; deciding what they
   may return is the kernel's authorization step, not a conversion step.
2. **Invocation, and the session channel behind it.** Nothing asks a host to
   invoke anything yet: a loaded plugin registers into the runtime's own
   machinery, so the lifecycle operations are the whole of what crosses today.
   When invocation arrives it needs the duplex session — the state machine is
   written and waiting for a driver, and the host needs its own bookkeeping for
   the same invariants from the other side, because a host that trusted the
   kernel to pace it would be trusting the side the boundary exists to distrust.
   Restarting is explicit rather than automatic: a host that exits is reported
   as `HostCrashed`, the backend can replace it, and the kernel decides whether
   to keep using the replacement, because only the kernel knows what the
   previous session was holding.

   The work decomposes into four pieces, in this order, because each needs the
   one before it:

   1. **A registration operation on the wire.** Registration is config-driven:
      the kernel initializes a plugin's components and the callbacks arrive
      then. In process the kernel both sends the configuration and receives the
      registrations, so the wire needs an operation that carries a component
      configuration to the host and returns the descriptors its registrations
      produced. `Load` cannot do it: it has no configuration to send and runs
      before any component exists.
   2. **Invoking one registration by name.** The kernel installs one proxy per
      reported registration, at the priority the plugin declared, and each proxy
      has to run *that* registration. Running the host's local chain instead
      would run every registration the plugin made on each call, so the host
      needs a narrow entry point in core — invoke the registration named N of
      class C with this input. Core's chain entry points are keyed by name and
      are not that.
   3. **The proxy, and `invoke` on the seam.** The kernel-side proxy is most
      naturally a `Plugin` implementation in `plugin-host` registering through
      `PluginRegistrationContext`, which is already public; the trait gains
      `invoke`, returning an outcome carrying `dispatch_state` and
      `outcome_certainty` so a channel that dies after a plugin may have
      dispatched becomes `UNKNOWN` rather than `FAILED`.
   4. **One class, then the next.** A unary class end to end — a tool request
      intercept is the smallest complete one — with the conformance suite
      extended to run it against both backends. Then continuations, deferred
      completions, pull streams, streaming intercepts and dynamic
      registrations, in that order, so no two state machines arrive at once.

   The `invoke` and `invoke_stream` RPCs already answer with structured refusals,
   so a host that cannot serve an invocation says so rather than looking like an
   empty success.
3. **Migrate Node, Python and FFI** off `PluginHostActivation`, which the
   architecture guard currently grandfathers by crate name.
4. **Resource limits beyond process separation and the deadline.** The child
   gets a filtered environment, its own socket directory and a kill at expiry;
   memory, file and child limits, platform sandboxing and destination network
   policy are not applied yet, and capabilities do not declare the profile they
   need.
5. **A production composition that states the managed caps.** The runtime now
   publishes a trusted budget on the real managed paths, and resolves it from
   the smallest of the inherited deadline, the durable lease expiry and the
   configured cap. Nothing composes a production plugin path yet, so nothing
   requires a production deployment to state those caps: an unstated cap
   publishes no budget, which a registration across the boundary refuses — fail
  closed, but silent until the composition that owns the decision exists.
6. **A consequential capability that actually runs a plugin.** The conversion
   from a plugin failure to a durable outcome exists and is tested against the
   kernel, but nothing in the tree composes a plugin-backed effect, so the
   conversion has no production caller yet. That is the provider-isolation
   milestone rather than a gap in the contract.

After invocation, the cutover milestones are what move the metric: production
selects the process backend and refuses the in-process one, the bindings stop
reaching the loader at all, and the native loader and its `unsafe` leave the
kernel's dependency graph. Only then does `kernel-process unsafe tokens` fall
from 621, by the loader's own weight rather than by reclassification.

## The process boundary

The boundary exists. `crates/plugin-host` builds `nemo-plugin-host`, which loads
native plugins and serves the kernel's lifecycle operations; the same crate
holds the supervisor that starts it and the backend that reaches it.

- **Spawn and handshake.** The supervisor creates a directory only it can read
  (`0700`), passes the socket path, a credential generated for that one session,
  the runtime binding digest and the protocol version through a filtered
  environment, and waits for the socket rather than sleeping a fixed time. The
  child serves the socket; stdout and stderr stay logs and never carry the
  protocol.
- **The approved artifact is the loaded artifact.** The kernel computes the
  manifest and library digests, the request carries them, and the host verifies
  both against the files it is about to open, immediately before the loader
  opens them. A mismatch is refused, and the descriptor reports the digest that
  was verified, so the approved identity, the verified identity and the reported
  one are the same value. An end-to-end test loads a real fixture through a real
  child, mutates one digest, and asserts the child refuses it.

  The verification lives in the loader rather than in its caller, because the
  loader is where the open happens: the manifest is read once and parsed from the
  bytes that were hashed, and the library is hashed through an open handle before
  its path is handed to `dlopen`. After the library is mapped, its path is hashed
  again: a change in that window means the loaded file is not the verified one,
  and the load is refused rather than attributed to the plugin. That is
  detection, not prevention — `dlopen` resolves a path, so preventing the swap
  outright would mean loading from a copy in a directory this process owns, which
  would change `@loader_path` for plugins that resolve resources relative to
  themselves. That is a decision about the plugin-loading contract rather than a
  hardening detail, so it is written down here instead of taken silently.
- **What the handshake binds.** Protocol version, runtime binding and frame
  limit are all checked on both sides. A host started under one runtime is
  refused by another, and a host that accepted a read capability it was not
  offered is refused rather than believed: the offer is the kernel's decision,
  and the host can only accept or decline.
- **Both sides validate the context.** The kernel refuses before it dispatches
  and the host refuses before it acts, through one shared validator: protocol
  version, request identity, runtime binding against the session's, response
  budget within the frame limit, a non-zero budget, and a deadline that has not
  passed. A peer that reaches the service with a structurally valid but
  semantically unusable context is rejected by the host rather than only by the
  side that happened to check first.
- **An answer names the invocation it answers.** The host states the operation
  it accepted in the outcome it returns, and the kernel checks that name instead
  of trusting the channel to have kept the pairing: an answer naming a different
  operation, or naming none, is refused as malformed rather than attributed to
  the call that asked. The host holds the same rule from its side — an invocation
  whose context names no operation is refused at the transport level, because an
  outcome nobody can attribute is not an answer, and answering in that message's
  shape would invite the kernel to read it as one. Correlation that lives only
  inside the transport is a property of the channel; a protocol that wants to be
  checkable has to carry it. This is the one wire change so far, so the recorded
  `InvokeOutcome` vector moves with it — `vectors.json` is regenerated
  deliberately, and the diff is the new field and nothing else.
- **The lifecycle is a contract, not a convention.** `PluginLifecycle`
  (`Absent`, `Loading`, `Loaded { generation }`) and the two rules that say what
  each state admits live in the contract crate, and the in-process backend asks
  them instead of deciding for itself: a backend that answered the wrong code
  would be a backend its caller cannot act on, and two implementations that
  disagreed would make the same request succeed or fail depending on which one
  was composed. `Loading` is a reservation rather than a status report, because
  a second load that also saw "not loaded" would run the loader twice and leave
  one instance unreachable. There is no `Unloading` state: an unload takes the
  instance out of the table while it holds the lock, so nothing can observe it
  half-removed, and a state no reader can observe would be a claim about
  concurrency that no reader could check.
- **The shared suite walks the lifecycle, on both backends.** `check_lifecycle`
  loads a real fixture, refuses an unapproved artifact and then loads the
  approved one — which is what proves a failed load released its reservation —
  inspects the handle, refuses another generation as `StaleHandle`, refuses a
  duplicate load as `AlreadyLoaded`, unloads, proves the identifier is now
  `UnknownPlugin` *rather than* stale, reloads, refuses the old handle as
  `StaleHandle` now that an instance exists at another generation, and leaves
  nothing loaded. The same function runs against `InProcessPluginBackend` and
  against a real child, so a case added for one is a case for the other. Verified
  by collapsing `StaleHandle` into `UnknownPlugin` in the contract and watching
  both runs fail — the distinction between "never there" and "not there any
  more" is the thing the suite exists to hold.
- **The other direction exists.** The protocol's service pair has always been
  two-sided, and only one side was served: the host answered the kernel, and a
  plugin's own host functions had nowhere to go, so a mark a plugin emitted went
  into the child's copy of the runtime and stopped there. The kernel now serves
  `RelayRuntime` on a second socket in the same private directory, bound before
  the child starts so the path it is told about exists by the time it could want
  it. The credential is a header rather than a payload field — it belongs to the
  channel — and the service refuses a caller without it even when the caller
  names the right session, which is the property the test asserts. `EmitMark` is
  served in full: the mark is resolved against *this* runtime's scope stack,
  converted through the same validator the wire uses, and emitted into this
  process's event stream, so a subscriber here sees a mark a plugin raised in
  another process. The parent is resolved under the lock and used after it is
  released, so emitting cannot deadlock against a lock the emit itself takes. A
  mark naming a scope this runtime does not have is refused rather than dropped
  or re-parented: a mark attached to the wrong scope is a different event than
  the one that was asked for. The other four operations are refused by name
  (`unimplemented`) rather than answered as empty successes, and arrive with the
  pieces that serve them — the scope and codec reads with the read capabilities,
  the continuation and the duplex channel with the session driver.
  **The host does not call back yet.** It is told the endpoint and given the
  credential, and nothing in the child uses them; the routing that makes a
  plugin's host functions cross is the next piece, and until it lands this is the
  kernel being able to answer rather than the boundary being used.
- **Routing a mark back, and the hop that is not covered yet.** The host now
  connects to the kernel at startup and forwards the marks its plugins raise:
  core has a `MarkForwarder` seam that a host installs around a callback and the
  child drains one channel with a flush step, so a mark is delivered *before* the
  answer that ends the invocation, and a mark that could not be delivered fails
  the invocation rather than disappearing. Attribution is explicit rather than
  guessed: the kernel's proxy registers an in-flight operation in
  `OperationScopes` while a registration runs, the service emits a forwarded mark
  inside that operation's scope, and a mark for an operation nothing is running —
  or one naming a scope from the host process — is refused rather than attached
  to whatever scope happened to be current on the server task. Kernel-side tests
  cover the credential, the session, attribution, an unnamed mark, a payload that
  is not JSON, and both refusals. **The end-to-end path does not work yet, and
  the reason is structural rather than a detail:** the SDK's `PluginContext`
  spawns a plugin's callback body onto its own executor
  (`crates/plugin/src/…`, `executor.spawn(...)`), so the callback runs in a task
  the host's forwarder window does not cover — a task-local set around the
  host's `invoke` is lost at that hop, and the mark lands in the child's own
  runtime exactly as before. Every seam below that hop is tested; the gap is the
  hop itself.
- **An additive observer crosses, with the family's failure rule.** Metadata
  injectors are servable: the kernel sends the event its dispatcher is about to
  publish, the child answers with the keys it wants added, and the kernel inserts
  them into that copy. Nothing an injector returns can reach the call that produced
  the event, which is the same guarantee the sanitizers carry and the reason the
  class is safe to run elsewhere. Its failure rule is the opposite of a sanitizer's
  and comes from the in-process chain rather than from here: **an injector that
  cannot answer preserves the event and continues without injection** — a
  sanitizer withholds a payload it could not sanitize, an injector adds nothing it
  could not compute — so a failure is recorded (`nemo.plugin.metadata.failed`)
  rather than made fatal, because an additive hook must not become a way to stop a
  runtime from publishing. The answer is also checked at the boundary: metadata is
  a JSON object, and anything else is refused rather than coerced into one. The
  test proves three things at once — the tool's own result is unchanged, the
  published copy carries the child's key, and the whole thing runs on a
  single-threaded caller.
- **A decision crosses, and that is its own kind of class.** Tool conditional
  guardrails are servable: the kernel sends the tool and its arguments, the child
  runs exactly the named registration, and the answer is the decision — a reason
  to refuse or nothing to allow. The kernel's own chain reports that as a
  rejection, and the guardrail's scope events are emitted by that chain around the
  *proxy* entry with the kernel's subscribers, so a remote guardrail looks exactly
  like an in-process one in the event stream. The test proves both halves: the
  call proceeds for a tool the fixture allows, and one the fixture refuses comes
  back as `GuardrailRejected` carrying the reason the child gave. That is the third
  behavioural category to cross — rewrites, observations, and now decisions — and
  it is the first class where the child's answer can stop the call.
- **A second class crosses: LLM request intercepts.** The same shape as the tool
  class, one level up. The kernel sends the invocation its own chain holds — the
  request *and* the annotation a codec produced, because a callback may rewrite
  either — and the child runs exactly the registration the kernel named. The
  outcome travels back whole, marks and evidence included, because an invocation
  that dropped those would not be the invocation the kernel's chain makes; that is
  also why this class was not treated as "generic JSON host call". Two things the
  composition test now proves: a plugin that registers both servable classes
  loads through `ProcessLoadedPlugins` with both registrations proxied, and an LLM
  request through this chain comes back rewritten by native code in the other
  process, under the same trusted budget the tool chain uses. What the kernel
  still owns is unchanged — ordering, priority, chain-break, budget and
  registration identity — and what the child owns is still "execute this exact
  registration". A plugin that registers anything else is still refused whole,
  which is the honest state until the remaining classes cross.
- **One composition, and a test that keeps it that way.** A new architecture
  check refuses `ProcessPluginBackend::launch`, `PluginHostSupervisor::spawn` and
  `proxy::install` outside `plugin-host`, so the CLI, FFI, Python and Node cannot
  each grow their own lifecycle semantics: they compose `ProcessLoadedPlugins` or
  they load in process.
- **A runtime can select the process backend.** `ProcessLoadedPlugins` is the
  composition that decision implies, in the order the boundary requires: start a
  host and handshake, load each approved artifact through the backend rather than
  through a loader in this process, activate the components each plugin was
  loaded for — so its register callbacks run where its library is — and install
  one proxy per registration the host reported, at the priority the plugin
  declared. It fails closed on a plugin whose registrations this kernel cannot
  serve: a load reporting success while a callback disappeared is worse than a
  refused load, because the plugin would believe it had registered something the
  runtime never calls. Lifecycle operations carry the session's own runtime
  binding and a bounded budget rather than a placeholder, so the checks the host
  enforces stay meaningful; the registration cap is a parameter and zero is
  refused, since "no time at all" is not a limit anybody means. Dropping the
  composition removes the proxies and kills the host, so a plugin's callback
  cannot outlive the runtime that installed it. **The CLI and the bindings do not
  select it yet**, and should not: the process backend refuses a plugin whose
  registrations it cannot all proxy, and the ABI covers one class today, so a
  cutover now would trade a working loader for a regressed plugin set. This is the
  piece the cutover will adopt once the classes cross.
- **The transport enforces the negotiated frame limit.** Client and server
  decoders are configured from the same value the handshake negotiates, so the
  limit is enforced rather than declared.
- **Deadlines.** Every operation is sent under its remaining budget, computed
  from the context the kernel derived rather than from anything the caller
  chose; a budget that has already passed means no request is sent at all, and a
  budget that passes mid-operation kills the process instead of asking a plugin
  to honour a cancellation token. A kill is reported as `DeadlineExceeded`, not
  as a crash.
- **Where that budget comes from.** A managed call publishes the smallest of
  three sources — the deadline its parent published, the durable action lease's
  *expiry*, and `now` plus the runtime's configured cap for that kind of call —
  and refuses to start when a source that exists has already passed. A lease
  contributes an expiry rather than a duration, because `now + 30` computed at a
  later layer is a lease silently extended, and a callback that started under one
  expiry keeps it even if another task renews the lease behind it. A call with
  none of the three publishes nothing: work that stays in process is unaffected,
  and a registration across the boundary refuses, since a deadline chosen inside
  the plugin path is the invention the trusted budget exists to prevent. Two
  gaps are named rather than hidden: nothing in the tree *states* the caps yet
  (item 5 above), and the streaming LLM path does not publish a budget, which is
  safe only because no remotely supported registration class is reachable from
  it. The kernel's own `kernel_deadline_unix_ms` still hard-codes 29 seconds for
  an action's deadline; that constant is the same shape of finding and moves when
  runtime policy owns the action budget rather than the per-call cap alone.
- **Uncertainty survives the crossing into a durable record.** A plugin failure
  that may have dispatched is not a failure the kernel may treat as definite, and
  the conversion from one to the other is now a single function rather than a
  rule every adapter re-derives. The dispatch state and the certainty the plugin
  boundary established are *copied* — not recomputed from the failure code, since
  a second derivation is a second place to get certainty wrong — and the
  reconciliation flag is itself derived from the state the kernel will compute,
  so two readers of one failure cannot disagree about whether anyone can still
  say what happened. Two kernel tests pin the halves: a plugin that may have
  dispatched becomes durable `UNKNOWN`, and retrying returns the same action
  without reaching the plugin a second time; a refusal *before* the backend
  finishes the action as a definite failure. Nothing in the tree calls the
  conversion yet (item 6 above), so this is the join being correct rather than the
  join being used.
- **Failure vocabulary.** A transport failure is reported as `HostCrashed` when
  the child has exited and as `Unavailable` when it is still running. The two
  call for different responses — one is a process that ended, the other is a
  message that did not arrive — so they are never collapsed.
- **Restart, without implying continuity.** A crashed host can be replaced, and
  the replacement holds nothing: a new session, nothing loaded, and a handle
  from before the crash addressing nothing. Restarting with the previous plugins
  in place would imply a continuity the crash took away, and the loaded set is
  the kernel's record rather than the backend's.
- **Lost transport integrity ends the session.** A channel that breaks while the
  host is still running leaves nobody able to say whether it acted on the
  request, so the host is killed rather than kept: the session's state becomes
  certain again, which is what restarting from nothing depends on.
- **Startup is one budget.** The socket appearing and the handshake completing
  are covered by the same timeout. A host that binds, accepts and then never
  answers is killed and its directory removed, rather than holding `spawn` open.
- **The support set is derived, not supplied.** `ProcessPluginBackend` says which
  registration classes it can proxy; a caller cannot enlarge it, because a
  caller that could declare support the backend does not have would break the
  guarantee that a load which cannot be served does not happen.
- **A stuck host is killed at the deadline.** The test stops the host process
  mid-session — the socket stays open and nothing will ever answer on it — and
  asserts the operation ends as `DeadlineExceeded` rather than as `HostCrashed`,
  because the kernel is the one that ended the process. The child is reaped, not
  abandoned, so nothing is left holding a socket nobody will read.
- **Closing is an outcome too.** `SessionClose` answers with a failure arm like
  every other lifecycle operation. It was the last one reporting a refusal as a
  transport status, which is the conflation the rest of the schema exists to
  prevent.
- **One suite for both backends.**
  `crates/plugin-host/tests/process_backend.rs` spawns a real host and runs the
  same conformance suite the in-process backend runs, so "implements the
  contract" is demonstrated rather than asserted. The same file kills a host
  mid-test and asserts the kernel survives it.
- **The architecture gate reads the workspace.** It enumerates members from the
  workspace manifest rather than a list someone has to remember to extend, so a
  new crate that loads a library is caught the moment it exists, and it checks
  the dependency side too: only one crate may declare the dynamic loader, and the
  kernel may not depend on the implementation of its own seam. Widening it found
  a false positive worth naming — the SDK declares the ABI's entry-point type,
  which is a signature rather than a load — and the token list no longer treats
  it as one.

### Mark and scope sanitizers: the projection design

The next class, written down because its first question is not the one the other
sanitizers asked. A payload sanitizer crosses as `(name, Json) -> Json`; these three
families — mark sanitize, scope-start sanitize, scope-end sanitize — are
`(Arc<Event>, EventSanitizeFields) -> EventSanitizeFields`, and the obvious
implementation, serialising the event, is the wrong one: it would ship the runtime's
whole internal event to a plugin because that is convenient for the host.

**What crosses is a projection.** The immutable identity a sanitizer decides on —
the event's name, whether it is a scope or a mark, and the scope phase when it is a
scope — plus the mutable observability fields it may change (`data`,
`category_profile`, `metadata`). Nothing else: not the uuid, not the timestamps, not
the propagation root. A sanitizer that needs more than that is asking for capability
it has not been given, and that should be a decision rather than a default.

**How the host runs it, and why that is the whole design.** The runtime's sanitizer
chain runs on an `Event`, not on fields, so the host *synthesises* an event from the
projection — name, kind, scope phase, fields — runs the chain with one entry against
it, and returns the fields. That is honest under the projection contract precisely
because the projection is what the sanitizer was promised: the synthetic event is
what it was told it would see, and the sanitized fields are the only thing that
crosses back. If the host instead serialised the real event, the projection would be
decoration, and the class would be carrying the whole runtime object over the
boundary for the sake of convenience.

**Failure is the sanitizer rule, not the injector's.** A sanitizer that fails or
cannot answer clears the mutable observability fields, so the event is still
published with no payload: a payload that could not be sanitized is not published
unsanitized. `nemo.plugin.sanitize.failed` already exists for this family and names
the registration and the reason, which is why the class arrives with its diagnostics
rather than needing them built.

**One shape, three registries.** The three families differ only in which registry a
registration lives in and how the runtime collects them; the payload, the answer,
the failure rule and the projection are identical, so this should be one installer
and one host branch parameterised by class rather than three copies.

**The projection needs a test that fails when the event grows.** The property here
is not "serialisation works" — it is that *the fields on the wire are exactly the
sanitizer-visible fields somebody approved*. Without a test, an internal field added
to `Event` later would appear to native plugins automatically, which is disclosure
by accident rather than by decision. So the increment includes a test that fails if
the projection stops matching its approved field list, in the same spirit as the
conversion-coverage manifest: adding a field to the projection is then an edit
somebody makes on purpose, and adding one to `Event` is not enough to leak it.

### The off-path client: the plan, including the two bugs I hit

The attach is in. This is what comes next, written down because I attempted it
twice and reverted twice, and both failures were mine rather than the design's.

**What it is for.** Subscribers, sanitizers, metadata injectors and mark/scope
sanitizers are all invoked by the *dispatcher*, off the call's own task. On a
single-threaded caller runtime the thread that would answer them is the thread
waiting for them, so they are refused there today (`install_tool_sanitize`) and
work only on a multi-threaded caller. A transport whose tasks live on the off-path
runtime removes the restriction for every one of those families at once, which is
why it is worth more than another class.

**The shape.**

- `attached.rs`: `ConnectionDescriptor { endpoint, session_credential,
  runtime_binding_digest, session_id, maximum_frame_bytes }`, and
  `AttachedClient::connect(descriptor)` which connects **and constructs the Tonic
  client on the runtime that calls it**, then `Attach`, then checks the joined
  session's `session_id`, `negotiated_frame_limit` and `runtime_binding_digest`
  against the descriptor. Its `invoke` checks the deadline before sending and reads
  the answer with `invocation_answer_from_wire`, and it returns
  `PluginInvocationError` — phases preserved. Do **not** route it through
  `PluginExecutionBackend` to keep the "manager is the only path" rule: that trait
  returns `PluginProtocolError`, which flattens the phase into text, which is the
  exact regression an earlier commit removed.
- `off_path.rs`: the executor gains `descriptor: Option<ConnectionDescriptor>` and
  `attached: Mutex<Option<Arc<AttachedClient>>>`; `attach_to(descriptor)`;
  `attached()` submits the connect *on the executor runtime* and caches the result;
  `invoke()` delegates to the client.
- `supervisor.rs`: `connection_descriptor()`. Store the credential and binding at
  spawn — `PluginSessionIdentity` does **not** carry the binding, so it cannot be
  read from the session.
- Composition: launch the backend **first**, then
  `OffPathPluginExecutor::start(&policy)?.attach_to(backend.connection_descriptor())`.
- Routing: sanitize proxies and observer deliveries go through `off_path.invoke`.
  The observer's drain loop must be spawned with `spawn_long_lived` on the off-path
  runtime.
- Remove the single-threaded refusal in `install_tool_sanitize`.

**Bug one.** `invoke_request_to_wire(request, session_id, context)` takes the
*session* id in its second argument. I passed `context.operation_request_id`, and
the host refused with "this request names a session this host did not establish" —
the check working, and a reminder that the wire's session field and the context's
operation field are easy to confuse.

**Bug two.** Routing the wiring up but leaving the observer's drain loop on
`Handle::current()` at install time looks correct and silently delivers nothing: on
a single-threaded caller the loop's runtime never runs. Moving the loop to the
off-path runtime is what made the observer witness pass.

**Acceptance.** Flip `the_composition_installs_a_plugin_from_another_process_into_this_chain`
and `a_real_tool_call_reaches_a_registration_inside_the_child` back to
`#[tokio::test]` (current-thread) and require: the tool executes, the event copy is
sanitized, the tool result is unchanged, and nothing times out. Then: an
unavailable off-path transport makes a sanitizer fail closed *and* record
`nemo.plugin.sanitize.failed` with the reason, while the primary call still
completes.

**Landed.** The client is in: `OffPathPluginExecutor::attach_to(descriptor)` and a
lazy `attached()` that submits the connect *on the off-path runtime* and caches
the transport, with sanitize proxies and observer deliveries routed through
`off_path.invoke`. The acceptance passes — both process-boundary tests run on a
current-thread runtime, the event copy is sanitized, the tool result is unchanged,
and nothing times out. The single-threaded refusal is gone, because the reason for
it is.

The sanitize timeout that defeated two attempts was exactly what the plan
predicted it would be: the *work* had moved to the off-path runtime while the
*connection* stayed on the caller's, so the reply had no thread to arrive on. The
transport primitive landed on its own first (`feat(plugin): land the transport a
second connection needs`), and the rerouting that followed it was then a small
change rather than a third attempt at both.

### The off-path client needs an attach, and the host does not have one yet

The verification the transport-affinity work depends on, done before building any
second connection, and it has a security-relevant answer.

**The host's session state records no transport.** `HostSession` is `New`,
`Active { session_id, supported_registration_operations }` or `Closed`, and every
request is authorised by `established(session_id)` plus the context checks. The
credential is checked in exactly one place: `handshake`, which is also the only
thing that can move `New → Active`. So the model today is "one session, one
connection, and the connection is the one that handshook" — not because the state
machine enforces it, but because nothing has ever opened a second one.

That has a consequence for the off-path client, and it is not the one the plan
assumed. A second connection to the same socket can already serve the live
session **without presenting the credential**: it never has to handshake, because
`invoke` only asks whether the session exists and whether the context matches it.
Today that is difficult to exploit — the session identity is a fresh UUID and the
socket lives in a directory only this user can read — but it means the credential
has stopped being the thing that authorises a transport, and a second connection
is exactly the change that would turn that from hard to notice into easy to
forget.

**So the off-path client is not the next commit on its own; the attach is.** The
operation it needs is not the handshake, and must not be:

| | handshake | attach |
|---|---|---|
| proves | the session credential, the runtime binding, the protocol version | the same three, **and** the session it is attaching to |
| may create a session | yes | never |
| may renegotiate limits or capabilities | yes, it establishes them | never; it inherits the session's |
| may change registration state | n/a | never |
| results in | `New → Active` | an additional transport for the session that is already `Active` |

An attach that created a second session, reloaded plugins, or accepted a weaker
capability set would solve runtime affinity by weakening the session model, which
is the trade this branch has refused everywhere else. The negotiated properties —
frame limit, protocol version, read capabilities, supported registration classes,
runtime binding — stay properties of the session; a second transport is a second
transport.

**The attach is implemented** (`rpc Attach`), and it validates against the
*established* session rather than against anything the caller supplies: the
session identity is stored whole in `Active`, and the answer reports those
parameters rather than recomputing them. The tests are mostly negative, because
that is where the contract lives: a wrong credential, a session this host did not
establish, a different runtime binding, a different protocol version, and a request
naming nothing are each refused; attaching before a session exists, or after it
closed, is refused for the same reasons a second handshake is. The positive case
proves the absence of a side effect rather than a stream of them — two attaches
return the same session identity, a second *handshake* is still refused (so an
attach creates no room for a second session), and the loaded set is unchanged.

**One limitation is recorded rather than hidden.** Attach authenticates the
client, but a Tonic service cannot track which connection a later request arrived
on, so later session-bound operations are still authorised by the session identity
and the context, not by the transport. A peer that can open the socket and knows
the session identity can therefore skip the attach. Closing that needs a
transport token minted by the attach and required in the metadata of every
session-bound request — a change to the primary client too, since the primary
transport would have to attach before it could issue anything. It is named here
as the follow-up rather than left as an implication of "attach exists".

What remains, in order, once the attach exists: a connection descriptor the
supervisor can hand out (endpoint, credential, session identity, negotiated
limits), an off-path client created lazily *on the off-path runtime* and cached
there, off-path calls routed through it rather than through the primary client,
and a broken off-path connection discarded and failed per family — reconnect and
reattach only while the session is alive, never to a session the host has
invalidated. The acceptance criteria are the ones already named: a
single-threaded caller with a remote sanitizer, a remote subscriber on the same
runtime, the primary client stalled while an off-path operation still completes,
an off-path connection killed with the primary call unaffected, and a reattached
connection that sees the same session, the same registrations and the same
generation.

### Observers cross, and the failure rule is what makes them safe to cross

Subscribers are the most-registered family in this repository (27 sites), and they
are now servable: the kernel's own subscriber list holds one proxy per
registration, the host runs exactly the registration the kernel named, and the
event crosses whole — the runtime's own event type in its canonical form, so a
field added to an event does not need a second definition to reach a subscriber
in another process.

Three rules make a remote observer safe, and all three are about what an observer
is rather than about the transport.

**An observer is never fatal.** A delivery that fails is recorded as a mark in
this runtime's stream and stops there. This is not a new rule — the in-process
dispatcher already catches a panicking subscriber and logs it — but it is the
reason a remote observer cannot break the work it is watching, and the reason the
record exists: harmless must not mean silent.

**An observer is bounded by a budget the runtime states.** It does not inherit the
action's budget, because nothing about that action depends on the delivery, and it
is not given a default, because a limit nobody chose is the thing this branch has
refused at every other layer. That budget is a *separate policy* from the managed
action budget — the work it bounds is work beside a call, not the call — and it
should be named as one (`plugin_observability_budget` beside
`managed_action_budget`) rather than folded into the action's. A runtime with no stated observer budget cannot have
remote observers: installation is refused rather than served with an invented
limit. A process test pins that refusal.

**A full queue drops, loudly.** Delivery is queued and performed by a task of its
own: the runtime's dispatch calls subscribers on the thread that serves every
observer, so a proxy that waited on an RPC there would make one plugin's latency
everyone's. A queue that overflows records the drop once per saturation rather
than per event, so the record cannot become the flood it reports, and an observer
is never told about its own delivery failures — that would ask it to fail again.

What the kernel still owns is unchanged: which events exist, which registrations
see them, and the ordering the runtime gives them. The witness in the process test
is a file the child writes, because a subscriber in another process has no other
way to show the caller what it saw.

## Coverage, which is the metric now

The useful question stopped being "how many registration classes are supported" and
became "which real plugin is closest to being fully servable by
`ProcessLoadedPlugins`". This is that calculation for the two fixtures the
repository ships, because they are the plugins it actually has.

`fixture_intercept` — the one the process tests drive end to end:

| | |
|---|---|
| registered classes | 9 (tool + LLM request intercept, subscriber, tool request/response sanitize, tool + LLM conditional, metadata injector, and the refusing guardrail) |
| remotely supported | 9 |
| remaining blockers | **0** — it is fully servable today |

`fixture_native` — the sixteen-surface fixture the in-process tests use:

| | |
|---|---|
| registered classes | tool + LLM request intercepts, subscriber, metadata injector, mark and scope-start/end sanitizers, tool and LLM request/response sanitizers, tool + LLM conditional, tool execution intercept, LLM execution intercept, LLM stream execution intercept |
| remotely supported | the eleven that are not sanitizers-of-marks-or-scopes, execution intercepts or stream intercepts |
| remaining blockers | mark sanitize, scope-start sanitize, scope-end sanitize, tool execution intercept, LLM execution intercept, LLM stream execution intercept |

`examples/rust-native-plugin` — the plugin a reader is pointed at first:

| | |
|---|---|
| registered classes | metadata injector, tool + LLM request intercepts, subscriber, mark and scope-start/end sanitizers, tool and LLM sanitize request/response, tool + LLM conditional, LLM execution intercept, LLM stream execution intercept |
| remotely supported | the same eleven that are not mark/scope sanitizers, execution intercepts or stream intercepts |
| remaining blockers | mark sanitize, scope-start sanitize, scope-end sanitize, LLM execution intercept, LLM stream execution intercept |

That is the number worth watching, and it is five rather than six: the example
registers the mark and scope sanitizer families that the next increment covers plus
two execution intercepts, and it registers *no* tool execution intercept. The
distinction matters because the execution-intercept count is what decides whether
duplex is on the path for a given plugin: this one needs the LLM execution and
stream intercepts, so it is not servable without duplex work — whereas a plugin that
registers only the first four categories is servable today.

So the answer to "which real plugin is closest to 100%" is the first one, and it is
already there — which is worth stating plainly, because it means the *coverage*
argument for the next class is not about that fixture. The argument is that a real
deployed plugin is much likelier to look like the second: mark and scope sanitizers
are among the most-registered families in this repository (9 + 6 + 6 sites), and
execution and stream intercepts are the duplex work.

That reframes the next two increments honestly. Mark and scope sanitizers are worth
doing because they are common, not because they unblock a fixture. And the duplex
question should be answered by the same calculation against a *real* plugin — if one
of its registration sets contains no execution or stream intercept, it is servable
without duplex work, and it should become the first cutover candidate rather than
waiting for the last class.

## Getting a plugin's registration set

The coverage subtraction needs one input per plugin: which surfaces it registers.
The 16 the ABI exposes are the ones the table above lists, and the answer belongs to
the binary rather than to a hand-written file — a manifest that can drift from what
the plugin actually registers is a second source of truth, which is the thing this
whole milestone exists to avoid.

Three ways to get it, in increasing order of how much they are worth trusting.

**Source.** For a plugin whose source you have, the registration calls are the
answer:

```bash
rg -n 'register_(tool|llm|scope|mark|event)_[a-z_]*|register_subscriber' path/to/plugin
```

That is fast and it is also the weakest answer, because it reads intent rather than
behaviour: a registration behind a configuration branch may never run.

**What the CLI knows.** `nemo-relay plugins inspect <id> --json` reports a
discovered dynamic plugin's canonical identity, manifest and lifecycle state. It
does *not* report registrations today, and the reason is structural rather than an
omission: registrations exist only after activation, and inspect does not activate.

**The assumed path for the tool does not work as sketched, and that is a finding.**
The natural design — start a host, load, activate, print the descriptors — cannot
report blockers, because activation *refuses the plugin whole* when it registers a
class the session cannot serve (`an_activation_that_registers_what_this_session_cannot_serve_is_refused_whole`).
That refusal is right for production: a load reporting success while a callback
disappears is worse than a refused load. It is wrong for inspection, whose whole
purpose is to find the classes this kernel *cannot* serve.

So the tool needs one of two things, and the choice is a protocol decision rather
than an implementation detail:

1. **A discovery activation.** The activate request would carry a flag saying this
   session is inspecting rather than serving: the child runs the register callbacks
   and reports every descriptor, including classes this kernel has no proxy for, and
   the session installs nothing. The report is then the measurement the coverage
   subtraction wants, with the unsupported classes named as the blockers — which is
   exactly the test the tool is supposed to satisfy ("unsupported registration
   appears as a blocker, not silently omitted"). The flag must not be usable to
   install anything: a discovery session has no proxies, so the only thing it can
   change is what it reports.
2. **Report the refusal.** Cheaper, and honest but weaker: activation against a
   serving session fails and names one unsupported class, so the tool can say "not
   fully servable, blocked by X" and re-run with that class offered until it
   activates — a search rather than a report, and it only works for classes the
   kernel can learn to offer, which is circular.

The first is the design that matches the requirement. It is a small protocol change
(one field on the activate request, one branch in the host, a test that a discovery
session installs nothing) and it is worth doing before the CLI is written, so the
command is thin plumbing over an honest report rather than a tool that cannot answer
its own question.

**Discovery is implemented, and running it found something.** `ActivateRequest` now
carries `discovery`: a serving session refuses a plugin whole when it registers a
class the session cannot serve — right for production, useless for inspection — and
an inspecting session reports every descriptor, unsupported classes included, so the
blockers are visible as what they are. Nothing is installed either way (the host
reports and the kernel decides, and proxy installation refuses a class the backend
does not support), so the flag changes what is *reported* and nothing else. The test
proves both halves against the same plugin in the same host: serving refuses,
inspecting reports, and the report contains an operation this kernel cannot serve.

Running it turned up a defect in the repository's own fixture: `fixture_native`
registers one injector name twice, and the *conversion* refuses a duplicate
registration at the same attachment point
(`a registration named …fixture_event_metadata_injector twice at the same attachment
point`). That has a consequence worth stating: the sixteen-surface fixture cannot be
activated *over the boundary* at all today, so it was never a valid coverage
measurement — the 10/16 above comes from reading its source. Fixing the fixture, or
deciding what a duplicate registration *means* (two injectors under one name is
either a plugin bug or a contract the conversion is too strict about), is a
prerequisite for measuring it properly.

**What NEMO already produces.** Activation is the authoritative source, and the
boundary already surfaces it: `ProcessPluginBackend::activate` returns one
`PluginDescriptor` per activated plugin, each carrying the registrations the plugin
made — identity, class and ordering — because the kernel needs exactly that to
install a proxy per registration. So the tool the coverage work wants is thin:
activate the plugin in a host and print the descriptors. That would give

```json
{"plugin": "my_plugin", "registrations": ["tool_request_intercept", "subscriber"]}
```

from what the binary really registered, in a child process, with no in-process load
— which is also a useful thing for a deployment to be able to run. Until that tool
exists, the coverage table above is built from source and says so.

## Two cutovers, and why duplex may not be on the path

The coverage calculation above makes a distinction the earlier plan did not draw.

**Functional cutover** is one consumer using `ProcessLoadedPlugins` for one plugin
known to be fully remotely supported. **Global cutover** is every supported
production plugin doing so, with no production consumer needing the in-process
fallback. The second is the one that lets the loader leave the kernel's dependency
graph — but nothing about the first requires waiting for it.

The complete-plugin regression is what makes the first one available: a plugin — the
nine-registration fixture — lives entirely behind the process composition. The test
now proves the whole shape rather than one class of it: every registration it makes
is served, the chain it installed here is this runtime's own, dropping the
composition takes every registration with it and releases the last handle to the
child, and the work never needed an in-process load.

**So duplex is not automatically next.** Execution intercepts, LLM stream
intercepts and the session families are the most complicated remaining protocol
work, and they are on the critical path only if a plugin somebody actually needs
registers one of them. The cheaper question comes first: take a real plugin's
registration set, subtract the removable classes, and look at what is left.

- If the remainder is empty, that plugin is servable **now** and should become the
  first functional-cutover candidate rather than waiting for the last class.
- If the remainder is execution or stream intercepts, then — and only then — duplex
  is what stands between that plugin and the cutover, and the work is justified by
  a named plugin rather than by ABI completeness.

Alongside that, a second metric becomes worth tracking per plugin: the share of its
registrations reachable **only** through the process host. Once one plugin reaches
all of them, the tests for that plugin can assert that its production composition
does not touch `load_native_plugins`, `PluginHostActivation` or the in-process
backend at all — which is how the loader extraction becomes incremental instead of
one final migration.

## Cutover matrix

Which registration families can cross today, and what the ones that cannot need.
The counts are how often each family is registered across the shipped fixtures,
examples and integrations, because the question this matrix answers is *coverage
per unit of added complexity* rather than protocol completeness.

| family | wire | host invoke | kernel proxy | registrations | what it needs |
|---|---|---|---|---|---|
| tool request intercept | yes | yes | yes | 7 | — |
| LLM request intercept | yes | yes | yes | 7 | — |
| tool conditional guardrail | `(name, Json) -> Option<String>` | yes | yes | 6 | — |
| LLM conditional guardrail | `(LlmRequest) -> Option<String>` | yes | yes | 6 | — |
| subscriber | event | no | no | 27 | one shared decision: what an event is on the wire, and what a remote observer's failure means |
| event metadata injector | event | no | no | 4 | that same decision |
| mark sanitize guardrail | event | no | no | 9 | that same decision |
| scope sanitize start/end guardrail | event | no | no | 6 + 6 | that same decision |
| tool sanitize request/response guardrail | `(name, Json) -> Json` | no (hangs) | no (hangs) | 6 + 6 | an off-path transport: see below |
| mark / scope sanitize guardrail | `(Arc<Event>, EventSanitizeFields) -> EventSanitizeFields` | no | no | 9 + 6 + 6 | the same, plus one field shape |
| LLM sanitize request/response guardrail | codec-bearing context | no | no | 6 + 6 | codec identity on the wire |
| event metadata injector | event → metadata map | yes | yes | 4 | — |
| tool execution intercept | continuation | no | no | 11 | the duplex session: it wraps the call, so the child has to call back |
| LLM execution intercept, stream intercept, continuations, completions, pull streams | continuation | no | no | 6 + 6 | the duplex session |

Two conclusions the counts support.

**The cheapest next class is a conditional guardrail.** Its callback is
`(name, args) -> Option<String>` — the same payload as the tool request intercept
that already crosses — and, unlike a stream or an execution intercept, it needs no
second direction. Its observable behaviour needs nothing new either: the kernel's
own chain emits the guardrail's scope start/end around the *proxy* entry, with the
kernel's subscribers, so a remote guardrail is exactly as observable as an
in-process one. What the child emits for its own copy of the call goes to a
runtime with no subscribers, which is where the duplicate belongs.

**The largest win is one decision, not one class — for observers.** The families
that *watch* share one shape: something the runtime already holds is shown to a
plugin, which answers with nothing or with metadata, and `PluginObservedEvent`
carries it. The families that *transform* do not share one shape, and an earlier
revision of this table said they did. There are four, and they are now listed
above: `(name, Json) -> Json`, `(Arc<Event>, EventSanitizeFields) ->
EventSanitizeFields`, a codec-bearing context, and a metadata map. That matters
because it says not to build one generic "sanitize" wire operation: each shape
would have to carry its own vocabulary anyway.

**A sanitizer's own wait belongs to the runtime that drives it.** The tool
sanitize pair was wired and hung: each invocation waited its whole budget (5s →
16s, 60s → 181s), the events arrived with their observability fields cleared, and
the guardrail itself is fine — invoked through its exact-registration runner in
process it returns in 0.03 s. What is left is the transport: the dispatcher runs
sanitizers on a private runtime of its own, while the connection's tasks make
progress on the runtime that composed it, so the wait can only end at the budget.
Observers do not have this problem because their delivery runs on a task of that
second runtime. The composition now owns a runtime for off-path work
(`OffPathPluginExecutor`), with a stated budget and a stated in-flight bound, and
the sanitize proxy submits to it rather than awaiting the call on whichever
runtime the dispatcher happened to be using. That buys three things that are
tested: the bound refuses work it cannot hold instead of growing a queue nobody
chose, a stopped executor fails pending operations cleanly rather than leaving
them to expire, and the runtime is a composition resource — one per host, shared
by every off-path family, ended in the background so teardown cannot block on a
plugin.

It does **not** yet remove the single-threaded restriction, and the reason is
narrower than the first one: the *connection* is still the composition's, and its
tasks live on the runtime that opened it. On a single-threaded caller that runtime
is blocked waiting for the sanitizer, so the reply has no thread to arrive on — the
work moved, the transport did not. Installing a sanitize proxy there is refused
with that reason rather than degraded silently, and the next step is an off-path
*client*: a second connection to the same host, opened on the off-path runtime, so
the transport belongs to the runtime that awaits it. The host accepts it because
the credential is checked at handshake and the session on every request.

Nothing in this matrix changes the ordering that moves the metric: coverage, then
the cutover, then the loader leaving, which is what finally drops the 621.

What has *not* moved: the loader still executes inside the kernel's address
space, because the backend the host process serves is the same in-process
implementation the kernel used before. That is deliberate — the boundary and its
contract exist first, so the step that moves the loader changes one
implementation rather than discovering a protocol — and it is why the metric
below has not moved.

This increment does not move `kernel-process unsafe tokens`, which is 621. The
number falls when native loading physically crosses the process boundary, and a
reduction achieved by reclassifying crates would not mean anything.
