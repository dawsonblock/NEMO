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

Increment 1 is complete. The next step is increment 2: take the interface into
`nemo-relay` and route the existing loader behind it without changing behaviour,
which is where the layer gate starts constraining the shape of the extraction.
