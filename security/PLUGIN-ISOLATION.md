<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Milestone: native plugin isolation

**Current status, as the tests enforce it** (the rest of this document is a
chronological record, so numbers inside it may be the ones that were true when a
section was written):

- **Registration coverage: 16 of 16.** Pinned by
  `the_boundary_serves_a_named_subset_of_the_registration_surface` in
  `crates/plugin-host/tests/architecture.rs`, whose unserved half is now empty. The last
  two to cross were the LLM sanitizers — one codec capability protocol, one bridge that
  turns a plugin's synchronous codec call into the kernel's asynchronous one, and a real
  child in each direction resolving the call's codec through the kernel. Every attachment
  point the ABI exposes is served, and the match that installs proxies is exhaustive: a
  class added to the ABI fails to compile there rather than being refused at runtime.
- **Kernel-process unsafe tokens: 648**, measured by `just tcb-report`.
- **Native ABI version: 5** (`NEMO_RELAY_NATIVE_ABI_VERSION` in `crates/plugin`).
- **Plugin compatibility:** the CLI serves plugins from another process; FFI, Node
  and Python still reach the in-process activation path, and that list is pinned by
  the architecture test rather than recorded only here.

Almost all of the kernel's `unsafe` is the native plugin path: 280 occurrences
in `crates/core/src/plugin/dynamic/native.rs` and another 315 in
`nemo-relay-plugin`. Together that is roughly 96% of the measured in-process
surface, and `just tcb-report` prints the number this milestone is judged on:

```
kernel-process unsafe tokens: 648
```

`just tcb-report` checks that figure against the measurement rather than
trusting this paragraph: a revision of this document said 617 here and 621 forty
lines later, which is what a hand-maintained number does.

The figure has since read 622 rather than 621 for a while, and now reads 648: the
boundary gained one `unsafe` block when the supervisor began applying the host's
resource ceilings between `fork` and `exec`, which is `pre_exec`, which is unsafe by
construction. It is one call that allocates nothing and takes no locks, and it lives
in the crate that is the *east* side of the boundary rather than the kernel proper —
counted here because that crate is still linked into the kernel's process today, the
same accounting that puts it in `[in_process]` and `[plugin_host]` at once. The
measured line budget moved with it, and with the kernel-side entry points the boundary
needs; every raise is recorded with its reason in `security/tcb.toml`.

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

**The mark window, and what it taught the ABI.** The one gap the qualification
pass found was that a mark raised by an asynchronous callback never left the host
process: the host opens its mark window around a *unary* callback, where the
callback body runs inside it, and an asynchronous callback's body runs on a task of
the plugin's own — outside any window this process opens. Installing the window
around the streaming registration as well changed nothing, which was the
measurement; the missing piece was that the window has to *follow execution*.

It now does, and the rule is general rather than streaming-specific: an ambient
context with semantic meaning has to be captured where it is set and restored
across every task boundary the plugin owns. Mark windows are the first casualty
observed, and the same rule applies to the scope stack the SDK already carries,
and to anything security-relevant added later.

The mechanism is ABI v5: `capture_mark_window_thread` reads the window the host
opened and answers one opaque handle, `emit_mark_in_window` emits through it and
nothing else, and `release_mark_window` gives it back. The handle names the
operation — a plugin cannot substitute an operation identity, because the identity
is the window's — and a window the host has closed refuses the mark rather than
attributing it to whatever holds that identity now. The plugin SDK captures at the
call, and carries the window into the executor task and into the *returned stream*
as well as into the callback's own future, which is the part a callback that merely
constructs and returns a stream would otherwise lose: the stream is polled long
after the call that created it returned, and its marks belong to the same
operation. Installation is per poll and taken back afterwards, because a poll is
synchronous and two streams on one thread must not see each other's window.

Two things fell out of building it. The host now offers an older plugin the version
it was built against — a frozen v4 table — rather than only the current one: a
plugin whose supported range ends at v4 refuses a v5 table, and that refusal says
nothing about what the two could have agreed on. And the host's end of a stream's
marks is ordered: a call's marks are delivered *before* the frame that ends the
call, and a failure to deliver them turns the ending into a failure, because a call
whose evidence the kernel will never see is not one the kernel may read as
complete.

`a_streaming_callback_s_mark_reaches_the_host_s_forwarder` is the first test: it
drives a streaming invocation to its end and requires the mark the callback raised
before opening its downstream stream to arrive at the forwarder with the operation
the window names and the position the plugin named. It was ignored while the
mechanism was missing and is not any more.

## Current state

This section is the authoritative statement of what the tree does today. The
rest of this document is the engineering journal that produced it, and sections
below that describe work as unfinished are describing the moment they were
written, not this one. Where the two disagree, this section is right.

**What crosses the boundary now.** Ten registration classes, listed in
`ProcessPluginBackend::supported_registration_operations` and each paired with
the kernel-side proxy that makes it true: tool request intercept, LLM request
intercept, subscriber, event metadata injector, tool and LLM conditional
execution guardrails, the tool sanitize request/response guardrails, and the tool
and LLM execution intercepts. A plugin registering anything else is refused
**whole** at activation, after the register callbacks have run and before the
kernel is told anything was served. Not yet crossing: mark and scope sanitizers,
the LLM sanitizers, and every streaming family.


That list is the price of the cutover rather than a detail of it: a plugin that
registered a class in the second group used to work in the CLI and no longer
activates there, because serving half a plugin would be worse than refusing it.
The two halves are pinned by a test so the gap cannot quietly become a claim.

**The continuation, for the classes that wrap a call.** An execution intercept is
the family whose answer is not the whole answer: the plugin decides *when* the
rest of the chain runs, and the rest of the chain is the kernel's. The kernel therefore holds its position for the operation while the
intercept runs (`crates/plugin-host/src/continuations.rs`) and resumes it when the
host asks, over the `Continue` RPC the protocol already defined. What that buys:

- the ABI's own rule for `next` — callable repeatedly and concurrently while the
  intercept runs, refused once it settles — is enforced by the chain the kernel
  parked, so a remote intercept sees exactly what an in-process one sees;
- a continuation for an operation nothing is holding is refused rather than
  resumed at the wrong position, which covers both "no such operation" and "the
  intercept already returned";
- what the plugin returns travels back whole: the result it decided on, plus the
  marks it asked for, which the kernel emits with the ones the continuation
  produced, in the order the in-process chain would have used.

The tool and provider halves are deliberately the same mechanism rather than two:
one parked position per operation, one unary resume, one set of budget, panic and
lexical rules. What differs is the shape that travels — arguments and a result, or
a request and a response — and which family a position belongs to travels in the
entry rather than on the wire, so a resume shaped for the wrong family is refused
by the position it addresses instead of by a discriminator a peer could set wrong.

`a_tool_execution_intercept_wraps_a_call_across_the_boundary` and
`an_llm_execution_intercept_wraps_a_call_across_the_boundary` drive the mechanism
from both sides, `a_wrapped_call_can_be_replaced_run_twice_or_failed_after` covers
the shapes the ABI allows — a plugin that answers without continuing, one that
continues twice, one that fails after the call it wrapped — and
`a_continuation_of_the_wrong_shape_is_refused` covers the mismatch the shared wire
makes possible.

**What a session is authorised by.** Two secrets, checked at different moments:
a per-session credential passed out of band at spawn, which authorises
establishing the session, and a 256-bit capability the kernel mints, which every
session-bound operation after it has to present. The capability exists because
the operations used to be authorised by naming the session, and a session's name
is what an attach announces — a peer that could reach the socket and learn the
session could call it. `crates/plugin-host/src/capability.rs` owns the minting
and the constant-time comparison; `SESSION_CAPABILITY_HEADER` carries it on the
handshake, the attach and every operation that reads or changes session state.
Both refusals are structured outcomes rather than transport failures, so the
kernel can tell "the host said no" from "the channel broke".

**The duplex session, which streaming needs.** Most of the boundary is one request
and one answer; a stream is not. A plugin wrapping a provider call pulls the
downstream stream a chunk at a time, may cancel it, and may release it while a pull
is outstanding, so the session channel carries open/pull/item/end/cancel/release
and the plugin paces the kernel's work behind them. The kernel's side of that
channel exists: `crates/plugin-host/src/session_driver.rs` turns those messages
into the kernel's actions — calling the parked chain position, producing the next
item, stopping when the plugin stops asking — while every validation stays in
`crates/plugin-host/src/session.rs`, which refuses a pull for a stream that is not
open, a second pull while one is outstanding, and a release of a stream the session
does not hold. A message the kernel does not receive from a host ends the channel
rather than being answered, because the two sides no longer agree about what the
channel is. `a_wrapped_stream_is_pulled_over_the_session_channel` drives it over a
real channel, credential check included.

The acceptance gate for listing the class, stated before the work rather than after
it: multi-chunk, one-chunk and zero-chunk completion; a plugin that answers without
pulling; repeated `next`; monotonic sequences and refusal of a duplicate, a gap, a
post-terminal chunk and a second terminal; credit exhaustion and production without
credit; a stalled consumer against a producer that would otherwise run ahead;
cancellation before the open, while open, and after the half-close; a deadline
before the first chunk and between chunks; a host crash mid-stream; a wrong
operation or call identity; concurrent streams; cleanup after every terminal and
error path; mark attribution during streaming; and a cumulative as well as a
per-frame byte budget. Several of those are already refused by `session.rs` and
covered by its tests (sequences, terminals, unknown streams), and the driver's own
tests cover the open/pull/end paths; the rest are the reason the class is not
listed.

Both ends of the channel now exist. `crates/plugin-host/src/session_channel.rs` is
the host's: a callback asks the kernel for the downstream stream of one operation
and gets a value it can poll, one task per stream does the pulling so a `poll_next`
never has to await, and the consumer dropping the stream reaches the kernel as a
cancellation rather than as a host that stopped asking without saying so.
`a_dropped_stream_cancels_the_kernel_s_producer` proves that from the kernel's side —
the producer is dropped — and `two_streams_on_one_channel_do_not_swap_answers`
proves answers are routed by the call that asked rather than by stream.

The window that test cannot reach is the one between asking the kernel for a stream
and the kernel answering: the caller can walk away while the open is in flight, and
then the identity of the stream the kernel is creating exists nowhere on this side.
An answer nobody is waiting for is the last place it can be named, so the channel's
reader cancels a `StreamOpened` it cannot deliver rather than dropping it, and
`an_open_the_caller_left_cancels_the_kernel_s_producer` holds the kernel inside the
open until the caller has gone and requires the producer to be dropped anyway.

The upstream direction now exists as well. `PluginHost::InvokeStream` runs a
streaming registration in the host and answers with the frames its *returned* stream
produces — one frame per poll, so a kernel that stops reading stops the plugin
rather than filling a queue — and the kernel's proxy parks the chain position the
plugin will pull from, starts that invocation, and hands the frames to the caller as
a managed stream. `a_streaming_intercept_pulls_downstream_and_answers_with_frames`
drives the whole loop in one call: the kernel's chain, the plugin's callback pulling
the downstream stream the kernel is producing for that operation, the chunks it
marked on the way back, and the terminal frame — both halves of the boundary,
end to end.

The kernel's side is no longer a loop that answers pulls itself. A pull is work,
and work that one stream's producer can park is work the session must not be
waiting on: `SessionDriver::handle` is not an `async fn` at all — it validates a
message against the session's record and routes it — and every stream is owned by
an actor of its own, which owns the producer, the stream's lifecycle, the pull it
is producing for and the identity of the next one. What the actor produces reaches
the plugin through the session's writer rather than through the dispatcher, so a
producer parked in `poll_next` cannot delay another stream's pull, the
cancellation of its own stream, or the arrival of anything else. Cancellation is
actor-owned and does not require cooperation: the actor is racing its poll against
its pulls closing, `biased`, so a cancellation that arrived while the producer was
also ready is the one that decides — the poll future is dropped and then the
producer. The pull identity a result is recorded against is checked rather than
assumed, and the session records a result only for the pull it is still waiting
for, so a result that arrives after a cancellation settled the pull is discarded
as stale rather than answered or refused. Actors are bounded (streams per session,
opens in flight), a producer's panic fails its stream and not the session, and a
session that ends drops every producer before its answer stream ends:
`a_session_channel_answers_while_a_producer_is_blocked`,
`a_parked_producer_holds_up_neither_the_session_nor_its_cancellation`, and
`a_session_that_ends_drops_the_producers_it_was_serving` are the evidence, with
the one-pull rule, cross-stream isolation and the panic case beside them.

Cancellation itself is idempotent where the stream is already settled, which the
actor work made necessary rather than optional: a consumer that read a stream to
its end and let it go sends the same message as one that cancelled a live stream,
and the two look the same from the far side of the boundary. Refusing the first
would end a session over a race the boundary creates — and did, until
`a_pull_yields_the_next_chunk_and_then_the_end` started asking the session to open
another stream after one finished. What stays refused is the cancellation that
names a stream this session has no record of, where it cannot tell a stale message
from an invented one, and the host now releases a stream it is done with so the
kernel can forget it rather than keeping a record of every stream it ever served.

Demand and cost are two counters in that actor, and they are what the class owes
the kernel's memory budget. Credit is granted by demand rather than ahead of it: a
pull grants one frame's worth and never more, so a stream nobody has asked about
is not polled at all — `a_stream_nobody_pulls_is_never_polled` counts the polls a
producer is asked for and requires zero while another stream is served and one
after the first pull. The three ceilings are the session's: `max_frame_bytes`,
`max_stream_bytes` and `max_stream_frames`, each checked before a frame crosses,
with the frame that opens a stream, its data, the failure that ends it and the
terminal frame all measured the same way (the wire crate's
`session_message_encoded_len`, the measurement the host already uses for its own
answers). A frame that would cross a ceiling is not sent and not charged: the
stream settles with a failure instead, the producer is dropped, and the actor is
gone, which is what makes the ceiling a bound on work rather than on a message.
`a_frame_one_byte_over_the_ceiling_ends_the_stream`,
`the_stream_byte_ceiling_counts_every_frame` and
`the_stream_frame_ceiling_counts_every_frame` each run limit−1, the limit and
limit+1, and one of them requires the plugin to read the ceiling it met in the
failure code. The credit reading is written down in the actor because it is a
decision rather than an accident: `initial_credit = 1` is a grant, not a head
start — a stream the plugin has not asked about has no credit and is not polled —
and a terminal frame does not spend a credit because it is what the pull that
asked for it was for.

The deadline is the operation's, not the consumer's: it is taken from the budget
the chain position was parked under, so a stream cannot outlive the call whose
chain it wraps. It is enforced in the three places a stream can be waiting — the
open, the demand, and a pull whose producer is still working — and it settles the
actor before it drops the producer, which is the order the two have to happen in:
what ended the stream is held for the next pull when nothing was outstanding,
because a stream's frames are answers to demand and the ending is one of them.
`a_deadline_before_the_first_frame_ends_the_stream`,
`a_deadline_while_a_pull_is_pending_answers_the_pull`,
`a_deadline_between_frames_ends_the_stream` and
`a_deadline_while_the_open_is_blocked_refuses_the_open` are the four states; the
first waits for the producer to be dropped before it asks for anything, so it is
the call's deadline being enforced rather than the consumer's.

Transport disappearance was the last thing the terminal frame was standing in for
without saying so. The host's end of the session used to read a broken session as
the end of the stream it was pulling: the pulling task's channel closed and the
consumer saw a clean end, which is exactly the "silently means successful EOF" the
terminal frame exists to prevent. Now every way that task can exit without the
kernel saying the stream ended — the session's side of the channel going away, a
call being dropped because the session ended, an answer of a shape a pull cannot
take — fails the stream with "the session ended before the stream did". The
reader, on its own exit, marks the channel ended and drops the calls still waiting
for answers, so the calls that follow learn it too instead of waiting for a kernel
that is no longer there, and a call that registers in the window between the two
finds its own registration taken back rather than left in a map nobody reads.
`a_session_that_ends_mid_stream_fails_the_stream` ends a session under a
mid-flight stream and requires the consumer to be told, and
`a_session_that_ends_drops_every_producer` requires both a producing stream and a
stream that was never asked for anything to lose their producers when the session
goes — at the driver level, where the actors are.

The same rule was standing in for itself in the other direction, where the kernel
reads the frames a host answered with: `FramesAsChunks` ended the caller's stream
when the frames stopped, whether or not the frame that says a streaming call is
over had arrived. A host that answered and stopped — or a session that broke
between two frames — was therefore handed to the caller as a finished stream. A
stream of frames without its terminal frame is now a failure naming what was
missing, and `a_stream_of_frames_that_stops_without_a_terminal_frame_is_a_failure`
pins all three shapes: answered and stopped (a failure), ended with the frame that
says so (an end), and failed (the failure, then an end).

What the streaming increment owed is closed. The order it was closed in, and the
one a later change should be held to: the duplex session; one actor per stream with
its lifecycle, demand, budgets and call-owned deadline; explicit credit; the three
ceilings; the strict terminal rule and the transport-loss rule; the producer, actor
and parked-position cleanup on every exit; and the mark window that follows
execution across the plugin's own task, with its four-position attribution,
lifecycle, non-reuse and negotiation gates. The gate list it was held to is the one
at the end of this document.

2. **The rest of the qualification matrix**, which needs no new mechanism: the
   cases are in the tree and the counts are asserted with them. Host death is
   `a_session_that_ends_mid_stream_fails_the_stream` (a caller is told rather than
   handed a clean end) and `a_session_that_ends_drops_every_producer` (a producing
   stream and one nobody asked about both lose their producers); a session that
   broke mid-stream, a host that stopped without the frame that ends the stream,
   and a stream that failed are the four shapes of
   `a_stream_of_frames_that_stops_without_a_terminal_frame_is_a_failure`, each of
   which also requires the kernel's held chain position to be given back with the
   stream; and `streams_that_end_every_way_at_once_leave_nothing_behind` runs the
   mixture — a stream finishing, one cancelled with a pull outstanding, and one
   released unpulled, over and over — requiring every producer to be dropped and
   both counts to return to zero each round.

**What keeps a host from outliving its kernel.** The supervisor kills the child when
it drops, and that is not enough on its own: a reference to the composition can be
released a moment after the drop, and a process that exits inside that window
leaves a host holding a socket nobody reads. The supervisor therefore opens a pipe
for the child and keeps the write end for the session's life, and the host exits
when that pipe closes — so a kernel that exits, crashes or is killed ends its host
whether or not any teardown ran. `a_host_exits_when_its_kernel_goes_away` starts a
host the way the supervisor does and abandons it the way a dead kernel does.

**What the host process is bounded by.** `PluginHostLimits`, applied between
`fork` and `exec` so nothing the plugin does afterwards can raise them: an
address-space ceiling and a descriptor ceiling, both soft and hard, plus
`no_new_privs` where the platform has it. The shipped defaults are 8 GiB of
address space and 4096 descriptors, and the address-space ceiling is asked for
only on Linux: macOS rejects that value with `EINVAL` and accepts no smaller one,
so a macOS deployment bounds memory some other way. A limit the platform refuses
is a host that does not start rather than a host that runs unbounded. Process
count is deliberately unset — `RLIMIT_NPROC` counts the *user's* processes, so a
value chosen without knowing the machine can stop the host from creating its own
threads.

**What is enforced rather than declared.** A per-operation `max_response_bytes`
is measured, as the encoded form of the answer, by the host before it sends and
by the kernel before it accepts; an answer over budget is refused with
`OversizedFrame` naming the operation. Frame limits are negotiated once and
carried by every transport: the kernel offers what it is configured for, the
host answers with the smaller of that and its own limit, and the session keeps
`min(kernel, host, protocol ceiling)`. Discovery — asking what a plugin would
register — activates under a guard that clears the configuration on every exit
path, so inspection leaves the process as it found it. Forwards of plugin marks
travel on a bounded queue whose capacity is host configuration, and a full queue
fails the mark rather than growing the host's heap.

**What is not true yet.** The three blockers, stated plainly:

1. **Three consumers still select the in-process loader.** The CLI has cut over:
   `crates/cli/src/server/mod.rs` composes `ProcessLoadedPlugins`, the native
   plugin's register callbacks run in the host process, and
   `cli_activation_serves_a_native_plugin_from_another_process` asserts both that
   the registration answers through the CLI's chain and that the plugin's kind is
   absent from the CLI's own registry — the fact the in-process path could not
   state. FFI, Node and Python still call
   `PluginHostActivation::activate_with_discovered_config`, so the TCB number has
   not moved yet: the loader is still in the kernel's dependency graph until the
   last of them stops reaching it.
   Their cutover is blocked on **registration coverage**, not on their
   composition: a plugin that registers any class the boundary cannot serve is
   refused *whole*, and the fixture all three suites load — and the shape a real
   plugin takes — registers all sixteen classes. *(The table below is the state this
   section was written in; the current count is at the top of this document and the
   current list is in the architecture test. It read ten served then and reads
   fourteen now.)*

   | served | not served |
   |---|---|
   | tool request intercept | LLM stream execution intercept |
   | LLM request intercept | mark sanitize guardrail |
   | subscriber | scope sanitize start guardrail |
   | event metadata injector | scope sanitize end guardrail |
   | tool conditional execution guardrail | LLM sanitize request guardrail |
   | LLM conditional execution guardrail | LLM sanitize response guardrail |
   | tool sanitize request guardrail | — |
   | tool sanitize response guardrail | — |
   | tool execution intercept | — |
   | LLM execution intercept | — |

   `the_boundary_serves_a_named_subset_of_the_registration_surface` in
   `crates/plugin-host/tests/architecture.rs` pins both halves. The tool execution
   intercept was the first to move: it needed the kernel to hold a suspended
   chain position and resume it when the host asked, which is what
   `crates/plugin-host/src/continuations.rs` and the `Continue` RPC now do, and the
   provider intercept reuses that machinery rather than adding a second. The
   streaming intercept needs the duplex session instead of a unary resume, and both
   halves of it exist — the kernel's driver, the host's channel, and the upstream
   direction where a callback's returned stream crosses back. What remains is
   credit, the three budget limits, stream deadlines, and the qualification
   matrix. Two things used to be on that list and are not any more: cancellation
   that reaches the producer behind a dropped consumer (it holds for every state a
   consumer can leave in, including the open that is still in flight) and
   interruptible pulls (a pull is routed to an actor, so no producer can hold up
   the session or its own cancellation). The other
   five classes need shapes of their own plus a core entry point that runs exactly
   one registration of that class.

   **This is a consequence of the CLI cutover too, and it is deliberate rather
   than incidental.** A plugin that registers one of the eight unserved classes
   used to work in the CLI and is now refused at activation, with the refusal
   naming the classes it could not serve. That is the trade the acceptance gates
   chose — "unsupported registrations fail closed" — and it is the reason the
   remaining families are now on the critical path rather than after it.

   When coverage does reach the fixture's shape, the three consumers still need
   one thing the CLI did not: a decision about where the host executable lives
   for an installed wheel or npm package. `PluginHostSupervisorConfig` resolves it
   from `NEMO_RELAY_PLUGIN_HOST`, then beside the running process, then one
   directory above it (which is where a cargo test harness finds the binary it
   exercises) — enough for source-first consumers, and not enough for a wheel,
   which would have to ship the binary inside the package and point this at it.
2. **The transport is Unix-only.** `crates/plugin-host`'s socket paths use
   `tokio::net::UnixStream` and `UnixListener` directly, with no `cfg` boundary,
   while `just test-rust` builds the workspace on Windows runners. A named-pipe
   backend behind one transport seam is what closes this; it is not written.
3. **There is no sandbox.** Address-space and descriptor limits bound what one
   host takes from the machine. They do not bound what a plugin may read, write
   or connect to, and there is no seccomp, Landlock, `no_new_privs`-plus-
   filesystem profile, or network policy. The threat model this code supports is
   *trusted native plugin, unreliable implementation*; a plugin that is assumed
   hostile needs the platform mechanisms this document has not adopted.

The measurements that decide the milestone live in `just tcb-report`; the
evidence for the claims above lives in the tests named next to the code, which
is the only version of a claim that cannot go stale without CI saying so.

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
`nemo-relay-plugin` for the ABI structs (252 more). Those two are 595 of the 622,
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

**Step three: production selects the process backend.** The CLI now composes
`ProcessLoadedPlugins` and no longer loads a native artifact in its own process;
the three bindings still call `activate_with_discovered_config`. This is the step
the metric waits on: until shipped runtimes stop linking the loader, moving it
changes a crate diagram and not an attack surface. It is also the step with three
language test suites attached, and the one the cross-process tool call now
qualifies.

**Step four: re-measure and record.** Remove the moved crates from
`[in_process]`, update `security/tcb.toml` and `security/BASELINE.md` with the
new surface, and expect the number to land near 26 — the loader's 280 and the
ABI's 252 having left, rather than having been renamed.

Still open, in the order they need closing:

1. **Serving the read capabilities.** Diagnostics and registration reads are
   negotiated in the handshake but nothing serves them yet; deciding what they
   may return is the kernel's authorization step, not a conversion step.
2. **Invocation, and the session channel behind it.** *Written when invocation
   did not exist; it does now, for nine classes — see the current state above.*
   What that paragraph was waiting for has partly arrived: unary invocation
   crosses for the classes the kernel can proxy, each with its own proxy and a
   response budget that is measured on both sides, and the tool execution
   intercepts have the continuation mechanism they needed
   (`crates/plugin-host/src/continuations.rs` plus the `Continue` RPC), and the
   provider family reuses the tool family's rather than adding one. What is still
   missing is the rest of the duplex session: the kernel's side of the channel is
   written (`crates/plugin-host/src/session_driver.rs`), so what remains is the
   host's side of it, the proxy that parks a stream position, the upstream
   direction where a plugin's returned stream crosses back, and the qualification
   streaming needs. The reasoning about restarting still
   holds and is still implemented: a host that exits is reported as
   `HostCrashed`, the backend can replace it, and the kernel decides whether to
   keep using the replacement, because only the kernel knows what the previous
   session was holding.

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
   gets a filtered environment, its own socket directory and a kill at expiry.
   Address-space and descriptor ceilings and `no_new_privs` are now applied
   between `fork` and `exec` (`crates/plugin-host/src/limits.rs`). Still not
   applied: a process-count limit that is safe to default, platform sandboxing,
   destination network policy, and the declaration of which profile a plugin
   needs — a plugin cannot yet say "I need to connect to this host" and have the
   runtime grant it.
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
from 622, by the loader's own weight rather than by reclassification.

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

**One limitation was recorded rather than hidden, and is now closed.** Attach
authenticates the client, but a Tonic service cannot track which connection a
later request arrived on, so session-bound operations *were* authorised by the
session identity and the context alone. A peer that could open the socket and
learn the session identity could therefore skip the attach.

The fix is the one this section predicted, with one change of hands: instead of
the attach minting a token for the transports that follow it, the **kernel** mints
the capability before the handshake, and the session requires it on every
operation that reads or changes session state — load, unload, activate, inspect,
invoke, health, session close and attach. The handshake is where the host learns
it, so the token is a property of the session rather than of the transport that
introduced it, and the primary client is authorised the same way a second one is
rather than being an exception. See `crates/plugin-host/src/capability.rs`, and
`an_operation_that_presents_no_capability_is_refused` plus the capability case in
the second-transport test for the evidence.

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

## Coverage: two metrics, which answer different questions

Class coverage measures *architectural completeness* — how much of the ABI the
boundary can carry at all. Plugin compatibility measures *migration impact* — how
close the plugins the repository actually has are to being servable. Neither
replaces the other: a boundary that served sixteen classes nobody registers would
be complete and useless, and a fixture that happens to register only servable
classes says nothing about the classes that do not cross.

**The event sanitizer design is frozen; implement it, don't revisit it.** The
composition, decided rather than discovered: event payload semantics from the
metadata injector's path, sanitizer failure semantics and off-path execution from
the tool pair. A `PluginObservedEvent` goes down with a kernel-owned class, a
kernel-owned registration identity and the operation's identity; what comes back is
`observed.event`, and the class, the identities and the observation envelope stay
the kernel's — the plugin transforms the event and nothing else. Serializing the
whole envelope back would let a shared wire type quietly widen what a plugin
controls, so it does not.

Identical serialization must not imply interchangeable capability. All three classes
share the event representation, which makes class confusion *easier* rather than
safer: a structurally valid answer for the wrong class is rejected, because the class
is part of the capability rather than a field inside it.

The Layer 2 gate, with the confidentiality property tested as itself rather than
inferred from an error: inject an unmistakable sentinel into every observable field,
force each failure path — refusal, plugin failure, malformed answer, wrong class,
wrong registration, wrong operation, budget exceeded, host gone — and assert that no
sentinel value can appear in anything subsequently publishable. "The proxy returned
an error" is weaker than "the secret cannot be published".

**The two reads Layer 2 was waiting on, answered.** The event type's field
conversion is public — `Event::sanitize_fields` and `Event::apply_sanitize_fields` in
`crates/types/src/api/event.rs` — so a proxy that is handed the sanitized event by the
host can turn it back into the fields the chain consumes, and no new core helper is
needed for the authority split to hold. And the event-carrying precedent to copy is
`install_metadata_injector` in
[proxy.rs](/Users/dawsonblock/Downloads/NeMo-Relay-main/crates/plugin-host/src/proxy.rs:1381), not the tool pair: it is the served class whose payload is an event,
with `install_tool_sanitize` supplying the off-path submission and the
do-not-publish-on-refusal rule. Layer 2 therefore has everything it needs and is a
write rather than a decision.

**Where Layer 2 of the event sanitizers starts, from the reconnaissance.** Two
things the next session should not have to rediscover, both found by reading the one
already-served class whose payload is an event:

- The wire already carries an event. `PluginObservedEvent` is what the metadata
  injector's path deserializes ([service.rs](/Users/dawsonblock/Downloads/NeMo-Relay-main/crates/plugin-host/src/service.rs:456)) and hands to
  `invoke_event_metadata_injector_registration` as `observed.event`. The event
  sanitizers take the same shape, so their payload is that type rather than anything
  invented, and the answer is the sanitized event serialized back.
- The proxy to model is therefore `install_event_metadata_injector`, not
  `install_tool_sanitize`: the injector's class already carries an event across the
  boundary, and its proxy shows where a returned event is applied. The tool pair
  remains the model for the *refusal* rule — a payload that could not be sanitized is
  not published unsanitized — and for the off-path submission the sanitizers need
  because they run beside a call.

**The Layer 2 gate is written, and it corrects one thing above.** The reconnaissance
in the two bullets above concluded that the wire carries an event. It does not, and
the contract that says so was already in the tree when that note was written: the
protocol crate declares `PluginEventSanitizeClass` (closed: mark, scope start, scope
end) and `PluginEventSanitizeCall` — the projection a sanitizer is shown, which is
the event's name, the scope phase when it is a scope event, and the mutable
observability fields, and nothing else. Not the uuid, not the timestamps, not the
propagation root. Shipping the runtime's own `Event` across the boundary because
this side happens to have one is what the projection exists to refuse, so the gate
is written against the projection rather than against `PluginObservedEvent`, and the
two types above were its first consumers. The disclosure ratchet that landed with it
(`the_sanitizer_projection_discloses_exactly_its_approved_fields`) is what keeps a
field from reaching a plugin by accident.

What landed is the host's half of the nine properties, in
[service.rs](/Users/dawsonblock/Downloads/NeMo-Relay-main/crates/plugin-host/src/service.rs):
exactly one registration runs when a call names it (three mark sanitizers with
distinct markers, one named, neither neighbour's marker on the answer); a neighbour
in the same family and in a family that shares the shape is not invoked; a call
whose class is not the registration's own is refused in both directions; and a
refusal, a throwing callback, a malformed projection, an answer above the
operation's response budget and a call naming another registration, session or
runtime each fail closed.

Every negative case carries two things that make it mean something. The first is the
**control**: the class is served at all before anything is required of it, because a
host that refuses every invocation of a class refuses the case under test as well —
without the control, four of the eight properties passed while the class was
unserved. The second is the **sentinel**:
[confidentiality.rs](/Users/dawsonblock/Downloads/NeMo-Relay-main/crates/plugin-host/src/confidentiality.rs)
plants an unmistakable value in every observable field (event name, payload at two
levels, metadata, category profile, scope phase), forces the failure, and asserts
that neither a planted value nor the marker they carry appears anywhere in the
answer — including in a refusal's own text, which is where a payload that was
supposed to be withheld comes back if nothing checks. The helper is public because
the two suites that need it sit on opposite sides of the boundary, exactly as
`conformance` does.

The tests are red today, deliberately, and with one reason: `cargo test -p
nemo-relay-plugin-host --lib` fails all eight — the exact-registration ones on the
call they name, the rest on their control — and every one of those failures names
the same cause, *"this host does not serve mark_sanitize_guardrail invocations
yet"*. The fixture registers the three families behind an `event_sanitizers`
configuration key for the same reason — its default set is "the classes a kernel can
serve", and until the proxy exists these are not those classes.

What this gate deliberately does not cover is the kernel's half: the proxy that
builds the projection, submits it beside the call and applies what comes back. It
cannot be reached without a peer, because a sanitize proxy's answer arrives over the
composition's own transport rather than over an in-process backend, so its tests are
process-boundary tests — the same suite that qualifies the class and moves the
metric. The sentinel helper is the part those tests will reuse unchanged.

**The five classes left, and the one question among them.** *(Three of these five have
since crossed — see "The event sanitizers cross" below. What remains of this note is
the LLM pair and the codec decision at its end.)* Four touch points per
class, in this order: a core entry point that runs exactly one registration of the
class (the shape of `invoke_tool_sanitize_request_registration`), a kernel proxy per
class (the shape of `install_tool_sanitize`, which hands the host the copy an event
would carry and treats a refusal as a payload not to publish), the host's invocation
path for that class, and then the served set, the architecture expectation and the
coverage tables.

The three event sanitizers — mark, scope start, scope end — are the tool pair's
shape and should go first: an event and the fields an observer would see, sanitized
and returned, with no second lifetime and no codec.

The LLM sanitize pair is not that shape, and the difference is a decision rather
than a port. An LLM sanitize chain is given an `LlmSanitizeRequestContext` beside the
request — a per-call codec identity with a resolved codec capability behind it —
and in the host that capability exists only as a *completion*-scoped ABI object. A
unary sanitize invocation across the boundary has no completion to hang it on, so
before this pair is implemented one of these has to be chosen, written down, and
held to:

- the kernel resolves the codec and sends the identity, and the host refuses the
  invocation when it cannot resolve that identity itself; or
- a sanitizer for a call that has a codec is refused whole across the boundary
  until a per-invocation codec capability exists.

Either is defensible. Which one is a design choice rather than an implementation
detail, which is why it is written here rather than discovered in a diff.

### The event sanitizers cross, and one rule they needed from the kernel

The three classes are served, and the shape they cross in is the projection the
protocol crate declared: a `PluginEventSanitizeCall` goes down (class, event name, the
phase when it is a scope event, and the mutable fields) and the fields come back. Four
pieces make it true, one per layer:

- the kernel's proxy per registration, built from the class it was installed for, so a
  mark sanitizer cannot be reached through the scope-start chain and the class a caller
  gets is one the kernel granted rather than one it asked for;
- the host's runner, which validates the projection's class against the registration's
  own record, builds the synthetic event, and answers with the mutable fields only;
- the core door per class, which runs exactly the registration the kernel names — three
  mark sanitizers in the fixture exist to make "the family, not the registration" a
  test failure rather than a reading of the code;
- and the sentinel, in every mutable field, asserted on the published event rather than
  on the proxy's return value, so "the payload cannot be published" is what the test
  says instead of "the call returned an error".

Qualified through a real child, not only in process: the process suite now shows a
managed call whose published copies carry the child's markers while the call's own
result carries none — a sanitizer changes what observers see and not what the tool did
— with each registration run exactly once per event (a host that ran the family per
call, or a kernel that collapsed three proxies into one, changes the fixture's log),
and a registered failure shape that must not be able to publish what it was shown.

**The one thing that was missing, and where it was**: recording a failure was itself a
mark. The kernel records a sanitizer that could not answer with
`nemo.plugin.sanitize.failed`, that record is an event, and a sanitizer that refuses
every mark is asked about it — so the first failure produced a record, the record
produced a failure, and the runtime recursed until its stack gave out. Found by the
real-child confidentiality case, which is the only place it shows: in process there was
no remote mark sanitizer to fail on the record.

The rule the fix states is the one observers already follow — *a record of a failure is
the runtime's own, and a family is not asked about its own failure records*. It is
implemented as `api::scope::runtime_mark`, which publishes a runtime-raised mark with
no sanitizers and no injectors, and the three off-path families record through it. It
is not a way to publish something a sanitizer should see: what a plugin emits is
forwarded and published through the ordinary path, and a call to `runtime_mark` from a
host process stays in that process, where the kernel has no subscribers.

**The Layer 1 doors owed two things, and both are paid.** First, they never made the
claim every other entry point makes: `ensure_runtime_owner()` was missing, so a process
already owned by another binding could have reached the registries through a door. The
check is one call in the shared helper now, which is also what fixes the three doors at
once rather than three times, and it is tested by authoring the refused state directly —
a published owner and a different current binding — and requiring the refusal before
anything is resolved.

Second, "run the registration named X" had no stated answer for a name held twice. It
can only be held twice across registries, because one registry refuses a second
registration under a name it already holds, so the pair is a process-global entry and a
scope-local one. The rule is the chain's own precedence, written down and pinned: the
door runs the entry the chain would run *first* — ascending priority, and on a tie the
global registration, because the merge appends globals first and sorts stably. Three
tests hold it: the lower priority wins, the tie goes to the global one, and a
scope-local registration is reachable while its scope lives and is not found once that
scope closes. The doors' remaining matrix is direct too: exact mark, exact scope-start,
exact scope-end, siblings that did not run, a name only another class holds, and a
failure that clears the fields and reports why.

**The projection was widened for compatibility, not convenience.** The projection was
chosen over shipping the event, and the price of that choice was checked rather than
assumed: *do any sanitizers the repository ships read what it leaves behind?* One does.
`nemo-relay-pii-redaction`'s event sanitizers gate the scope sanitizers on
`event.category()` (their `sanitize_llm` / `sanitize_tool` configuration) and recognize a
Relay metric mark by `event.data_schema()`. Every other first-party sanitizer ignores
the event and works on the fields alone.

That is a semantic requirement rather than a hypothetical one, so the projection grew
two fields rather than wait: `category` and `data_schema`, both kernel-authored and
read-only. The distinction matters in both directions. They are *not* "kernel-only" —
that phrase belongs to what a plugin may never mention — they are kernel-owned inputs to
a decision a sanitizer is entitled to make. And they are not mutable: the response is
still `EventSanitizeFields`, so there is nowhere for an answer to put a category, a
schema, an identity, or anything else a sanitizer does not own. The boundary now reads:

    PLUGIN MAY READ      class, name, scope category, event category, data schema
    PLUGIN MAY MODIFY    EventSanitizeFields (data, category_profile, metadata)
    PLUGIN NEVER COMES   uuid, timestamp, parent, propagation root, ATOF version,
    NEAR                 event kind, operation identity, registration identity,
                         publication decision

Three tests make that more than a diagram. The disclosure ratchet's approved list
includes the two fields, and its retained list — the names a projection must never
carry — keeps uuid, timestamp, parent, propagation root, ATOF version and kind. A
round-trip test carries a category and a data schema through projection and synthetic
event for all three classes, and refuses a scope projection that states no category
rather than fabricating one. And the semantic test is the one that matters: a fixture
registration branches exactly as the PII component does — metric mark by its data
schema first, otherwise by category — and the process suite drives it through a real
child, requiring the llm path for a mark categorized `llm`, the metric path for a mark
carrying the metric schema, and the tool path for a managed call's scope start. The
published copies still carry the kernel's own category and schema afterwards, because
what a sanitizer decides *with* is not something it can change.

The contract is frozen again at that shape. A further field is added when another
concrete sanitizer dependency demonstrates the need, not in anticipation of one.

### The codec capability protocol, frozen and qualified

The last two classes are the LLM sanitize pair, and the reason they are last is a
decision rather than more of the same: an LLM sanitizer is given the call's *codec* beside
the payload, and a codec is a live object this side holds. It cannot cross, and a plugin
that could name any codec it liked would be choosing how the runtime reads a payload
rather than being told. So the pair needs a capability protocol before it needs an
implementation, which is the order this landed in.

What a plugin gets is a **reference**, not a codec: `codec-<uuid v7>`, issued for one
invocation and one direction. Three properties make that a capability rather than a name:

- **Invocation binding.** A reference issued for operation A is not usable by operation
  B, even when both calls use the same codec. Sequential reuse is refused, and so is
  reuse between two calls that are both in flight.
- **Direction binding.** A request codec and a response codec are different traits, so a
  reference for one direction is not a weaker reference for the other.
- **Identity binding.** The capability records which codec it was issued for; a plugin
  asking to resolve a different *kind* of codec, or another codec of the same kind, is
  refused for what it is rather than handed the one that was issued.

**Lifetime is a guard, not a convention.** Issuing returns the reference beside a guard;
when the invocation ends the guard drops and the record is gone. A reference used
afterwards is not "expired" in any interesting sense — it is *unknown*, because nothing
remembers it, and keeping every reference this process ever forgot would be a leak in
exchange for a better sentence. That is why the refusal for a finished capability and the
refusal for one that was never issued are the same refusal, which the tests state rather
than leave to be discovered.

This is deliberately the worker subsystem's shape rather than a new one. The worker
boundary solved the same problem the same way (`WorkerCodecCapability` beside
`WorkerCodecCapabilityGuard`, `codec-<uuid>` references, an invocation check and a
direction check), and the native path adopts its invariants. What differs is which side
holds the object.

**What is qualified now, and what is not.** The reference's wire shape and its validation
(bounded, prefixed, alphanumeric tail — a peer that guesses a well-formed reference has
guessed a name, not a permission) and the capability record itself with the full refusal
matrix are in, with tests: accept, unknown, finished, wrong operation, wrong direction,
wrong kind, wrong identity, sequential reuse across calls, concurrent reuse between two
live calls, and a guard that takes back only its own capability. The pair of exact
registration doors the host will run — request and response — is in too, with the same
rule as the event doors (exactly the named registration, the family never) and the same
reporting (an omitted payload is an answer; the reason travels beside it), plus the
property the codec work rests on: the door hands the sanitizer *the caller's* context
rather than manufacturing one.

The transport is being built in the order the protocol implies, and the first step is in:
**the kernel serves `ResolveCodec`**, which it refused as unimplemented until the record
existed. It resolves a reference against that record, requires the invocation, the
direction and — from the caller's own payload — the codec to agree with what it issued,
and executes the work with the codec object the record holds. What makes that safe to
serve is not that the caller is the host: the host is the untrusted side. It is that the
reference is one this kernel issued for the invocation the call names, and that the
capability does not outlive it.

Three steps remain, in this order:

1. the host process answers a plugin's codec calls by asking the kernel over that RPC, so
   the SDK's invocation-scoped codec handle works where the plugin runs;
2. the kernel-side proxy per LLM sanitize class issues the capability for the sanitize
   invocation, sends the reference with the payload and holds the guard for exactly the
   call;
3. the host arms rebuild the context, run the door, and answer.

**The nested call completes, and the class is served — 15 of 16.** The host side of the
request sanitizer works end to end: the proxy issues a capability for the sanitize invocation
and holds the guard for exactly that call, the host arm builds the context the plugin's callback
sees, and a plugin's *synchronous* codec call is turned into the kernel's *asynchronous* one by a
bridge that opens and drives its own connection on its own runtime — the affinity rule this
repository has now paid for three times. A real child resolves the call's codec through the
kernel and the published request carries what the codec read, which is the qualification this
class needed.

**What the hunt cost, recorded because it will save the next session the same week.** The
symptom was a sanitize invocation that ran out its budget while the bridge sat on a job the
kernel never answered, and the obvious readings were all wrong: it was not the caller's runtime
flavour, not the capability record, not the codec, not the nesting, and not the second
connection — the control in the tree proves a second connection works, called from an ordinary
async task, in ten milliseconds. Instrumenting *inside* the call then showed the whole round trip
completing, which left only the code around it: the bridge's own `Drop` joined its thread before
giving up the sender, so the thread's `receive` never ended and the dropper waited on a thread
waiting on the dropper. Every call succeeded and the teardown hung, and the sanitize invocation
waiting on that answer read it as a timeout. Both tests are in the tree — the isolated bridge and
its async control — and the drop is the regression they hold.

**The response direction crossed on its own qualification, and the difference is the point.** It
is the same shape — the response the runtime is about to record goes down with the call's codec
identity and a reference, and what comes back is the sanitized copy — but a response *codec* is a
different trait on this side, so the capability the kernel checks is the one it issued for that
direction. A request capability used to decode a response is refused by the record rather than
quietly adapted, and that is the test the direction needed rather than an assumption that the
request's qualification covered it.

**And the boundary has no unproxied class left.** The install match is exhaustive now: the
refusal that used to sit in its `other` arm is gone because there is no other arm, which turns "a
class the kernel cannot proxy" from a runtime refusal into a compile error the day the ABI grows.
The runtime refusal it replaced still exists where it belongs — a plugin registering a class the
*session* does not offer is refused whole at activation — so a future class stays a decision.

**One constraint the class carries, named rather than hidden.** The kernel serves the plugin's
codec call *while* the call that needs it is in flight, and a single-threaded kernel runtime does
not get to serve it: the qualification test is multi-threaded for that reason, and the fixture
keeps its LLM sanitizer behind a configuration key so every other composition test does not wait
out a budget. That is the same shape of problem the tool sanitizers had before the off-path
transport, and it wants the same treatment on the kernel side of this path.

Three steps remain, in this order:

1. the host process answers a plugin's codec calls by asking the kernel over that RPC, so
   the SDK's invocation-scoped codec handle works where the plugin runs;
2. the kernel-side proxy per LLM sanitize class issues the capability for the sanitize
   invocation, sends the reference with the payload and holds the guard for exactly the
   call;
3. the host arms rebuild the context, run the door, and answer.

**The first step is built and the nested call does not complete — recorded, not advertised.**
The host side of the request sanitizer is in: the arm builds the context the plugin's callback
sees, and because a plugin reaches its codec through a *synchronous* ABI call while the work is
an *asynchronous* call into the kernel, a bridge thread turns one into the other — it opens its
own connection to the kernel on its own runtime (a client's tasks belong to the runtime that
opened them, which is the affinity lesson this repository has learned twice already) and blocks
the plugin's thread on the answer.

What works is everything up to the boundary and the codec call leaving the host's side: the
fixture's sanitizer resolves the codec, hands the request through, and the bridge receives the
job. What does not is the return: the kernel's `ResolveCodec` handler is never entered — the
instrumented run prints the bridge's job and never the kernel's receipt — so the sanitize
invocation runs out its budget and the family omits the payload, which is at least the
fail-closed direction.

The finding is bounded, and a second experiment bounded it further. The host is not the
problem and neither is the nesting: with no host in the picture at all — a plain kernel service
on a socket, a capability issued for one operation, and a *blocking* caller on a thread of its
own — the bridge still hangs. That experiment is in the tree, ignored, with that reason on it.
What is ruled out by measurement: the caller's runtime flavour (current-thread and four-worker
both hang in the host test), the capability record (the service-level tests resolve, refuse and
execute against it), the codec (the same tests execute it), the second connection being refused
(the bridge connects, and the kernel's server answers the host's first connection every day),
and the host's arm (the isolated experiment has no host).

What is left is the bridge's own call, and the control that came with the experiment says so
precisely: the *same* socket, the *same* capability and the *same* call made from an async task
instead of a bridge thread **passes**. So a second connection works, a client driven from an
ordinary async context works, and the fault is in how the bridge drives its call — the one
difference the control leaves. It is not the shape: the bridge has been changed twice (one
`block_on` covering both the connection and the calls, and a multi-thread runtime in place of a
current-thread one) and hangs either way. The next step is not another shape but a measurement
*inside* the call — instrument the client's send and the server's accept rather than the code
around them — because the remaining difference is between a task and a foreign thread, and
guessing at it has already cost two attempts. Until that is understood, **the class is not
served**: `supported_registration_operations` does not list it, the fixture registers its
sanitizer only when a test asks for it (a plugin that registered it would be refused whole),
and the real-child test that would qualify it is in the tree, ignored, with that reason on it.
The count stays 14 of 16, and the implementation existing is not qualification.

**What the pair's qualification owes, before it is called done.** The three steps are the
mechanism; these are the properties the mechanism has to hold to, and they are the
acceptance criteria for the commit that advertises the pair:

- **No lock that serves a host→kernel callback is held across the outbound sanitize RPC.**
  The execution nests — kernel sends a sanitize invocation, the plugin calls back for
  codec work, the kernel answers, the plugin continues — so a mutex, an operation-scope
  lock, a continuation lock or a host permit held across that send is a deadlock, whether
  or not the transport supports concurrent traffic. The tests have to run the nesting
  itself: a normal nested resolution, several codec calls inside one sanitize operation,
  concurrent sanitizers, cancellation while a callback is inside `ResolveCodec`, a host
  crash during resolution, and a deliberately constrained executor.
- **The reference is bound to everything that makes it mean something**: session, plugin
  binding, invocation, sanitize call, direction, codec identity, the operations it
  authorizes, and its lifetime. The guard revokes it on every exit — an answer, a
  refusal, a codec failure, a timeout, a cancellation, a crashed host, a dropped
  connection, a panic — and a reference meant for one sanitize invocation is enforced as
  one, not documented as one.
- **Replay is tested as replay.** Not "a wrong invocation is refused" but: capture a
  legitimate reference from invocation A and present it during B, after A finished, after
  a cancellation, after a host restart, from the other direction, and against a different
  codec with the same human-readable id. Every one fails closed.
- **The caller's claim stays evidence and never becomes authority.** `codec_kind` and
  `codec_id` in a payload are checked against the capability record; the record is what
  decides which codec executes. A refactor that turns the claim back into a lookup is the
  one change that would quietly undo the protocol.
- **Hostile operation selection is part of the same matrix**: a request capability must
  not serve a response-only operation, unknown operation values are refused as unknown,
  malformed and well-formed-but-unissued references are refused before any lookup, and a
  stale credential or a reference from another invocation is refused for what it is.

**The kernel's deadline is no longer a constant.** It used to be `now + 29_000` wherever
the kernel needed one, which made every kernel operation run under a deadline no caller
had agreed to: a caller with two seconds left was given twenty-nine, and so was one with
a minute. It now comes from the trusted budget the caller published, narrowed by the
kernel's own ceiling — the same arithmetic everywhere else in the runtime uses, where a
cap can shorten a budget and nothing can lengthen it. The ceiling stays, because a store
wait needs some bound when nobody above this layer stated one.

**And the TCB budgets now have to come back down.** Every raise this migration needed is
recorded as a *temporary* ceiling in `security/tcb.toml` with the milestone that removes
it and the value it must fall to, and `scripts/tcb/report.py` refuses an entry that does
not promise a decrease, one that describes a ceiling the policy does not have, and one
whose target has already been reached while the raise is still in place. The three
outstanding entries are all the loader's: the kernel's lines, its unsafe tokens (288 of
the 307 are the loader's), and the ABI crate's place in the kernel's policy at all. The
loader-removal milestone cannot pass the gate without taking them with it, which is the
difference between a budget and a counter.

Only then can either class be advertised, because a class whose sanitizers cannot resolve
the codec the call is using would have to either refuse calls that have one — most of them
— or let a sanitizer think it had resolved something it had not. Until all four land,
**the pair stays unserved and the count stays 14 of 16**: implementation existing is not
qualification, and neither is half a protocol.

**Class coverage: 14 of 16** *(at the time this section was written; the LLM request
sanitizer has since crossed, and the current figure is at the top of this document)*.
The three that crossed together are the mark, scope-start
and scope-end sanitizers: one shape, one projection, and one installer parameterised
by class. What each needed was a kernel proxy, a host-side runner and a core door that
runs exactly the registration the kernel names, and all three were qualified through a
real child before the served set grew — see *The event sanitizers cross* below. The
pair that does not cross is the two LLM sanitizers, and the reason is a decision rather
than work: an LLM sanitize call is given a codec capability, and in the host that
capability exists only as a *completion*-scoped ABI object, so a unary invocation
across the boundary has no completion to hang one on. Pinned by
`the_boundary_serves_a_named_subset_of_the_registration_surface`, which fails on any
change to either half.

**Plugin compatibility: measured per plugin the repository ships.** Two of them
are fixtures the tests drive, and one is the plugin a reader is pointed at first,
so all three are real registration sets rather than hypotheticals.

`fixture_intercept` — the one the process tests drive end to end:

| | |
|---|---|
| registered classes | 11 (tool + LLM request intercept, subscriber, tool and LLM sanitize, tool + LLM conditional, metadata injector, the refusing guardrail, and the tool and provider execution intercepts) |
| remotely supported | 11 |
| remaining blockers | **0** — it is fully servable today |

`fixture_native` — the sixteen-surface fixture the in-process tests use:

| | |
|---|---|
| registrations | 17 attachment points across all 16 classes (two subscribers, one from each plugin in the fixture's library) |
| remotely supported | 11 (everything except the five named next) |
| remaining blockers | 5 — mark sanitize, scope-start sanitize, scope-end sanitize, LLM sanitize request, LLM sanitize response |

`examples/rust-native-plugin` — the plugin a reader is pointed at first:

| | |
|---|---|
| registered classes | 15: metadata injector, tool + LLM request intercepts, subscriber, mark and scope-start/end sanitizers, tool and LLM sanitize request/response, tool + LLM conditional, tool and LLM execution intercepts, LLM stream execution intercept |
| remotely supported | 11 (everything except the five named next) |
| remaining blockers | 5 — mark sanitize, scope-start sanitize, scope-end sanitize, LLM sanitize request, LLM sanitize response |

That is the number worth watching, and for the example it is six: three
mark/scope sanitizers, two LLM sanitizers, and the streaming intercept. Both of its
execution intercepts are servable now — the tool one and the provider one — so what
it waits on is the sanitizer shapes and streaming. A plugin that registers only the
classes in the supported list is servable today, and this one is one class away from
being servable whole.

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

Running it turned up a defect, and the first reading of it was wrong. The
conversion refused the report with "a registration named
…fixture_event_metadata_injector twice at the same attachment point", which looked
like a fixture that registered a name twice. It is not: the fixture registers each
of its seventeen attachment points once, and the runtime's own registry refuses a
name it already holds, so a genuine duplicate could not have been installed at all.

What had happened is that `NativePluginInstance` recorded a *log* of every
registration an instance ever made rather than the registrations it currently has.
The flow that exposed it runs the plugin's register callbacks twice — a serving
activation that is refused whole, then the inspection that asks what it registered
— so the descriptor described seventeen attachment points as thirty-four, and the
conversion refused the duplicate. The description was unreadable exactly when an
operator needed it: the plugin whose load had just been refused was the one they
were asking about.

The loader now records the current registrations, keyed by attachment point, and
`the_full_fixture_is_inspectable_over_the_boundary` drives the flow over a real
child and asserts the report names all sixteen classes, seventeen attachment
points, each once. That is the authoritative discovery the coverage below rests
on: it is measured over the boundary now rather than by reading the fixture's
source.

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
| subscriber | event | yes | yes | 27 | — (the wire decision was made: `PluginObservedEvent`, and a remote observer's failure is recorded, never allowed to change the call it watched) |
| event metadata injector | event → metadata map | yes | yes | 4 | — |
| tool sanitize request/response guardrail | `(name, Json) -> Json` | yes | yes | 6 + 6 | — (the off-path transport landed; see the section above on the off-path client) |
| mark sanitize guardrail | event | no | no | 9 | that same decision |
| scope sanitize start/end guardrail | event | no | no | 6 + 6 | that same decision |
| mark / scope sanitize guardrail | `(Arc<Event>, EventSanitizeFields) -> EventSanitizeFields` | no | no | 9 + 6 + 6 | the same, plus one field shape |
| LLM sanitize request/response guardrail | codec-bearing context | no | no | 6 + 6 | codec identity on the wire |
| tool execution intercept | continuation | yes | yes | 11 | — (the kernel holds the suspended chain position and the `Continue` RPC resumes it) |
| LLM execution intercept | continuation | yes | yes | 6 | — (the same machinery, tagged by family; the request and response shapes are the only difference) |
| LLM stream intercept, continuations, completions, pull streams | continuation | no | no | 6 | the duplex session: streaming needs ordering, backpressure, half-close, cancellation and terminal states, which a unary resume does not express |

The "yes" rows are not a claim about prose: each one is a class in
`ProcessPluginBackend::supported_registration_operations`, and a class appears
there only next to a proxy that makes it true. Run
`cargo test -p nemo-relay-plugin-host` to check the table against the code rather
than the other way round.

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
the transport belongs to the runtime that awaits it. The off-path client now
exists (`crates/plugin-host/src/attached.rs`) and is created on the off-path
runtime; the host accepts it because the attach presents the credential *and* the
session's capability, and every operation after that presents the capability too.

Nothing in this matrix changes the ordering that moves the metric: coverage, then
the cutover, then the loader leaving, which is what finally drops the 622.

What has *not* moved: the loader still executes inside the kernel's address
space, because the backend the host process serves is the same in-process
implementation the kernel used before. That is deliberate — the boundary and its
contract exist first, so the step that moves the loader changes one
implementation rather than discovering a protocol — and it is why the metric
below has not moved.

This increment does not move `kernel-process unsafe tokens`, which is 622. The
number falls when native loading physically crosses the process boundary, and a
reduction achieved by reclassifying crates would not mean anything.
