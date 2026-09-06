<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Runtime queue inventory

This inventory records the asynchronous buffers that can retain runtime work.
Every production queue has an explicit bound and an overflow policy. The
capacity values are deliberately conservative starting points for the
`0.9.1-rc.2` stabilization line; pressure qualification should tune them with
measured event sizes and service latency.

| Queue | Capacity | Overflow behavior | Shutdown behavior |
| --- | ---: | --- | --- |
| Subscriber dispatcher | 4096 | Low-priority events are dropped at the 512-message reserve; lifecycle, security, authority, audit, and control messages backpressure. | Dispatcher drains through the existing flush barrier. |
| Nested publication buffer | 1024 (low-priority reserve 128) | Low-priority nested publications are dropped at the reserve; all nested publications are hard-capped. | The bounded buffer is drained at the enclosing publication barrier. |
| Detached publication executor | 256 | New detached publication jobs are rejected when full. | Sender drop lets the worker finish queued jobs. |
| Adaptive telemetry drain | 1024 | Telemetry is dropped with a warning when full; pending-event accounting is restored. | Receiver close and runtime deregistration drain and terminate cleanly. |
| ATOF endpoint worker | 1024 (one control slot reserved) | Observational event delivery is dropped when full; flush and close retain the reserved control path. | Close is queued when possible and the sender is always dropped. |
| ATOF WebSocket retry backlog | 1024 | Events are dropped once the retry backlog reaches its bound. | Close drains the bounded backlog and closes the socket. |
| ATOF NDJSON request body | 1024 (one control slot reserved) | Events are dropped when the request body is stalled; flush remains observable. | Closing the body finishes or times out the upload. |
| ATIF remote upload worker | 32 | Upload submissions apply synchronous backpressure while the dedicated storage worker drains them. | Dropping the sender lets the worker finish queued uploads. |
| Plugin mutation executor | 256 | Activation and teardown return a retryable capacity error instead of queueing another future. | The host thread drains queued mutations before its sender is released. |
| Node push-stream bridge | 32 | The synchronous compatibility push returns `false`; the typed adapter awaits bounded capacity. | Cancellation wakes a producer waiting for capacity. |
| NeMo Guardrails worker commands | 256 | Commands are rejected with a retryable capacity error when the child stdin writer is saturated. | Sender drop lets the writer flush and exit. |
| NeMo Guardrails worker stream | 256 | The worker reader blocks on the bounded stream channel, applying backpressure to the child process. | Closed consumers release the reader; worker shutdown sends a terminal error. |

The runtime still has intentionally bounded collections that are not transport
queues, such as cache eviction windows and adaptive learner windows. New
asynchronous producers must add an entry here and include a saturation test
before using a channel or pending collection in a production path.
