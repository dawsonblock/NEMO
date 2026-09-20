// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! gRPC protocol for the out-of-process native plugin host.
//!
//! This crate is the single authority for what crosses the kernel↔host
//! boundary. `nemo-relay-plugin-protocol` holds the semantic vocabulary — the
//! domain types the kernel reasons about and the trait it calls — while this
//! crate holds the wire form of the same messages. Keeping them apart lets the
//! kernel depend on the vocabulary without taking on a protobuf toolchain, and
//! an architecture test keeps the wire from being declared anywhere else.
//!
//! The services are deliberately a pair. `PluginHost` is served by the host
//! process and answers the kernel's operations; `RelayRuntime` is served by the
//! kernel and answers the calls a running plugin makes back into it. A
//! request-only model cannot express the second direction, and the native ABI is
//! bidirectional: plugins are handed a table of host functions and the host
//! re-enters their callbacks.

#![deny(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]

/// Generated messages and clients for `nemo.relay.plugin.v1`.
#[allow(missing_docs)]
pub mod v1 {
    tonic::include_proto!("nemo.relay.plugin.v1");
}

/// Protocol revision this crate encodes.
///
/// Must equal `nemo_relay_plugin_protocol::PROTOCOL_VERSION`; a test asserts it,
/// because a wire schema silently lagging the vocabulary it serialises is the
/// kind of drift that only shows up in production.
pub const PROTOCOL_VERSION: u32 = 1;

/// Largest framed message either side will accept.
pub const MAX_FRAME_BYTES: u32 = 8 * 1024 * 1024;

/// `PluginHost` and `RelayRuntime` clients.
pub use v1::plugin_host_client::PluginHostClient;
pub use v1::plugin_host_server::{PluginHost, PluginHostServer};
pub use v1::relay_runtime_client::RelayRuntimeClient;
pub use v1::relay_runtime_server::{RelayRuntime, RelayRuntimeServer};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wire_revision_matches_the_vocabulary_it_serialises() {
        assert_eq!(
            PROTOCOL_VERSION,
            u32::from(nemo_relay_plugin_protocol::PROTOCOL_VERSION),
            "the wire schema and the semantic vocabulary have to agree on the revision"
        );
    }

    #[test]
    fn the_frame_limit_matches_the_vocabulary() {
        assert_eq!(MAX_FRAME_BYTES, nemo_relay_plugin_protocol::MAX_FRAME_BYTES);
    }
}
