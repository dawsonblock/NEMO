<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Plugin wire vectors — `nemo-plugin-protocol-v1-rc1`

`vectors.json` records the encoded bytes of a fixed set of plugin wire
messages.

The `.proto` file in `crates/plugin-proto` is the cross-language schema: another
language generates its own types from it rather than parsing an example here.
What these vectors add is drift detection. A field that is renumbered or
retyped still compiles on both sides, and the failure shows up as a peer
decoding nonsense; recording the bytes turns that into a failing test.

Regenerate deliberately:

```bash
UPDATE_PLUGIN_VECTORS=1 cargo test -p nemo-relay-plugin-proto --test golden_vectors
```

Review the diff before committing it. A change here is a wire change, and the
protocol is at `rc1`: it may still change, but not silently.
