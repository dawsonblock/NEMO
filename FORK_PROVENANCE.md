<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# NEMO fork provenance

NEMO is a derived development fork of [NVIDIA NeMo Relay](https://github.com/NVIDIA/NeMo-Relay).
It is not an official NVIDIA release or a substitute for NVIDIA's published
release artifacts.

The supplied upstream source was an archive, not a Git checkout. Its SHA-256 is
`8b84004ecfb5d214db2a827d8d7828bc070ff2b28e8211de74e7ce4de7fce53f` and its
observed workspace version was `0.9.0`. Because that archive contained no
upstream Git metadata, this repository deliberately does not invent an
upstream commit or tree hash.

The fork lineage is:

```text
supplied 0.9.0 archive → 0.9.1-rc.1 hardened development line → 0.9.1-rc.2 stabilization line
```

Machine-readable provenance is in [`release/provenance.json`](release/provenance.json).
The exact source tree and qualification environment for any run are recorded
separately in [`qualification/provenance.json`](qualification/provenance.json).
