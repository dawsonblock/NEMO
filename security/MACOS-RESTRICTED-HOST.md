<!--
SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Milestone: macOS restricted native plugin host

**Status** (this document is the plan and the record of what is already enforced;
the sections below say which is which):

- **The policy exists and is explicit.** `NativeIsolationPolicy` names the level a
  deployment selects — `trusted-process`, the level that was implicit before it had
  a name, and `restricted-macos`. A level this build cannot deliver is refused at
  startup, before anything is created, rather than served with a host that runs
  without the confinement the configuration states.
- **A confined host is a bundle.** `scripts/package-plugin-host-app.py` produces
  `nemo-plugin-host.app` from the built executable, with `Contents/Info.plist` and
  the entitlements in `security/entitlements/`, signed ad hoc. macOS applies App
  Sandbox from a signed bundle's entitlements, and a bare executable carrying the
  same entitlement is refused at launch: the confinement is a packaging fact
  rather than a flag.
- **The resolver knows the bundle.** Where a host is looked for now includes
  `nemo-plugin-host.app/Contents/MacOS/nemo-plugin-host` beside the runtime, and a
  path a caller supplied is used only when it is already that shape.
- **The sandbox contract has a focused macOS probe.** `just verify-macos-sandbox`
  packages a purpose-built probe executable with the restricted entitlements. It
  proves the container and its `Library/Application Support/NeMo Relay` staging
  path are writable, while shared temporary storage, the account's real home, an
  outbound connection and a library outside the container are refused. The lane
  also requires the release host binary to exist, but the probe is not that host.
- **Transfer, quarantine handoff, and the confined load are implemented and
  qualified on macOS.** An authenticated client stream carries the approved
  manifest and bounded library chunks into per-session staging. The host checks
  offsets, length and both stream/file SHA-256 values, fsyncs and atomically
  promotes the artifact, and resolves loads only through the approved copy. The
  unconfined supervisor derives its location from the session and kernel-minted
  artifact IDs, opens each path component without following symlinks, rechecks the
  approved library digest, and removes only `com.apple.quarantine` through that
  file descriptor. The loader then loads that container-owned file in place and
  checks its digest again after `dlopen`; it does not try to create a second copy
  outside the sandbox. The signed-bundle process test completes transfer, load,
  and a real registration, while the focused probe verifies the same entitlements'
  filesystem and network denials.

## Target

> A native plugin approved by Relay executes in a dedicated App Sandbox process
> with no ambient access to the user's filesystem, network, devices, or other
> protected resources beyond capabilities Relay deliberately provides.

That is a narrower claim than "hostile-safe", and the difference is worth stating
in the same breath. App Sandbox is kernel-enforced confinement of a same-kernel
process; it materially reduces what a malicious plugin can reach, and it is not
the boundary for code assumed adversarial. The three levels are:

```text
TRUSTED      ordinary child process
             crash containment, bounded execution, resource ceilings
RESTRICTED   App Sandbox child
             the above, plus filesystem, network and device confinement
HOSTILE      a VM boundary                 (not implemented; a different mechanism)
```

## The boundary

```text
      Python / Node / CLI / FFI
                │
                ▼
            Relay kernel
                │  authenticated session (the existing protocol)
                ▼
┌──────────────────────────────────────────────┐
│ nemo-plugin-host.app                         │
│   App Sandbox · Hardened Runtime             │
│   disable-library-validation  (*)            │
│                                              │
│   native-loader                              │
│        │                                     │
│        ▼                                     │
│   approved plugin, staged inside the         │
│   host's own container                       │
└──────────────────────────────────────────────┘

(*) only for the bundle signed to load plugins from another signer, and only in
    that bundle: the strict variant keeps library validation on.
```

## The first principle: the host owns its container

The sandboxed host cannot read the source path the kernel approved — that is the
point of it — so the source path never crosses the boundary. The artifact crosses
as bytes over the authenticated session, and the host writes it where the platform
allows it to write:

```text
kernel reads the approved artifact, verifies its digest
        │
        ▼
BeginArtifact { expected_digest, expected_length }     ─┐
ArtifactChunk …                                        │ the existing session,
FinalizeArtifact                                       ─┘ nothing new to trust
        │
        ▼
host streams chunks into a file inside its container, hashing as it writes
        │
        ▼
fsync → length check → digest check → atomic rename
        │
        ▼
SHA256(bytes the host wrote) == the digest the kernel approved → dlopen
```

Two things this buys, and one it costs:

- The supervisor does not choose an arbitrary path inside the app container. It
  derives the one approved library location from the stable bundle container,
  session ID, artifact ID and manifest path only for the quarantine handoff.
- The integrity story gets *stronger* rather than weaker: what is loaded is what
  the kernel approved, verified again on the side that loads it, and the file it
  is loaded from was written by the process that loads it.
- The costs are a copy through the session, bounded by the length the kernel
  announces in the begin message — an announced length the host enforces, so a
  malformed far side cannot turn the transfer into unbounded disk use — and a
  narrow xattr-removal operation in the unconfined supervisor. That operation is
  part of the trusted computing base and refuses paths, symlinks, files or digests
  outside the kernel-approved staging record.

Security-scoped bookmarks are deliberately **not** part of this milestone. They
are the right mechanism for a plugin that genuinely needs a user-selected file,
and they belong with the capability types (`ReadFile(bookmark)`,
`WriteDirectory(bookmark)`, `NetworkClient(...)`) that come after the baseline.

## What is enforced now, and by what

| claim | enforced by |
|---|---|
| A confinement this build cannot deliver is refused before anything starts | `a_confinement_this_build_cannot_deliver_is_refused_before_anything_starts` |
| A confined host is the bundle's executable, and a bare one is refused | `a_restricted_host_outside_a_bundle_is_refused`, `the_bundle_layout_is_structurally_recognised` |
| The bundle has the layout macOS reads entitlements from | `test_the_bundle_has_the_layout_macos_reads_entitlements_from` |
| The weaker entitlement is not what a build gets by default | `test_the_weakening_variant_is_not_the_default` |
| The confinement denies what it must and permits what the host is for | `just verify-macos-sandbox` in the macOS lane |
| The parent removes only quarantine from the kernel-approved staged dylib | `macos_quarantine::tests::clears_only_quarantine_after_rechecking_the_approved_digest`, plus the signed-bundle process test |

The bundle layout, entitlements and resolver have structural tests. The actual
host's sandboxed launch, transfer and load are exercised by the opt-in
`a_restricted_bundle_loads_only_the_transferred_approved_copy` process-backend
test when supplied a signed app-bundle executable. The focused probe establishes
the operating-system denial behavior; neither result substitutes for the other.

## What is implemented, and what still needs qualification

1. **Artifact transfer is implemented in the protocol and staging layer.** `TransferArtifact` uses the existing
   authenticated session and capability. The parent sends manifest identity and
   bounded chunks; the host owns the staging path and the load accepts only its
   verified, atomically promoted copy. RPC integration coverage verifies the
   approved load resolution and per-session cleanup. Digest mismatch, interruption,
   and over-limit behavior are covered at the staging layer. These tests run
   outside App Sandbox, so they do not prove the complete confined transfer path.
2. **The macOS quarantine interaction is handled by the supervisor.** Apple
   documents that sandbox-created files are quarantined and developer support
   confirms the sandbox cannot remove that attribute. The
   `com.apple.security.files.user-selected.executable` entitlement did not change
   quarantine on the staged library. The kernel therefore performs a narrowly
   scoped handoff after the host approves the transferred bytes: it derives the
   expected bundle-container path, walks it without following symlinks, verifies
   the approved SHA-256 on an open file descriptor, and removes only the
   quarantine attribute. This adds filesystem metadata mutation to the kernel's
   trusted computing base. The end-to-end test confirms the staged file loads and
   executes a registration with the restricted entitlements.
   See [Apple's App Sandbox guidance](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html)
   and [Apple DTS's quarantine guidance](https://developer.apple.com/forums/thread/811450).
3. **Packaging.** The bundle has to travel in the artifacts that carry a host: the
   CLI release archive and wheel, the Python wheel, and the Node platform package.
   Each needs its install layout decided rather than assumed — a wheel's
   `.data/scripts` is a directory pip fills, and npm's `bin` is one flat
   directory — and that is why it is a step of its own.
4. **The macOS qualification lanes.** The real signed-bundle process test covers
   transfer, load and registration. `just verify-macos-sandbox` covers these
   filesystem and network denials with a probe signed using the same entitlements:

   ```text
   ✓ the plugin loads from the host's container
   ✓ a real registration executes, in a process that is not the kernel's
   ✓ the kernel survives the plugin crashing
   ✓ the execution budget still refuses an over-long call
   ✗ cannot write /tmp
   ✗ cannot read or write an arbitrary file in the user's home
   ✗ cannot connect outbound
   ✗ cannot load a library that is not the staged one
   ```

   These are complementary checks: the host process test verifies the plugin path,
   and the probe verifies the OS denials imposed by the same signed entitlements.
   The approved digest is also rechecked by the supervisor before quarantine is
   removed and by the loader after `dlopen`.
5. **Capabilities.** A way for a plugin to declare what it needs and for the
   runtime to grant exactly that, rather than widening the bundle every plugin
   runs inside.

## Signing, in three separate things

- **Development proof: ad hoc.** `codesign --sign -` with the entitlements is what
  makes the sandbox implementable and testable here, and it is not a distribution
  signature — it carries no team identity and a quarantined artifact signed that
  way is not accepted by the system's own checks.
- **Security architecture: the entitlements.** Deny by default, with the weakened
  library-validation variant as a separate bundle rather than a flag.
- **Distribution: Developer ID and notarization.** Tracked as its own row in the
  qualification matrix rather than assumed, because it is a CI and key-custody
  decision and not an architecture one.
