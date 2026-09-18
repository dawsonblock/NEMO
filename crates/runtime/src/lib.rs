// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Production composition root for durable NeMo Relay runtime wiring.

#[cfg(feature = "production")]
/// Bootstrap and dependency wiring entrypoints.
pub mod bootstrap;
#[cfg(feature = "production")]
/// Runtime configuration types.
pub mod config;
#[cfg(feature = "production")]
/// Runtime health projections.
pub mod health;
#[cfg(feature = "production")]
/// Runtime identity resolution helpers.
pub mod identity;
