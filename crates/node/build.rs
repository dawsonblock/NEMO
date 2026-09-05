// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build script that configures `napi-rs` code generation for this crate.

extern crate napi_build;

fn main() {
    napi_build::setup();
}
