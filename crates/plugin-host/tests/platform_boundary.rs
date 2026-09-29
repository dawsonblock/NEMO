// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keeps platform transport details out of modules shared by Unix and Windows.

#[test]
fn common_modules_do_not_reach_unix_socket_apis() {
    let common = [
        ("activation", include_str!("../src/activation.rs")),
        ("error", include_str!("../src/error.rs")),
        ("host_location", include_str!("../src/host_location.rs")),
        (
            "isolation_policy",
            include_str!("../src/isolation_policy.rs"),
        ),
        ("limits", include_str!("../src/limits.rs")),
        ("off_path_policy", include_str!("../src/off_path_policy.rs")),
        (
            "operation_context",
            include_str!("../src/operation_context.rs"),
        ),
    ];
    let forbidden = ["std::os::unix", "tokio::net::Unix", "UnixListenerStream"];

    for (module, source) in common {
        for token in forbidden {
            assert!(
                !source.contains(token),
                "common module {module} contains Unix-only API token {token}"
            );
        }
    }
}
