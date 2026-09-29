// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use serde_json::{Map, Value as Json};

#[test]
fn dynamic_plugin_specs_require_unique_nonempty_input() {
    let empty = validate_dynamic_plugin_specs(&[]).unwrap_err().to_string();
    assert!(
        empty.contains("requires at least one dynamic plugin"),
        "{empty}"
    );

    let duplicate = DynamicPluginActivationSpec {
        plugin_id: "fixture.duplicate".into(),
        kind: DynamicPluginKind::RustDynamic,
        manifest_ref: "relay-plugin.toml".into(),
        environment_ref: None,
        config: Map::new(),
    };
    let error = validate_dynamic_plugin_specs(&[duplicate.clone(), duplicate])
        .unwrap_err()
        .to_string();
    assert!(error.contains("duplicate dynamic plugin id"), "{error}");
}

#[test]
fn plugin_error_context_preserves_each_error_class() {
    use nemo_relay::plugin::PluginError;

    let serialization = serde_json::from_str::<Json>("{").unwrap_err();
    let errors = [
        PluginError::InvalidConfig("invalid".into()),
        PluginError::Conflict("conflict".into()),
        PluginError::NotFound("missing".into()),
        PluginError::Serialization(serialization),
        PluginError::Internal("internal".into()),
        PluginError::RegistrationFailed("registration".into()),
    ];

    for error in errors {
        let message = plugin_error_context("dynamic load", error).to_string();
        assert!(message.contains("dynamic load"), "{message}");
    }
}

#[test]
fn retained_runtime_errors_include_cleanup_details_when_available() {
    let default_error = retained_runtime_error(Vec::new()).to_string();
    assert!(
        default_error.contains("teardown was incomplete"),
        "{default_error}"
    );

    let detailed_error =
        retained_runtime_error(vec!["registry remained active".into()]).to_string();
    assert!(
        detailed_error.contains("registry remained active"),
        "{detailed_error}"
    );
}
