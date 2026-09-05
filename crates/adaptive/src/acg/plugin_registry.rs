// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Plugin registry for storing and retrieving provider plugins.
//!
//! [`PluginRegistry`] is an instance-scoped (not global static) store for
//! [`ProviderPlugin`] trait objects. Plugins are stored as
//! `Arc<dyn ProviderPlugin>` keyed by plugin ID.
//!
//! Instance-scoped design is more testable and can be promoted to a static
//! later if needed.

use std::collections::HashMap;
use std::sync::Arc;

use crate::acg::error::{AcgError, Result};
use crate::acg::plugin::ProviderPlugin;

/// Registry for storing and retrieving provider plugins.
///
/// Instance-scoped (not a global static) for testability. Stores plugins
/// as `Arc<dyn ProviderPlugin>` keyed by plugin ID.
pub struct PluginRegistry {
    plugins: HashMap<String, Arc<dyn ProviderPlugin>>,
}

impl PluginRegistry {
    /// Create a new empty plugin registry.
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    /// Register a plugin in the registry.
    ///
    /// Returns `Err(AcgError::PluginAlreadyRegistered)` if a plugin with
    /// the same ID is already registered.
    pub fn register(&mut self, plugin: Arc<dyn ProviderPlugin>) -> Result<()> {
        let id = plugin.plugin_id().to_string();
        if self.plugins.contains_key(&id) {
            return Err(AcgError::PluginAlreadyRegistered(id));
        }
        self.plugins.insert(id, plugin);
        Ok(())
    }

    /// Retrieve a plugin by ID, returning an `Arc` clone.
    pub fn get(&self, plugin_id: &str) -> Option<Arc<dyn ProviderPlugin>> {
        self.plugins.get(plugin_id).cloned()
    }

    /// Return a sorted list of all registered plugin IDs.
    pub fn list_plugin_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.plugins.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Remove a plugin from the registry, returning `true` if it was present.
    pub fn deregister(&mut self, plugin_id: &str) -> bool {
        self.plugins.remove(plugin_id).is_some()
    }

    /// Return the number of registered plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Return `true` if the registry contains no plugins.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for PluginRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginRegistry")
            .field("plugin_ids", &self.list_plugin_ids())
            .finish()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/acg/plugin_registry_tests.rs"]
mod tests;
