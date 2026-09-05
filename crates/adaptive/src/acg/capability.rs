// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Capability registry tracking per-backend and per-model-family supported features.
//!
//! The registry provides feature discovery so the policy engine knows which
//! optimization intents can be expressed on which backend/model combinations.
//!
//! # Two-Level Feature Lookup
//!
//! [`BackendCapabilities`] stores backend-level defaults plus per-model-family
//! overrides via [`ModelFamilyCapabilities`]. Feature lookups check the model
//! family first, falling back to backend-level if the family is not registered.
//!
//! # Built-in Defaults
//!
//! [`CapabilityRegistry::with_defaults()`] returns a registry pre-populated
//! with known Anthropic and OpenAI capabilities.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

// ===================================================================
// ProviderFeature enum
// ===================================================================

/// Feature that a backend or model family may support.
///
/// Used by the capability registry and policy engine to determine
/// which optimization intents can be expressed for a given target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFeature {
    /// Backend supports explicit cache control breakpoints (e.g., Anthropic).
    ExplicitCacheBreakpoints,
    /// Backend uses automatic prefix caching (e.g., OpenAI).
    AutomaticPrefixCaching,
    /// Backend supports retention tier control.
    RetentionTiers,
    /// Backend supports priority-based scheduling.
    PriorityScheduling,
    /// Backend supports model routing/selection.
    ModelRouting,
    /// Backend supports deferred tool loading.
    DeferredToolLoading,
    /// Backend supports file/artifact references in prompts.
    FileReferences,
    /// Backend supports structured output schemas.
    StructuredOutput,
    /// Backend supports prefix-affinity routing hints.
    PrefixAffinityHints,
    /// Backend reports per-chunk token counts in streaming responses.
    StreamingTokenCounts,
}

/// Provider/model-specific cache economics used by the internal planner.
///
/// These values are kept on the capability surface so the core planner can
/// stay provider-agnostic while concrete plugins/model families supply the
/// pricing model that makes a cache write profitable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheEconomics {
    /// Input cost multiplier for creating a short-lived cache entry.
    pub write_short_multiplier: f64,
    /// Optional input cost multiplier for creating a longer-lived cache entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub write_long_multiplier: Option<f64>,
    /// Input cost multiplier for reading from cache.
    pub read_multiplier: f64,
}

// ===================================================================
// ModelFamilyCapabilities
// ===================================================================

/// Per-model-family capability overrides within a backend.
///
/// Some features vary by model within the same backend (e.g., Claude 3.5
/// Sonnet supports 4 cache breakpoints while older models support fewer).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelFamilyCapabilities {
    /// Model family identifier (e.g., "claude-3.5-sonnet", "gpt-4o").
    pub model_family: String,
    /// Features supported by this model family.
    pub supported_features: HashSet<ProviderFeature>,
    /// Maximum number of cache breakpoints (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub max_cache_breakpoints: Option<u32>,
    /// Minimum tokens required for a block to be cacheable.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub min_cacheable_tokens: Option<u32>,
    /// Provider/model-specific cache economics for explicit cache planning.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub cache_economics: Option<CacheEconomics>,
}

impl ModelFamilyCapabilities {
    /// Check if this model family supports a specific feature.
    pub fn supports(&self, feature: ProviderFeature) -> bool {
        self.supported_features.contains(&feature)
    }
}

// ===================================================================
// BackendCapabilities
// ===================================================================

/// Capabilities of a specific backend provider.
///
/// Two-level model: backend-level defaults plus per-model-family overrides.
/// Feature lookup checks model-family first, falls back to backend-level.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackendCapabilities {
    /// Backend identifier (e.g., "anthropic", "openai", "passthrough").
    pub backend_id: String,
    /// Backend-level supported features (default for all models).
    pub supported_features: HashSet<ProviderFeature>,
    /// Per-model-family capability overrides.
    pub model_families: HashMap<String, ModelFamilyCapabilities>,
}

impl BackendCapabilities {
    /// Create capabilities with no features (used by passthrough plugin).
    pub fn none(backend_id: &str) -> Self {
        Self {
            backend_id: backend_id.to_string(),
            supported_features: HashSet::new(),
            model_families: HashMap::new(),
        }
    }

    /// Check if the backend supports a feature at the backend level.
    pub fn supports(&self, feature: ProviderFeature) -> bool {
        self.supported_features.contains(&feature)
    }

    /// Check if a specific model family supports a feature.
    ///
    /// Falls back to backend-level if the model family is not registered.
    pub fn model_supports(&self, model_family: &str, feature: ProviderFeature) -> bool {
        if let Some(family_caps) = self.model_families.get(model_family) {
            family_caps.supports(feature)
        } else {
            self.supports(feature)
        }
    }

    /// Add a model family capability override.
    pub fn add_model_family(&mut self, caps: ModelFamilyCapabilities) {
        self.model_families.insert(caps.model_family.clone(), caps);
    }
}

// ===================================================================
// CapabilityRegistry
// ===================================================================

/// Registry holding capabilities for all known backends.
///
/// Provides feature discovery so the policy engine and validation
/// framework know which intents can be expressed on which targets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilityRegistry {
    backends: HashMap<String, BackendCapabilities>,
}

impl CapabilityRegistry {
    /// Create a new empty capability registry.
    pub fn new() -> Self {
        Self {
            backends: HashMap::new(),
        }
    }

    /// Create a registry pre-populated with known Anthropic and OpenAI capabilities.
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();

        // -----------------------------------------------------------------
        // Anthropic backend
        // -----------------------------------------------------------------
        let anthropic_features: HashSet<ProviderFeature> = [
            ProviderFeature::ExplicitCacheBreakpoints,
            ProviderFeature::RetentionTiers,
            ProviderFeature::StreamingTokenCounts,
        ]
        .into_iter()
        .collect();

        let mut anthropic = BackendCapabilities {
            backend_id: "anthropic".to_string(),
            supported_features: anthropic_features.clone(),
            model_families: HashMap::new(),
        };

        // Current model families (2026)
        anthropic.add_model_family(ModelFamilyCapabilities {
            model_family: "claude-opus-4.6".to_string(),
            supported_features: anthropic_features.clone(),
            max_cache_breakpoints: Some(4),
            min_cacheable_tokens: Some(4096),
            cache_economics: Some(CacheEconomics {
                write_short_multiplier: 1.25,
                write_long_multiplier: Some(2.0),
                read_multiplier: 0.1,
            }),
        });

        anthropic.add_model_family(ModelFamilyCapabilities {
            model_family: "claude-opus-4.5".to_string(),
            supported_features: anthropic_features.clone(),
            max_cache_breakpoints: Some(4),
            min_cacheable_tokens: Some(4096),
            cache_economics: Some(CacheEconomics {
                write_short_multiplier: 1.25,
                write_long_multiplier: Some(2.0),
                read_multiplier: 0.1,
            }),
        });

        anthropic.add_model_family(ModelFamilyCapabilities {
            model_family: "claude-opus-4.1".to_string(),
            supported_features: anthropic_features.clone(),
            max_cache_breakpoints: Some(4),
            min_cacheable_tokens: Some(1024),
            cache_economics: Some(CacheEconomics {
                write_short_multiplier: 1.25,
                write_long_multiplier: Some(2.0),
                read_multiplier: 0.1,
            }),
        });

        anthropic.add_model_family(ModelFamilyCapabilities {
            model_family: "claude-opus-4".to_string(),
            supported_features: anthropic_features.clone(),
            max_cache_breakpoints: Some(4),
            min_cacheable_tokens: Some(1024),
            cache_economics: Some(CacheEconomics {
                write_short_multiplier: 1.25,
                write_long_multiplier: Some(2.0),
                read_multiplier: 0.1,
            }),
        });

        anthropic.add_model_family(ModelFamilyCapabilities {
            model_family: "claude-sonnet-4.6".to_string(),
            supported_features: anthropic_features.clone(),
            max_cache_breakpoints: Some(4),
            min_cacheable_tokens: Some(2048),
            cache_economics: Some(CacheEconomics {
                write_short_multiplier: 1.25,
                write_long_multiplier: Some(2.0),
                read_multiplier: 0.1,
            }),
        });

        anthropic.add_model_family(ModelFamilyCapabilities {
            model_family: "claude-sonnet-4.5".to_string(),
            supported_features: anthropic_features.clone(),
            max_cache_breakpoints: Some(4),
            min_cacheable_tokens: Some(1024),
            cache_economics: Some(CacheEconomics {
                write_short_multiplier: 1.25,
                write_long_multiplier: Some(2.0),
                read_multiplier: 0.1,
            }),
        });

        anthropic.add_model_family(ModelFamilyCapabilities {
            model_family: "claude-sonnet-4".to_string(),
            supported_features: anthropic_features.clone(),
            max_cache_breakpoints: Some(4),
            min_cacheable_tokens: Some(1024),
            cache_economics: Some(CacheEconomics {
                write_short_multiplier: 1.25,
                write_long_multiplier: Some(2.0),
                read_multiplier: 0.1,
            }),
        });

        anthropic.add_model_family(ModelFamilyCapabilities {
            model_family: "claude-haiku-4.5".to_string(),
            supported_features: anthropic_features.clone(),
            max_cache_breakpoints: Some(4),
            min_cacheable_tokens: Some(4096),
            cache_economics: Some(CacheEconomics {
                write_short_multiplier: 1.25,
                write_long_multiplier: Some(2.0),
                read_multiplier: 0.1,
            }),
        });

        anthropic.add_model_family(ModelFamilyCapabilities {
            model_family: "claude-haiku-3.5".to_string(),
            supported_features: anthropic_features.clone(),
            max_cache_breakpoints: Some(4),
            min_cacheable_tokens: Some(2048),
            cache_economics: Some(CacheEconomics {
                write_short_multiplier: 1.25,
                write_long_multiplier: Some(2.0),
                read_multiplier: 0.1,
            }),
        });

        // Legacy model families (backward compatibility)
        anthropic.add_model_family(ModelFamilyCapabilities {
            model_family: "claude-3.5-sonnet".to_string(),
            supported_features: anthropic_features.clone(),
            max_cache_breakpoints: Some(4),
            min_cacheable_tokens: Some(1024),
            cache_economics: Some(CacheEconomics {
                write_short_multiplier: 1.25,
                write_long_multiplier: Some(2.0),
                read_multiplier: 0.1,
            }),
        });

        anthropic.add_model_family(ModelFamilyCapabilities {
            model_family: "claude-3-opus".to_string(),
            supported_features: anthropic_features.clone(),
            max_cache_breakpoints: Some(4),
            min_cacheable_tokens: Some(2048),
            cache_economics: Some(CacheEconomics {
                write_short_multiplier: 1.25,
                write_long_multiplier: Some(2.0),
                read_multiplier: 0.1,
            }),
        });

        anthropic.add_model_family(ModelFamilyCapabilities {
            model_family: "claude-3-haiku".to_string(),
            supported_features: anthropic_features,
            max_cache_breakpoints: Some(4),
            min_cacheable_tokens: Some(1024),
            cache_economics: Some(CacheEconomics {
                write_short_multiplier: 1.25,
                write_long_multiplier: Some(2.0),
                read_multiplier: 0.1,
            }),
        });

        registry.register_backend(anthropic);

        // -----------------------------------------------------------------
        // OpenAI backend
        // -----------------------------------------------------------------
        let openai_features: HashSet<ProviderFeature> = [
            ProviderFeature::AutomaticPrefixCaching,
            ProviderFeature::StreamingTokenCounts,
            ProviderFeature::StructuredOutput,
        ]
        .into_iter()
        .collect();

        let mut openai = BackendCapabilities {
            backend_id: "openai".to_string(),
            supported_features: openai_features.clone(),
            model_families: HashMap::new(),
        };

        openai.add_model_family(ModelFamilyCapabilities {
            model_family: "gpt-4o".to_string(),
            supported_features: openai_features.clone(),
            max_cache_breakpoints: None,
            min_cacheable_tokens: None,
            cache_economics: None,
        });

        openai.add_model_family(ModelFamilyCapabilities {
            model_family: "gpt-4o-mini".to_string(),
            supported_features: openai_features,
            max_cache_breakpoints: None,
            min_cacheable_tokens: None,
            cache_economics: None,
        });

        // o1 reasoning models: only streaming token counts (no prefix caching)
        let o1_features: HashSet<ProviderFeature> = [ProviderFeature::StreamingTokenCounts]
            .into_iter()
            .collect();

        openai.add_model_family(ModelFamilyCapabilities {
            model_family: "o1".to_string(),
            supported_features: o1_features,
            max_cache_breakpoints: None,
            min_cacheable_tokens: None,
            cache_economics: None,
        });

        registry.register_backend(openai);

        registry
    }

    /// Register a backend's capabilities in the registry.
    pub fn register_backend(&mut self, caps: BackendCapabilities) {
        self.backends.insert(caps.backend_id.clone(), caps);
    }

    /// Retrieve a backend's capabilities by ID.
    pub fn get_backend(&self, backend_id: &str) -> Option<&BackendCapabilities> {
        self.backends.get(backend_id)
    }

    /// Check if a backend supports a feature at the backend level.
    pub fn supports_feature(&self, backend_id: &str, feature: ProviderFeature) -> bool {
        self.backends
            .get(backend_id)
            .is_some_and(|b| b.supports(feature))
    }

    /// Check if a specific model family on a backend supports a feature.
    ///
    /// Falls back to backend-level if the model family is not registered.
    pub fn model_supports_feature(
        &self,
        backend_id: &str,
        model_family: &str,
        feature: ProviderFeature,
    ) -> bool {
        self.backends
            .get(backend_id)
            .is_some_and(|b| b.model_supports(model_family, feature))
    }

    /// Return a sorted list of all registered backend IDs.
    pub fn list_backend_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.backends.keys().cloned().collect();
        ids.sort();
        ids
    }
}

#[cfg(test)]
#[path = "../../tests/unit/acg/capability_tests.rs"]
mod tests;
