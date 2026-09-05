// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Semantic hint translation contracts for provider-specific ACG behavior.
//!
//! A translator emits a surface-agnostic `hint plan` keyed to PromptIR spans
//! and stable-prefix boundaries. Applying that plan to a concrete request
//! surface happens later in `crate::acg::request_surfaces`, so translators must
//! stay independent from Anthropic Messages, OpenAI Chat, and OpenAI Responses
//! wire layouts. Core request codecs remain request-intercept helpers, and
//! response codecs remain observability-only helpers.

pub mod anthropic;
pub mod openai;

use crate::acg::plugin::PluginInput;
use crate::acg::prompt_ir::SpanId;
use crate::acg::types::{SharingScope, TranslationReport};

/// Semantic, request-surface-agnostic translation output.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HintTranslation {
    pub hint_plan: HintPlan,
    pub translation_report: TranslationReport,
}

/// Internal contract for provider-semantic hint translation.
pub(crate) trait HintTranslator: Send + Sync {
    fn provider_id(&self) -> &str;
    fn translate(&self, input: &PluginInput<'_>) -> crate::acg::Result<HintTranslation>;
}

/// Surface-agnostic hint plan keyed to PromptIR spans or stable-prefix boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HintPlan {
    pub provider: String,
    pub directives: Vec<HintDirective>,
}

impl HintPlan {
    pub fn new(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            directives: Vec::new(),
        }
    }

    pub fn push(&mut self, directive: impl Into<HintDirective>) {
        self.directives.push(directive.into());
    }

    pub fn has_anthropic_breakpoint(&self) -> bool {
        self.directives.iter().any(|directive| {
            matches!(
                directive,
                HintDirective::Anthropic(AnthropicHintDirective::CacheBreakpoint { .. })
            )
        })
    }
}

/// Semantic targeting keyed to PromptIR spans and stable-prefix boundaries.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HintTarget {
    Span {
        span_id: SpanId,
    },
    StablePrefix {
        end_exclusive: usize,
        last_span_id: Option<SpanId>,
    },
}

impl HintTarget {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn span(span_id: SpanId) -> Self {
        Self::Span { span_id }
    }

    pub fn stable_prefix(end_exclusive: usize, last_span_id: Option<SpanId>) -> Self {
        Self::StablePrefix {
            end_exclusive,
            last_span_id,
        }
    }

    pub fn last_span_id(&self) -> Option<&SpanId> {
        match self {
            Self::Span { span_id } => Some(span_id),
            Self::StablePrefix { last_span_id, .. } => last_span_id.as_ref(),
        }
    }

    pub fn end_exclusive(&self) -> Option<usize> {
        match self {
            Self::StablePrefix { end_exclusive, .. } => Some(*end_exclusive),
            Self::Span { .. } => None,
        }
    }
}

/// Provider-semantic directives that remain independent from any wire surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HintDirective {
    Anthropic(AnthropicHintDirective),
    OpenAI(OpenAIHintDirective),
}

impl From<AnthropicHintDirective> for HintDirective {
    fn from(value: AnthropicHintDirective) -> Self {
        Self::Anthropic(value)
    }
}

impl From<OpenAIHintDirective> for HintDirective {
    fn from(value: OpenAIHintDirective) -> Self {
        Self::OpenAI(value)
    }
}

/// Provider-agnostic stable-prefix target builder from PromptIR context.
pub(crate) fn stable_prefix_target(
    prompt_ir: &crate::acg::prompt_ir::PromptIR,
    end_exclusive: usize,
) -> HintTarget {
    let clamped_end = end_exclusive.min(prompt_ir.blocks.len());
    let last_span_id = clamped_end
        .checked_sub(1)
        .and_then(|index| prompt_ir.blocks.get(index))
        .map(|block| block.span_id.clone());

    HintTarget::stable_prefix(clamped_end, last_span_id)
}

/// Anthropic directive payloads expressed on PromptIR semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AnthropicHintDirective {
    CanonicalizeToolSchemas,
    CacheBreakpoint {
        target: HintTarget,
        scope: SharingScope,
    },
    ApplyTtl {
        ttl: AnthropicCacheTtl,
    },
}

/// Anthropic retention mapping after semantic translation.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnthropicCacheTtl {
    OneHour,
}

/// OpenAI directive payloads expressed on PromptIR semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OpenAIHintDirective {
    CanonicalizeToolSchemas,
    CanonicalizeStablePrefix { target: HintTarget },
}

#[cfg(test)]
#[path = "../../../tests/unit/acg/translation_tests.rs"]
mod tests;
