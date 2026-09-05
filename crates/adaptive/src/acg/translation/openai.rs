// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenAI semantic hint translation.

use chrono::Utc;
use uuid::Uuid;

use crate::acg::plugin::PluginInput;
use crate::acg::translation::{
    HintPlan, HintTranslation, HintTranslator, OpenAIHintDirective, stable_prefix_target,
};
use crate::acg::types::{
    IntentOutcome, IntentType, OptimizationIntent, ReasonCode, TranslationReport, TranslationStatus,
};

/// OpenAI semantic hint translator.
pub(crate) struct OpenAIHintTranslator;

impl HintTranslator for OpenAIHintTranslator {
    fn provider_id(&self) -> &str {
        "openai"
    }

    fn translate(&self, input: &PluginInput<'_>) -> crate::acg::Result<HintTranslation> {
        let mut hint_plan = HintPlan::new(self.provider_id());
        let mut outcomes = Vec::new();

        for intent in &input.intent_bundle.intents {
            match intent {
                OptimizationIntent::CacheStability(cache_stability) => {
                    hint_plan.push(OpenAIHintDirective::CanonicalizeToolSchemas);
                    hint_plan.push(OpenAIHintDirective::CanonicalizeStablePrefix {
                        target: stable_prefix_target(
                            input.prompt_ir,
                            cache_stability.stable_prefix_end,
                        ),
                    });

                    outcomes.push(IntentOutcome {
                        intent_id: Uuid::new_v4(),
                        intent_type: IntentType::CacheStability,
                        status: TranslationStatus::Applied,
                        reason: ReasonCode::FullySupported,
                        detail: Some(
                            "deterministic serialization planned for tool schemas and stable prompt prefix"
                                .to_string(),
                        ),
                    });
                }
                OptimizationIntent::Retention(_) => {
                    outcomes.push(IntentOutcome {
                        intent_id: Uuid::new_v4(),
                        intent_type: IntentType::Retention,
                        status: TranslationStatus::Ignored,
                        reason: ReasonCode::UnsupportedByBackend,
                        detail: Some(
                            "OpenAI automatic caching does not support retention control; cache duration is managed automatically by OpenAI".to_string(),
                        ),
                    });
                }
                other => {
                    let intent_type = other.discriminant();
                    outcomes.push(IntentOutcome {
                        intent_id: Uuid::new_v4(),
                        intent_type,
                        status: TranslationStatus::Ignored,
                        reason: ReasonCode::NotRelevant,
                        detail: Some(format!(
                            "OpenAI plugin does not handle {intent_type:?} intents"
                        )),
                    });
                }
            }
        }

        Ok(HintTranslation {
            hint_plan,
            translation_report: TranslationReport {
                request_id: input.intent_bundle.request_id,
                plugin_id: self.provider_id().to_string(),
                outcomes,
                created_at: Utc::now(),
            },
        })
    }
}
