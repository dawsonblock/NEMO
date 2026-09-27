// SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]

//! The native plugin ABI: the layout a built plugin compiles against.
//!
//! This crate is what a plugin's compiled code depends on at the boundary: the
//! opaque handles the host owns, the `#[repr(C)]` structs that cross in both
//! directions, the `extern "C"` callback and function-pointer signatures, the
//! versioned host tables, and the revision constants and status codes both sides
//! report. It depends on nothing, which is the property that makes the tables
//! freezable: a table that is coupled to the code implementing its host side
//! cannot be frozen independently of that code, and a frozen table is the whole of
//! what an already-built plugin relies on.
//!
//! What is deliberately *not* here is anything that needs the runtime model. The
//! conversions between the ABI's discriminators and the runtime's own types belong
//! to the SDK (`nemo_relay_plugin`), which re-exports everything in this crate so
//! that every author-facing path is unchanged. That split is why this crate has no
//! dependencies rather than a dependency on the model it is the boundary to.
//!
//! The revisions are named rather than numbered so that a check reads as "this
//! table predates that feature" instead of as a comparison of numbers nobody can
//! date. A host retains the frozen tables for the older revisions, because an
//! already-built plugin asks for the one it was built against.

use std::ffi::{c_char, c_void};
use std::marker::{PhantomData, PhantomPinned};
use std::ptr;

/// Native plugin ABI version supported by this crate.
///
/// Version 4 adds completion-scoped codecs, pull-based LLM streams, extended
/// mark emission, runtime diagnostics, and activation-owned runtime-registration
/// discovery and dynamic conditional middleware guardrail control. Version 5 adds
/// the mark window: an invocation-scoped attribution context the host captures and
/// a plugin carries across its own asynchronous work, so a mark raised outside the
/// synchronous call that created a callback still belongs to the operation whose
/// callback raised it. Hosts retain frozen version-4, version-3 and version-2
/// tables for already-built plugins that target those layouts.
pub const NEMO_RELAY_NATIVE_ABI_VERSION: u32 = 5;
/// ABI version that introduced completion-based asynchronous middleware.
pub const NEMO_RELAY_NATIVE_ABI_VERSION_ASYNC_MIDDLEWARE: u32 = 3;
/// ABI version that introduced the v4 host extension: completion-scoped codecs,
/// pull-based LLM streams, extended mark emission, runtime diagnostics, and
/// activation-owned dynamic gate control.
pub const NEMO_RELAY_NATIVE_ABI_VERSION_COMPLETION_CODECS: u32 = 4;

/// Legacy native plugin ABI accepted by Relay hosts for compatibility.
pub const NEMO_RELAY_NATIVE_ABI_VERSION_LEGACY: u32 = 2;

/// Status codes returned by stable native ABI functions.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NemoRelayStatus {
    /// Operation completed successfully.
    Ok = 0,
    /// A resource with the given name already exists.
    AlreadyExists = 1,
    /// The requested resource was not found.
    NotFound = 2,
    /// The scope stack is empty.
    ScopeStackEmpty = 3,
    /// A guardrail rejected the operation.
    GuardrailRejected = 4,
    /// An internal runtime error occurred.
    Internal = 5,
    /// A required pointer argument was null.
    NullPointer = 6,
    /// A JSON string argument could not be parsed.
    InvalidJson = 7,
    /// A string argument contained invalid UTF-8.
    InvalidUtf8 = 8,
    /// A function argument had an invalid value.
    InvalidArg = 9,
    /// A stream reached end-of-stream and has no chunk to return.
    StreamEnd = 10,
    /// A bounded stream queue is full; retry this operation after it advances.
    Backpressured = 11,
}
/// Opaque host-owned UTF-8 string or JSON byte buffer.
#[repr(C)]
pub struct NemoRelayNativeString {
    _private: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// Opaque callback-scoped request codec capability owned by the host.
#[repr(C)]
pub struct NemoRelayNativeLlmRequestCodec {
    _private: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// Opaque callback-scoped response codec capability owned by the host.
#[repr(C)]
pub struct NemoRelayNativeLlmResponseCodec {
    _private: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// Discriminator for the codec supplied to an LLM sanitizer over the native ABI.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NemoRelayNativeLlmCodecKind {
    /// No codec was active for this call.
    None = 0,
    /// A Relay built-in codec was active.
    BuiltIn = 1,
    /// A runtime-registered codec was active.
    Runtime = 2,
    /// A codec was active but has no registered identity.
    Opaque = 3,
}

/// Per-call LLM sanitizer context passed over the native ABI.
///
/// `codec_id` is borrowed for the duration of the callback. It is null for
/// [`NemoRelayNativeLlmCodecKind::None`] and
/// [`NemoRelayNativeLlmCodecKind::Opaque`]. For `BuiltIn`, it is one of the
/// stable built-in codec IDs; for `Runtime`, it is the registered codec ID.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NemoRelayNativeLlmSanitizeRequestContext {
    /// Discriminator for the active codec.
    pub codec_kind: NemoRelayNativeLlmCodecKind,
    /// Optional borrowed codec identifier.
    pub codec_id: *const NemoRelayNativeString,
    /// Borrowed request codec capability, or null when no codec is active.
    pub codec: *const NemoRelayNativeLlmRequestCodec,
}

/// Per-call response sanitizer context passed over the native ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NemoRelayNativeLlmSanitizeResponseContext {
    /// Discriminator for the active codec.
    pub codec_kind: NemoRelayNativeLlmCodecKind,
    /// Optional borrowed codec identifier.
    pub codec_id: *const NemoRelayNativeString,
    /// Borrowed response codec capability, or null when no codec is active.
    pub codec: *const NemoRelayNativeLlmResponseCodec,
}

/// Opaque plugin registration context borrowed from the host during registration.
#[repr(C)]
pub struct NemoRelayNativePluginContext {
    _private: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// Opaque activation-owned runtime capability used by native plugins.
#[repr(C)]
pub struct NemoRelayNativePluginRuntime {
    _private: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// Opaque host-owned scope handle.
#[repr(C)]
pub struct NemoRelayNativeScopeHandle {
    _private: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// Opaque host-owned scope stack handle.
#[repr(C)]
pub struct NemoRelayNativeScopeStack {
    _private: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// Opaque host-owned captured scope-stack binding.
#[repr(C)]
pub struct NemoRelayNativeScopeStackBinding {
    _private: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// Scope category used by native plugins when opening scopes.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NemoRelayNativeScopeType {
    /// Top-level agent scope.
    Agent = 0,
    /// Generic function scope.
    Function = 1,
    /// Tool invocation scope.
    Tool = 2,
    /// LLM call scope.
    Llm = 3,
    /// Retriever scope.
    Retriever = 4,
    /// Embedder scope.
    Embedder = 5,
    /// Reranker scope.
    Reranker = 6,
    /// Guardrail evaluation scope.
    Guardrail = 7,
    /// Evaluator scope.
    Evaluator = 8,
    /// User-defined custom scope.
    Custom = 9,
    /// Unknown or unspecified scope type.
    Unknown = 10,
}

/// Optional destructor for user data captured by native callbacks.
pub type NemoRelayNativeFreeFn = Option<unsafe extern "C" fn(user_data: *mut c_void)>;

/// Native callback executed while a host scope stack is temporarily active.
pub type NemoRelayNativeWithScopeStackCb =
    unsafe extern "C" fn(user_data: *mut c_void) -> NemoRelayStatus;

/// Runtime-provided continuation for tool execution intercepts.
///
/// On success, `out_json` contains canonical `ToolExecutionResult` JSON. The
/// returned host-owned string must be released with the active host table's
/// `string_free` hook.
pub type NemoRelayNativeToolNextFn = unsafe extern "C" fn(
    args_json: *const NemoRelayNativeString,
    next_ctx: *mut c_void,
    out_json: *mut *mut NemoRelayNativeString,
) -> NemoRelayStatus;

/// Runtime-provided continuation for LLM execution intercepts.
pub type NemoRelayNativeLlmNextFn = unsafe extern "C" fn(
    request_json: *const NemoRelayNativeString,
    next_ctx: *mut c_void,
    out_json: *mut *mut NemoRelayNativeString,
) -> NemoRelayStatus;

/// Native stream poll callback.
///
/// Return [`NemoRelayStatus::Ok`] with `out_json` set for one chunk,
/// [`NemoRelayStatus::StreamEnd`] with `out_json` null at end of stream, or an
/// error status for stream failure.
pub type NemoRelayNativeLlmStreamPollFn = unsafe extern "C" fn(
    user_data: *mut c_void,
    out_json: *mut *mut NemoRelayNativeString,
) -> NemoRelayStatus;

/// Optional native stream cancellation callback.
pub type NemoRelayNativeLlmStreamCancelFn =
    Option<unsafe extern "C" fn(user_data: *mut c_void) -> NemoRelayStatus>;

/// Optional native stream destructor callback.
pub type NemoRelayNativeLlmStreamDropFn = Option<unsafe extern "C" fn(user_data: *mut c_void)>;

/// Native LLM JSON stream handle table.
#[repr(C)]
pub struct NemoRelayNativeLlmStreamV1 {
    /// Size of this struct as seen by the producer.
    pub struct_size: usize,
    /// Stream state passed back to poll/cancel/drop callbacks.
    pub user_data: *mut c_void,
    /// Polls the next stream chunk.
    pub next: Option<NemoRelayNativeLlmStreamPollFn>,
    /// Cancels an in-flight stream when a consumer stops before stream end.
    pub cancel: NemoRelayNativeLlmStreamCancelFn,
    /// Drops stream state after stream completion, error, or cancellation.
    pub drop: NemoRelayNativeLlmStreamDropFn,
}

impl Default for NemoRelayNativeLlmStreamV1 {
    fn default() -> Self {
        Self {
            struct_size: std::mem::size_of::<Self>(),
            user_data: ptr::null_mut(),
            next: None,
            cancel: None,
            drop: None,
        }
    }
}

/// Runtime-provided continuation for LLM stream execution intercepts.
pub type NemoRelayNativeLlmStreamNextFn = unsafe extern "C" fn(
    request_json: *const NemoRelayNativeString,
    next_ctx: *mut c_void,
    out_stream: *mut NemoRelayNativeLlmStreamV1,
) -> NemoRelayStatus;

/// Native event subscriber callback.
pub type NemoRelayNativeEventSubscriberCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    event_json: *const NemoRelayNativeString,
) -> NemoRelayStatus;

/// Native event observability-field sanitizer callback.
pub type NemoRelayNativeEventSanitizeCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    event_json: *const NemoRelayNativeString,
    fields_json: *const NemoRelayNativeString,
    out_fields_json: *mut *mut NemoRelayNativeString,
) -> NemoRelayStatus;

/// Native JSON transform callback for tool request/response sanitizers and tool request intercepts.
pub type NemoRelayNativeToolJsonCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    name: *const NemoRelayNativeString,
    payload_json: *const NemoRelayNativeString,
    out_json: *mut *mut NemoRelayNativeString,
) -> NemoRelayStatus;

/// Native tool conditional-execution callback.
pub type NemoRelayNativeToolConditionalCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    name: *const NemoRelayNativeString,
    args_json: *const NemoRelayNativeString,
    out_reason: *mut *mut NemoRelayNativeString,
) -> NemoRelayStatus;

/// Native callback deciding whether a matching runtime registration is eligible.
///
/// `kinds_json` contains a JSON set of configured registration kinds and
/// `registration_name` is the target's effective name. Return a host-allocated
/// reason through `out_reason` to disable the target, or leave it null to keep
/// the target enabled. The input strings are borrowed for the callback only.
/// Relay treats a non-OK status or invalid output as an allow decision.
pub type NemoRelayNativeConditionalMiddlewareCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    kinds_json: *const NemoRelayNativeString,
    registration_name: *const NemoRelayNativeString,
    out_reason: *mut *mut NemoRelayNativeString,
) -> NemoRelayStatus;

/// Native tool execution intercept callback.
///
/// A successful callback must set `out_outcome_json` to canonical
/// `ToolExecutionInterceptOutcome` JSON allocated through the host. The
/// `next_ctx` capability is valid only while this callback is active and must
/// not be retained.
pub type NemoRelayNativeToolExecutionCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    name: *const NemoRelayNativeString,
    args_json: *const NemoRelayNativeString,
    next_fn: NemoRelayNativeToolNextFn,
    next_ctx: *mut c_void,
    out_outcome_json: *mut *mut NemoRelayNativeString,
) -> NemoRelayStatus;

/// Native LLM request sanitizer callback. Return a successful null output to
/// omit the observability payload and annotation. `request_json` is borrowed,
/// but may be written directly to `out_request_json` as a pass-through; the
/// host releases an aliased input/output once. Any other non-null output must
/// be host-allocated and transfers ownership to the host.
pub type NemoRelayNativeLlmSanitizeRequestCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    request_json: *const NemoRelayNativeString,
    context: NemoRelayNativeLlmSanitizeRequestContext,
    out_request_json: *mut *mut NemoRelayNativeString,
) -> NemoRelayStatus;

/// Native LLM response sanitizer callback. Return a successful null output to
/// omit the observability payload and annotation. `payload_json` is borrowed,
/// but may be written directly to `out_json` as a pass-through; the host
/// releases an aliased input/output once. Any other non-null output must be
/// host-allocated and transfers ownership to the host.
pub type NemoRelayNativeLlmSanitizeResponseCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    payload_json: *const NemoRelayNativeString,
    context: NemoRelayNativeLlmSanitizeResponseContext,
    out_json: *mut *mut NemoRelayNativeString,
) -> NemoRelayStatus;

/// Native LLM conditional-execution callback.
pub type NemoRelayNativeLlmConditionalCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    request_json: *const NemoRelayNativeString,
    out_reason: *mut *mut NemoRelayNativeString,
) -> NemoRelayStatus;

/// Native LLM request intercept callback.
pub type NemoRelayNativeLlmRequestInterceptCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    name: *const NemoRelayNativeString,
    request_json: *const NemoRelayNativeString,
    annotated_json: *const NemoRelayNativeString,
    out_outcome_json: *mut *mut NemoRelayNativeString,
) -> NemoRelayStatus;

/// Native LLM execution intercept callback.
pub type NemoRelayNativeLlmExecutionCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    name: *const NemoRelayNativeString,
    request_json: *const NemoRelayNativeString,
    next_fn: NemoRelayNativeLlmNextFn,
    next_ctx: *mut c_void,
    out_json: *mut *mut NemoRelayNativeString,
) -> NemoRelayStatus;

/// Native LLM stream execution intercept callback.
pub type NemoRelayNativeLlmStreamExecutionCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    name: *const NemoRelayNativeString,
    request_json: *const NemoRelayNativeString,
    next_fn: NemoRelayNativeLlmStreamNextFn,
    next_ctx: *mut c_void,
    out_stream: *mut NemoRelayNativeLlmStreamV1,
) -> NemoRelayStatus;

/// Native plugin validation callback.
pub type NemoRelayNativePluginValidateFn = unsafe extern "C" fn(
    user_data: *mut c_void,
    plugin_config_json: *const NemoRelayNativeString,
    out_diagnostics_json: *mut *mut NemoRelayNativeString,
) -> NemoRelayStatus;

/// Native plugin registration callback.
pub type NemoRelayNativePluginRegisterFn = unsafe extern "C" fn(
    user_data: *mut c_void,
    plugin_config_json: *const NemoRelayNativeString,
    ctx: *mut NemoRelayNativePluginContext,
) -> NemoRelayStatus;

/// Native plugin drop callback.
pub type NemoRelayNativePluginDropFn = Option<unsafe extern "C" fn(user_data: *mut c_void)>;

/// Versioned host API table passed to native plugin entry symbols.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NemoRelayNativeHostApiV1 {
    /// ABI version implemented by this table.
    pub abi_version: u32,
    /// Size of this struct as seen by the host.
    pub struct_size: usize,
    /// Null-terminated host Relay version string.
    pub relay_version: *const c_char,
    /// Allocates a host-owned string from UTF-8 bytes.
    pub string_new: unsafe extern "C" fn(
        data: *const u8,
        len: usize,
        out: *mut *mut NemoRelayNativeString,
    ) -> NemoRelayStatus,
    /// Returns the string data pointer for a host-owned string.
    pub string_data: unsafe extern "C" fn(value: *const NemoRelayNativeString) -> *const u8,
    /// Returns the byte length for a host-owned string.
    pub string_len: unsafe extern "C" fn(value: *const NemoRelayNativeString) -> usize,
    /// Frees a host-owned string.
    pub string_free: unsafe extern "C" fn(value: *mut NemoRelayNativeString),
    /// Clears the host thread-local native ABI error message.
    pub last_error_clear: unsafe extern "C" fn(),
    /// Sets the host thread-local native ABI error message.
    pub last_error_set: unsafe extern "C" fn(message: *const NemoRelayNativeString),
    /// Decodes an LLM request through a callback-scoped codec capability.
    pub llm_request_codec_decode: unsafe extern "C" fn(
        codec: *const NemoRelayNativeLlmRequestCodec,
        request_json: *const NemoRelayNativeString,
        out: *mut *mut NemoRelayNativeString,
    ) -> NemoRelayStatus,
    /// Encodes normalized request changes through a callback-scoped codec capability.
    pub llm_request_codec_encode: unsafe extern "C" fn(
        codec: *const NemoRelayNativeLlmRequestCodec,
        annotated_json: *const NemoRelayNativeString,
        original_json: *const NemoRelayNativeString,
        out: *mut *mut NemoRelayNativeString,
    ) -> NemoRelayStatus,
    /// Decodes an LLM response through a callback-scoped codec capability.
    pub llm_response_codec_decode: unsafe extern "C" fn(
        codec: *const NemoRelayNativeLlmResponseCodec,
        response_json: *const NemoRelayNativeString,
        out: *mut *mut NemoRelayNativeString,
    ) -> NemoRelayStatus,
    /// Registers an event subscriber through the plugin context.
    pub plugin_context_register_subscriber: unsafe extern "C" fn(
        ctx: *mut NemoRelayNativePluginContext,
        name: *const NemoRelayNativeString,
        cb: NemoRelayNativeEventSubscriberCb,
        user_data: *mut c_void,
        free_fn: NemoRelayNativeFreeFn,
    ) -> NemoRelayStatus,
    /// Registers a tool sanitize-request guardrail through the plugin context.
    pub plugin_context_register_tool_sanitize_request_guardrail:
        unsafe extern "C" fn(
            ctx: *mut NemoRelayNativePluginContext,
            name: *const NemoRelayNativeString,
            priority: i32,
            cb: NemoRelayNativeToolJsonCb,
            user_data: *mut c_void,
            free_fn: NemoRelayNativeFreeFn,
        ) -> NemoRelayStatus,
    /// Registers a tool sanitize-response guardrail through the plugin context.
    pub plugin_context_register_tool_sanitize_response_guardrail:
        unsafe extern "C" fn(
            ctx: *mut NemoRelayNativePluginContext,
            name: *const NemoRelayNativeString,
            priority: i32,
            cb: NemoRelayNativeToolJsonCb,
            user_data: *mut c_void,
            free_fn: NemoRelayNativeFreeFn,
        ) -> NemoRelayStatus,
    /// Registers a tool conditional-execution guardrail through the plugin context.
    pub plugin_context_register_tool_conditional_execution_guardrail:
        unsafe extern "C" fn(
            ctx: *mut NemoRelayNativePluginContext,
            name: *const NemoRelayNativeString,
            priority: i32,
            cb: NemoRelayNativeToolConditionalCb,
            user_data: *mut c_void,
            free_fn: NemoRelayNativeFreeFn,
        ) -> NemoRelayStatus,
    /// Registers a tool request intercept through the plugin context.
    pub plugin_context_register_tool_request_intercept: unsafe extern "C" fn(
        ctx: *mut NemoRelayNativePluginContext,
        name: *const NemoRelayNativeString,
        priority: i32,
        break_chain: bool,
        cb: NemoRelayNativeToolJsonCb,
        user_data: *mut c_void,
        free_fn: NemoRelayNativeFreeFn,
    )
        -> NemoRelayStatus,
    /// Registers a tool execution intercept through the plugin context.
    pub plugin_context_register_tool_execution_intercept: unsafe extern "C" fn(
        ctx: *mut NemoRelayNativePluginContext,
        name: *const NemoRelayNativeString,
        priority: i32,
        cb: NemoRelayNativeToolExecutionCb,
        user_data: *mut c_void,
        free_fn: NemoRelayNativeFreeFn,
    )
        -> NemoRelayStatus,
    /// Registers an LLM sanitize-request guardrail through the plugin context.
    pub plugin_context_register_llm_sanitize_request_guardrail:
        unsafe extern "C" fn(
            ctx: *mut NemoRelayNativePluginContext,
            name: *const NemoRelayNativeString,
            priority: i32,
            cb: NemoRelayNativeLlmSanitizeRequestCb,
            user_data: *mut c_void,
            free_fn: NemoRelayNativeFreeFn,
        ) -> NemoRelayStatus,
    /// Registers an LLM sanitize-response guardrail through the plugin context.
    pub plugin_context_register_llm_sanitize_response_guardrail:
        unsafe extern "C" fn(
            ctx: *mut NemoRelayNativePluginContext,
            name: *const NemoRelayNativeString,
            priority: i32,
            cb: NemoRelayNativeLlmSanitizeResponseCb,
            user_data: *mut c_void,
            free_fn: NemoRelayNativeFreeFn,
        ) -> NemoRelayStatus,
    /// Registers an LLM conditional-execution guardrail through the plugin context.
    pub plugin_context_register_llm_conditional_execution_guardrail:
        unsafe extern "C" fn(
            ctx: *mut NemoRelayNativePluginContext,
            name: *const NemoRelayNativeString,
            priority: i32,
            cb: NemoRelayNativeLlmConditionalCb,
            user_data: *mut c_void,
            free_fn: NemoRelayNativeFreeFn,
        ) -> NemoRelayStatus,
    /// Registers an LLM request intercept through the plugin context.
    pub plugin_context_register_llm_request_intercept: unsafe extern "C" fn(
        ctx: *mut NemoRelayNativePluginContext,
        name: *const NemoRelayNativeString,
        priority: i32,
        break_chain: bool,
        cb: NemoRelayNativeLlmRequestInterceptCb,
        user_data: *mut c_void,
        free_fn: NemoRelayNativeFreeFn,
    ) -> NemoRelayStatus,
    /// Registers an LLM execution intercept through the plugin context.
    pub plugin_context_register_llm_execution_intercept: unsafe extern "C" fn(
        ctx: *mut NemoRelayNativePluginContext,
        name: *const NemoRelayNativeString,
        priority: i32,
        cb: NemoRelayNativeLlmExecutionCb,
        user_data: *mut c_void,
        free_fn: NemoRelayNativeFreeFn,
    )
        -> NemoRelayStatus,
    /// Registers an LLM stream execution intercept through the plugin context.
    pub plugin_context_register_llm_stream_execution_intercept:
        unsafe extern "C" fn(
            ctx: *mut NemoRelayNativePluginContext,
            name: *const NemoRelayNativeString,
            priority: i32,
            cb: NemoRelayNativeLlmStreamExecutionCb,
            user_data: *mut c_void,
            free_fn: NemoRelayNativeFreeFn,
        ) -> NemoRelayStatus,
    /// Frees a host-owned scope handle.
    pub scope_handle_free: unsafe extern "C" fn(handle: *mut NemoRelayNativeScopeHandle),
    /// Retrieves the current scope handle from the active stack.
    pub scope_get_current:
        unsafe extern "C" fn(out: *mut *mut NemoRelayNativeScopeHandle) -> NemoRelayStatus,
    /// Pushes a scope, emits its start event, and returns its handle.
    pub scope_push: unsafe extern "C" fn(
        name: *const NemoRelayNativeString,
        scope_type: NemoRelayNativeScopeType,
        parent: *const NemoRelayNativeScopeHandle,
        attributes: u32,
        data_json: *const NemoRelayNativeString,
        metadata_json: *const NemoRelayNativeString,
        input_json: *const NemoRelayNativeString,
        timestamp_unix_micros: *const i64,
        out: *mut *mut NemoRelayNativeScopeHandle,
    ) -> NemoRelayStatus,
    /// Pops a scope handle, emits its end event, and clears scope-local registrations.
    pub scope_pop: unsafe extern "C" fn(
        handle: *const NemoRelayNativeScopeHandle,
        output_json: *const NemoRelayNativeString,
        metadata_json: *const NemoRelayNativeString,
        timestamp_unix_micros: *const i64,
    ) -> NemoRelayStatus,
    /// Emits a mark event under the current or provided parent scope.
    pub emit_mark: unsafe extern "C" fn(
        name: *const NemoRelayNativeString,
        parent: *const NemoRelayNativeScopeHandle,
        data_json: *const NemoRelayNativeString,
        metadata_json: *const NemoRelayNativeString,
        timestamp_unix_micros: *const i64,
    ) -> NemoRelayStatus,
    /// Creates a new independent scope stack with its own root scope.
    pub scope_stack_create:
        unsafe extern "C" fn(out: *mut *mut NemoRelayNativeScopeStack) -> NemoRelayStatus,
    /// Frees a host-owned scope stack handle.
    pub scope_stack_free: unsafe extern "C" fn(stack: *mut NemoRelayNativeScopeStack),
    /// Binds a scope stack to the current OS thread.
    pub scope_stack_set_thread:
        unsafe extern "C" fn(stack: *const NemoRelayNativeScopeStack) -> NemoRelayStatus,
    /// Captures the current thread-local scope-stack binding.
    pub scope_stack_capture_thread:
        unsafe extern "C" fn(out: *mut *mut NemoRelayNativeScopeStackBinding) -> NemoRelayStatus,
    /// Restores and frees a captured thread-local scope-stack binding.
    pub scope_stack_restore_thread:
        unsafe extern "C" fn(binding: *mut NemoRelayNativeScopeStackBinding) -> NemoRelayStatus,
    /// Frees a captured thread-local binding without restoring it.
    pub scope_stack_binding_free:
        unsafe extern "C" fn(binding: *mut NemoRelayNativeScopeStackBinding),
    /// Returns whether the current context has an explicitly active scope stack.
    pub scope_stack_active: unsafe extern "C" fn() -> bool,
    /// Runs a callback with the provided scope stack visible to host runtime APIs.
    pub scope_stack_with_current: unsafe extern "C" fn(
        stack: *const NemoRelayNativeScopeStack,
        cb: NemoRelayNativeWithScopeStackCb,
        user_data: *mut c_void,
    ) -> NemoRelayStatus,
    /// Registers a mark event sanitizer through the plugin context.
    pub plugin_context_register_mark_sanitize_guardrail: unsafe extern "C" fn(
        ctx: *mut NemoRelayNativePluginContext,
        name: *const NemoRelayNativeString,
        priority: i32,
        cb: NemoRelayNativeEventSanitizeCb,
        user_data: *mut c_void,
        free_fn: NemoRelayNativeFreeFn,
    )
        -> NemoRelayStatus,
    /// Registers a scope-start event sanitizer through the plugin context.
    pub plugin_context_register_scope_sanitize_start_guardrail:
        unsafe extern "C" fn(
            ctx: *mut NemoRelayNativePluginContext,
            name: *const NemoRelayNativeString,
            priority: i32,
            cb: NemoRelayNativeEventSanitizeCb,
            user_data: *mut c_void,
            free_fn: NemoRelayNativeFreeFn,
        ) -> NemoRelayStatus,
    /// Registers a scope-end event sanitizer through the plugin context.
    pub plugin_context_register_scope_sanitize_end_guardrail:
        unsafe extern "C" fn(
            ctx: *mut NemoRelayNativePluginContext,
            name: *const NemoRelayNativeString,
            priority: i32,
            cb: NemoRelayNativeEventSanitizeCb,
            user_data: *mut c_void,
            free_fn: NemoRelayNativeFreeFn,
        ) -> NemoRelayStatus,
}

/// Middleware surface selected by the native async registration hook.
///
/// The host only exposes this through the ABI-v3 extension table.  It keeps
/// every asynchronous callback shape uniform while allowing the host to
/// deserialize the surface-specific invocation and result payloads.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NemoRelayNativeAsyncMiddlewareKind {
    /// Tool start-event request sanitizer.
    ToolSanitizeRequest = 0,
    /// Tool end-event response sanitizer.
    ToolSanitizeResponse = 1,
    /// Tool execution admission guardrail.
    ToolConditionalExecution = 2,
    /// Tool request rewrite intercept.
    ToolRequestIntercept = 3,
    /// Tool execution intercept with a continuation.
    ToolExecutionIntercept = 4,
    /// LLM start-event request sanitizer.
    LlmSanitizeRequest = 5,
    /// LLM end-event response sanitizer.
    LlmSanitizeResponse = 6,
    /// LLM execution admission guardrail.
    LlmConditionalExecution = 7,
    /// LLM request rewrite intercept.
    LlmRequestIntercept = 8,
    /// LLM execution intercept with a continuation.
    LlmExecutionIntercept = 9,
    /// Reserved legacy discriminant for streaming LLM execution intercepts.
    ///
    /// Hosts reject this kind from the generic completion-based registration
    /// hook. Use `plugin_context_register_async_stream_middleware` so chunks
    /// remain incremental.
    LlmStreamExecutionIntercept = 10,
    /// Mark event sanitizer.
    MarkSanitize = 11,
    /// Scope-start event sanitizer.
    ScopeSanitizeStart = 12,
    /// Scope-end event sanitizer.
    ScopeSanitizeEnd = 13,
    /// Event metadata injector.
    EventMetadataInjector = 14,
}

impl TryFrom<u32> for NemoRelayNativeAsyncMiddlewareKind {
    type Error = ();

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ToolSanitizeRequest),
            1 => Ok(Self::ToolSanitizeResponse),
            2 => Ok(Self::ToolConditionalExecution),
            3 => Ok(Self::ToolRequestIntercept),
            4 => Ok(Self::ToolExecutionIntercept),
            5 => Ok(Self::LlmSanitizeRequest),
            6 => Ok(Self::LlmSanitizeResponse),
            7 => Ok(Self::LlmConditionalExecution),
            8 => Ok(Self::LlmRequestIntercept),
            9 => Ok(Self::LlmExecutionIntercept),
            10 => Ok(Self::LlmStreamExecutionIntercept),
            11 => Ok(Self::MarkSanitize),
            12 => Ok(Self::ScopeSanitizeStart),
            13 => Ok(Self::ScopeSanitizeEnd),
            14 => Ok(Self::EventMetadataInjector),
            _ => Err(()),
        }
    }
}

/// Indicates whether an asynchronous native callback settled before returning.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NemoRelayNativeAsyncCallbackState {
    /// The callback settled its completion before returning.
    Complete = 0,
    /// The callback retained its completion for later settlement.
    Pending = 1,
}

impl TryFrom<u32> for NemoRelayNativeAsyncCallbackState {
    type Error = ();

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Complete),
            1 => Ok(Self::Pending),
            _ => Err(()),
        }
    }
}

/// Opaque one-shot completion retained by a pending native callback.
#[repr(C)]
pub struct NemoRelayNativeAsyncCompletion {
    _private: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// Opaque native execution continuation supplied only to execution intercepts.
#[repr(C)]
pub struct NemoRelayNativeAsyncNext {
    _private: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// Opaque incremental output channel supplied to native async stream intercepts.
#[repr(C)]
pub struct NemoRelayNativeAsyncStream {
    _private: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// Opaque pull-based downstream LLM stream owned by the host.
#[repr(C)]
pub struct NemoRelayNativeLlmAsyncStream {
    _private: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// Receives the result of asynchronously opening a downstream LLM stream.
///
/// Exactly one of `stream` and `error` is non-null. A non-null stream is an
/// owned plugin reference and must be released exactly once.
pub type NemoRelayNativeAsyncLlmStreamOpenCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    stream: *const NemoRelayNativeLlmAsyncStream,
    error: *const NemoRelayNativeString,
);

/// Receives one item from a pull-based downstream LLM stream.
///
/// A chunk has non-null `chunk_json` and `done = false`; clean completion has
/// both strings null and `done = true`; failure has non-null `error` and
/// `done = true`. Only one pull may be outstanding per stream.
pub type NemoRelayNativeAsyncLlmStreamPullCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    chunk_json: *const NemoRelayNativeString,
    error: *const NemoRelayNativeString,
    done: bool,
);

/// Receives one downstream stream item. `chunk_json` is non-null for a chunk,
/// `error` is non-null for failure or consumer cancellation, and `done` marks
/// clean completion. Unless the callback itself returns `false`, the host
/// invokes one terminal callback so the plugin can reclaim `user_data`.
/// Return `false` to cancel downstream production after the current callback;
/// in that case, reclaim `user_data` before returning because no later callback
/// is made.
pub type NemoRelayNativeAsyncNextStreamCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    chunk_json: *const NemoRelayNativeString,
    error: *const NemoRelayNativeString,
    done: bool,
) -> bool;

/// Receives one completion from a unary execution-continuation invocation.
///
/// Exactly one of `value_json` and `error` is non-null. The callback owns its
/// `user_data` and is invoked exactly once after a successful
/// `async_next_invoke_result` call, including when the owning interceptor
/// settles and cancels unfinished downstream work. For a tool continuation,
/// `value_json` contains canonical `ToolExecutionResult` JSON.
pub type NemoRelayNativeAsyncNextResultCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    value_json: *const NemoRelayNativeString,
    error: *const NemoRelayNativeString,
);

/// Incremental native LLM stream intercept callback.
///
/// The callback owns `next` and `stream` and must release each exactly once.
/// It may push chunks before returning or retain the handles and return
/// `Pending`; no implicit timeout is applied. Relay can invoke separate
/// middleware calls concurrently without stable OS-thread affinity. Retained
/// handles may be used from a plugin-owned thread, while callbacks supplied to
/// `async_next_invoke_stream` run on a Relay runtime worker. The output stream
/// owns the callback lifetime: `next` may be invoked repeatedly or concurrently
/// until that stream finishes, rejects, or is cancelled, and each invocation
/// has independent callback state. Relay rejects or cancels unfinished and
/// later invocations after settlement. The plugin must synchronize shared
/// `user_data` and callback state and serialize each handle's final release
/// after its last operation returns.
pub type NemoRelayNativeAsyncStreamMiddlewareCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    invocation_json: *const NemoRelayNativeString,
    next: *const NemoRelayNativeAsyncNext,
    stream: *const NemoRelayNativeAsyncStream,
) -> u32;

/// Completion-based native middleware callback.
///
/// `invocation_json` is borrowed for the call. A callback that returns
/// [`NemoRelayNativeAsyncCallbackState::Pending`] as a `u32` owns one
/// completion reference and must settle it then call the v3
/// `async_completion_release` hook. The host validates the returned
/// discriminant. When `next` is non-null, the callback owns that handle for
/// the invocation and must call `async_next_release` exactly once after its
/// final use, regardless of whether it returns `Complete` or `Pending`. The
/// host never reclaims a `next` handle after handing it to the callback.
/// `next` is null for non-execution middleware. Relay invokes the callback on
/// the Tokio runtime worker polling that middleware invocation, without stable
/// OS-thread affinity; separate invocations may run concurrently. After
/// returning `Pending`, retained completion and `next` handles may be used from
/// a plugin-owned thread until the completion settles. Every `next` operation
/// must finish before resolving or rejecting the completion; Relay rejects or
/// cancels unfinished and later continuation calls. The plugin must synchronize
/// shared `user_data` and callback state and serialize each handle's final
/// release after its last operation returns. A tool-execution callback must
/// resolve its completion with canonical `ToolExecutionInterceptOutcome`
/// JSON.
pub type NemoRelayNativeAsyncMiddlewareCb = unsafe extern "C" fn(
    user_data: *mut c_void,
    invocation_json: *const NemoRelayNativeString,
    next: *const NemoRelayNativeAsyncNext,
    completion: *const NemoRelayNativeAsyncCompletion,
) -> u32;

/// ABI-v3 host extension appended to [`NemoRelayNativeHostApiV1`].
///
/// Its first field is the complete v1/v2 table, so legacy plugins can keep
/// treating the pointer as a [`NemoRelayNativeHostApiV1`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NemoRelayNativeHostApiV3 {
    /// Compatibility prefix for ABI-v1/v2 plugins.
    pub v1: NemoRelayNativeHostApiV1,
    /// Resolves an async callback completion with a JSON value.
    ///
    /// Tool-execution middleware must supply canonical
    /// `ToolExecutionInterceptOutcome` JSON.
    pub async_completion_resolve_json: unsafe extern "C" fn(
        completion: *const NemoRelayNativeAsyncCompletion,
        value_json: *const NemoRelayNativeString,
    ) -> NemoRelayStatus,
    /// Rejects an async callback completion with a UTF-8 message.
    pub async_completion_reject: unsafe extern "C" fn(
        completion: *const NemoRelayNativeAsyncCompletion,
        message: *const NemoRelayNativeString,
    ) -> NemoRelayStatus,
    /// Returns true after the awaiting runtime has cancelled the invocation.
    pub async_completion_is_cancelled:
        unsafe extern "C" fn(completion: *const NemoRelayNativeAsyncCompletion) -> bool,
    /// Releases the callback-owned reference after a pending completion settles.
    pub async_completion_release:
        unsafe extern "C" fn(completion: *const NemoRelayNativeAsyncCompletion),
    /// Invokes an execution continuation and settles a supplied completion.
    ///
    /// Cancellation of that completion aborts an in-flight continuation. This
    /// legacy convenience hook is one-shot because its result settles the
    /// middleware completion; use `async_next_invoke_result` for repeated or
    /// concurrent calls. For a tool continuation, the host resolves the
    /// completion with canonical `ToolExecutionInterceptOutcome` JSON.
    pub async_next_invoke: unsafe extern "C" fn(
        next: *const NemoRelayNativeAsyncNext,
        invocation_json: *const NemoRelayNativeString,
        completion: *const NemoRelayNativeAsyncCompletion,
    ) -> NemoRelayStatus,
    /// Releases the callback-owned continuation reference.
    ///
    /// Execution callbacks must call this exactly once after their final use
    /// for both `Complete` and `Pending` return states.
    pub async_next_release: unsafe extern "C" fn(next: *const NemoRelayNativeAsyncNext),
    /// Registers a completion-based asynchronous middleware surface.
    ///
    /// `kind` must be a valid [`NemoRelayNativeAsyncMiddlewareKind`]
    /// discriminant. The host rejects unknown `u32` values and
    /// [`NemoRelayNativeAsyncMiddlewareKind::LlmStreamExecutionIntercept`],
    /// which must use `plugin_context_register_async_stream_middleware`.
    pub plugin_context_register_async_middleware: unsafe extern "C" fn(
        ctx: *mut NemoRelayNativePluginContext,
        kind: u32,
        name: *const NemoRelayNativeString,
        priority: i32,
        break_chain: bool,
        cb: NemoRelayNativeAsyncMiddlewareCb,
        user_data: *mut c_void,
        free_fn: NemoRelayNativeFreeFn,
    ) -> NemoRelayStatus,
    /// Pushes one JSON chunk to an incremental native stream without blocking.
    ///
    /// A full bounded host queue returns [`NemoRelayStatus::Backpressured`];
    /// retry this same logical chunk after the consumer advances.
    pub async_stream_push_json: unsafe extern "C" fn(
        stream: *const NemoRelayNativeAsyncStream,
        chunk_json: *const NemoRelayNativeString,
    ) -> NemoRelayStatus,
    /// Finishes an incremental native stream successfully.
    pub async_stream_finish:
        unsafe extern "C" fn(stream: *const NemoRelayNativeAsyncStream) -> NemoRelayStatus,
    /// Rejects an incremental native stream without blocking.
    ///
    /// A full bounded queue returns [`NemoRelayStatus::Backpressured`]; retry
    /// this same rejection after the consumer advances.
    pub async_stream_reject: unsafe extern "C" fn(
        stream: *const NemoRelayNativeAsyncStream,
        message: *const NemoRelayNativeString,
    ) -> NemoRelayStatus,
    /// Returns true when the consumer cancelled or released the stream.
    pub async_stream_is_cancelled:
        unsafe extern "C" fn(stream: *const NemoRelayNativeAsyncStream) -> bool,
    /// Releases the callback-owned incremental stream reference.
    pub async_stream_release: unsafe extern "C" fn(stream: *const NemoRelayNativeAsyncStream),
    /// Invokes a downstream stream and reports chunks incrementally.
    ///
    /// The host reports consumer cancellation through one terminal callback
    /// with a non-null error. If a result callback returns `false`, it must
    /// reclaim its own `user_data` before returning because no terminal
    /// callback follows. This hook may be called repeatedly or concurrently
    /// with independent callback state while the output stream remains active.
    pub async_next_invoke_stream: unsafe extern "C" fn(
        next: *const NemoRelayNativeAsyncNext,
        invocation_json: *const NemoRelayNativeString,
        stream: *const NemoRelayNativeAsyncStream,
        cb: NemoRelayNativeAsyncNextStreamCb,
        user_data: *mut c_void,
    ) -> NemoRelayStatus,
    /// Registers an incremental asynchronous LLM stream intercept.
    pub plugin_context_register_async_stream_middleware: unsafe extern "C" fn(
        ctx: *mut NemoRelayNativePluginContext,
        name: *const NemoRelayNativeString,
        priority: i32,
        cb: NemoRelayNativeAsyncStreamMiddlewareCb,
        user_data: *mut c_void,
        free_fn: NemoRelayNativeFreeFn,
    )
        -> NemoRelayStatus,
    /// Invokes a unary execution continuation with an independent result sink.
    ///
    /// Unlike the legacy completion-coupled `async_next_invoke`, this hook may
    /// be called repeatedly or concurrently with distinct `user_data`. For a
    /// tool continuation, the result callback receives canonical
    /// `ToolExecutionResult` JSON.
    pub async_next_invoke_result: unsafe extern "C" fn(
        next: *const NemoRelayNativeAsyncNext,
        invocation_json: *const NemoRelayNativeString,
        cb: NemoRelayNativeAsyncNextResultCb,
        user_data: *mut c_void,
    ) -> NemoRelayStatus,
}

/// Extended native mark-emission function introduced in ABI v4.
pub type NemoRelayNativeEmitMarkV2Fn = unsafe extern "C" fn(
    name: *const NemoRelayNativeString,
    parent: *const NemoRelayNativeScopeHandle,
    data_json: *const NemoRelayNativeString,
    metadata_json: *const NemoRelayNativeString,
    data_schema_json: *const NemoRelayNativeString,
    severity: *const NemoRelayNativeString,
    timestamp_unix_micros: *const i64,
) -> NemoRelayStatus;

/// Reads the active host runtime-diagnostics snapshot as canonical JSON.
pub type NemoRelayNativeGetRuntimeDiagnosticsFn =
    unsafe extern "C" fn(out_json: *mut *mut NemoRelayNativeString) -> NemoRelayStatus;

/// Opaque handle on the mark window an invocation is running under.
///
/// The host owns the handle: it is what the host captured when it opened the
/// window around a callback, and it names the operation that callback belongs to.
/// A plugin may carry one and emit marks through it; it cannot read it, change it,
/// or make one up that names an operation the host did not open a window for.
pub struct NemoRelayNativeMarkWindow;

/// Captures the mark window the calling invocation is running under.
///
/// Called on the thread the host invoked a callback on, before the callback's work
/// moves to a task of the plugin's own: what is captured is the window the host
/// opened, and from then on it is the plugin's to carry rather than the thread's.
/// On success `out` receives one owned handle, which must be released exactly once
/// with [`NemoRelayNativeReleaseMarkWindowFn`]. A host that opened no window writes
/// a null handle and answers [`NemoRelayStatus::Ok`]: a mark raised with no window
/// is the host process's own, which is what an invocation outside a plugin
/// callback means.
pub type NemoRelayNativeCaptureMarkWindowFn =
    unsafe extern "C" fn(out: *mut *mut NemoRelayNativeMarkWindow) -> NemoRelayStatus;

/// Releases one owned mark-window handle.
pub type NemoRelayNativeReleaseMarkWindowFn =
    unsafe extern "C" fn(window: *mut NemoRelayNativeMarkWindow);

/// Emits a mark through the window it was raised under.
///
/// The attribution — which operation the mark belongs to — comes from the window
/// and not from the call: a plugin chooses what a mark says, not whose it is.
/// A window the host has already settled (the operation was cancelled, ended, or
/// failed) refuses the mark rather than attributing it to whatever holds that
/// identity now.
pub type NemoRelayNativeEmitMarkInWindowFn = unsafe extern "C" fn(
    window: *const NemoRelayNativeMarkWindow,
    name: *const NemoRelayNativeString,
    parent: *const NemoRelayNativeScopeHandle,
    data_json: *const NemoRelayNativeString,
    metadata_json: *const NemoRelayNativeString,
    data_schema_json: *const NemoRelayNativeString,
    severity: *const NemoRelayNativeString,
    timestamp_unix_micros: *const i64,
) -> NemoRelayStatus;

/// ABI-v4 host extension for typed asynchronous middleware, mark options,
/// diagnostics, and activation-owned dynamic gate control.
///
/// The complete ABI-v3 table is the prefix, preserving layout compatibility.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NemoRelayNativeHostApiV4 {
    /// Frozen ABI-v3 compatibility prefix.
    pub v3: NemoRelayNativeHostApiV3,
    /// Decodes an LLM request using the request codec attached to `completion`.
    pub async_completion_llm_request_codec_decode: unsafe extern "C" fn(
        completion: *const NemoRelayNativeAsyncCompletion,
        request_json: *const NemoRelayNativeString,
        out: *mut *mut NemoRelayNativeString,
    ) -> NemoRelayStatus,
    /// Encodes an annotated LLM request using the request codec attached to `completion`.
    pub async_completion_llm_request_codec_encode: unsafe extern "C" fn(
        completion: *const NemoRelayNativeAsyncCompletion,
        annotated_json: *const NemoRelayNativeString,
        original_json: *const NemoRelayNativeString,
        out: *mut *mut NemoRelayNativeString,
    ) -> NemoRelayStatus,
    /// Decodes an LLM response using the response codec attached to `completion`.
    pub async_completion_llm_response_codec_decode: unsafe extern "C" fn(
        completion: *const NemoRelayNativeAsyncCompletion,
        response_json: *const NemoRelayNativeString,
        out: *mut *mut NemoRelayNativeString,
    ) -> NemoRelayStatus,
    /// Opens an independent pull-based downstream LLM stream.
    pub async_next_open_llm_stream: unsafe extern "C" fn(
        next: *const NemoRelayNativeAsyncNext,
        request_json: *const NemoRelayNativeString,
        cb: NemoRelayNativeAsyncLlmStreamOpenCb,
        user_data: *mut c_void,
    ) -> NemoRelayStatus,
    /// Requests one item from a pull-based downstream LLM stream.
    pub async_llm_stream_pull: unsafe extern "C" fn(
        stream: *const NemoRelayNativeLlmAsyncStream,
        cb: NemoRelayNativeAsyncLlmStreamPullCb,
        user_data: *mut c_void,
    ) -> NemoRelayStatus,
    /// Cancels a pull-based downstream LLM stream.
    pub async_llm_stream_cancel:
        unsafe extern "C" fn(stream: *const NemoRelayNativeLlmAsyncStream) -> NemoRelayStatus,
    /// Releases the plugin-owned stream reference exactly once.
    pub async_llm_stream_release:
        unsafe extern "C" fn(stream: *const NemoRelayNativeLlmAsyncStream),
    /// Retains a completion capability for a codec facade that outlives the
    /// callback's original completion reference.
    pub async_completion_retain:
        unsafe extern "C" fn(completion: *const NemoRelayNativeAsyncCompletion) -> NemoRelayStatus,
    /// Returns whether the output queue is currently full.
    ///
    /// Use [`NemoRelayStatus::Backpressured`] from the individual push or
    /// rejection operation to decide whether that operation must be retried.
    pub async_stream_is_backpressured:
        unsafe extern "C" fn(stream: *const NemoRelayNativeAsyncStream) -> bool,
    /// Emits a mark with optional data-schema and telemetry-severity fields.
    pub emit_mark_v2: NemoRelayNativeEmitMarkV2Fn,
    /// Returns a bounded snapshot of active host runtime diagnostics.
    pub get_runtime_diagnostics: NemoRelayNativeGetRuntimeDiagnosticsFn,
    /// Creates an activation-owned runtime capability from a registration context.
    ///
    /// On success, `out` receives one owned reference. Every owned reference must
    /// be released exactly once with `plugin_runtime_release`.
    pub plugin_context_runtime: unsafe extern "C" fn(
        ctx: *mut NemoRelayNativePluginContext,
        out: *mut *const NemoRelayNativePluginRuntime,
    ) -> NemoRelayStatus,
    /// Retains a runtime capability for a cloned SDK handle.
    ///
    /// A successful call creates one additional owned reference.
    pub plugin_runtime_retain:
        unsafe extern "C" fn(runtime: *const NemoRelayNativePluginRuntime) -> NemoRelayStatus,
    /// Releases one owned runtime capability reference.
    pub plugin_runtime_release: unsafe extern "C" fn(runtime: *const NemoRelayNativePluginRuntime),
    /// Lists global runtime registrations as JSON.
    pub plugin_runtime_list_registrations: unsafe extern "C" fn(
        runtime: *const NemoRelayNativePluginRuntime,
        kinds_json: *const NemoRelayNativeString,
        out_json: *mut *mut NemoRelayNativeString,
    ) -> NemoRelayStatus,
    /// Legacy constant-reason gate registration retained for v4 compatibility.
    pub plugin_runtime_register_conditional_middleware_guardrail:
        unsafe extern "C" fn(
            runtime: *const NemoRelayNativePluginRuntime,
            name: *const NemoRelayNativeString,
            kinds_json: *const NemoRelayNativeString,
            registration_name: *const NemoRelayNativeString,
            reason: *const NemoRelayNativeString,
            out_handle: *mut *mut NemoRelayNativeString,
        ) -> NemoRelayStatus,
    /// Deregisters an activation-owned gate by opaque handle.
    pub plugin_runtime_deregister_conditional_middleware_guardrail:
        unsafe extern "C" fn(
            runtime: *const NemoRelayNativePluginRuntime,
            handle: *const NemoRelayNativeString,
            out_removed: *mut bool,
        ) -> NemoRelayStatus,
    /// Legacy constant-reason component gate retained for v4 compatibility.
    pub plugin_context_register_conditional_middleware_guardrail:
        unsafe extern "C" fn(
            ctx: *mut NemoRelayNativePluginContext,
            name: *const NemoRelayNativeString,
            kinds_json: *const NemoRelayNativeString,
            registration_name: *const NemoRelayNativeString,
            reason: *const NemoRelayNativeString,
        ) -> NemoRelayStatus,
    /// Registers an activation-owned callback gate and returns its handle.
    ///
    /// Relay invokes `cb` synchronously and consumes `user_data` on every return
    /// path. A null callback reason leaves the target enabled.
    pub plugin_runtime_register_conditional_middleware_guardrail_callback:
        unsafe extern "C" fn(
            runtime: *const NemoRelayNativePluginRuntime,
            name: *const NemoRelayNativeString,
            kinds_json: *const NemoRelayNativeString,
            registration_name: *const NemoRelayNativeString,
            cb: NemoRelayNativeConditionalMiddlewareCb,
            user_data: *mut c_void,
            free_fn: NemoRelayNativeFreeFn,
            out_handle: *mut *mut NemoRelayNativeString,
        ) -> NemoRelayStatus,
    /// Declares a callback gate during component registration.
    ///
    /// Relay invokes `cb` synchronously and consumes `user_data` on every return
    /// path. A null callback reason leaves the target enabled.
    pub plugin_context_register_conditional_middleware_guardrail_callback:
        unsafe extern "C" fn(
            ctx: *mut NemoRelayNativePluginContext,
            name: *const NemoRelayNativeString,
            kinds_json: *const NemoRelayNativeString,
            registration_name: *const NemoRelayNativeString,
            cb: NemoRelayNativeConditionalMiddlewareCb,
            user_data: *mut c_void,
            free_fn: NemoRelayNativeFreeFn,
        ) -> NemoRelayStatus,
}

unsafe impl Send for NemoRelayNativeHostApiV3 {}
unsafe impl Sync for NemoRelayNativeHostApiV3 {}

/// ABI-v5 host extension for the mark window.
///
/// The complete ABI-v4 table is the prefix, preserving layout compatibility.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NemoRelayNativeHostApiV5 {
    /// Frozen ABI-v4 compatibility prefix.
    pub v4: NemoRelayNativeHostApiV4,
    /// Captures the mark window the calling invocation runs under.
    pub capture_mark_window_thread: NemoRelayNativeCaptureMarkWindowFn,
    /// Releases one owned mark-window handle.
    pub release_mark_window: NemoRelayNativeReleaseMarkWindowFn,
    /// Emits a mark through the window it was raised under.
    pub emit_mark_in_window: NemoRelayNativeEmitMarkInWindowFn,
}

// SAFETY: the v5 host table is immutable after construction. Its function
// pointers and inherited host metadata may be invoked from any plugin thread.
unsafe impl Send for NemoRelayNativeHostApiV5 {}
unsafe impl Sync for NemoRelayNativeHostApiV5 {}

// SAFETY: the v4 host table is immutable after construction. Its function
// pointers and inherited host metadata may be invoked from any plugin thread.
unsafe impl Send for NemoRelayNativeHostApiV4 {}
unsafe impl Sync for NemoRelayNativeHostApiV4 {}

// The host API table is immutable after construction. Function pointers and
// the null-terminated version string pointer are safe to share across threads.
unsafe impl Send for NemoRelayNativeHostApiV1 {}
unsafe impl Sync for NemoRelayNativeHostApiV1 {}

/// Versioned plugin descriptor returned by native plugin entry symbols.
#[repr(C)]
pub struct NemoRelayNativePluginV1 {
    /// Size of this struct as seen by the plugin.
    pub struct_size: usize,
    /// Host-owned plugin kind string.
    pub plugin_kind: *mut NemoRelayNativeString,
    /// Whether this plugin kind supports multiple configured components.
    pub allows_multiple_components: bool,
    /// Plugin-owned state pointer passed to callbacks.
    pub user_data: *mut c_void,
    /// Optional validation callback.
    pub validate: Option<NemoRelayNativePluginValidateFn>,
    /// Required registration callback.
    pub register: Option<NemoRelayNativePluginRegisterFn>,
    /// Optional plugin-owned state destructor.
    pub drop: NemoRelayNativePluginDropFn,
}

impl Default for NemoRelayNativePluginV1 {
    fn default() -> Self {
        Self {
            struct_size: std::mem::size_of::<Self>(),
            plugin_kind: ptr::null_mut(),
            allows_multiple_components: true,
            user_data: ptr::null_mut(),
            validate: None,
            register: None,
            drop: None,
        }
    }
}

/// Native entry symbol type loaded by the host.
pub type NemoRelayNativePluginEntry = unsafe extern "C" fn(
    host: *const NemoRelayNativeHostApiV1,
    out: *mut NemoRelayNativePluginV1,
) -> NemoRelayStatus;
