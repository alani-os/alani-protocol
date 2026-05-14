#![cfg_attr(not(feature = "std"), no_std)]

//! Dependency-free protocol contracts for the Alani MVK.
//!
//! `alani-protocol` is the compatibility root for transport envelopes, IPC
//! message schemas, audit-event records, config payloads, device descriptors,
//! corpus metadata, and model metadata. This crate intentionally keeps concrete
//! enforcement and storage behavior in sibling repositories.

pub mod audit;
pub mod config;
pub mod ipc;
pub mod message;
pub mod schema;

pub use audit::{
    AuditDecision, AuditDescriptor, AuditEvent, AuditEventKind, AuditRecordHeader, AuditStatus,
    AUDIT_EVENT_SCHEMA_VERSION, MAX_AUDIT_LABEL_LEN,
};
pub use config::{
    ConfigDescriptor, ConfigDocument, ConfigDomain, ConfigEntry, ConfigFormat, ConfigValue,
    ConfigValueKind, CONFIG_SCHEMA_VERSION, MAX_CONFIG_ENTRIES, MAX_CONFIG_KEY_LEN,
};
pub use ipc::{
    EndpointKind, IpcDescriptor, IpcEndpoint, IpcEnvelope, IpcFlow, IpcRouteHint, IpcStatus,
    MAX_ENDPOINT_LABEL_LEN,
};
pub use message::{
    MessageDescriptor, MessageEnvelope, MessageHeader, MessageKind, PayloadRef, PayloadStorage,
    MAX_MESSAGE_LABEL_LEN, MAX_PAYLOAD_REFS, MESSAGE_FLAG_AUDIT_REQUIRED, MESSAGE_FLAG_COMPRESSED,
    MESSAGE_FLAG_ENCRYPTED, MESSAGE_FLAG_REQUIRES_REPLY, MESSAGE_FLAG_SHARED_MEMORY,
    MESSAGE_KNOWN_FLAGS, MESSAGE_SCHEMA_VERSION,
};
pub use schema::{
    CorpusMetadata, DeviceClass, DeviceDescriptor, DeviceState, MetadataRecord, ModelFormat,
    ModelMetadata, SchemaDescriptor, SchemaKind, SchemaRegistry, SchemaVersion,
    CORPUS_METADATA_SCHEMA_VERSION, DEVICE_DESCRIPTOR_SCHEMA_VERSION,
    MODEL_METADATA_SCHEMA_VERSION, SCHEMA_REGISTRY_VERSION,
};

/// Repository name.
pub const REPOSITORY: &str = "alani-protocol";

/// Crate version.
pub const VERSION: &str = "0.1.0";

/// Public module names exposed by this crate.
pub const MODULES: &[&str] = &["message", "ipc", "audit", "config", "schema"];

/// Feature bit for transport message envelopes.
pub const PROTOCOL_FEATURE_MESSAGES: u64 = 1 << 0;
/// Feature bit for IPC endpoint and route schemas.
pub const PROTOCOL_FEATURE_IPC: u64 = 1 << 1;
/// Feature bit for audit-event schema records.
pub const PROTOCOL_FEATURE_AUDIT: u64 = 1 << 2;
/// Feature bit for config payload schemas.
pub const PROTOCOL_FEATURE_CONFIG: u64 = 1 << 3;
/// Feature bit for shared metadata schemas.
pub const PROTOCOL_FEATURE_SCHEMA_REGISTRY: u64 = 1 << 4;
/// Feature bit for trace context propagation.
pub const PROTOCOL_FEATURE_TRACE_CONTEXT: u64 = 1 << 5;
/// Feature bit for redaction and data-class metadata.
pub const PROTOCOL_FEATURE_REDACTION: u64 = 1 << 6;

/// All protocol feature bits known by this crate version.
pub const PROTOCOL_KNOWN_FEATURES: u64 = PROTOCOL_FEATURE_MESSAGES
    | PROTOCOL_FEATURE_IPC
    | PROTOCOL_FEATURE_AUDIT
    | PROTOCOL_FEATURE_CONFIG
    | PROTOCOL_FEATURE_SCHEMA_REGISTRY
    | PROTOCOL_FEATURE_TRACE_CONTEXT
    | PROTOCOL_FEATURE_REDACTION;

/// Maximum schema-version label length.
pub const MAX_SCHEMA_VERSION_LEN: usize = 64;

/// Maximum component, operation, resource, or generic metadata label length.
pub const MAX_PROTOCOL_LABEL_LEN: usize = 128;

/// Invalid event/message/record identifier.
pub const INVALID_PROTOCOL_ID: u128 = 0;

/// Result alias used by protocol validation APIs.
pub type ProtocolResult<T> = Result<T, ProtocolError>;

/// Error taxonomy for protocol schemas and envelopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// A required field was empty or omitted.
    MissingField,
    /// A bounded string field exceeded its documented limit.
    FieldTooLong,
    /// Reserved flag, feature, kind, or rights bits were supplied.
    ReservedBits,
    /// Schema version was missing, malformed, or incompatible.
    InvalidSchemaVersion,
    /// Message envelope or payload metadata was invalid.
    InvalidMessage,
    /// Inline or referenced payload exceeded bounds.
    PayloadTooLarge,
    /// IPC endpoint, route, or flow metadata was invalid.
    InvalidIpc,
    /// Audit event or audit record metadata was invalid.
    InvalidAudit,
    /// Configuration document or entry metadata was invalid.
    InvalidConfig,
    /// Shared metadata schema record was invalid.
    InvalidMetadata,
    /// Data classification and redaction state are incompatible.
    InvalidRedaction,
    /// Trace identifiers are malformed.
    InvalidTrace,
    /// Requested operation requires authority that is not represented.
    AccessDenied,
    /// Fixed-capacity collection is full.
    CapacityExceeded,
    /// Internal invariant failed.
    Internal,
}

impl ProtocolError {
    /// Stable reason label for diagnostics, audit records, and tests.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::MissingField => "missing_field",
            Self::FieldTooLong => "field_too_long",
            Self::ReservedBits => "reserved_bits",
            Self::InvalidSchemaVersion => "invalid_schema_version",
            Self::InvalidMessage => "invalid_message",
            Self::PayloadTooLarge => "payload_too_large",
            Self::InvalidIpc => "invalid_ipc",
            Self::InvalidAudit => "invalid_audit",
            Self::InvalidConfig => "invalid_config",
            Self::InvalidMetadata => "invalid_metadata",
            Self::InvalidRedaction => "invalid_redaction",
            Self::InvalidTrace => "invalid_trace",
            Self::AccessDenied => "access_denied",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::Internal => "internal",
        }
    }

    /// Returns `true` when the error represents a fail-closed trust boundary.
    pub const fn is_security_relevant(self) -> bool {
        matches!(
            self,
            Self::ReservedBits
                | Self::InvalidSchemaVersion
                | Self::InvalidMessage
                | Self::PayloadTooLarge
                | Self::InvalidIpc
                | Self::InvalidAudit
                | Self::InvalidConfig
                | Self::InvalidMetadata
                | Self::InvalidRedaction
                | Self::InvalidTrace
                | Self::AccessDenied
        )
    }
}

/// Implementation maturity marker for generated repository metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentStatus {
    /// API is present as a draft skeleton.
    Draft,
    /// API is implemented enough for host-mode experimentation.
    Experimental,
    /// API is compatible and stable.
    Stable,
}

/// Stable component identity record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentInfo {
    /// Repository name.
    pub repository: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Current implementation status.
    pub status: ComponentStatus,
}

/// Returns stable component identity metadata.
pub const fn component_info() -> ComponentInfo {
    ComponentInfo {
        repository: REPOSITORY,
        version: VERSION,
        status: ComponentStatus::Experimental,
    }
}

/// Returns the repository name.
pub const fn repository_name() -> &'static str {
    REPOSITORY
}

/// Returns public module names.
pub fn module_names() -> &'static [&'static str] {
    MODULES
}

/// Stable trace context propagated across protocol boundaries.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TraceContext {
    /// Trace identifier.
    pub trace_id: u64,
    /// Span identifier.
    pub span_id: u64,
    /// Parent span identifier when known.
    pub parent_span_id: u64,
    /// Trace flags.
    pub flags: u32,
}

impl TraceContext {
    /// Empty trace context used when no trace exists.
    pub const EMPTY: Self = Self {
        trace_id: 0,
        span_id: 0,
        parent_span_id: 0,
        flags: 0,
    };

    /// Creates a trace context with trace and span identifiers.
    pub const fn new(trace_id: u64, span_id: u64) -> Self {
        Self {
            trace_id,
            span_id,
            parent_span_id: 0,
            flags: 0,
        }
    }

    /// Sets parent span identifier.
    pub const fn with_parent(mut self, parent_span_id: u64) -> Self {
        self.parent_span_id = parent_span_id;
        self
    }

    /// Sets trace flags.
    pub const fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Returns `true` when trace and span identifiers are both present.
    pub const fn is_present(self) -> bool {
        self.trace_id != 0 && self.span_id != 0
    }

    /// Validates trace identifiers.
    pub const fn validate(self) -> ProtocolResult<()> {
        if (self.trace_id == 0) != (self.span_id == 0) {
            return Err(ProtocolError::InvalidTrace);
        }
        if self.parent_span_id != 0 && !self.is_present() {
            return Err(ProtocolError::InvalidTrace);
        }
        Ok(())
    }
}

/// Data sensitivity classification for protocol records.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataClass {
    /// Public metadata.
    Public = 0,
    /// Operational metadata suitable for trusted operators.
    Operational = 1,
    /// Sensitive metadata requiring redaction before broad export.
    Sensitive = 2,
    /// Secret metadata that must never be exported in raw form.
    Secret = 3,
}

impl DataClass {
    /// Stable class label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Operational => "operational",
            Self::Sensitive => "sensitive",
            Self::Secret => "secret",
        }
    }

    /// Returns `true` when broad export requires redaction.
    pub const fn requires_redaction(self) -> bool {
        matches!(self, Self::Sensitive | Self::Secret)
    }
}

/// Redaction state for payloads and metadata.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedactionState {
    /// Public content.
    Public = 0,
    /// Operational metadata.
    Operational = 1,
    /// Sensitive fields were redacted.
    SensitiveRedacted = 2,
    /// Secret fields were redacted.
    SecretRedacted = 3,
    /// Sensitive fields are present and must not be exported broadly.
    UnredactedSensitive = 4,
}

impl RedactionState {
    /// Stable redaction label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Operational => "operational",
            Self::SensitiveRedacted => "sensitive_redacted",
            Self::SecretRedacted => "secret_redacted",
            Self::UnredactedSensitive => "unredacted_sensitive",
        }
    }
}

/// Validates that a data class has an acceptable redaction state.
pub const fn validate_redaction(
    data_class: DataClass,
    redaction: RedactionState,
) -> ProtocolResult<()> {
    match data_class {
        DataClass::Public => {
            if matches!(redaction, RedactionState::Public) {
                Ok(())
            } else {
                Err(ProtocolError::InvalidRedaction)
            }
        }
        DataClass::Operational => {
            if matches!(
                redaction,
                RedactionState::Operational | RedactionState::Public
            ) {
                Ok(())
            } else {
                Err(ProtocolError::InvalidRedaction)
            }
        }
        DataClass::Sensitive => {
            if matches!(redaction, RedactionState::SensitiveRedacted) {
                Ok(())
            } else {
                Err(ProtocolError::InvalidRedaction)
            }
        }
        DataClass::Secret => {
            if matches!(redaction, RedactionState::SecretRedacted) {
                Ok(())
            } else {
                Err(ProtocolError::InvalidRedaction)
            }
        }
    }
}

/// Validates a protocol-facing label.
pub const fn validate_label(label: &str, max_len: usize) -> ProtocolResult<()> {
    if label.is_empty() {
        return Err(ProtocolError::MissingField);
    }
    if label.len() > max_len {
        return Err(ProtocolError::FieldTooLong);
    }
    Ok(())
}

/// Validates a schema version label.
pub fn validate_schema_version(version: &str) -> ProtocolResult<()> {
    validate_label(version, MAX_SCHEMA_VERSION_LEN)?;
    if !version.starts_with("alani.") || !version.ends_with(".v1") {
        return Err(ProtocolError::InvalidSchemaVersion);
    }
    Ok(())
}

/// Compact root view of the protocol crate contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolCatalog {
    /// Repository name.
    pub repository: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Feature bitmap.
    pub features: u64,
    /// Public module count.
    pub module_count: usize,
    /// Maximum generic protocol label length.
    pub max_label_len: usize,
}

impl ProtocolCatalog {
    /// Current protocol catalog.
    pub const CURRENT: Self = Self {
        repository: REPOSITORY,
        version: VERSION,
        features: PROTOCOL_KNOWN_FEATURES,
        module_count: MODULES.len(),
        max_label_len: MAX_PROTOCOL_LABEL_LEN,
    };

    /// Returns the current protocol catalog.
    pub const fn current() -> Self {
        Self::CURRENT
    }

    /// Validates catalog metadata.
    pub const fn validate(self) -> ProtocolResult<()> {
        if self.repository.is_empty() || self.version.is_empty() {
            return Err(ProtocolError::MissingField);
        }
        if self.features & !PROTOCOL_KNOWN_FEATURES != 0 {
            return Err(ProtocolError::ReservedBits);
        }
        if self.module_count != MODULES.len() || self.max_label_len == 0 {
            return Err(ProtocolError::InvalidMetadata);
        }
        Ok(())
    }
}

/// Current protocol catalog.
pub const PROTOCOL_CATALOG: ProtocolCatalog = ProtocolCatalog::CURRENT;

/// Returns the current protocol catalog.
pub const fn protocol_catalog() -> ProtocolCatalog {
    ProtocolCatalog::CURRENT
}
