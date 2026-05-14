//! Audit event schema records shared across repositories.
//!
//! Durable storage, hash-chain append behavior, and query enforcement belong to
//! `alani-audit`. This module owns the stable protocol fields and validation
//! rules that those crates consume.

use crate::{
    validate_label, validate_redaction, validate_schema_version, DataClass, ProtocolError,
    ProtocolResult, RedactionState, TraceContext, INVALID_PROTOCOL_ID,
};

/// Audit event schema version.
pub const AUDIT_EVENT_SCHEMA_VERSION: &str = "alani.event.v1";

/// Maximum audit label length.
pub const MAX_AUDIT_LABEL_LEN: usize = 128;

/// Hash byte length used by audit record headers.
pub const AUDIT_HASH_LEN: usize = 32;

/// Audit hash bytes.
pub type AuditHash = [u8; AUDIT_HASH_LEN];

/// Zero hash placeholder.
pub const ZERO_AUDIT_HASH: AuditHash = [0u8; AUDIT_HASH_LEN];

/// Audit event category.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditEventKind {
    /// Unknown placeholder.
    Unknown = 0,
    /// Security denial or sandbox violation.
    SecurityDenial = 1,
    /// Capability derivation, attenuation, or revocation.
    CapabilityDerivation = 2,
    /// Device open or privileged device use.
    DeviceOpen = 3,
    /// Memory sharing, sealing, or ownership transfer.
    MemoryShare = 4,
    /// Model inference or cognitive memory access.
    ModelInference = 5,
    /// Corpus import or generated-data ingest.
    CorpusImport = 6,
    /// Release packaging, signing, or evidence generation.
    ReleasePackaging = 7,
    /// CI waiver or policy exception.
    CiWaiver = 8,
    /// Audit query or export request.
    AuditQuery = 9,
    /// Audit hash-chain verification.
    AuditVerification = 10,
    /// Task lifecycle transition with security impact.
    TaskLifecycle = 11,
    /// Persistent storage mutation.
    StorageMutation = 12,
    /// Policy decision for an operation.
    PolicyDecision = 13,
    /// Configuration mutation or policy-affecting config read.
    ConfigAccess = 14,
}

impl AuditEventKind {
    /// Stable event-kind label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::SecurityDenial => "security_denial",
            Self::CapabilityDerivation => "capability_derivation",
            Self::DeviceOpen => "device_open",
            Self::MemoryShare => "memory_share",
            Self::ModelInference => "model_inference",
            Self::CorpusImport => "corpus_import",
            Self::ReleasePackaging => "release_packaging",
            Self::CiWaiver => "ci_waiver",
            Self::AuditQuery => "audit_query",
            Self::AuditVerification => "audit_verification",
            Self::TaskLifecycle => "task_lifecycle",
            Self::StorageMutation => "storage_mutation",
            Self::PolicyDecision => "policy_decision",
            Self::ConfigAccess => "config_access",
        }
    }

    /// Returns `true` when this event must not be sampled out.
    pub const fn is_audit_critical(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// Policy decision recorded by the audit event.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditDecision {
    /// Operation was allowed.
    Allow = 1,
    /// Operation was denied.
    Deny = 2,
    /// Operation required escalation.
    Escalate = 3,
    /// No policy decision applied.
    NotApplicable = 4,
}

impl AuditDecision {
    /// Stable decision label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Escalate => "escalate",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// Operation status captured by an audit event.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditStatus {
    /// Operation started.
    Started = 1,
    /// Operation completed successfully.
    Succeeded = 2,
    /// Operation failed.
    Failed = 3,
    /// Operation was denied before execution.
    Denied = 4,
    /// Operation was skipped or cancelled.
    Cancelled = 5,
}

impl AuditStatus {
    /// Stable status label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Structured audit event protocol record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditEvent<'a> {
    /// Schema version.
    pub schema_version: &'a str,
    /// Stable event identifier.
    pub event_id: u128,
    /// Monotonic sequence in the producing segment.
    pub sequence: u64,
    /// Timestamp in nanoseconds when available.
    pub timestamp_ns: u64,
    /// Monotonic counter supplied by producer.
    pub monotonic_counter: u64,
    /// Event category.
    pub kind: AuditEventKind,
    /// Principal responsible for the event.
    pub principal: &'a str,
    /// Emitting component.
    pub component: &'a str,
    /// Operation label.
    pub operation: &'a str,
    /// Resource label.
    pub resource: &'a str,
    /// Decision label.
    pub decision: AuditDecision,
    /// Operation status.
    pub status: AuditStatus,
    /// Data class.
    pub data_class: DataClass,
    /// Redaction state.
    pub redaction: RedactionState,
    /// Trace context.
    pub trace: TraceContext,
}

impl<'a> AuditEvent<'a> {
    /// Creates an audit event with conservative defaults.
    pub const fn new(
        event_id: u128,
        sequence: u64,
        kind: AuditEventKind,
        principal: &'a str,
        operation: &'a str,
        resource: &'a str,
    ) -> Self {
        Self {
            schema_version: AUDIT_EVENT_SCHEMA_VERSION,
            event_id,
            sequence,
            timestamp_ns: 0,
            monotonic_counter: 0,
            kind,
            principal,
            component: "unknown",
            operation,
            resource,
            decision: AuditDecision::NotApplicable,
            status: AuditStatus::Started,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
            trace: TraceContext::EMPTY,
        }
    }

    /// Creates an event for a security denial.
    pub const fn security_denial(
        event_id: u128,
        sequence: u64,
        principal: &'a str,
        operation: &'a str,
        resource: &'a str,
    ) -> Self {
        Self {
            decision: AuditDecision::Deny,
            status: AuditStatus::Denied,
            data_class: DataClass::Sensitive,
            redaction: RedactionState::SensitiveRedacted,
            ..Self::new(
                event_id,
                sequence,
                AuditEventKind::SecurityDenial,
                principal,
                operation,
                resource,
            )
        }
    }

    /// Sets timestamp and monotonic counter.
    pub const fn with_time(mut self, timestamp_ns: u64, monotonic_counter: u64) -> Self {
        self.timestamp_ns = timestamp_ns;
        self.monotonic_counter = monotonic_counter;
        self
    }

    /// Sets emitting component.
    pub const fn with_component(mut self, component: &'a str) -> Self {
        self.component = component;
        self
    }

    /// Sets decision and status.
    pub const fn with_outcome(mut self, decision: AuditDecision, status: AuditStatus) -> Self {
        self.decision = decision;
        self.status = status;
        self
    }

    /// Sets redaction metadata.
    pub const fn with_redaction(
        mut self,
        data_class: DataClass,
        redaction: RedactionState,
    ) -> Self {
        self.data_class = data_class;
        self.redaction = redaction;
        self
    }

    /// Sets trace context.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Returns `true` when the event is audit critical.
    pub const fn is_audit_critical(self) -> bool {
        self.kind.is_audit_critical() || matches!(self.decision, AuditDecision::Deny)
    }

    /// Validates the event fields.
    pub fn validate(self) -> ProtocolResult<()> {
        validate_schema_version(self.schema_version)?;
        if self.event_id == INVALID_PROTOCOL_ID {
            return Err(ProtocolError::InvalidAudit);
        }
        if self.timestamp_ns == 0 && self.monotonic_counter == 0 {
            return Err(ProtocolError::MissingField);
        }
        validate_label(self.principal, MAX_AUDIT_LABEL_LEN)?;
        validate_label(self.component, MAX_AUDIT_LABEL_LEN)?;
        validate_label(self.operation, MAX_AUDIT_LABEL_LEN)?;
        validate_label(self.resource, MAX_AUDIT_LABEL_LEN)?;
        if matches!(self.kind, AuditEventKind::Unknown) {
            return Err(ProtocolError::InvalidAudit);
        }
        if matches!(self.decision, AuditDecision::Deny)
            && !matches!(self.status, AuditStatus::Denied | AuditStatus::Failed)
        {
            return Err(ProtocolError::InvalidAudit);
        }
        self.trace.validate()?;
        validate_redaction(self.data_class, self.redaction)
    }
}

/// Audit record header for append-only segment protocols.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditRecordHeader<'a> {
    /// Schema version.
    pub schema_version: &'a str,
    /// Segment identifier.
    pub segment_id: u64,
    /// Sequence within the segment.
    pub sequence: u64,
    /// Previous record hash.
    pub previous_hash: AuditHash,
    /// Current event hash.
    pub event_hash: AuditHash,
}

impl<'a> AuditRecordHeader<'a> {
    /// Creates an audit record header.
    pub const fn new(
        segment_id: u64,
        sequence: u64,
        previous_hash: AuditHash,
        event_hash: AuditHash,
    ) -> Self {
        Self {
            schema_version: AUDIT_EVENT_SCHEMA_VERSION,
            segment_id,
            sequence,
            previous_hash,
            event_hash,
        }
    }

    /// Validates header metadata.
    pub fn validate(self) -> ProtocolResult<()> {
        validate_schema_version(self.schema_version)?;
        if self.segment_id == 0 {
            return Err(ProtocolError::InvalidAudit);
        }
        if self.event_hash == ZERO_AUDIT_HASH {
            return Err(ProtocolError::InvalidAudit);
        }
        if self.sequence == 0 && self.previous_hash != ZERO_AUDIT_HASH {
            return Err(ProtocolError::InvalidAudit);
        }
        Ok(())
    }
}

/// Module boundary descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditDescriptor<'a> {
    /// Human-readable descriptor name.
    pub name: &'a str,
    /// Descriptor version.
    pub version: u32,
}

impl<'a> AuditDescriptor<'a> {
    /// Creates an audit descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
