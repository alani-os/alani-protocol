//! Transport message envelopes and payload reference schemas.
//!
//! These types describe message metadata shared by IPC, runtime, terminal,
//! observability, and test crates. They validate sizes, schema versions,
//! redaction state, trace context, and reserved flag bits, but they do not own
//! delivery or queueing behavior.

use crate::{
    validate_label, validate_redaction, validate_schema_version, DataClass, ProtocolError,
    ProtocolResult, RedactionState, TraceContext, INVALID_PROTOCOL_ID, MAX_PROTOCOL_LABEL_LEN,
};

/// Message schema version owned by this crate.
pub const MESSAGE_SCHEMA_VERSION: &str = "alani.message.v1";

/// Maximum component, route, or payload label length.
pub const MAX_MESSAGE_LABEL_LEN: usize = 128;

/// Maximum inline message payload bytes.
pub const MAX_INLINE_PAYLOAD_BYTES: u64 = 64 * 1024;

/// Maximum payload references in one envelope.
pub const MAX_PAYLOAD_REFS: usize = 4;

/// Message expects a response.
pub const MESSAGE_FLAG_REQUIRES_REPLY: u32 = 1 << 0;
/// Message references shared memory.
pub const MESSAGE_FLAG_SHARED_MEMORY: u32 = 1 << 1;
/// Message decision or operation must be audited.
pub const MESSAGE_FLAG_AUDIT_REQUIRED: u32 = 1 << 2;
/// Payload is encrypted and requires decryption metadata outside this skeleton.
pub const MESSAGE_FLAG_ENCRYPTED: u32 = 1 << 3;
/// Payload is compressed.
pub const MESSAGE_FLAG_COMPRESSED: u32 = 1 << 4;

/// All message flags known by this crate version.
pub const MESSAGE_KNOWN_FLAGS: u32 = MESSAGE_FLAG_REQUIRES_REPLY
    | MESSAGE_FLAG_SHARED_MEMORY
    | MESSAGE_FLAG_AUDIT_REQUIRED
    | MESSAGE_FLAG_ENCRYPTED
    | MESSAGE_FLAG_COMPRESSED;

/// Message kind used by protocol envelopes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    /// Request expecting optional response.
    Request = 1,
    /// Response to a request.
    Response = 2,
    /// Event notification.
    Event = 3,
    /// Signal or wakeup notification.
    Signal = 4,
    /// Control-plane message.
    Control = 5,
    /// Audit/event evidence transport.
    Evidence = 6,
}

impl MessageKind {
    /// Stable kind label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
            Self::Event => "event",
            Self::Signal => "signal",
            Self::Control => "control",
            Self::Evidence => "evidence",
        }
    }

    /// Returns `true` when messages of this kind are security-sensitive.
    pub const fn is_audit_relevant(self) -> bool {
        matches!(self, Self::Control | Self::Evidence)
    }
}

/// Payload storage class.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadStorage {
    /// Payload bytes are carried inline by the transport.
    Inline = 1,
    /// Payload bytes are in a shared-memory handle described by the sender.
    SharedMemory = 2,
    /// Payload bytes are external and content-addressed.
    External = 3,
}

impl PayloadStorage {
    /// Stable storage label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::SharedMemory => "shared_memory",
            Self::External => "external",
        }
    }
}

/// Payload reference inside a protocol message envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PayloadRef<'a> {
    /// Human-readable payload label.
    pub label: &'a str,
    /// Storage class.
    pub storage: PayloadStorage,
    /// Offset within inline/shared storage.
    pub offset: u32,
    /// Payload length in bytes.
    pub len: u32,
    /// Stable content identifier or external URI. Empty for purely inline data.
    pub content_ref: &'a str,
    /// Payload data class.
    pub data_class: DataClass,
    /// Payload redaction state.
    pub redaction: RedactionState,
}

impl<'a> PayloadRef<'a> {
    /// Creates an inline payload reference.
    pub const fn inline(label: &'a str, offset: u32, len: u32) -> Self {
        Self {
            label,
            storage: PayloadStorage::Inline,
            offset,
            len,
            content_ref: "",
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
        }
    }

    /// Creates a shared-memory payload reference.
    pub const fn shared(label: &'a str, content_ref: &'a str, len: u32) -> Self {
        Self {
            label,
            storage: PayloadStorage::SharedMemory,
            offset: 0,
            len,
            content_ref,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
        }
    }

    /// Creates an external content-addressed payload reference.
    pub const fn external(label: &'a str, content_ref: &'a str, len: u32) -> Self {
        Self {
            label,
            storage: PayloadStorage::External,
            offset: 0,
            len,
            content_ref,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
        }
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

    /// Returns `true` when the payload is carried outside the inline envelope.
    pub const fn is_referenced(self) -> bool {
        !matches!(self.storage, PayloadStorage::Inline)
    }

    /// Validates payload metadata.
    pub fn validate(self) -> ProtocolResult<()> {
        validate_label(self.label, MAX_MESSAGE_LABEL_LEN)?;
        if self.len == 0 {
            return Err(ProtocolError::InvalidMessage);
        }
        if self.len as u64 > MAX_INLINE_PAYLOAD_BYTES {
            return Err(ProtocolError::PayloadTooLarge);
        }
        if self.is_referenced() {
            validate_label(self.content_ref, MAX_PROTOCOL_LABEL_LEN)?;
        }
        validate_redaction(self.data_class, self.redaction)
    }
}

/// Message header shared by transport and IPC envelopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageHeader<'a> {
    /// Schema version.
    pub schema_version: &'a str,
    /// Stable message identifier.
    pub message_id: u128,
    /// Correlation identifier for request/response flows.
    pub correlation_id: u128,
    /// Source component or endpoint label.
    pub source: &'a str,
    /// Target component or endpoint label.
    pub target: &'a str,
    /// Operation name.
    pub operation: &'a str,
    /// Message kind.
    pub kind: MessageKind,
    /// Priority bucket. Zero is normal.
    pub priority: u8,
    /// Message flags.
    pub flags: u32,
    /// Trace context.
    pub trace: TraceContext,
    /// Header data class.
    pub data_class: DataClass,
    /// Header redaction state.
    pub redaction: RedactionState,
}

impl<'a> MessageHeader<'a> {
    /// Creates a message header.
    pub const fn new(
        message_id: u128,
        source: &'a str,
        target: &'a str,
        operation: &'a str,
        kind: MessageKind,
    ) -> Self {
        Self {
            schema_version: MESSAGE_SCHEMA_VERSION,
            message_id,
            correlation_id: 0,
            source,
            target,
            operation,
            kind,
            priority: 0,
            flags: 0,
            trace: TraceContext::EMPTY,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
        }
    }

    /// Sets correlation id.
    pub const fn with_correlation(mut self, correlation_id: u128) -> Self {
        self.correlation_id = correlation_id;
        self
    }

    /// Sets flags.
    pub const fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Sets trace context.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Sets data classification.
    pub const fn with_redaction(
        mut self,
        data_class: DataClass,
        redaction: RedactionState,
    ) -> Self {
        self.data_class = data_class;
        self.redaction = redaction;
        self
    }

    /// Returns `true` when audit evidence should be emitted.
    pub const fn requires_audit(self) -> bool {
        self.kind.is_audit_relevant() || self.flags & MESSAGE_FLAG_AUDIT_REQUIRED != 0
    }

    /// Validates header metadata.
    pub fn validate(self) -> ProtocolResult<()> {
        validate_schema_version(self.schema_version)?;
        if self.message_id == INVALID_PROTOCOL_ID {
            return Err(ProtocolError::InvalidMessage);
        }
        validate_label(self.source, MAX_MESSAGE_LABEL_LEN)?;
        validate_label(self.target, MAX_MESSAGE_LABEL_LEN)?;
        validate_label(self.operation, MAX_MESSAGE_LABEL_LEN)?;
        if self.flags & !MESSAGE_KNOWN_FLAGS != 0 {
            return Err(ProtocolError::ReservedBits);
        }
        self.trace.validate()?;
        validate_redaction(self.data_class, self.redaction)
    }
}

/// Complete protocol message envelope with fixed payload-reference capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageEnvelope<'a, const N: usize> {
    /// Message header.
    pub header: MessageHeader<'a>,
    payloads: [Option<PayloadRef<'a>>; N],
    payload_count: usize,
}

impl<'a, const N: usize> MessageEnvelope<'a, N> {
    /// Creates an empty message envelope.
    pub const fn new(header: MessageHeader<'a>) -> Self {
        Self {
            header,
            payloads: [None; N],
            payload_count: 0,
        }
    }

    /// Returns payload-reference count.
    pub const fn payload_count(self) -> usize {
        self.payload_count
    }

    /// Returns `true` when no payload references are present.
    pub const fn is_empty(self) -> bool {
        self.payload_count == 0
    }

    /// Adds a payload reference.
    pub fn add_payload(&mut self, payload: PayloadRef<'a>) -> ProtocolResult<()> {
        if self.payload_count >= N || self.payload_count >= MAX_PAYLOAD_REFS {
            return Err(ProtocolError::CapacityExceeded);
        }
        payload.validate()?;
        self.payloads[self.payload_count] = Some(payload);
        self.payload_count += 1;
        Ok(())
    }

    /// Returns a payload by index.
    pub fn payload(self, index: usize) -> Option<PayloadRef<'a>> {
        if index >= self.payload_count {
            None
        } else {
            self.payloads[index]
        }
    }

    /// Computes the declared payload byte length.
    pub fn payload_len(self) -> u64 {
        let mut total = 0u64;
        let mut index = 0;
        while index < self.payload_count {
            if let Some(payload) = self.payloads[index] {
                total = total.saturating_add(payload.len as u64);
            }
            index += 1;
        }
        total
    }

    /// Validates header and payload references.
    pub fn validate(self) -> ProtocolResult<()> {
        self.header.validate()?;
        if self.payload_count > N || self.payload_count > MAX_PAYLOAD_REFS {
            return Err(ProtocolError::InvalidMessage);
        }
        let mut has_shared = false;
        let mut index = 0;
        while index < self.payload_count {
            let Some(payload) = self.payloads[index] else {
                return Err(ProtocolError::Internal);
            };
            payload.validate()?;
            has_shared |= matches!(payload.storage, PayloadStorage::SharedMemory);
            index += 1;
        }
        if has_shared && self.header.flags & MESSAGE_FLAG_SHARED_MEMORY == 0 {
            return Err(ProtocolError::InvalidMessage);
        }
        Ok(())
    }
}

/// Module boundary descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageDescriptor<'a> {
    /// Human-readable descriptor name.
    pub name: &'a str,
    /// Descriptor version.
    pub version: u32,
}

impl<'a> MessageDescriptor<'a> {
    /// Creates a message descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
