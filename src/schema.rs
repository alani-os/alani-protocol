//! Shared metadata schema records.
//!
//! Doc 42 assigns `alani-protocol` ownership for device descriptors, corpus
//! metadata, and model metadata. Feature crates may refine implementation
//! details, but cross-repository contracts should flow through these stable
//! protocol schemas.

use crate::{
    validate_label, validate_redaction, validate_schema_version, DataClass, ProtocolError,
    ProtocolResult, RedactionState, TraceContext,
};

/// Schema registry version.
pub const SCHEMA_REGISTRY_VERSION: &str = "alani.schema_registry.v1";
/// Device descriptor schema version.
pub const DEVICE_DESCRIPTOR_SCHEMA_VERSION: &str = "alani.device.v1";
/// Corpus metadata schema version.
pub const CORPUS_METADATA_SCHEMA_VERSION: &str = "alani.corpus.v1";
/// Model metadata schema version.
pub const MODEL_METADATA_SCHEMA_VERSION: &str = "alani.model.v1";

/// Maximum metadata identifier length.
pub const MAX_METADATA_ID_LEN: usize = 96;
/// Maximum metadata label length.
pub const MAX_METADATA_LABEL_LEN: usize = 128;
/// Maximum artifact/source URI length.
pub const MAX_METADATA_URI_LEN: usize = 256;
/// Maximum corpus labels.
pub const MAX_CORPUS_LABELS: usize = 8;

/// Schema version record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaVersion<'a> {
    /// Schema kind.
    pub kind: SchemaKind,
    /// Version label.
    pub version: &'a str,
}

impl<'a> SchemaVersion<'a> {
    /// Creates a schema version record.
    pub const fn new(kind: SchemaKind, version: &'a str) -> Self {
        Self { kind, version }
    }

    /// Validates schema version metadata.
    pub fn validate(self) -> ProtocolResult<()> {
        validate_schema_version(self.version)
    }
}

/// Schema family owned by this crate.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaKind {
    /// Message envelope schema.
    Message = 1,
    /// IPC envelope schema.
    Ipc = 2,
    /// Audit event schema.
    AuditEvent = 3,
    /// Config payload schema.
    Config = 4,
    /// Device descriptor schema.
    DeviceDescriptor = 5,
    /// Corpus metadata schema.
    CorpusMetadata = 6,
    /// Model metadata schema.
    ModelMetadata = 7,
}

impl SchemaKind {
    /// Stable schema-kind label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Ipc => "ipc",
            Self::AuditEvent => "audit_event",
            Self::Config => "config",
            Self::DeviceDescriptor => "device_descriptor",
            Self::CorpusMetadata => "corpus_metadata",
            Self::ModelMetadata => "model_metadata",
        }
    }
}

/// Device class shared in protocol descriptors.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceClass {
    /// Generic device.
    Generic = 1,
    /// Block storage.
    Block = 2,
    /// Network adapter.
    Network = 3,
    /// Display or terminal I/O.
    Display = 4,
    /// Entropy source.
    Entropy = 5,
    /// Cognitive model/accelerator device.
    Cognitive = 6,
    /// Audit storage device.
    AuditStorage = 7,
}

impl DeviceClass {
    /// Stable class label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Block => "block",
            Self::Network => "network",
            Self::Display => "display",
            Self::Entropy => "entropy",
            Self::Cognitive => "cognitive",
            Self::AuditStorage => "audit_storage",
        }
    }

    /// Returns `true` when access is security/audit critical by default.
    pub const fn requires_audit(self) -> bool {
        matches!(
            self,
            Self::Cognitive | Self::AuditStorage | Self::Block | Self::Network
        )
    }
}

/// Device lifecycle state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceState {
    /// Device was discovered.
    Discovered = 1,
    /// Device was registered.
    Registered = 2,
    /// Device was configured.
    Configured = 3,
    /// Device is open.
    Open = 4,
    /// Device is suspended.
    Suspended = 5,
    /// Device was removed.
    Removed = 6,
    /// Device faulted.
    Faulted = 7,
}

impl DeviceState {
    /// Stable state label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::Registered => "registered",
            Self::Configured => "configured",
            Self::Open => "open",
            Self::Suspended => "suspended",
            Self::Removed => "removed",
            Self::Faulted => "faulted",
        }
    }
}

/// Protocol-owned device descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceDescriptor<'a> {
    /// Schema version.
    pub schema_version: &'a str,
    /// Stable device identifier.
    pub device_id: u64,
    /// Device name.
    pub name: &'a str,
    /// Device class.
    pub class: DeviceClass,
    /// Vendor/provider label.
    pub vendor: &'a str,
    /// Device state.
    pub state: DeviceState,
    /// Device capability bits as declared by the device crate.
    pub capability_bits: u64,
    /// Maximum payload bytes for direct calls.
    pub max_payload_len: u64,
    /// Data class.
    pub data_class: DataClass,
    /// Redaction state.
    pub redaction: RedactionState,
    /// Trace context for descriptor export.
    pub trace: TraceContext,
}

impl<'a> DeviceDescriptor<'a> {
    /// Creates a device descriptor.
    pub const fn new(device_id: u64, name: &'a str, class: DeviceClass) -> Self {
        Self {
            schema_version: DEVICE_DESCRIPTOR_SCHEMA_VERSION,
            device_id,
            name,
            class,
            vendor: "unknown",
            state: DeviceState::Registered,
            capability_bits: 0,
            max_payload_len: 0,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
            trace: TraceContext::EMPTY,
        }
    }

    /// Sets vendor.
    pub const fn with_vendor(mut self, vendor: &'a str) -> Self {
        self.vendor = vendor;
        self
    }

    /// Sets capability bits and max payload length.
    pub const fn with_capabilities(mut self, capability_bits: u64, max_payload_len: u64) -> Self {
        self.capability_bits = capability_bits;
        self.max_payload_len = max_payload_len;
        self
    }

    /// Sets trace context.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Returns `true` when descriptor access should be audited.
    pub const fn requires_audit(self) -> bool {
        self.class.requires_audit() || matches!(self.state, DeviceState::Faulted)
    }

    /// Validates descriptor metadata.
    pub fn validate(self) -> ProtocolResult<()> {
        validate_schema_version(self.schema_version)?;
        if self.device_id == 0 {
            return Err(ProtocolError::InvalidMetadata);
        }
        validate_label(self.name, MAX_METADATA_LABEL_LEN)?;
        validate_label(self.vendor, MAX_METADATA_LABEL_LEN)?;
        if matches!(self.state, DeviceState::Removed | DeviceState::Faulted) {
            return Err(ProtocolError::InvalidMetadata);
        }
        self.trace.validate()?;
        validate_redaction(self.data_class, self.redaction)
    }
}

/// Corpus split.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorpusSplit {
    /// Training split.
    Train = 1,
    /// Validation split.
    Validation = 2,
    /// Test split.
    Test = 3,
    /// Fixture or smoke-test split.
    Fixture = 4,
}

impl CorpusSplit {
    /// Stable split label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Train => "train",
            Self::Validation => "validation",
            Self::Test => "test",
            Self::Fixture => "fixture",
        }
    }
}

/// License review state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LicenseState {
    /// Approved for release-facing use.
    Approved = 1,
    /// Internal synthetic draft accepted for MVK fixtures.
    InternalDraft = 2,
    /// Review is required before release.
    NeedsReview = 3,
    /// Restricted and requires policy gating.
    Restricted = 4,
    /// Prohibited and must fail closed.
    Prohibited = 5,
}

impl LicenseState {
    /// Stable label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::InternalDraft => "internal_draft",
            Self::NeedsReview => "needs_review",
            Self::Restricted => "restricted",
            Self::Prohibited => "prohibited",
        }
    }

    /// Returns `true` when data may be used in MVK fixtures.
    pub const fn allows_mvk(self) -> bool {
        matches!(self, Self::Approved | Self::InternalDraft)
    }
}

/// Corpus metadata shared across corpus/model/release boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorpusMetadata<'a> {
    /// Schema version.
    pub schema_version: &'a str,
    /// Stable record or corpus identifier.
    pub record_id: &'a str,
    /// Corpus split.
    pub split: CorpusSplit,
    /// Task label.
    pub task: &'a str,
    /// Source/provenance label.
    pub source: &'a str,
    /// License review state.
    pub license: LicenseState,
    /// Data class.
    pub data_class: DataClass,
    /// Redaction state.
    pub redaction: RedactionState,
    labels: [Option<&'a str>; MAX_CORPUS_LABELS],
    label_count: usize,
}

impl<'a> CorpusMetadata<'a> {
    /// Creates corpus metadata.
    pub const fn new(
        record_id: &'a str,
        split: CorpusSplit,
        task: &'a str,
        source: &'a str,
    ) -> Self {
        Self {
            schema_version: CORPUS_METADATA_SCHEMA_VERSION,
            record_id,
            split,
            task,
            source,
            license: LicenseState::InternalDraft,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
            labels: [None; MAX_CORPUS_LABELS],
            label_count: 0,
        }
    }

    /// Sets license state.
    pub const fn with_license(mut self, license: LicenseState) -> Self {
        self.license = license;
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

    /// Adds a label.
    pub fn add_label(&mut self, label: &'a str) -> ProtocolResult<()> {
        if self.label_count >= MAX_CORPUS_LABELS {
            return Err(ProtocolError::CapacityExceeded);
        }
        validate_label(label, MAX_METADATA_LABEL_LEN)?;
        self.labels[self.label_count] = Some(label);
        self.label_count += 1;
        Ok(())
    }

    /// Returns label count.
    pub const fn label_count(self) -> usize {
        self.label_count
    }

    /// Returns a label by index.
    pub fn label(self, index: usize) -> Option<&'a str> {
        if index >= self.label_count {
            None
        } else {
            self.labels[index]
        }
    }

    /// Validates corpus metadata.
    pub fn validate(self) -> ProtocolResult<()> {
        validate_schema_version(self.schema_version)?;
        validate_label(self.record_id, MAX_METADATA_ID_LEN)?;
        validate_label(self.task, MAX_METADATA_LABEL_LEN)?;
        validate_label(self.source, MAX_METADATA_URI_LEN)?;
        if !self.license.allows_mvk() {
            return Err(ProtocolError::InvalidMetadata);
        }
        let mut index = 0;
        while index < self.label_count {
            let Some(label) = self.labels[index] else {
                return Err(ProtocolError::Internal);
            };
            validate_label(label, MAX_METADATA_LABEL_LEN)?;
            index += 1;
        }
        validate_redaction(self.data_class, self.redaction)
    }
}

/// Model artifact format.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelFormat {
    /// Deterministic host-mode fixture.
    Mock = 1,
    /// SafeTensors artifact.
    SafeTensors = 2,
    /// GGUF artifact.
    Gguf = 3,
    /// ONNX artifact.
    Onnx = 4,
    /// TorchScript artifact.
    TorchScript = 5,
    /// Custom model pack.
    Custom = 6,
}

impl ModelFormat {
    /// Stable format label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::SafeTensors => "safetensors",
            Self::Gguf => "gguf",
            Self::Onnx => "onnx",
            Self::TorchScript => "torchscript",
            Self::Custom => "custom",
        }
    }
}

/// Model metadata shared across cognition, model-pack, and release boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelMetadata<'a> {
    /// Schema version.
    pub schema_version: &'a str,
    /// Stable model identifier.
    pub model_id: &'a str,
    /// Human-readable model family.
    pub family: &'a str,
    /// Model version or revision.
    pub revision: &'a str,
    /// Artifact format.
    pub format: ModelFormat,
    /// Artifact URI or content reference.
    pub artifact_ref: &'a str,
    /// Capability bits declared by model crate.
    pub capability_bits: u64,
    /// License state.
    pub license: LicenseState,
    /// Data class.
    pub data_class: DataClass,
    /// Redaction state.
    pub redaction: RedactionState,
    /// Trace context for model metadata export.
    pub trace: TraceContext,
}

impl<'a> ModelMetadata<'a> {
    /// Creates model metadata.
    pub const fn new(
        model_id: &'a str,
        family: &'a str,
        revision: &'a str,
        format: ModelFormat,
        artifact_ref: &'a str,
    ) -> Self {
        Self {
            schema_version: MODEL_METADATA_SCHEMA_VERSION,
            model_id,
            family,
            revision,
            format,
            artifact_ref,
            capability_bits: 0,
            license: LicenseState::InternalDraft,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
            trace: TraceContext::EMPTY,
        }
    }

    /// Sets capability bits.
    pub const fn with_capabilities(mut self, capability_bits: u64) -> Self {
        self.capability_bits = capability_bits;
        self
    }

    /// Sets license state.
    pub const fn with_license(mut self, license: LicenseState) -> Self {
        self.license = license;
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

    /// Validates model metadata.
    pub fn validate(self) -> ProtocolResult<()> {
        validate_schema_version(self.schema_version)?;
        validate_label(self.model_id, MAX_METADATA_ID_LEN)?;
        validate_label(self.family, MAX_METADATA_LABEL_LEN)?;
        validate_label(self.revision, MAX_METADATA_LABEL_LEN)?;
        validate_label(self.artifact_ref, MAX_METADATA_URI_LEN)?;
        if !self.license.allows_mvk() {
            return Err(ProtocolError::InvalidMetadata);
        }
        self.trace.validate()?;
        validate_redaction(self.data_class, self.redaction)
    }
}

/// Shared metadata record enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataRecord<'a> {
    /// Device descriptor metadata.
    Device(DeviceDescriptor<'a>),
    /// Corpus metadata.
    Corpus(CorpusMetadata<'a>),
    /// Model metadata.
    Model(ModelMetadata<'a>),
}

impl<'a> MetadataRecord<'a> {
    /// Returns schema kind.
    pub const fn kind(self) -> SchemaKind {
        match self {
            Self::Device(_) => SchemaKind::DeviceDescriptor,
            Self::Corpus(_) => SchemaKind::CorpusMetadata,
            Self::Model(_) => SchemaKind::ModelMetadata,
        }
    }

    /// Returns stable identifier.
    pub const fn id(self) -> &'a str {
        match self {
            Self::Device(device) => device.name,
            Self::Corpus(corpus) => corpus.record_id,
            Self::Model(model) => model.model_id,
        }
    }

    /// Validates record metadata.
    pub fn validate(self) -> ProtocolResult<()> {
        match self {
            Self::Device(device) => device.validate(),
            Self::Corpus(corpus) => corpus.validate(),
            Self::Model(model) => model.validate(),
        }
    }
}

/// Fixed-capacity schema registry for host-mode protocol tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaRegistry<'a, const N: usize> {
    records: [Option<MetadataRecord<'a>>; N],
    len: usize,
}

impl<'a, const N: usize> SchemaRegistry<'a, N> {
    /// Creates an empty schema registry.
    pub const fn new() -> Self {
        Self {
            records: [None; N],
            len: 0,
        }
    }

    /// Returns number of records.
    pub const fn len(self) -> usize {
        self.len
    }

    /// Returns `true` when no records are registered.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Adds a record.
    pub fn add(&mut self, record: MetadataRecord<'a>) -> ProtocolResult<()> {
        if self.len >= N {
            return Err(ProtocolError::CapacityExceeded);
        }
        record.validate()?;
        if self.find(record.kind(), record.id()).is_some() {
            return Err(ProtocolError::InvalidMetadata);
        }
        self.records[self.len] = Some(record);
        self.len += 1;
        Ok(())
    }

    /// Finds a metadata record by kind and id.
    pub fn find(self, kind: SchemaKind, id: &str) -> Option<MetadataRecord<'a>> {
        let mut index = 0;
        while index < self.len {
            if let Some(record) = self.records[index] {
                if record.kind() == kind && record.id().as_bytes() == id.as_bytes() {
                    return Some(record);
                }
            }
            index += 1;
        }
        None
    }
}

impl<'a, const N: usize> Default for SchemaRegistry<'a, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Module boundary descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaDescriptor<'a> {
    /// Human-readable descriptor name.
    pub name: &'a str,
    /// Descriptor version.
    pub version: u32,
}

impl<'a> SchemaDescriptor<'a> {
    /// Creates a schema descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
