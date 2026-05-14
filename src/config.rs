//! Configuration payload schemas.
//!
//! `alani-config` owns loading and typed accessors. This module defines the
//! shared protocol representation for configuration documents and scalar
//! entries crossing repository boundaries.

use crate::{
    validate_label, validate_redaction, validate_schema_version, DataClass, ProtocolError,
    ProtocolResult, RedactionState, TraceContext, MAX_PROTOCOL_LABEL_LEN,
};

/// Config schema version.
pub const CONFIG_SCHEMA_VERSION: &str = "alani.config.v1";

/// Maximum config key length.
pub const MAX_CONFIG_KEY_LEN: usize = 96;

/// Maximum config scalar string length.
pub const MAX_CONFIG_VALUE_LEN: usize = 256;

/// Maximum entries in a host-mode config document skeleton.
pub const MAX_CONFIG_ENTRIES: usize = 64;

/// Config document domain.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigDomain {
    /// Bootloader and kernel handoff settings.
    Boot = 1,
    /// Device discovery and device policy settings.
    Devices = 2,
    /// Userspace runtime settings.
    Runtime = 3,
    /// Security and trust settings.
    Security = 4,
    /// Policy bundle and policy-engine settings.
    Policy = 5,
    /// Corpus and dataset settings.
    Corpus = 6,
    /// Release and evidence settings.
    Release = 7,
    /// Environment profile settings.
    Environment = 8,
}

impl ConfigDomain {
    /// Stable domain label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::Devices => "devices",
            Self::Runtime => "runtime",
            Self::Security => "security",
            Self::Policy => "policy",
            Self::Corpus => "corpus",
            Self::Release => "release",
            Self::Environment => "environment",
        }
    }

    /// Returns `true` when changes in this domain should be audited.
    pub const fn is_audit_relevant(self) -> bool {
        matches!(
            self,
            Self::Boot
                | Self::Devices
                | Self::Runtime
                | Self::Security
                | Self::Policy
                | Self::Release
        )
    }
}

/// Config serialization format.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigFormat {
    /// TOML config document.
    Toml = 1,
    /// JSON config document.
    Json = 2,
    /// Binary ABI-facing config payload.
    Binary = 3,
}

impl ConfigFormat {
    /// Stable format label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Toml => "toml",
            Self::Json => "json",
            Self::Binary => "binary",
        }
    }
}

/// Config scalar kind.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigValueKind {
    /// UTF-8 string scalar.
    String = 1,
    /// Unsigned integer scalar.
    Integer = 2,
    /// Boolean scalar.
    Boolean = 3,
}

impl ConfigValueKind {
    /// Stable kind label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
        }
    }
}

/// Borrowed config scalar value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigValue<'a> {
    /// Empty placeholder.
    Empty,
    /// String scalar.
    String(&'a str),
    /// Integer scalar.
    Integer(u64),
    /// Boolean scalar.
    Boolean(bool),
}

impl<'a> ConfigValue<'a> {
    /// Returns value kind.
    pub const fn kind(self) -> Option<ConfigValueKind> {
        match self {
            Self::Empty => None,
            Self::String(_) => Some(ConfigValueKind::String),
            Self::Integer(_) => Some(ConfigValueKind::Integer),
            Self::Boolean(_) => Some(ConfigValueKind::Boolean),
        }
    }

    /// Validates scalar metadata.
    pub fn validate(self) -> ProtocolResult<()> {
        match self {
            Self::Empty => Err(ProtocolError::InvalidConfig),
            Self::String(value) => {
                validate_label(value, MAX_CONFIG_VALUE_LEN)?;
                Ok(())
            }
            Self::Integer(_) | Self::Boolean(_) => Ok(()),
        }
    }
}

/// One config entry in a protocol document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigEntry<'a> {
    /// Config domain.
    pub domain: ConfigDomain,
    /// Key within domain.
    pub key: &'a str,
    /// Scalar value.
    pub value: ConfigValue<'a>,
    /// Data class.
    pub data_class: DataClass,
    /// Redaction state.
    pub redaction: RedactionState,
    /// Source line when known.
    pub source_line: u32,
}

impl<'a> ConfigEntry<'a> {
    /// Creates a config entry.
    pub const fn new(domain: ConfigDomain, key: &'a str, value: ConfigValue<'a>) -> Self {
        Self {
            domain,
            key,
            value,
            data_class: DataClass::Operational,
            redaction: RedactionState::Operational,
            source_line: 0,
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

    /// Sets source line.
    pub const fn with_source_line(mut self, source_line: u32) -> Self {
        self.source_line = source_line;
        self
    }

    /// Returns `true` when entry should be audited.
    pub const fn requires_audit(self) -> bool {
        self.domain.is_audit_relevant()
    }

    /// Validates entry metadata.
    pub fn validate(self) -> ProtocolResult<()> {
        validate_label(self.key, MAX_CONFIG_KEY_LEN)?;
        self.value.validate()?;
        validate_redaction(self.data_class, self.redaction)
    }
}

/// Fixed-capacity config document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigDocument<'a, const N: usize> {
    /// Schema version.
    pub schema_version: &'a str,
    /// Profile label.
    pub profile: &'a str,
    /// Document format.
    pub format: ConfigFormat,
    /// Trace context for loading or export.
    pub trace: TraceContext,
    entries: [Option<ConfigEntry<'a>>; N],
    len: usize,
}

impl<'a, const N: usize> ConfigDocument<'a, N> {
    /// Creates an empty config document.
    pub const fn new(profile: &'a str, format: ConfigFormat) -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            profile,
            format,
            trace: TraceContext::EMPTY,
            entries: [None; N],
            len: 0,
        }
    }

    /// Sets trace context.
    pub const fn with_trace(mut self, trace: TraceContext) -> Self {
        self.trace = trace;
        self
    }

    /// Returns entry count.
    pub const fn len(self) -> usize {
        self.len
    }

    /// Returns `true` when document is empty.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Adds an entry.
    pub fn add_entry(&mut self, entry: ConfigEntry<'a>) -> ProtocolResult<()> {
        if self.len >= N || self.len >= MAX_CONFIG_ENTRIES {
            return Err(ProtocolError::CapacityExceeded);
        }
        entry.validate()?;
        if self.contains(entry.domain, entry.key) {
            return Err(ProtocolError::InvalidConfig);
        }
        self.entries[self.len] = Some(entry);
        self.len += 1;
        Ok(())
    }

    /// Returns an entry by index.
    pub fn entry(self, index: usize) -> Option<ConfigEntry<'a>> {
        if index >= self.len {
            None
        } else {
            self.entries[index]
        }
    }

    /// Finds an entry.
    pub fn find(self, domain: ConfigDomain, key: &str) -> Option<ConfigEntry<'a>> {
        let mut index = 0;
        while index < self.len {
            if let Some(entry) = self.entries[index] {
                if entry.domain == domain && entry.key.as_bytes() == key.as_bytes() {
                    return Some(entry);
                }
            }
            index += 1;
        }
        None
    }

    /// Returns `true` when a domain/key exists.
    pub fn contains(self, domain: ConfigDomain, key: &str) -> bool {
        self.find(domain, key).is_some()
    }

    /// Validates document metadata.
    pub fn validate(self) -> ProtocolResult<()> {
        validate_schema_version(self.schema_version)?;
        validate_label(self.profile, MAX_PROTOCOL_LABEL_LEN)?;
        self.trace.validate()?;
        if self.len > N || self.len > MAX_CONFIG_ENTRIES {
            return Err(ProtocolError::InvalidConfig);
        }
        let mut index = 0;
        while index < self.len {
            let Some(entry) = self.entries[index] else {
                return Err(ProtocolError::Internal);
            };
            entry.validate()?;
            index += 1;
        }
        Ok(())
    }
}

/// Module boundary descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigDescriptor<'a> {
    /// Human-readable descriptor name.
    pub name: &'a str,
    /// Descriptor version.
    pub version: u32,
}

impl<'a> ConfigDescriptor<'a> {
    /// Creates a config descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
