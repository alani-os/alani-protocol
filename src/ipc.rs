//! IPC endpoint, route, and envelope schemas.
//!
//! `alani-protocol` owns the wire-facing IPC metadata while `alani-ipc` owns
//! concrete queues, routing tables, shared-memory grants, and enforcement.

use crate::message::{MessageEnvelope, MessageKind};
use crate::{validate_label, ProtocolError, ProtocolResult, MAX_PROTOCOL_LABEL_LEN};

/// Maximum endpoint label length.
pub const MAX_ENDPOINT_LABEL_LEN: usize = 96;

/// IPC schema version.
pub const IPC_SCHEMA_VERSION: &str = "alani.ipc.v1";

/// Endpoint may send messages.
pub const IPC_ENDPOINT_FLAG_SEND: u32 = 1 << 0;
/// Endpoint may receive messages.
pub const IPC_ENDPOINT_FLAG_RECEIVE: u32 = 1 << 1;
/// Endpoint may be routed through a broker.
pub const IPC_ENDPOINT_FLAG_ROUTABLE: u32 = 1 << 2;
/// Endpoint is audit critical.
pub const IPC_ENDPOINT_FLAG_AUDIT: u32 = 1 << 3;

/// All endpoint flags known by this crate version.
pub const IPC_ENDPOINT_KNOWN_FLAGS: u32 = IPC_ENDPOINT_FLAG_SEND
    | IPC_ENDPOINT_FLAG_RECEIVE
    | IPC_ENDPOINT_FLAG_ROUTABLE
    | IPC_ENDPOINT_FLAG_AUDIT;

/// IPC endpoint kind.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointKind {
    /// Kernel endpoint.
    Kernel = 1,
    /// Runtime service endpoint.
    Runtime = 2,
    /// Agent endpoint.
    Agent = 3,
    /// Device endpoint.
    Device = 4,
    /// Audit service endpoint.
    Audit = 5,
    /// Observability service endpoint.
    Observability = 6,
    /// Terminal/user endpoint.
    Terminal = 7,
    /// External adapter endpoint.
    External = 8,
}

impl EndpointKind {
    /// Stable kind label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Runtime => "runtime",
            Self::Agent => "agent",
            Self::Device => "device",
            Self::Audit => "audit",
            Self::Observability => "observability",
            Self::Terminal => "terminal",
            Self::External => "external",
        }
    }

    /// Returns `true` when endpoint traffic is security sensitive by default.
    pub const fn is_audit_relevant(self) -> bool {
        matches!(self, Self::Kernel | Self::Device | Self::Audit)
    }
}

/// Stable IPC endpoint descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcEndpoint<'a> {
    /// Endpoint identifier. Zero is invalid.
    pub endpoint_id: u64,
    /// Endpoint kind.
    pub kind: EndpointKind,
    /// Stable endpoint label.
    pub label: &'a str,
    /// Owning component label.
    pub component: &'a str,
    /// Endpoint flags.
    pub flags: u32,
}

impl<'a> IpcEndpoint<'a> {
    /// Creates an IPC endpoint.
    pub const fn new(
        endpoint_id: u64,
        kind: EndpointKind,
        label: &'a str,
        component: &'a str,
    ) -> Self {
        Self {
            endpoint_id,
            kind,
            label,
            component,
            flags: IPC_ENDPOINT_FLAG_SEND | IPC_ENDPOINT_FLAG_RECEIVE,
        }
    }

    /// Sets endpoint flags.
    pub const fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Returns `true` when endpoint can send.
    pub const fn can_send(self) -> bool {
        self.flags & IPC_ENDPOINT_FLAG_SEND != 0
    }

    /// Returns `true` when endpoint can receive.
    pub const fn can_receive(self) -> bool {
        self.flags & IPC_ENDPOINT_FLAG_RECEIVE != 0
    }

    /// Returns `true` when endpoint traffic should be audited.
    pub const fn requires_audit(self) -> bool {
        self.kind.is_audit_relevant() || self.flags & IPC_ENDPOINT_FLAG_AUDIT != 0
    }

    /// Validates endpoint metadata.
    pub fn validate(self) -> ProtocolResult<()> {
        if self.endpoint_id == 0 {
            return Err(ProtocolError::InvalidIpc);
        }
        validate_label(self.label, MAX_ENDPOINT_LABEL_LEN)?;
        validate_label(self.component, MAX_PROTOCOL_LABEL_LEN)?;
        if self.flags & !IPC_ENDPOINT_KNOWN_FLAGS != 0 {
            return Err(ProtocolError::ReservedBits);
        }
        if !self.can_send() && !self.can_receive() {
            return Err(ProtocolError::InvalidIpc);
        }
        Ok(())
    }
}

/// IPC delivery status.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcStatus {
    /// Envelope is pending delivery.
    Pending = 1,
    /// Envelope was delivered.
    Delivered = 2,
    /// Envelope was denied by policy or capability gates.
    Denied = 3,
    /// Envelope expired before delivery.
    Expired = 4,
    /// Delivery failed.
    Failed = 5,
}

impl IpcStatus {
    /// Stable status label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Failed => "failed",
        }
    }

    /// Returns `true` when status should be audited.
    pub const fn requires_audit(self) -> bool {
        matches!(self, Self::Denied | Self::Failed)
    }
}

/// IPC flow metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcFlow<'a> {
    /// Source endpoint.
    pub source: IpcEndpoint<'a>,
    /// Target endpoint.
    pub target: IpcEndpoint<'a>,
    /// Flow label.
    pub flow_label: &'a str,
    /// Deadline in monotonic nanoseconds. Zero means no deadline.
    pub deadline_ns: u64,
    /// Delivery status.
    pub status: IpcStatus,
}

impl<'a> IpcFlow<'a> {
    /// Creates an IPC flow.
    pub const fn new(
        source: IpcEndpoint<'a>,
        target: IpcEndpoint<'a>,
        flow_label: &'a str,
    ) -> Self {
        Self {
            source,
            target,
            flow_label,
            deadline_ns: 0,
            status: IpcStatus::Pending,
        }
    }

    /// Sets deadline.
    pub const fn with_deadline(mut self, deadline_ns: u64) -> Self {
        self.deadline_ns = deadline_ns;
        self
    }

    /// Sets status.
    pub const fn with_status(mut self, status: IpcStatus) -> Self {
        self.status = status;
        self
    }

    /// Returns `true` when the flow is expired at `now_ns`.
    pub const fn is_expired(self, now_ns: u64) -> bool {
        self.deadline_ns != 0 && now_ns > self.deadline_ns
    }

    /// Returns `true` when the flow should emit audit evidence.
    pub const fn requires_audit(self) -> bool {
        self.source.requires_audit() || self.target.requires_audit() || self.status.requires_audit()
    }

    /// Validates flow metadata.
    pub fn validate(self) -> ProtocolResult<()> {
        self.source.validate()?;
        self.target.validate()?;
        validate_label(self.flow_label, MAX_ENDPOINT_LABEL_LEN)?;
        if !self.source.can_send() || !self.target.can_receive() {
            return Err(ProtocolError::AccessDenied);
        }
        Ok(())
    }
}

/// Route hint carried in a protocol envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcRouteHint<'a> {
    /// Route identifier. Zero means unassigned.
    pub route_id: u64,
    /// Route label.
    pub route_label: &'a str,
    /// Optional broker or router endpoint.
    pub broker: &'a str,
    /// Hop count already traversed.
    pub hop_count: u8,
    /// Maximum hops allowed.
    pub max_hops: u8,
}

impl<'a> IpcRouteHint<'a> {
    /// Empty route hint.
    pub const EMPTY: Self = Self {
        route_id: 0,
        route_label: "",
        broker: "",
        hop_count: 0,
        max_hops: 0,
    };

    /// Creates a route hint.
    pub const fn new(route_id: u64, route_label: &'a str, max_hops: u8) -> Self {
        Self {
            route_id,
            route_label,
            broker: "",
            hop_count: 0,
            max_hops,
        }
    }

    /// Sets broker label.
    pub const fn with_broker(mut self, broker: &'a str) -> Self {
        self.broker = broker;
        self
    }

    /// Returns `true` when no route hint is present.
    pub const fn is_empty(self) -> bool {
        self.route_id == 0 && self.max_hops == 0
    }

    /// Validates route metadata.
    pub fn validate(self) -> ProtocolResult<()> {
        if self.is_empty() {
            return Ok(());
        }
        if self.route_id == 0 || self.max_hops == 0 || self.hop_count > self.max_hops {
            return Err(ProtocolError::InvalidIpc);
        }
        validate_label(self.route_label, MAX_ENDPOINT_LABEL_LEN)?;
        if !self.broker.is_empty() {
            validate_label(self.broker, MAX_ENDPOINT_LABEL_LEN)?;
        }
        Ok(())
    }
}

/// IPC protocol envelope over a message envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcEnvelope<'a, const N: usize> {
    /// IPC flow metadata.
    pub flow: IpcFlow<'a>,
    /// Route hint.
    pub route: IpcRouteHint<'a>,
    /// Message envelope.
    pub message: MessageEnvelope<'a, N>,
}

impl<'a, const N: usize> IpcEnvelope<'a, N> {
    /// Creates an IPC envelope.
    pub const fn new(flow: IpcFlow<'a>, message: MessageEnvelope<'a, N>) -> Self {
        Self {
            flow,
            route: IpcRouteHint::EMPTY,
            message,
        }
    }

    /// Sets route hint.
    pub const fn with_route(mut self, route: IpcRouteHint<'a>) -> Self {
        self.route = route;
        self
    }

    /// Returns `true` when audit evidence should be emitted.
    pub const fn requires_audit(self) -> bool {
        self.flow.requires_audit() || self.message.header.requires_audit()
    }

    /// Validates envelope metadata.
    pub fn validate(self) -> ProtocolResult<()> {
        self.flow.validate()?;
        self.route.validate()?;
        self.message.validate()?;
        if self.message.header.source.as_bytes() != self.flow.source.label.as_bytes()
            || self.message.header.target.as_bytes() != self.flow.target.label.as_bytes()
        {
            return Err(ProtocolError::InvalidIpc);
        }
        if matches!(self.message.header.kind, MessageKind::Response)
            && self.message.header.correlation_id == 0
        {
            return Err(ProtocolError::InvalidMessage);
        }
        Ok(())
    }
}

/// Module boundary descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpcDescriptor<'a> {
    /// Human-readable descriptor name.
    pub name: &'a str,
    /// Descriptor version.
    pub version: u32,
}

impl<'a> IpcDescriptor<'a> {
    /// Creates an IPC descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
