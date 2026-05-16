use alani_protocol::schema::{CorpusSplit, LicenseState};
use alani_protocol::{
    protocol_catalog, protocol_schemas, schema_descriptor, validate_protocol_schemas,
    AuditDecision, AuditEvent, AuditEventKind, AuditRecordHeader, AuditStatus, ComponentStatus,
    ConfigDocument, ConfigDomain, ConfigEntry, ConfigFormat, ConfigValue, CorpusMetadata,
    DataClass, DeviceClass, DeviceDescriptor, EndpointKind, IpcEndpoint, IpcEnvelope, IpcFlow,
    IpcRouteHint, MessageEnvelope, MessageHeader, MessageKind, MetadataRecord, ModelFormat,
    ModelMetadata, PayloadRef, ProtocolError, ProtocolWireFormat, RedactionState, SchemaKind,
    SchemaRegistry, SchemaVersion, TraceContext, AUDIT_EVENT_SCHEMA_VERSION,
    MESSAGE_FLAG_SHARED_MEMORY, MESSAGE_SCHEMA_VERSION, PROTOCOL_SCHEMA_COUNT, TRACE_FLAG_REMOTE,
    TRACE_FLAG_SAMPLED,
};

#[test]
fn repository_identity_and_catalog_are_stable() {
    let info = alani_protocol::component_info();
    assert_eq!(alani_protocol::repository_name(), "alani-protocol");
    assert_eq!(info.repository, "alani-protocol");
    assert_eq!(info.status, ComponentStatus::Experimental);
    assert_eq!(
        alani_protocol::module_names(),
        &["message", "ipc", "audit", "config", "schema"]
    );
    assert_eq!(protocol_catalog().validate(), Ok(()));
    assert!(protocol_catalog().features & alani_protocol::PROTOCOL_FEATURE_MESSAGES != 0);
}

#[test]
fn trace_context_rejects_reserved_flags_and_bad_parent_spans() {
    let trace = TraceContext::root(10, 11).with_flags(TRACE_FLAG_SAMPLED | TRACE_FLAG_REMOTE);
    assert!(trace.is_present());
    assert!(trace.has_flags(TRACE_FLAG_REMOTE));
    assert_eq!(trace.validate(), Ok(()));

    let child = trace.child(12);
    assert_eq!(child.parent_span_id, 11);
    assert_eq!(child.validate(), Ok(()));

    let reserved = TraceContext::new(1, 2).with_flags(1 << 31);
    assert_eq!(reserved.validate(), Err(ProtocolError::ReservedBits));

    let self_parent = TraceContext::new(1, 2).with_parent(2);
    assert_eq!(self_parent.validate(), Err(ProtocolError::InvalidTrace));
}

#[test]
fn schema_catalog_advertises_formats_and_rejects_version_drift() {
    assert_eq!(protocol_schemas().len(), PROTOCOL_SCHEMA_COUNT);
    assert_eq!(validate_protocol_schemas(), Ok(()));

    let message_version = SchemaVersion::current(SchemaKind::Message);
    assert_eq!(message_version.version, MESSAGE_SCHEMA_VERSION);
    assert_eq!(message_version.validate(), Ok(()));

    let drifted = SchemaVersion::new(SchemaKind::Message, AUDIT_EVENT_SCHEMA_VERSION);
    assert_eq!(drifted.validate(), Err(ProtocolError::InvalidSchemaVersion));

    let audit = schema_descriptor(SchemaKind::AuditEvent).unwrap();
    assert_eq!(audit.format, ProtocolWireFormat::JsonLines);
    assert!(audit.format.is_text());
    assert!(audit.format.is_record_stream());

    let config = schema_descriptor(SchemaKind::Config).unwrap();
    assert_eq!(config.format, ProtocolWireFormat::Toml);
    assert!(config.validate().is_ok());
}

#[test]
fn message_envelope_validates_shared_memory_flags_and_redaction() {
    let header = MessageHeader::new(
        1,
        "runtime:init",
        "agent:alpha",
        "infer.request",
        MessageKind::Request,
    )
    .with_trace(TraceContext::new(10, 11))
    .with_flags(MESSAGE_FLAG_SHARED_MEMORY);
    let mut envelope = MessageEnvelope::<4>::new(header);
    envelope
        .add_payload(PayloadRef::shared("prompt", "shm:7", 128))
        .unwrap();
    assert_eq!(envelope.validate(), Ok(()));
    assert_eq!(envelope.payload_len(), 128);

    let missing_flag_header = MessageHeader::new(
        2,
        "runtime:init",
        "agent:alpha",
        "infer.request",
        MessageKind::Request,
    );
    let mut missing_flag = MessageEnvelope::<4>::new(missing_flag_header);
    missing_flag
        .add_payload(PayloadRef::shared("prompt", "shm:8", 64))
        .unwrap();
    assert_eq!(missing_flag.validate(), Err(ProtocolError::InvalidMessage));

    let bad_redaction = PayloadRef::inline("secret", 0, 16)
        .with_redaction(DataClass::Secret, RedactionState::Operational);
    assert_eq!(
        bad_redaction.validate(),
        Err(ProtocolError::InvalidRedaction)
    );
}

#[test]
fn ipc_envelope_validates_endpoint_flow_and_response_correlation() {
    let source = IpcEndpoint::new(1, EndpointKind::Runtime, "runtime:init", "runtime");
    let target = IpcEndpoint::new(2, EndpointKind::Agent, "agent:alpha", "runtime");
    let flow = IpcFlow::new(source, target, "runtime_to_agent");
    let header = MessageHeader::new(
        3,
        "runtime:init",
        "agent:alpha",
        "agent.request",
        MessageKind::Request,
    );
    let envelope = MessageEnvelope::<2>::new(header);
    let ipc = IpcEnvelope::new(flow, envelope).with_route(IpcRouteHint::new(5, "agent_route", 4));
    assert_eq!(ipc.validate(), Ok(()));

    let mismatch_header = MessageHeader::new(
        4,
        "runtime:init",
        "agent:other",
        "agent.request",
        MessageKind::Request,
    );
    let mismatch = IpcEnvelope::new(flow, MessageEnvelope::<2>::new(mismatch_header));
    assert_eq!(mismatch.validate(), Err(ProtocolError::InvalidIpc));

    let response_header = MessageHeader::new(
        5,
        "runtime:init",
        "agent:alpha",
        "agent.response",
        MessageKind::Response,
    );
    let bad_response = IpcEnvelope::new(flow, MessageEnvelope::<2>::new(response_header));
    assert_eq!(bad_response.validate(), Err(ProtocolError::InvalidMessage));
}

#[test]
fn audit_events_require_time_redaction_and_consistent_denials() {
    let event = AuditEvent::security_denial(6, 1, "agent:alpha", "device.open", "device:camera")
        .with_time(100, 1)
        .with_component("kernel.syscall")
        .with_trace(TraceContext::new(99, 100));
    assert_eq!(event.validate(), Ok(()));
    assert!(event.is_audit_critical());

    let missing_time = AuditEvent::new(
        7,
        2,
        AuditEventKind::PolicyDecision,
        "agent:alpha",
        "policy.check",
        "policy:active",
    );
    assert_eq!(missing_time.validate(), Err(ProtocolError::MissingField));

    let inconsistent = AuditEvent::new(
        8,
        3,
        AuditEventKind::PolicyDecision,
        "agent:alpha",
        "policy.check",
        "policy:active",
    )
    .with_time(101, 2)
    .with_outcome(AuditDecision::Deny, AuditStatus::Succeeded);
    assert_eq!(inconsistent.validate(), Err(ProtocolError::InvalidAudit));

    let mut hash = [0u8; 32];
    hash[0] = 1;
    let header = AuditRecordHeader::new(1, 0, [0u8; 32], hash);
    assert_eq!(header.validate(), Ok(()));
}

#[test]
fn config_documents_reject_duplicate_keys_and_bad_secret_redaction() {
    let mut document = ConfigDocument::<4>::new("mvk-host", ConfigFormat::Toml)
        .with_trace(TraceContext::new(1, 2));
    document
        .add_entry(ConfigEntry::new(
            ConfigDomain::Runtime,
            "init",
            ConfigValue::String("/svc/runtime"),
        ))
        .unwrap();
    assert_eq!(document.validate(), Ok(()));
    assert!(document.contains(ConfigDomain::Runtime, "init"));

    let duplicate = document.add_entry(ConfigEntry::new(
        ConfigDomain::Runtime,
        "init",
        ConfigValue::String("/svc/other"),
    ));
    assert_eq!(duplicate, Err(ProtocolError::InvalidConfig));

    let secret = ConfigEntry::new(
        ConfigDomain::Security,
        "token",
        ConfigValue::String("do-not-log"),
    )
    .with_redaction(DataClass::Secret, RedactionState::Operational);
    assert_eq!(secret.validate(), Err(ProtocolError::InvalidRedaction));
}

#[test]
fn schema_registry_tracks_device_corpus_and_model_metadata() {
    let device = DeviceDescriptor::new(1, "mock-accelerator", DeviceClass::Cognitive)
        .with_vendor("alani-mock")
        .with_capabilities(0b101, 4096)
        .with_trace(TraceContext::new(7, 8));
    assert_eq!(device.validate(), Ok(()));

    let mut corpus =
        CorpusMetadata::new("rec-0001", CorpusSplit::Fixture, "policy_case", "synthetic")
            .with_license(LicenseState::InternalDraft);
    corpus.add_label("policy").unwrap();
    corpus.add_label("allow").unwrap();
    assert_eq!(corpus.validate(), Ok(()));

    let model = ModelMetadata::new(
        "mock-default",
        "mock",
        "v0",
        ModelFormat::Mock,
        "artifact:mock-default",
    )
    .with_capabilities(0b1)
    .with_trace(TraceContext::new(9, 10));
    assert_eq!(model.validate(), Ok(()));

    let mut registry = SchemaRegistry::<4>::new();
    registry.add(MetadataRecord::Device(device)).unwrap();
    registry.add(MetadataRecord::Corpus(corpus)).unwrap();
    registry.add(MetadataRecord::Model(model)).unwrap();
    assert_eq!(registry.len(), 3);
    assert!(registry
        .find(SchemaKind::ModelMetadata, "mock-default")
        .is_some());

    let prohibited = ModelMetadata::new(
        "blocked",
        "mock",
        "v0",
        ModelFormat::Mock,
        "artifact:blocked",
    )
    .with_license(LicenseState::Prohibited);
    assert_eq!(prohibited.validate(), Err(ProtocolError::InvalidMetadata));
}
