# alani-protocol

Shared wire and data schemas for IPC envelopes, audit events, device descriptors, config records, corpus metadata, and model metadata.

| Field | Value |
|---|---|
| Tier | MVK required |
| Owner | Interface owners |
| Aliases | None |
| Architectural dependencies | `alani-abi` |

## Quick start

```bash
cargo fmt -- --check
cargo test --all-features
cargo test --no-default-features
cargo clippy --all-features -- -D warnings
```

## Public API Surface

- `message`: transport message headers, payload references, schema versions, trace context, and redaction-aware envelopes.
- `ipc`: IPC endpoint, flow, route-hint, and message-envelope schemas.
- `audit`: audit event and record-header schemas for append-only evidence contracts.
- `config`: config document, domain, scalar value, and entry schemas.
- `schema`: discoverable protocol schema catalog, shared device descriptor, corpus metadata, model metadata, and schema-registry records.

The crate remains dependency-free while sibling repositories stabilize. Keep public API changes synchronized with `docs/repositories/alani-protocol.md`, Doc 42, and Doc 43.
