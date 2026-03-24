# Changelog

## 2026-03-24

### Entry 1
What we did:
- Scaffolded the QuantumLink Cargo workspace and crate layout from the product specification.
- Added the initial root files: workspace manifest, deny configuration, CI/release workflow placeholders, docs placeholders, and copied `product.md` into the monorepo.
- Added skeleton library or binary targets for all listed crates so the workspace could compile.
- Verified the Step 1 smoke path by wiring `ql-crypto` to `oqs` and passing the `ML-KEM-768` smoke test.

Where we are:
- The workspace structure is established and builds successfully.
- The project has a reproducible starting point for deeper implementation work.

What we are doing next:
- Continue replacing crate placeholders with spec-driven implementations in dependency order.
- Keep validating each step with targeted `cargo test` and workspace builds before moving on.

### Entry 2
What we did:
- Implemented `ql-core` shared types and configuration schema.
- Added TOML-deserializable client config structures for server, crypto, network, split-tunnel, and mesh settings.
- Added stable IPC command and event enums, tunnel and connection state enums, relay policy definitions, and the unified `QuantumLinkError` type.
- Added tests for config parsing and error cloning behavior.

Where we are:
- Shared API contracts now exist for the rest of the workspace.
- Downstream crates can build against stable config and IPC definitions.

What we are doing next:
- Continue implementing the security-critical crates against these shared types.
- Preserve API stability for later daemon and GUI integration.

### Entry 3
What we did:
- Implemented `ql-crypto` with hybrid X25519 + ML-KEM-768 key exchange.
- Implemented hybrid Ed25519 + ML-DSA-65 signing and verification.
- Added HKDF-SHA3-256 shared secret derivation and zeroizing secret-bearing key types.
- Added tests for KEM roundtrip, tamper rejection, signature roundtrip, signature rejection, zeroization, serde roundtrip, and an `ML-KEM-768` KAT path.
- Resolved local build issues around vendored `liboqs`, including `cmake` installation and test-time helper compilation for the KAT flow.

Where we are:
- The highest-priority cryptographic crate is implemented and passing its required tests.
- The monorepo now has a real PQC core instead of placeholder logic.

What we are doing next:
- Build out the surrounding networking and process-management crates that depend on this crypto layer.
- Keep Linux-only functionality behind explicit target gates while preserving macOS workspace builds.

### Entry 4
What we did:
- Implemented `ql-wireguard` with a Linux-targeted backend and non-Linux stubs.
- Added tunnel configuration, stats reporting, peer endpoint update support, PSK injection support, route installation, and DNS configuration handling.
- Used `wireguard-uapi` for interface and peer control and retained portable stubs for non-Linux targets.
- Added tests for key material zeroization in tunnel configuration.

Where we are:
- The WireGuard management surface exists and compiles cleanly in the current workspace.
- Linux implementation hooks are defined while non-Linux targets remain explicitly unsupported in v0.1.

What we are doing next:
- Continue wiring the sidecar and network-protection layers around the tunnel lifecycle.
- Prepare the daemon-facing infrastructure needed for connection orchestration.

### Entry 5
What we did:
- Implemented `ql-rosenpass` as a supervised sidecar manager.
- Added async start and stop handling, restart backoff supervision, command-line construction for `rosenpass exchange`, and key generation via `rosenpass gen-keys`.
- Implemented PSK age tracking from observed process output.
- Added tests for Rosenpass command argument construction.

Where we are:
- The Rosenpass integration layer is present and compile-tested.
- The process-management model for PQ PSK rotation is defined for later daemon integration.

What we are doing next:
- Continue with surrounding system controls so the daemon can safely bring tunnels up and down.
- Fill in the remaining server-side and mesh-adjacent crates in sequence.

### Entry 6
What we did:
- Implemented `ql-firewall` with Linux nftables ruleset generation and non-Linux stubs.
- Added kill switch rules, DNS-only protection rules, idempotent cleanup behavior, and active-state checks.
- Scoped all firewall rules under the dedicated `quantumlink` nftables table.
- Added tests for constructor behavior and Linux ruleset generation shape.

Where we are:
- The network protection layer exists as a crate-level API and compiles cleanly.
- The daemon now has a concrete firewall manager interface to build against later.

What we are doing next:
- Keep expanding the v0.1 surface area with required stubs and coordination services.
- Preserve clean cross-platform builds while implementing Linux behavior where the spec requires it.

### Entry 7
What we did:
- Implemented `ql-stun` API definitions with v0.1 `NotImplemented` behavior.
- Added `StunConfig`, `NatType`, `StunResult`, and async method stubs for probing and port mapping.
- Added a basic unit test to validate the result structure shape.

Where we are:
- The NAT traversal API is now stable for later mesh work.
- The crate compiles without prematurely implementing v0.2 functionality.

What we are doing next:
- Continue implementing server-side coordination and relay components.
- Keep mesh-facing interfaces stable so the daemon can depend on them early.

### Entry 8
What we did:
- Implemented `ql-signal` as an in-memory async signaling service using `axum` and `tokio`.
- Added peer registration, peer listing, mailbox creation, mailbox send/receive/delete, health endpoint, optional metrics endpoint, mailbox TTL handling, and mailbox rate limiting.
- Added tests for default configuration and peer snapshot generation.

Where we are:
- The signaling service crate now exists as a working HTTP coordination layer.
- Crate-level validation has passed through Step 8 implementations.

What we are doing next:
- Re-run a full workspace build after the latest service-crate additions.
- Continue into the next implementation steps, starting with the relay path and then pairing and mesh-related crates.