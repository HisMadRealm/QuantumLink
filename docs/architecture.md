# Architecture

QuantumLink is organized as a Rust workspace with small crates that separate cryptography, transport integration, mesh control, and user-facing orchestration.

## Current crate roles

- `ql-core`: shared config, IPC contracts, tunnel state, relay policy, certificate metadata, revocation model, and common errors
- `ql-crypto`: hybrid X25519 + ML-KEM-768 key exchange and Ed25519 + ML-DSA-65 authentication
- `ql-wireguard`: WireGuard interface lifecycle, peer configuration, PSK injection, and tunnel stats
- `ql-rosenpass`: supervised Rosenpass sidecar management and key generation
- `ql-firewall`: nftables-based kill-switch and DNS-protection control surface for Linux
- `ql-stun`: forward-compatible NAT traversal API surface reserved for later mesh transport work
- `ql-signal`: in-memory HTTP signaling service for peer registration and mailbox flows, plus a lightweight client used by daemon pairing commands
- `ql-relay`: blind UDP relay that forwards encrypted datagrams without decryption
- `ql-pair`: pairing primitives plus signed certificate and enrollment-bundle handoff types for post-authentication trust distribution
- `ql-mesh`: peer lifecycle and path-selection manager for direct and relayed mesh connectivity, including certificate-to-peer projection
- `ql-daemon`: client orchestration binary that composes config, tunnel planning, Rosenpass, and firewall behavior
- `ql-server`: server orchestration binary that composes `ql-signal` and `ql-relay`
- `ql-gui`: platform-neutral GUI view model for a future GTK4 frontend

## Runtime topology

### Client side

The `qld` daemon is the control point for Mode A and Mode B behavior. It loads shared config from `ql-core`, builds a connection plan, and then coordinates:

- WireGuard tunnel creation via `ql-wireguard`
- Rosenpass process supervision via `ql-rosenpass`
- Linux firewall state via `ql-firewall`
- Mesh status and relay policy selection via `ql-mesh`
- Pairing UX and command dispatch for GUI consumers via `ql-pair` and `ql-gui`

### Server side

The `qls` daemon composes:

- `ql-signal` for peer registration and pairing mailbox traffic
- `ql-relay` for dumb encrypted UDP forwarding when direct mesh paths are unavailable

This keeps the server blind to mesh payload contents while still providing a self-hosted fallback path.

## Platform model

The current implementation keeps v0.1 runtime behavior Linux-first while still compiling on macOS:

- Linux-specific WireGuard and firewall logic is implemented behind target gates
- Non-Linux targets return explicit `NotImplemented` errors where runtime platform support is intentionally deferred
- GUI logic is currently modeled as shared state instead of binding to GTK4 directly in this workspace

## Current boundaries

The workspace now covers the core control-plane and crypto-plane responsibilities. What remains is the final polish layer:

- richer key-generation and certificate issuance workflow integration
- fully realized GTK4 frontend
- release packaging and documentation refinement beyond the baseline workflows and docs added here

The certificate workflow is now deeper than metadata only: `qld` can issue, verify, revoke, export, import, send, receive, initiate, and accept enrollment bundles over the pairing mailbox path. The shared GUI model and IPC surface now understand that pairing workflow, but a polished platform frontend still needs to bind those controls and states to real desktop UI.
