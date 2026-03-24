# QuantumLink

QuantumLink is an open-source post-quantum VPN and mesh networking system built around two operating modes:

- Mode A: self-hosted VPN exit through the user's own VPS or home server
- Mode B: direct peer-to-peer mesh connectivity with relay fallback

The project is designed around a zero-vendor-infrastructure model. QuantumLink does not depend on a vendor-operated control plane. The intended trust model is that users operate their own server node and own their own keys.

## Goals

- Hybrid post-quantum security using X25519 + ML-KEM-768 and Ed25519 + ML-DSA-65
- Rosenpass-managed PQ pre-shared key rotation on top of unmodified WireGuard
- Linux-first daemon and service implementation for the v0.1 milestone
- Forward-compatible interfaces for mesh, pairing, relay, and GUI features planned for later milestones

## Current Status

This repository is under active scaffold and implementation from the project specification in [product.md](/Users/rickglenn/Desktop/QuantumLink%20PQC%20VPN/quantumlink/product.md).

Implemented so far:

- Workspace scaffold and crate layout
- Shared core config and IPC types in `ql-core`
- Hybrid PQC primitives in `ql-crypto`
- Linux-gated WireGuard management surface in `ql-wireguard`
- Rosenpass sidecar supervision in `ql-rosenpass`
- Linux nftables firewall management surface in `ql-firewall`
- v0.1 STUN API stubs in `ql-stun`
- In-memory signaling service in `ql-signal`

Still in progress:

- Relay service
- Pairing protocol
- Mesh manager
- Client daemon
- Server daemon
- GUI
- Key management
- Full CI and release automation
- Project documentation completion

## Workspace Layout

```text
quantumlink/
├── Cargo.toml
├── Cargo.lock
├── README.md
├── changelog.md
├── product.md
├── deny.toml
├── .github/workflows/
├── crates/
│   ├── ql-core/
│   ├── ql-crypto/
│   ├── ql-wireguard/
│   ├── ql-rosenpass/
│   ├── ql-firewall/
│   ├── ql-stun/
│   ├── ql-signal/
│   ├── ql-relay/
│   ├── ql-mesh/
│   ├── ql-pair/
│   ├── ql-daemon/
│   ├── ql-server/
│   └── ql-gui/
└── docs/
```

## Build Requirements

Current local development requirements observed during scaffold work:

- Rust toolchain compatible with the workspace `rust-version`
- `cmake` for vendored `liboqs` builds used by `oqs`
- A Unix-like shell environment

Linux-only runtime components will additionally require platform tools such as:

- `ip`
- `wg`
- `nft`
- optionally `resolvectl`
- `rosenpass`

## Build and Test

From the repository root:

```sh
cargo build --workspace
cargo test --workspace
```

Targeted examples used during implementation:

```sh
cargo test -p ql-core
cargo test -p ql-crypto
cargo test -p ql-wireguard
cargo test -p ql-rosenpass
cargo test -p ql-firewall
cargo test -p ql-stun
cargo test -p ql-signal
```

## Security Notes

- WireGuard remains unmodified
- Rosenpass is integrated as a sidecar, not reimplemented
- Secret-bearing key material in implemented crypto paths is zeroized
- Linux-specific tunnel and firewall operations are explicitly gated and return `NotImplemented` on unsupported targets in v0.1-facing crates

## Repository Tracking

Progress updates are logged in [changelog.md](/Users/rickglenn/Desktop/QuantumLink%20PQC%20VPN/quantumlink/changelog.md).

## Roadmap Snapshot

- Finish relay, pairing, and mesh crate surfaces
- Implement `qld` client orchestration
- Implement `qls` server orchestration
- Complete Linux GUI integration
- Fill out architecture, threat model, cryptography, and pairing documentation
- Expand CI to match the full project checklist

## License

Planned license: Apache-2.0, aligned with the project specification.
