# QuantumLink

QuantumLink is an open-source post-quantum VPN and mesh networking system built around two operating modes:

- Mode A: self-hosted VPN exit through the user's own VPS or home server
- Mode B: direct peer-to-peer mesh connectivity with relay fallback

The project is designed around a zero-vendor-infrastructure model. QuantumLink does not depend on a vendor-operated control plane. The intended trust model is that users operate their own server node and own their own keys.

Current product direction: QuantumLink is pivoting to a macOS-first release strategy. The repository retains cross-platform and Linux-oriented components where they are useful for shared logic, backend prototyping, and future portability, but the first productized release target is a native macOS desktop client and self-hosted server workflow.

## Goals

- Hybrid post-quantum security using X25519 + ML-KEM-768 and Ed25519 + ML-DSA-65
- Rosenpass-managed PQ pre-shared key rotation on top of unmodified WireGuard
- macOS-first desktop product with a native frontend and platform integration
- Reuse of shared Rust core, crypto, pairing, signaling, and mesh logic across future platforms
- Forward-compatible interfaces for mesh, pairing, relay, and GUI features planned for later milestones

## Current Status

This repository is under active scaffold and implementation from the project specification in [product.md](product.md).

Implemented so far:

- Workspace scaffold and crate layout
- Shared core config and IPC types in `ql-core`
- Hybrid PQC primitives in `ql-crypto`
- Linux-gated WireGuard management surface in `ql-wireguard` as a reference backend
- Rosenpass sidecar supervision in `ql-rosenpass`
- Linux nftables firewall management surface in `ql-firewall` as a reference backend
- v0.1 STUN API stubs in `ql-stun`
- In-memory signaling service in `ql-signal`
- Blind relay, pairing, mesh, daemon and server orchestration crates
- Certificate lifecycle, enrollment bundles, and high-level pairing workflows
- Platform-neutral GUI state model for a future native frontend

Still in progress:

- Native macOS runtime integration for tunnel management and leak protection
- Native macOS frontend implementation and packaging
- STUN, LAN discovery, and additional mesh hardening for a polished desktop release
- VPS deployment and operator workflow refinement
- Release hardening, signing, and reproducible-distribution work for the macOS product

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

Linux reference runtime components additionally require platform tools such as:

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

Progress updates are logged in [changelog.md](changelog.md).

## Roadmap Snapshot

- Productize a native macOS client around the existing shared Rust crates
- Implement macOS tunnel and system-network integration layers
- Build the first native frontend on top of the current GUI state and daemon IPC model
- Refine Mode A first-release workflows, with mesh capability following behind the same product shell
- Expand release engineering to signed, distributable macOS artifacts

## License

Planned license: Apache-2.0, aligned with the project specification.
