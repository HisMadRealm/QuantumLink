# macOS Runtime Architecture

## Purpose

Define the runtime boundary for a macOS-first QuantumLink product so shared Rust logic can be reused while Linux-specific tunnel and firewall implementations are replaced with native macOS integrations.

## Design Goals

- preserve the existing shared Rust core for crypto, pairing, signaling, mesh state, and daemon workflows
- isolate platform-specific tunnel and leak-protection behavior behind narrow runtime facades
- allow the current Linux implementation to remain as a reference backend during the macOS pivot
- make Mode A self-hosted VPN exit the first release gate for macOS

## Runtime Split

### Shared Product Logic

The following crates remain the product core and should stay platform-neutral:

- `ql-core`
- `ql-crypto`
- `ql-pair`
- `ql-signal`
- `ql-relay`
- `ql-mesh`
- large portions of `ql-daemon`
- `ql-gui` as the UI state model and daemon-facing contract

### Platform Runtime Layer

The following responsibilities must be selected per target platform:

- tunnel creation and lifecycle
- endpoint updates and PSK injection
- DNS routing and resolver behavior
- leak protection and kill-switch behavior
- OS lifecycle handling such as sleep, wake, and network changes

For this pivot, the runtime layer is centered around two facades:

- `PlatformTunnel` in `ql-wireguard`
- `PlatformFirewall` in `ql-firewall`

`ql-daemon` should depend on these facades instead of directly assuming a Linux implementation.

## Current State

### Linux Reference Backend

The existing Linux backend remains valid as a reference implementation for:

- WireGuard interface management
- route installation
- DNS configuration
- nftables-based leak protection

It is useful for validating daemon orchestration and preserving a tested backend while the macOS path is built.

### macOS Product Backend

The macOS product backend must replace Linux assumptions with native platform behavior.

Required properties:

- app-controlled tunnel lifecycle suitable for a signed desktop product
- predictable DNS behavior under tunnel activation and teardown
- leak-protection semantics matching the product intent of the current firewall layer
- reliable reconnect behavior across sleep, wake, and network transitions

## Daemon Boundary

`ql-daemon` should remain the owner of connection intent and orchestration:

- build tunnel configuration from user config and runtime args
- decide whether kill switch or DNS-only protection is required
- start and stop Rosenpass
- emit state changes and algorithm status

The platform runtime layer should remain the owner of execution details:

- create and activate the tunnel
- apply or remove platform leak-protection state
- expose tunnel stats and endpoint updates

This keeps the product workflow stable while allowing the underlying platform implementation to change.

## Native macOS App Structure

Recommended macOS application shape:

- native app shell owns user interaction and packaging concerns
- shared Rust code owns domain logic and protocol behavior
- daemon or daemon-equivalent runtime owns session orchestration
- platform runtime adapter owns tunnel and leak-protection behavior

The first binding target is the existing shared GUI and daemon contract, not a rewrite of product state management.

## Implementation Sequence

1. Introduce explicit platform facades in `ql-wireguard` and `ql-firewall`.
2. Update `ql-daemon` to depend on those facades instead of Linux-specific type names.
3. Keep the Linux backend wired behind the new facades.
4. Add a macOS backend scaffold behind the same facades.
5. Bind the native macOS app to the shared GUI and daemon surfaces.
6. Validate Mode A end to end before expanding first-release scope.

## Current Scaffold Status

The repository now distinguishes three runtime states explicitly:

- `linux-reference`: current working reference backend
- `macos-scaffold`: target-specific placeholder for the future native macOS backend
- `stub`: generic non-product fallback for unsupported targets

This means the codebase no longer treats macOS as just another generic non-Linux platform. The next step is replacing the scaffold behavior with real macOS runtime execution.

The tunnel layer now has a typed macOS backend shape built around:

- a dedicated macOS backend type in `ql-wireguard`
- an explicit Network Extension driver assumption
- a prepared backend state for future lifecycle transitions
- a backend descriptor that higher layers can inspect without relying on target-specific type names

The firewall layer now matches that structure with:

- a dedicated macOS backend type in `ql-firewall`
- an explicit packet-filter driver assumption
- leak-protection mode modeling for full kill switch vs DNS-only protection
- a prepared backend state and anchor naming shape for future native execution
- a backend descriptor that mirrors the tunnel-side target-state reporting

Both runtime crates now expose bridge-request models that a native macOS app or extension layer can consume directly. This is the first explicit data contract between the shared Rust runtime and a future native macOS execution layer.

They also now expose executor interfaces, which means a native macOS host can move from passive request inspection to active execution without changing the higher-level daemon and runtime contracts.

The repository now also includes a dedicated adapter target, `ql-macos-runtime`, which is the first concrete library intended to sit between the shared Rust runtime and a future native macOS host or extension layer.

The repository now also includes a host-side shell target, `ql-macos-app`, which owns the shared GUI model and the macOS runtime adapter. This gives the macOS-first architecture a concrete application-side home for command queuing, daemon event projection, and host-operation planning.

The repository now also includes a dedicated helper executable target, `ql-macos-helper`, which defines the first concrete external-process contract consumed by `ql-macos-runtime`. Tunnel operations still retain a development stub path there, but the firewall side now has a real PF-backed execution mode that can enable PF, install per-interface anchors, query active rules, and tear them down cleanly.

The runtime adapter also now exposes an explicit `network-extension` execution mode for tunnel operations. That mode no longer treats the future native path as just another generic helper invocation: it requires a dedicated tunnel-controller executable, carries the full interface-address and WireGuard-key material needed for real Apple-side tunnel configuration, and keeps firewall execution on its own bridge.

The Swift sources under `macos/QuantumLinkMacApp` now include a separate `QuantumLinkTunnelController` target plus a `QuantumLinkPacketTunnelProvider` target. The provider retains a SwiftPM-safe scaffold path for local builds, but it also now contains a `WireGuardKit`-backed implementation path that can build a real tunnel configuration, update endpoints, inject PSKs, and read runtime stats when compiled through the Xcode product target with the package dependency available.

The Rust host shell now also treats tunnel and firewall maturity separately. In `network-extension` mode, tunnel connect, status, and disconnect can proceed through the dedicated tunnel controller even when no firewall bridge has been configured yet. That keeps the tunnel path testable without pretending kill-switch work is already done.

The repository now also includes an initial native host scaffold under `macos/QuantumLinkMacApp`. This SwiftUI shell launches `ql-macos-app serve` and calls into its localhost HTTP endpoints, which keeps the first native UI iteration aligned with the shared Rust host-shell contract instead of inventing a parallel application model.

That host scaffold now does more than fire demo actions. It polls the shared `/status` endpoint, consumes session state from either the development stub, the external helper path, or the new tunnel-controller path, allows a configurable Mode A endpoint for the connect path, and shows the resulting tunnel and firewall activity directly from the shared Rust boundary.

The host/runtime seam also now has a concrete local-service shape inside `ql-macos-app`. The Rust host shell exposes `/health`, `/status`, `/mode-a/connect`, and `/mode-a/disconnect` over loopback so the native app can hold a persistent runtime process instead of spawning a fresh CLI command for every UI action. That service now has macOS integration coverage for both the original stub path and a tunnel-only `network-extension` path driven by a mock native controller.

The repository now also contains a reproducible Xcode product path under `macos/QuantumLinkMacApp`. The generated `QuantumLinkMacApp.xcodeproj` includes:

- the signed macOS app target
- the Packet Tunnel Provider app extension target
- the tunnel-controller command-line target
- an external build target for `WireGuardGoBridgemacOS`
- the `WireGuardKit` package dependency

That gives the product path a concrete packaging shape compatible with the release-gate requirement that the macOS runtime be delivered as a signed native app plus extension, even though full `xcodebuild` validation still depends on a machine with full Xcode installed.

## First macOS Release Gate

The first macOS product milestone should be considered complete when:

- a user can connect and disconnect from a self-hosted QuantumLink server
- the active PQC stack is visible in product UI
- certificate and enrollment flows do not require CLI-only normal-case recovery
- tunnel teardown and failure paths leave the product in a recoverable state
- the runtime layer is packaged in a way compatible with signed macOS distribution

## Deferred Until After The Runtime Pivot

- broad cross-platform parity work
- shipping every mesh feature before Mode A is stable on macOS
- mobile runtime integration
- full v1.0 audit and formal-verification scope as a prerequisite for the first macOS deliverable
