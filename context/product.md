# QuantumLink for macOS — Product Specification

**Version:** 0.3.0-draft
**Status:** Active implementation context
**License:** Apache 2.0 (planned)
**Primary target:** macOS 14+
**Delivery goal:** a fully implemented and tested macOS-only, zero-vendor-infrastructure PQC VPN

---

## 1. Product Direction

QuantumLink for macOS is a native SwiftUI desktop VPN client with a Rust runtime core that delivers post-quantum protected connectivity without any QuantumLink-operated infrastructure.

The product is serverless in the vendor sense:
- QuantumLink operates no control plane, no relay network, no hosted accounts, and no telemetry service.
- Users either connect to their own self-hosted server node for VPN exit mode or pair directly with their own devices later through user-selected infrastructure.
- The company behind QuantumLink must not be in a position to inspect, terminate, or correlate user traffic.

For this context, the product scope is intentionally narrowed:
- macOS only
- native SwiftUI frontend
- real macOS runtime integration
- production-quality testing and validation
- Mode A first: self-hosted VPN exit
- Mode B interfaces may exist, but direct-mesh shipping is deferred until after the macOS VPN path is real and tested

---

## 2. What Done Means

QuantumLink is not considered done when the repository has all planned crates. It is done for this context only when a macOS user can install the app, point it at their own server, connect through a real tunnel, and recover cleanly from errors.

The minimum finished outcome is:
- a native macOS app launches successfully
- the app can connect to a self-hosted QuantumLink server through a real macOS tunnel path
- post-quantum primitives and Rosenpass-managed PSK rotation are used by the shared runtime
- kill switch and DNS leak protection are enforced through real macOS mechanisms, not placeholders
- connection state, PQC state, and failure state are surfaced in the app UI
- the entire flow is covered by automated tests plus one documented end-to-end validation path

Anything less is still scaffolding.

---

## 3. Scope

### In Scope

- macOS desktop client only
- SwiftUI application shell
- Rust shared runtime and product logic
- macOS runtime adapter and helper boundary
- self-hosted VPN exit mode using the user's own server
- hybrid PQC key exchange and authentication surfaces already defined by the project
- Rosenpass sidecar integration
- real tunnel lifecycle management on macOS
- real firewall and leak-protection behavior on macOS
- local IPC between SwiftUI host and Rust runtime
- reproducible developer test workflow for macOS

### Explicitly Out of Scope For This Context

- Linux GTK frontend work
- Windows, iOS, Android, or Flutter work
- broad v1.0 roadmap completion
- community relay ecosystem
- enterprise features
- hosted service features of any kind
- shipping direct mesh mode before the macOS VPN exit path is real

---

## 4. Architecture

The current product architecture is split into four layers:

1. SwiftUI host
   - native macOS application
   - owns presentation, controls, and app lifecycle
   - never owns security-critical VPN logic directly

2. Rust host shell
   - translates app intent into runtime operations
   - exposes local commands and local IPC endpoints for the native host
   - projects status, operations, and PQC state back to the app

3. macOS runtime boundary
   - narrow platform-specific contract for tunnel and firewall operations
   - supports stub mode for development and real mode for actual system integration
   - owns execution through helpers, extensions, or system services as needed

4. Shared core
   - cryptography
   - pairing and identity models
   - signal and relay services for self-hosted infrastructure
   - daemon and GUI-facing state models

The repository already contains this split. The remaining work is to replace the last macOS placeholder seams with real implementations and validate them thoroughly.

---

## 5. Operating Mode

### Mode A — Self-Hosted VPN Exit

This is the shipping mode for the macOS product in this context.

User story:
- the user operates their own QuantumLink server on a VPS or home machine
- the macOS app connects to that server
- traffic exits through that user-controlled node
- QuantumLink as a vendor is not in the path

Functional requirements:
- one-click connect and disconnect from the app
- persistent tunnel lifecycle across app actions
- kill switch that blocks unsafe traffic on tunnel failure
- DNS leak protection and clear resolver behavior
- visible PQC status in the UI
- clear disconnected, connecting, connected, and error states

### Mode B — Direct Peer Connectivity

Mode B is deferred as a shipping deliverable for this context.

The codebase may keep forward-compatible types and internal models for mesh features, but implementation effort should not outrank the work required to finish Mode A on macOS.

---

## 6. Cryptographic Requirements

The product keeps the project-wide cryptographic direction:
- transport: unmodified WireGuard
- key exchange: X25519 + ML-KEM-768 hybrid
- authentication: Ed25519 + ML-DSA-65 hybrid
- additional PQ forward secrecy: Rosenpass-managed PSK rotation

Requirements:
- no reimplementation of Rosenpass protocol internals
- no modification of WireGuard protocol semantics
- all sensitive key material must be zeroized where practical in Rust
- secret-bearing values must never be logged
- runtime state exposed to the app must contain diagnostics, not secrets

---

## 7. macOS Product Requirements

### 7.1 App Experience

The macOS app must provide:
- connect and disconnect controls
- current server endpoint display
- session status summary
- tunnel and firewall status visibility
- PQC transparency panel
- recent operation or diagnostic output suitable for troubleshooting

The UI should feel like a real product shell, not a developer harness.

### 7.2 Runtime Integration

The product must move from helper-backed simulation to real system behavior.

Acceptable real integrations include:
- Network Extension based tunnel lifecycle management
- a signed helper or extension path for privileged operations
- packet-filter or equivalent macOS firewall control required for kill switch behavior

Unacceptable end state:
- a purely simulated helper
- a fake tunnel marked as connected in UI
- placeholder firewall status with no real leak protection

### 7.3 IPC

The local interface between the SwiftUI app and the Rust shell must be stable and testable.

Current direction:
- persistent localhost service mode exposed by the Rust host shell
- SwiftUI client talks to that service rather than spawning a new process per action

This IPC layer must support:
- health checks
- status retrieval
- connect and disconnect actions
- structured error reporting

---

## 8. Serverless Infrastructure Model

QuantumLink must continue to follow a zero-vendor-infrastructure trust model.

That means:
- no QuantumLink-operated coordination servers
- no QuantumLink-operated relays
- no accounts
- no telemetry

For Mode A, user-controlled infrastructure may still exist:
- self-hosted `qls`
- self-hosted signal service where needed
- self-hosted relay capability for future mesh work

This is compatible with a serverless vendor model because the infrastructure is owned and selected by the user, not by QuantumLink.

---

## 9. Testing Standard

This context requires real testing, not only compilation.

### Required Automated Coverage

- Rust unit tests for shared core logic
- Rust tests for macOS app-shell status and operation projection
- HTTP or IPC contract tests for the local service layer
- helper contract tests where helper execution still exists
- Swift build validation for the native app

### Required System Validation

At least one documented macOS validation path must exercise:
- app or runtime startup
- connect
- status transition to connected
- kill-switch or leak-protection enablement
- disconnect
- cleanup back to a safe disconnected state

### Quality Bar

The product context should prefer:
- fixing root causes
- validating changes immediately
- narrowing platform-specific seams
- preserving testability across the Rust and Swift boundary

---

## 10. Release Gate

The first macOS release gate for this context is met only when all of the following are true:
- the app is macOS-native and launches cleanly
- a real tunnel can be established to a self-hosted server
- tunnel teardown is reliable
- DNS and kill-switch behavior are enforceable through real macOS integrations
- session and PQC state are visible in the UI
- automated tests cover the shell and IPC paths
- manual validation instructions exist for the real runtime path

If the tunnel or leak-protection path is still simulated, the release gate is not met.

---

## 11. Implementation Priorities

Work should be prioritized in this order:
1. Replace macOS tunnel placeholder behavior with real execution.
2. Replace macOS firewall placeholder behavior with real execution.
3. Keep the SwiftUI host and Rust IPC path stable while the runtime becomes real.
4. Strengthen automated tests around the app-shell and service contract.
5. Validate the full connect or disconnect path against a real or realistically provisioned macOS environment.
6. Only then expand into broader mesh or future-platform work.

---

## 12. Non-Goals For This Context Rewrite

This document does not ask for a full multi-platform roadmap rewrite. It intentionally narrows the mission so the repository can converge on a real macOS product instead of a broad but unfinished architecture.

The right question is no longer "how do we scaffold everything?"

The right question is:

"What must be implemented and tested so QuantumLink becomes a real macOS-only zero-vendor-infrastructure PQC VPN?"
