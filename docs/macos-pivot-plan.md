# macOS-First Pivot Plan

## Objective

Pivot QuantumLink from a broad cross-platform roadmap to a macOS-first product release while preserving the shared Rust core and self-hosted trust model.

## Product Decision

- First productized release target: macOS desktop only
- Primary release mode: Mode A self-hosted VPN exit
- Secondary scope: keep mesh and high-level pairing under active development, but treat them as follow-on capabilities unless they reach release quality within the macOS effort
- Deferred from the first release: Windows, Linux desktop productization, Android, iOS, and other platform-specific frontends

## What Stays

- `ql-core` shared configuration, IPC, and identity models
- `ql-crypto` hybrid PQC implementation
- `ql-pair` pairing and enrollment bundle logic
- `ql-signal` signaling and mailbox transport
- `ql-relay` dumb relay implementation
- `ql-mesh` peer and path-selection logic
- `ql-daemon` workflow and orchestration logic where it remains platform-neutral
- `ql-gui` shared view-model concepts as the source of truth for frontend state

## What Changes

- `ql-wireguard` needs a macOS backend instead of relying on the current Linux-only runtime implementation
- `ql-firewall` needs a macOS leak-protection and kill-switch strategy instead of nftables
- the current GUI model needs a real native macOS frontend rather than a platform-neutral state crate alone
- release engineering shifts from general workspace validation to notarized, signed macOS app distribution

## Release Scope

### Phase 1: macOS Core MVP

- Native macOS app shell
- Connect and disconnect to a self-hosted QuantumLink server
- Certificate initialization, enrollment, and renewal workflows surfaced in product UI
- PQC status and transparency panel
- Basic pairing UX only where required to complete server enrollment
- Signed builds for local testing and internal distribution

### Phase 2: macOS Product Beta

- Full high-level pairing UX
- Mesh dashboard backed by live daemon state
- Relay policy presentation and path indicators
- Improved onboarding and VPS/operator flows
- Hardened logging, diagnostics, and update path

### Phase 3: macOS Release Candidate

- Production-grade app packaging and notarization
- Leak-protection hardening and failure-path handling
- End-to-end QA of connect, reconnect, sleep/wake, and renewal paths
- Documentation and support runbooks for self-hosting users

## Workstreams

### 1. Platform Runtime

- design the macOS tunnel backend boundary expected by `ql-daemon`
- implement a macOS-specific tunnel controller compatible with the app packaging model
- define a macOS leak-protection strategy and translate existing firewall intent into that model
- validate sleep, wake, network changes, and reconnect behavior

### 2. Native Frontend

- create the native macOS app shell
- bind the shared `ql-gui` state model and daemon IPC into the UI
- implement onboarding, connection card, PQC transparency panel, and pairing flows
- add diagnostics export and operator-facing error handling

### 3. Product Scope Control

- make Mode A the release gate
- keep mesh behind a quality threshold instead of letting it block the first ship decision
- defer LAN discovery and other platform expansion items until after the first macOS release unless they become necessary for onboarding

### 4. Release Engineering

- produce signed macOS artifacts
- add packaging, notarization, and distribution automation
- document install, permissions, self-hosted server setup, and rollback procedures

## Immediate Implementation Order

1. Define the macOS runtime abstraction boundary for tunnel management and leak protection.
2. Build the native macOS app shell and bind it to existing shared GUI and daemon models.
3. Deliver a complete Mode A connect or disconnect flow on macOS.
4. Surface certificate lifecycle and high-level pairing in the macOS UI.
5. Harden packaging, signing, and recovery paths.
6. Re-evaluate mesh for inclusion in the first public macOS beta.

## Exit Criteria For The First macOS Release

- A user can install the app on macOS, connect to their self-hosted server, and reconnect reliably.
- The app exposes the active PQC stack and key-rotation state clearly.
- Certificate and enrollment workflows work without CLI-only recovery steps for standard cases.
- Failure cases leave the user with a clear state and recoverable next action.
- Distribution artifacts are signed and suitable for real user installation.

## Non-Goals For The Pivot

- simultaneous Windows and Linux desktop parity
- mobile clients
- shipping every mesh feature before the first macOS release
- full v1.0 audit and formal-verification scope as a prerequisite for the first macOS product milestone