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

## 2026-03-25

### Entry 1
What we did:
- Implemented `ql-relay` as a blind UDP relay with control-plane session registration, unchanged packet forwarding between registered peers, idle-session pruning, runtime stats, and crate tests that verify the relay forwards opaque ciphertext without interpreting it.
- Implemented `ql-pair` with QR pairing URI encode/decode support, wormhole-style human-readable pairing codes, single-use setup key helpers, emoji verification derived from the pairing secret, and a real symmetric `SPAKE2` wrapper for mailbox-based pairing.
- Implemented `ql-mesh` as the peer lifecycle and path-selection manager with relay-policy enforcement, direct-versus-relayed path selection, automatic direct-path upgrade behavior, live dashboard snapshots, and mesh state tests.
- Re-ran `cargo build --workspace` after these additions and confirmed the workspace still compiles cleanly.

Where we are:
- Relay, pairing, and mesh state-management crates now exist as real implementations instead of placeholders.
- The project is ready to move from mesh primitives into daemon and server orchestration.

What we are doing next:
- Implement `ql-daemon` and `ql-server` to orchestrate the crates that are now in place.
- Then fill in the remaining user-facing and lifecycle pieces: GUI scaffolding, key-management flows, and the CI/documentation checklist.

### Entry 2
What we did:
- Implemented `qld` in `ql-daemon` as a real orchestration binary with config loading, structured connection planning, CLI parsing for plan/status/connect flows, tunnel and Rosenpass lifecycle management, and JSON status output built on the shared `ql-core` IPC types.
- Implemented `qls` in `ql-server` as a composed server daemon that starts `ql-signal` and `ql-relay` together, exposes structured runtime status, and supports plan/run modes for self-hosted deployment flows.
- Added binary-level tests for `qld` and `qls` and revalidated the full workspace build after the new orchestration layer landed.
- Fixed a shutdown race in `ql-signal` and `ql-relay` by making stop-path signaling bounded and abort-safe so composed server shutdown cannot hang indefinitely.

Where we are:
- The daemon and server orchestration layer now exists, so the core v0.1 service topology is no longer placeholder-only.
- The remaining major gaps are the GUI surface, key-management flow completion, and the final CI/documentation pass.

What we are doing next:
- Implement the `ql-gui` scaffold against the daemon status and command surfaces now present in the workspace.
- Then fill in key-management support and finish the remaining release-engineering and documentation checklist items from the original prompt.

### Entry 3
What we did:
- Implemented `ql-gui` as a platform-neutral GUI state model with daemon command queueing, tray status projection, PQC transparency panel state, and mesh dashboard projection for a future GTK4 frontend.
- Added shared key-management and certificate lifecycle models to `ql-core`, covering CA metadata, device certificates, revocation lists, local key-storage layout, and device-activity checks against revocation state.
- Replaced CI and release workflow placeholders with workspace-level build and test automation and binary packaging steps for tagged releases.
- Replaced the top-level architecture, threat model, cryptography, and pairing protocol placeholders with real project documentation based on the implemented workspace.
- Re-ran `cargo test --workspace` and confirmed the full workspace test suite passes cleanly on the current machine.

Where we are:
- The workspace now has real implementations for the major core crates, daemon and server orchestration, GUI-facing state projection, shared identity models, and baseline automation/docs.
- The remaining gaps are deeper certificate issuance workflows, fuller platform-native GUI implementations, and higher-assurance release hardening beyond the baseline workflows now in place.

What we are doing next:
- Push the current repository state if publication is desired.
- Continue from baseline scaffolding into deeper certificate issuance, audit, and platform-specific UX work rather than placeholder replacement.

### Entry 4
What we did:
- Extended `ql-crypto` with offline CA signing-key persistence helpers so hybrid Ed25519 plus ML-DSA-65 CA material can be exported, reloaded, and reused for later certificate operations.
- Expanded `qld` with an `identity` command family covering offline CA initialization, certificate issuance, certificate verification, certificate renewal, and revocation-list updates, along with local JSON storage and audit-log persistence under the QuantumLink key layout.
- Added daemon-level lifecycle tests that exercise CA creation, certificate issuance, verification, and revocation end to end against the persisted identity state.
- Re-ran `cargo test --workspace` and confirmed the full workspace test suite still passes after the identity workflow additions.

Where we are:
- QuantumLink now has a working offline certificate lifecycle path instead of only shared certificate metadata types.
- The remaining gaps are integrating these identity artifacts into broader peer-enrollment and policy-distribution flows, building the platform-native GUI on top of the current model crate, and hardening release packaging further.

What we are doing next:
- Wire the new identity workflow into higher-level enrollment and trust-distribution flows so pairing and mesh membership can consume issued certificates directly.
- Continue into platform-specific UX and operational hardening rather than adding more placeholder surface area.

## 2026-03-26

### Entry 1
What we did:
- Promoted signed device certificates and enrollment bundles into `ql-pair` so the post-pairing trust artifact is a shared crate-level type instead of a `qld`-private JSON format.
- Added enrollment-bundle verification helpers built on the hybrid CA signature path and revocation snapshot, with new crate tests covering valid and revoked bundle handling.
- Extended `qld identity` with enrollment export and import commands so an issued certificate can be packaged with its trust anchor and then installed into a target device layout.
- Extended `ql-mesh` with certificate-to-peer projection so mesh membership can derive peer identity directly from issued certificates.
- Re-ran `cargo test -p ql-pair -p ql-mesh -p ql-daemon` and confirmed the touched crates pass after the integration.

Where we are:
- Pairing no longer stops at raw authenticated exchange primitives; the workspace now has an explicit trust-distribution bundle for the handoff into enrollment.
- The remaining gap is automating delivery of that bundle through the actual signaling or LAN confirmation flow and then surfacing it in the GUI.

What we are doing next:
- Thread enrollment-bundle transport through the final pairing UX instead of requiring explicit CLI import or export.
- Expose the new enrollment and certificate state through the platform UX and continue release hardening.

### Entry 2
What we did:
- Added typed mailbox identities and mailbox payloads to `ql-pair`, including a concrete `EnrollmentBundle` transport payload and role-derived pairing identities for initiator and responder flows.
- Extended `ql-signal` with a lightweight HTTP client and pairing-token mailbox authentication so the existing mailbox service can be used directly from daemon-side pairing flows.
- Extended `qld` with mailbox-based pairing commands that create a mailbox and send or receive enrollment bundles over the signal path instead of requiring file-only handoff.
- Added end-to-end tests in `ql-signal` and `qld` that start a live signal server and verify enrollment data can traverse the mailbox path and install successfully on the receiving side.

Where we are:
- The workspace now has an actual remote transport path from pairing rendezvous to certificate installation, not just offline bundle export and import helpers.
- The remaining gap is UX orchestration: the operator still drives these steps through explicit low-level commands rather than one integrated pairing workflow.

What we are doing next:
- Collapse the SPAKE2 exchange, mailbox creation, enrollment-bundle send, and receive steps into a higher-level pairing workflow.
- Then expose that flow in the GUI and continue hardening operational trust distribution.

## 2026-03-27

### Entry 1
What we did:
- Extended the macOS tunnel bridge contract so the Rust runtime now supplies interface addresses alongside the existing WireGuard key material, endpoint, DNS, and MTU fields. This closes a hard blocker for real Apple-side tunnel configuration because the Packet Tunnel Provider can now construct a real interface configuration instead of guessing addresses.
- Updated the Swift tunnel shared models and the `QuantumLinkPacketTunnelProvider` so the provider can consume those interface addresses and, when `WireGuardKit` is available through the Xcode product path, build a real WireGuard tunnel configuration for activation, endpoint updates, PSK injection, and runtime-stat reads.
- Added environment-driven Mode A tunnel-config override support to `ql-macos-app`, which allows the macOS validation path to consume a real self-hosted server configuration instead of a baked-in sample tunnel.
- Added target-specific Xcode configuration files plus a reproducible `generate_xcodeproj.rb` script that emits `QuantumLinkMacApp.xcodeproj` with the macOS app target, Packet Tunnel Provider extension target, tunnel-controller target, the external `WireGuardGoBridgemacOS` build target, and the `WireGuardKit` package dependency.

Where we are:
- The repository now has a concrete signed-product path for the real macOS tunnel stack instead of only a SwiftPM scaffold: app target, Packet Tunnel Provider target, `WireGuardKit` dependency wiring, and a provider implementation that can speak the actual WireGuardKit model when built in that environment.
- The remaining tunnel-side gap is product execution, not schema definition. This environment still cannot run `xcodebuild` because full Xcode is unavailable, so the Xcode-generated path is in place and verified structurally, but not compiled here as a signed app-extension bundle.

What we are doing next:
- Run the generated Xcode project on a full macOS/Xcode machine, set signing, install the packet tunnel extension, and validate tunnel establishment against a real self-hosted server.
- Tighten any provider-runtime mismatches that appear once the real Network Extension and `WireGuardKit` runtime are exercised under macOS entitlement and signing rules.

### Entry 2
What we did:
- Replaced the firewall-only macOS helper stub with a real PF-backed execution mode in `ql-macos-helper`. The helper can now enable PF, load per-interface anchors, query active rules, flush anchors on disconnect, and release PF enable tokens cleanly.
- Extended the macOS firewall bridge request so kill-switch rules can explicitly permit the selected VPN peer endpoint while still blocking unsafe outbound traffic, and wired the Rust host planning path to pass that endpoint through during Mode A connect.
- Implemented concrete PF rule generation for full kill-switch and DNS-only protection modes, including loopback allowance, tunnel-interface allowance, DNS allowlisting where required, and teardown-safe cleanup behavior.
- Added a documented `mode_a_validate.sh` workflow and `docs/macos-mode-a-validation.md`, which together define the real end-to-end Mode A validation procedure: startup, connect, connected status, PF enforcement, disconnect, and cleanup.

Where we are:
- The macOS leak-protection path is no longer purely simulated. The repository now contains a real PF execution backend with tests, plus a documented validation flow that exercises the intended release-gate lifecycle.
- The remaining firewall-side gap is machine validation, not design. We still need to run the PF-backed flow on a real signed macOS app-extension installation with a live self-hosted server config.

What we are doing next:
- Execute the validation script on a macOS machine with full Xcode, a signed installed Packet Tunnel Provider extension, and a real Mode A server configuration.
- Harden any PF edge cases uncovered by real network transitions, including sleep/wake and partial tunnel-failure teardown behavior.

### Entry 3
What we did:
- Hardened the PF helper state machine so it can recover from stale references and partial teardown cases more safely. The helper now tracks the active anchor name, flushes old anchors when reconnecting on a different interface, reacquires a PF enable token if the stored token survives but PF is no longer enabled, and clears stale token state when query results show that the firewall rules are already gone.
- Added targeted helper tests that cover the new failure edges: reconnecting onto a new anchor, disabling when the requested anchor and stored anchor differ, recovering after PF is disabled while a stale token remains in state, and clearing stale state after inactive queries.
- Tightened the generated Xcode product path for signed delivery: added shared signing and hardened-runtime settings in `Config/Signing.xcconfig`, corrected the Packet Tunnel Provider framework runpath to the app-extension-safe form, made the controller target explicitly unsigned as a developer utility, and updated the generated app scheme to archive from `Release`.
- Added `Scripts/archive_release.sh` plus `docs/macos-distribution.md` so the repository now has a reproducible archive/export path for the signed macOS app and an optional notarytool submission flow.

Where we are:
- The repository now has a materially better macOS release path than the earlier scaffold: the app and extension targets are configured like signed deliverables, and the PF helper is more resilient to crash, sleep/wake-adjacent, and partial-cleanup edge cases.
- The remaining gap is still machine execution. Full archive, export, and notarization were not run here because this environment does not have full Xcode, and the live Mode A validation still requires a real tunnel config and server.

What we are doing next:
- Run the archive/export script on a full Xcode machine with a real team ID and verify the generated app and extension sign cleanly.
- Run the first live Mode A validation against a real self-hosted server and fix any entitlement, provider-runtime, or PF behavior issues that appear under actual macOS execution.

### Entry 4
What we did:
- Added an explicit `network-extension` mode to `ql-macos-runtime` so tunnel execution now has a dedicated native-controller path instead of being modeled only as a generic external helper.
- Added a `QuantumLinkTunnelController` Swift target and taught the SwiftUI host to select `network-extension` mode when a native tunnel controller has been provided.
- Updated `ql-macos-app` status and tray projection so the service reports stub, helper-backed, and native tunnel-controller sessions distinctly.
- Added Rust coverage for the new adapter mode and environment parsing, then validated the updated Rust crates plus the Swift package build.
- Taught `ql-macos-app` to keep `network-extension` mode tunnel-operable even when no firewall bridge is configured yet, so connect, status, and disconnect can run honestly as tunnel-only operations.
- Added a macOS service integration test that launches `ql-macos-app serve` in `network-extension` mode against a mock native tunnel controller and verifies connect, connected status, disconnect, and cleanup through the HTTP contract.

Where we are:
- The repository now has an explicit native tunnel bridge target for the macOS path rather than only a generic helper seam.
- The native tunnel path can now be exercised end to end through the Rust service without requiring a fake firewall bridge.
- This is still not a finished signed Network Extension integration, but the control surface now matches the intended product direction much more closely.

What we are doing next:
- Replace the tunnel-controller stub behavior with real Network Extension lifecycle work.
- Move the firewall path to the same level of native integration so kill switch and leak protection become system-real instead of bridge-planned.

### Entry 5
What we did:
- Replaced the validation-only `ql-macos-helper` behavior with a stateful execution stub that persists simulated tunnel and firewall state, returns structured firewall query results, and reports tunnel stats.
- Updated `ql-macos-runtime` to parse helper JSON responses so firewall queries and tunnel-stat reads can flow through the existing executor interfaces instead of always falling back to hardcoded defaults.
- Extended `ql-macos-app` with JSON-oriented commands for status, Mode A demo connect, and Mode A demo disconnect so a native host can consume structured output from the shared Rust shell.
- Added a first SwiftUI macOS host scaffold under `macos/QuantumLinkMacApp` that now launches `ql-macos-app serve`, talks to it over localhost HTTP, and displays runtime status, planned operations, and raw JSON output.
- Tightened the Rust and Swift status flow so `status-json` reports helper-backed session activity, the connect JSON path accepts an explicit server endpoint, and the SwiftUI shell polls real session state through the shared service instead of treating everything as a one-shot demo.
- Added HTTP-level tests around the `ql-macos-app` service endpoints and switched service failures to real HTTP status codes so invalid requests no longer come back as successful text responses.

Where we are:
- The macOS helper contract now behaves like a stateful execution seam rather than a pure payload validator.
- The repository has a concrete native macOS UI entry point that can exercise and display helper-backed Rust session state through a persistent localhost IPC service without waiting for FFI or Network Extension work.

What we are doing next:
- Replace the localhost service seam with native signed integration once the Network Extension and firewall execution path is ready.
- Keep replacing demo-only execution with real tunnel, firewall, and certificate lifecycle behavior.

### Entry 6
What we did:
- Added `ql-macos-app` as the native macOS host-shell crate that owns the shared `ql-gui` model and the `ql-macos-runtime` adapter.
- Implemented host-side planning helpers that translate shared GUI and daemon intent into native tunnel and firewall operations for the macOS runtime boundary.
- Cleaned up the workspace wiring after the initial scaffold pass so the root workspace manifest remains workspace-only and the new crate owns its own package metadata.
- Added a minimal `ql-macos-app` binary entrypoint so the host shell can be instantiated directly with stub or external-process adapter configuration.

Where we are:
- The macOS-first runtime stack now has a concrete host-side layer above the adapter instead of only runtime-side bridge contracts.
- Shared GUI state, daemon event projection, and native operation planning now have a single application-side home for the macOS path.

What we are doing next:
- Validate the new app-shell crate alongside `ql-macos-runtime`, `ql-wireguard`, `ql-firewall`, and `ql-daemon`.
- Keep building toward a signed native macOS product shell that can own the eventual platform UI and helper-process integration.

### Entry 7
What we did:
- Added high-level `qld pair-initiate` and `qld pair-accept` workflows that compose mailbox creation, SPAKE2 exchange, verification-word derivation, enrollment-bundle transport, bundle import, and mailbox cleanup into one command per side.
- Adjusted mailbox lifecycle behavior in `ql-signal` so a pairing mailbox can survive a multi-stage exchange instead of being deleted after the first empty roundtrip.
- Added daemon tests that verify the full high-level pairing flow against a live signal server, with both sides deriving the same verification words and the responder successfully importing the issued certificate.

Where we are:
- The workspace now has a usable remote pairing workflow instead of only low-level transport primitives and manually chained daemon commands.
- The main remaining gap is turning this daemon-oriented pairing workflow into a GUI-driven and less operator-heavy experience.

What we are doing next:
- Expose the high-level pairing flow through the GUI model and command surface.
- Then continue with operational trust-distribution hardening and LAN confirmation integration.

### Entry 8
What we did:
- Extended the shared `ql-core` daemon IPC surface with high-level pairing commands and events for initiator or responder workflows, verification words, and successful pairing completion.
- Extended `ql-gui` with a dedicated pairing panel state model so the future desktop frontend can queue high-level pairing commands and present live pairing progress, mailbox details, verification words, and completion status.
- Added GUI tests that verify the new command queueing and pairing-event projection behavior.

Where we are:
- The high-level pairing workflow now exists in the daemon, in the shared command and event contract, and in the GUI-facing state model.
- The remaining gap is the actual platform frontend that binds these model states and commands to GTK controls, dialogs, and user confirmation screens.

What we are doing next:
- Bind the pairing workflow into the GUI frontend layer and tray interactions.
- Then continue with LAN confirmation and operational trust-distribution hardening.

### Entry 9
What we did:
- Repositioned the repository documentation around a macOS-first product strategy instead of a broad simultaneous platform push.
- Updated the top-level README to describe the current shared-Rust-core plus native-macOS-product direction and to demote Linux runtime pieces to reference-backend status where appropriate.
- Added a dedicated macOS pivot plan document that defines the narrowed first-release scope, immediate workstreams, and exit criteria for a macOS-only product milestone.

Where we are:
- QuantumLink now has an explicit product-direction document for a macOS-first release rather than only an implicit roadmap in the original specification.
- The core shared logic remains reusable, but the next implementation focus is clear: macOS runtime integration, native frontend delivery, and release packaging.

What we are doing next:
- Define the macOS tunnel and leak-protection abstraction boundary that will replace the current Linux-only runtime assumptions.
- Build the native macOS frontend around the existing shared GUI and daemon models, with Mode A as the release gate.

### Entry 10
What we did:
- Added a dedicated macOS runtime architecture document that defines the platform boundary between shared Rust product logic and platform-specific tunnel plus leak-protection execution.
- Introduced `PlatformTunnel` and `PlatformFirewall` facades so higher layers no longer need to depend directly on Linux-specific runtime type names.
- Updated `qld` to depend on the new platform facades, keeping the current Linux implementation as the wired backend while preparing the codebase for a macOS backend.

Where we are:
- The macOS-first pivot now has both a documented runtime boundary and an initial code scaffold for platform selection.
- The next engineering step is to add a macOS backend behind these facades instead of letting daemon orchestration continue to point directly at Linux runtime assumptions.

What we are doing next:
- Add the first macOS backend scaffold for tunnel and leak-protection responsibilities.
- Then bind the native macOS app shell onto the shared GUI and daemon surfaces.

### Entry 11
What we did:
- Added an explicit `macos-scaffold` backend path in both `ql-wireguard` and `ql-firewall` so Apple targets are no longer treated as a generic non-Linux stub.
- Added macOS-specific `NotImplemented` messages that describe the missing native runtime pieces more precisely: tunnel lifecycle, endpoint updates, PSK injection, leak protection, and state reporting.
- Updated the runtime architecture document to reflect the new backend-state split: `linux-reference`, `macos-scaffold`, and generic `stub`.

Where we are:
- QuantumLink now has an explicit macOS runtime placeholder path in code, which makes the next native implementation step concrete instead of implied.
- The remaining gap is replacing the scaffold behavior with actual macOS tunnel and leak-protection execution, then binding it into a native app shell.

What we are doing next:
- Replace the `macos-scaffold` tunnel and firewall paths with the first native execution layer.
- Then start the native macOS frontend shell on top of the existing shared GUI and daemon model.

### Entry 12
What we did:
- Refined the macOS tunnel scaffold in `ql-wireguard` into a typed backend shape instead of a flat target-specific stub.
- Added a backend descriptor surface so higher layers can inspect whether the active target backend is a product target and whether it already performs native execution.
- Introduced explicit macOS tunnel backend metadata for driver choice, prepared-state lifecycle, and provider bundle identifier shape, with crate tests covering the new scaffold state on macOS.

Where we are:
- The macOS tunnel path now has a concrete backend structure ready for native execution work rather than only placeholder methods behind a target gate.
- The next gap is implementing actual execution through the native macOS tunnel path and then bringing the firewall side to the same level of structural specificity.

What we are doing next:
- Replace the macOS tunnel backend placeholder methods with the first native execution integration.
- Then refine the macOS firewall scaffold to match the tunnel side before binding the native app shell.

### Entry 13
What we did:
- Refined the macOS firewall scaffold in `ql-firewall` into a typed backend shape instead of flat target-gated placeholder methods.
- Added a firewall backend descriptor surface so higher layers can inspect whether the selected firewall backend is a product target and whether it already performs native execution.
- Introduced explicit macOS firewall backend metadata for driver choice, prepared-state lifecycle, anchor naming, and leak-protection mode modeling, with crate tests covering the new scaffold state on macOS.

Where we are:
- The macOS runtime layer now has parallel typed backend shapes on both sides: tunnel and firewall.
- The next gap is replacing those typed placeholder methods with real native execution and then binding them into a native app shell.

What we are doing next:
- Replace the macOS tunnel and firewall placeholder methods with the first native execution integration points.
- Then start the native macOS frontend shell on top of the existing shared GUI and daemon model.

### Entry 14
What we did:
- Added public macOS bridge-request models in `ql-wireguard` and `ql-firewall` so the Rust runtime can now emit structured native-integration requests instead of only hiding target-specific placeholder logic internally.
- Added bridge-request accessors for the macOS tunnel and firewall paths, including tunnel session configuration and firewall operation payloads for kill switch, DNS-only protection, disable, and query actions.
- Added crate tests on macOS that verify the emitted bridge requests carry the expected configuration and runtime metadata.

Where we are:
- The macOS runtime layer now exposes a real integration seam that a native app shell or extension can consume.
- The next gap is executing those bridge requests through an actual native implementation rather than only generating them in Rust.

What we are doing next:
- Introduce the first native-execution adapter that consumes the macOS bridge requests.
- Then begin the native macOS app shell that will own and drive those adapters.

### Entry 15
What we did:
- Added macOS executor interfaces in `ql-wireguard` and `ql-firewall` so the runtime can now drive native execution through explicit adapter traits instead of stopping at bridge payload generation.
- Added executor-backed helper methods on the platform facades, allowing higher-level code to activate tunnels, update endpoints, inject PSKs, query stats, and apply firewall operations through supplied macOS executors.
- Added macOS tests with recording executors that verify the new execution hooks consume the expected bridge requests in the correct operation sequence.

Where we are:
- QuantumLink now has both halves of the Rust-side native integration seam: bridge payload models and executor interfaces.
- The next gap is a concrete native adapter implementation and then the app shell that owns it.

What we are doing next:
- Add the first concrete macOS native adapter implementation target for the executor interfaces.
- Then scaffold the native macOS app shell around those adapters and the shared GUI plus daemon model.

### Entry 16
What we did:
- Added a new `ql-macos-runtime` crate as the first concrete macOS adapter target in the workspace.
- Implemented a configurable adapter that consumes the macOS tunnel and firewall executor traits, serializes bridge requests, and can operate either in stub mode or through external helper processes.
- Added tests that verify the adapter emits the expected serialized tunnel and firewall payloads and participates correctly in the new executor seam.

Where we are:
- QuantumLink now has a concrete adapter library target for the macOS runtime boundary, not just traits and request models.
- The remaining gap is the native host itself: a real app or extension process that owns these adapters and backs the external execution mode.

What we are doing next:
- Scaffold the native macOS app shell that owns the adapter and shared GUI plus daemon surfaces.
- Then define the first concrete native helper or extension entrypoint that can back the adapter's external process mode.

### Entry 17
What we did:
- Added a new `ql-macos-app` crate as the first native macOS host-shell target in the workspace.
- Implemented a host model that owns the shared `ql-gui` model and the `ql-macos-runtime` adapter, and can queue daemon commands, apply daemon events, and plan connect or disconnect host operations.
- Added host-shell tests that verify GUI command flow, daemon-event projection, and macOS connect or disconnect operation planning against the stub adapter path.

Where we are:
- QuantumLink now has a concrete host-side layer above the adapter, not just runtime crates and bridge contracts.
- The remaining gap is the actual native frontend and helper or extension process that would sit on top of this shell and back the adapter's external execution mode.

What we are doing next:
- Define the first helper or extension entrypoint contract that backs `ql-macos-runtime` external-process execution.
- Then start the native frontend shell implementation on top of `ql-macos-app`.

### Entry 18
What we did:
- Added a runnable `ql-macos-app` binary entrypoint so the host shell can be instantiated directly from the workspace instead of only through tests.
- Wired environment-driven adapter selection into that bootstrap path, including stub mode and external-helper configuration placeholders for tunnel and firewall execution.
- Re-ran focused validation for `ql-macos-app` and exercised the new bootstrap with `cargo run -p ql-macos-app -- status` to confirm the shared GUI state and pending-command flow come up correctly.

Where we are:
- The macOS-first stack now has both a reusable host-shell library and a concrete executable bootstrap path for local integration work.
- The remaining gap is replacing stub execution with a real native helper or extension process and then binding the shell into a true macOS frontend.

What we are doing next:
- Add the first concrete helper or extension contract that backs `ql-macos-runtime` external-process mode.
- Then replace the bootstrap CLI with a real native macOS UI host around the same shared shell.

### Entry 19
What we did:
- Added `ql-macos-helper` as the first concrete external-process helper target for the macOS runtime boundary.
- Updated `ql-macos-runtime` external-process dispatch to invoke helpers with target-aware arguments and capture helper output on success.
- Extended the `ql-macos-app` bootstrap with Mode A demo connect and disconnect commands that can drive the host shell through either stub mode or the new helper-backed external mode.

Where we are:
- The macOS-first stack now has a real executable contract for external helper execution instead of only placeholder helper-path configuration.
- The remaining gap is replacing payload validation with actual Network Extension and packet-filter work, then binding the same flow into a native macOS UI.

What we are doing next:
- Replace the validation-only helper path with the first native tunnel and firewall implementation behind the same contract.
- Then promote the app-shell demo flow into a true macOS frontend rather than a bootstrap CLI.
