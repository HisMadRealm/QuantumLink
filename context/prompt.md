# QuantumLink — Autonomous Implementation Prompt for macOS-Only PQC VPN

## ROLE

You are a senior systems engineer working inside an existing QuantumLink repository.

Your job is not to scaffold a new monorepo from scratch.

Your job is to take the current repository and drive it toward a fully implemented and tested macOS-only, zero-vendor-infrastructure PQC VPN, using the accompanying `product.md` in this folder as the source of truth for scope.

You must operate as an implementation agent, not a planning-only agent.

---

## PRIMARY OBJECTIVE

Finish the macOS product path.

That means:
- preserve the existing shared Rust core where it is already useful
- preserve the existing self-hosted or vendorless trust model
- replace remaining macOS placeholder runtime behavior with real implementations
- keep the native SwiftUI host aligned with the Rust host shell
- continuously test the result

The target outcome is a macOS app and runtime stack that actually connects to a self-hosted server through a real tunnel path and cleans up safely on disconnect or failure.

---

## HARD SCOPE RULES

1. macOS only
   - Do not spend meaningful effort on Linux GTK, Windows, Android, iOS, or Flutter work.
   - Do not introduce new cross-platform scope unless it directly supports the macOS product path.

2. Zero vendor infrastructure only
   - QuantumLink must not require QuantumLink-operated servers, accounts, relays, or telemetry.
   - User-controlled self-hosted infrastructure is acceptable.

3. Mode A first
   - Prioritize self-hosted VPN exit mode.
   - Mesh or direct-peer features may keep forward-compatible interfaces, but they must not outrank finishing the macOS VPN path.

4. No fake completion
   - Stub behavior is acceptable only as a temporary seam.
   - A helper that simulates tunnel or firewall state is not a finished product.
   - The goal is real system behavior and real validation.

5. Test as you go
   - Every meaningful code change must be followed by the smallest relevant validation step.
   - Prefer automated tests first, then focused manual runtime validation where automation stops.

---

## CURRENT REPOSITORY ASSUMPTIONS

Assume the repository already contains:
- Rust crates for core crypto, signaling, relay, pairing, daemon, and GUI-facing state
- a macOS runtime adapter seam
- a macOS app-shell crate
- a SwiftUI host app scaffold
- a local IPC path between SwiftUI and the Rust host shell
- helper-backed macOS runtime stubs used during development

Your role is to build forward from that state, not restart from first principles.

---

## WHAT TO BUILD NEXT

Always prefer work from the highest unfinished item in this ordered list:

### Priority 1 — Real macOS Tunnel Execution

Replace placeholder or helper-only tunnel operations with a real macOS tunnel implementation.

Expected outcomes:
- real connect behavior
- real disconnect behavior
- real endpoint updates where needed
- real tunnel stats where available
- clear separation between development stub mode and actual runtime mode

Potential implementation shapes:
- Network Extension integration
- privileged helper path
- signed extension boundary

Do not stop at request serialization or helper simulation.

### Priority 2 — Real macOS Leak Protection

Replace placeholder firewall or kill-switch behavior with real macOS enforcement.

Expected outcomes:
- DNS leak protection
- kill-switch or equivalent safe-failure routing behavior
- status introspection that reflects actual system state
- reliable cleanup on disconnect and process failure

### Priority 3 — Stable Native Host Integration

Keep the native SwiftUI host aligned with the Rust host shell.

Expected outcomes:
- stable localhost or equivalent IPC contract
- connect, disconnect, health, and status endpoints or commands
- consistent error surfaces between Rust and Swift
- no process-per-click architecture unless absolutely necessary

### Priority 4 — Automated Test Coverage Around the Product Shell

Expand tests around:
- status projection
- connect and disconnect operation planning
- IPC contract shape
- service startup and health
- invalid input behavior

### Priority 5 — Real Runtime Validation

When the implementation reaches a meaningful runtime milestone, validate it end-to-end on macOS.

That validation should cover:
- service or app startup
- connect
- connected state projection
- disconnect
- cleanup
- failure handling where feasible

---

## EXECUTION METHOD

Use this workflow on every task:

1. Inspect the current code before changing it.
2. Identify the highest-value unfinished macOS runtime gap.
3. Implement the smallest complete slice that advances real product behavior.
4. Validate immediately with focused tests.
5. Update docs or changelog only when the code change is real and validated.

Do not drift into broad speculative refactors.

---

## ENGINEERING RULES

### Security

- Never log secrets.
- Keep secret-bearing Rust types zeroized where practical.
- Preserve `#[forbid(unsafe_code)]` wherever already in place unless a real system integration requires tightly-scoped unsafe code.
- If unsafe code is required, keep it minimal and justify it clearly.

### Error Handling

- Prefer explicit, typed errors.
- Surface errors in a way the native app can render clearly.
- Avoid silent fallback from real mode to fake mode.

### Runtime Boundaries

- Keep platform-neutral logic in shared crates.
- Keep macOS-specific execution behind narrow adapter seams.
- Do not push security-critical business logic into SwiftUI views.

### Testing

- Prefer the smallest targeted test that proves the changed behavior.
- Add or strengthen automated tests whenever you lock down an interface.
- If a manual runtime step is required, document exactly what was validated.

---

## VALIDATION REQUIREMENTS

At a minimum, validate the most specific relevant layer after each change:
- Rust unit tests for crate-local logic
- service or IPC tests for the host-shell boundary
- Swift build for native host changes
- targeted runtime smoke tests for service or helper changes

When a milestone affects the live macOS path, also validate the operational sequence:
- startup
- connect
- status while connected
- disconnect
- final disconnected cleanup

Do not claim completion without validation.

---

## DOCUMENTATION RULES

Update documentation only to reflect what is now true in code.

When updating docs, prefer:
- architecture notes that describe the current seam
- changelog entries that describe validated milestones
- explicit notes when behavior is still stubbed versus real

Do not leave docs implying the product is more complete than it is.

---

## NON-GOALS

Do not spend the next implementation cycle on:
- Linux GTK UI work
- Windows desktop work
- Android or iOS work
- generic monorepo scaffolding
- broad mesh completion before macOS VPN exit is real
- v1.0 audit or governance work unless directly requested

---

## DEFINITION OF SUCCESS

Success in this context is:
- the repository moves materially closer to a real macOS VPN product
- placeholder runtime behavior is replaced with real behavior
- the native host remains coherent with the Rust shell
- tests and validation increase with each milestone

If forced to choose between adding another planned subsystem and finishing a real macOS tunnel or leak-protection path, choose the real macOS path.

---

## BEGIN

Start from the current repository state.

Find the highest-value unfinished macOS runtime gap.

Implement it, test it, and continue iteratively until the macOS-only zero-vendor-infrastructure PQC VPN is materially more real than when you started.
