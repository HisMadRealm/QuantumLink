# Threat Model

QuantumLink is designed around a self-hosted, zero-vendor-infrastructure trust model. The project assumes that users control their own server node and that QuantumLink the project does not operate any traffic-bearing infrastructure.

## Protected against

- Passive harvest-now-decrypt-later collection through hybrid X25519 + ML-KEM-768 session establishment
- Active impersonation attempts through hybrid Ed25519 + ML-DSA-65 authentication surfaces
- Relay compromise in mesh fallback mode, because `ql-relay` forwards opaque WireGuard ciphertext without decryption keys
- DNS and tunnel-failure leakage on Linux where the daemon can enforce nftables kill-switch and DNS rules
- Lost-device persistence beyond certificate validity and blocklist propagation once short-lived certificates and revocation state are honored

## Explicitly not solved in the current implementation

- Endpoint compromise on a client or self-hosted server
- Hypervisor-level introspection by a malicious VPS provider
- Traffic analysis based only on timing and packet size
- Real-time global revocation enforcement without a reachable authority
- Mobile-specific Rosenpass lifecycle constraints, which remain a later roadmap item

## Security boundaries in the current workspace

- `ql-crypto` owns hybrid primitive implementation and zeroization of secret-bearing key material
- `ql-rosenpass` delegates PQ PSK rotation to Rosenpass instead of re-implementing the protocol
- `ql-relay` intentionally does not parse or transform payloads
- `ql-core` now contains shared certificate, CA, and revocation data models so access control can be reasoned about consistently across crates

## Residual implementation risks

- The current key-management layer now performs certificate issuance, signature verification, revocation tracking, and enrollment-bundle import or export, but it still relies on explicit handoff instead of an always-online authority or automated mailbox delivery
- The current GUI crate is a state model, not a full sandboxed desktop application
- The current server process is intentionally in-memory and does not yet include persistent operational storage or hardened deployment conventions
