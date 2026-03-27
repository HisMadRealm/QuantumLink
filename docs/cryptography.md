# Cryptography

QuantumLink’s current cryptographic implementation follows the hybrid model described in the product specification and maps directly onto the workspace crates.

## Transport and handshake layers

- Transport tunnel: WireGuard
- Classical key agreement: X25519
- Post-quantum key agreement: ML-KEM-768
- Classical authentication: Ed25519
- Post-quantum authentication: ML-DSA-65
- PQ PSK rotation layer: Rosenpass sidecar integration

## Implemented hybrid KEM behavior

`ql-crypto` combines classical and PQ shared secrets and derives the tunnel secret with HKDF-SHA3-256 over:

`classical_ss || pq_ss`

using the workspace salt and context constants defined in the crate.

The result is that the shared secret remains usable if either the classical or post-quantum component remains secure.

## Implemented hybrid signature behavior

The current authentication model signs with both Ed25519 and ML-DSA-65 and requires both verification steps to succeed. This closes the authentication gap the product spec calls out as missing in current consumer offerings.

## Rosenpass role

QuantumLink does not re-implement Rosenpass. Instead:

- `ql-rosenpass` supervises the sidecar process
- `qld` composes Rosenpass into the client connection lifecycle
- the long-term design remains to inject PQ-derived PSKs into WireGuard without modifying WireGuard itself

## Current limitations

- The workspace now supports offline hybrid certificate issuance, verification, revocation, and enrollment-bundle verification, but does not yet automate transport of those bundles through the live pairing mailbox flow
- The current daemon orchestration starts Rosenpass and reports PSK age, but deeper always-online renewal and fleet-wide trust distribution workflows are not complete yet
- macOS builds may emit vendored `liboqs` object-file version warnings during tests on this machine, but the workspace test suite still passes
