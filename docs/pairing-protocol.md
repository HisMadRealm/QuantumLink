# Pairing Protocol

QuantumLink currently implements the reusable pairing primitives needed for the product’s QR, wormhole, and setup-key flows.

## QR pairing

`ql-pair` models QR offers as `ql://pair?...` URIs containing:

- WireGuard public key material reference
- Rosenpass public key fingerprint
- rendezvous or mailbox location
- ephemeral bootstrap key bytes
- expiration timestamp

This matches the product requirement that the QR payload carry compact identifiers and fingerprints rather than full Rosenpass key material.

## Wormhole-style remote pairing

The current crate provides:

- human-readable code generation and validation
- symmetric SPAKE2 session establishment using the `spake2` crate
- shared-secret derivation from the exchanged SPAKE2 messages
- a deterministic 5-word verification phrase derived from the pairing secret

This is the basis for the remote “read the code over another channel” UX described in the product spec.

## Setup keys

The current setup-key helper provides:

- single-string serialization
- expiration timestamps
- parsing and validation helpers

This supports the “add device to existing mesh” bootstrap flow without baking transport-specific assumptions into the pairing crate.

## Enrollment bundle handoff

Pairing now has a concrete trust-distribution artifact for the post-authentication step.

`ql-pair` models an enrollment bundle containing:

- CA metadata
- CA verifying key
- signed device certificate
- revocation snapshot

This lets `qld` export a verified enrollment package after offline issuance and import it on the target device after the initial authenticated exchange.

The current transport path now also covers mailbox delivery:

- `ql-signal` exposes a small HTTP client alongside the mailbox service
- `ql-pair` provides typed mailbox payloads and role-derived mailbox identities
- `qld` can create a mailbox and send or receive an enrollment bundle over that mailbox path

This is the first concrete bridge from the remote pairing rendezvous flow into certificate installation on the target device.

The daemon now adds a higher-level orchestration layer on top of those pieces:

- `qld pair-initiate` creates the mailbox, performs the initiator SPAKE2 step, waits for the responder, derives verification words, and sends the enrollment bundle
- `qld pair-accept` performs the responder SPAKE2 step, derives the same verification words, receives the enrollment bundle, imports it, and deletes the mailbox

This turns the previous low-level mailbox choreography into a single command per side while keeping the lower-level transport available for debugging and future GUI wiring.

## What is still missing

- GUI-driven or daemon-managed pairing orchestration that hides the remaining command-line parameters from end users
- LAN discovery and local confirmation flow integration
- LAN confirmation transport for the enrollment bundle and later revocation refresh
