# QuantumLink — Product Specification

**Version:** 0.2.0-draft
**Status:** Pre-development
**License:** Apache 2.0 (planned)
**Repository:** github.com/quantumlink/quantumlink (placeholder)

---

## 1. Vision & Strategic Positioning

QuantumLink is the **first fully open-source, consumer-ready, post-quantum secure VPN with serverless P2P mesh networking** — delivering the cryptographic transparency privacy advocates demand, the zero-infrastructure trust model power users require, and the seamless usability everyday users expect.

**QuantumLink operates zero infrastructure.** There are no QuantumLink servers, no QuantumLink accounts, no QuantumLink telemetry, no centralized anything. Users self-host their own server node (on a $2/month VPS or a Raspberry Pi), and that node becomes their personal coordination hub, relay, and exit point. For pure device-to-device connections, even the VPS is optional — peers pair directly using a magic-wormhole-style exchange and connect over public STUN infrastructure.

### The three-sentence pitch

Every commercial PQC VPN (NordVPN, ExpressVPN, Mullvad) is a black box: users trust the vendor's word that post-quantum crypto is correctly implemented, correctly deployed, and not logging their traffic. Every open-source PQC VPN tool (Rosenpass, liboqs) is a developer library — no GUI, no mobile apps, no pairing flow, no consumer experience. QuantumLink is neither: it is a fully auditable, formally verified, self-sovereign post-quantum VPN with P2P mesh networking and a consumer-grade interface, where the cryptographic code is published, the threat model is published, and the audit report is published — and the company running it cannot see your traffic because it has no servers.

### Core differentiators (in priority order)

1. **Zero vendor infrastructure** — QuantumLink operates no servers, collects no data, has no accounts. Your VPS is your server.
2. **Full source transparency** — every cryptographic component is auditable; the server software is the same codebase as the client
3. **PQC across both key exchange AND authentication** — ML-KEM-768 + ML-DSA-65, the only consumer VPN to close the authentication gap
4. **Crypto-agile modes** — Classical → Hybrid → PQ-Only, negotiated automatically
5. **P2P mesh networking** — direct device-to-device connections with PQ security; no traffic through any server when direct path is available
6. **Consumer-grade UX** — magic-wormhole pairing, QR codes, one-click connect; no cryptography knowledge required
7. **Dedicated PQC security audit published before v1.0**
8. **Formal verification of the core handshake protocol**

---

## 2. Target Users

### Primary
Privacy-conscious consumers and prosumers who want:
- A VPN with independently verifiable security and no trust-me-bro cryptography
- Protection against harvest-now-decrypt-later attacks
- Control over their own infrastructure — their data never touches a third-party server
- Direct device-to-device connectivity for personal file sharing, remote access, and small team collaboration

### Secondary
- Developers and security researchers wanting a reference PQC VPN implementation
- Journalists, activists, and high-risk individuals needing maximum-assurance communications
- Small teams and individuals ahead of NIST IR 8547, CNSA 2.0, and EU NIS2 regulatory deadlines
- Self-hosters who already run a VPS or Raspberry Pi and want to add quantum-safe networking

### Explicitly not targeting (v1.0)
- Enterprise organizations (no SSO, LDAP, compliance dashboards)
- Users who want a turn-key "just works" hosted VPN — QuantumLink requires owning a server

---

## 3. Architecture Overview

QuantumLink has two complementary modes that share the same cryptographic stack:

```
┌─────────────────────────────────────────────────────────────────┐
│                    QuantumLink Client (qld)                      │
│                                                                  │
│  ┌──────────┐   ┌────────────────────────────────────────────┐  │
│  │  GUI App │   │              ql-mesh                        │  │
│  │(platform)│◄──►  ┌──────────┐  ┌──────────┐  ┌─────────┐  │  │
│  └──────────┘   │  │ql-crypto │  │ql-stun   │  │ql-pair  │  │  │
│                 │  │ML-KEM-768│  │STUN/NATPMP│  │SPAKE2   │  │  │
│                 │  │ML-DSA-65 │  │Hole-punch │  │QR/Link  │  │  │
│                 │  │Ed25519   │  └────┬─────┘  └────┬────┘  │  │
│                 │  │X25519    │       │              │        │  │
│                 │  └────┬─────┘  ┌───▼──────────────▼────┐  │  │
│                 │       │        │      ql-rosenpass       │  │  │
│                 │       │        │  PQ PSK injection/mesh  │  │  │
│                 │       │        └────────────┬────────────┘  │  │
│                 └───────┼─────────────────────┼───────────────┘  │
└─────────────────────────┼─────────────────────┼─────────────────┘
                          │                     │
                 ┌────────▼─────────────────────▼──────────┐
                 │         WireGuard Tunnel (unmodified)     │
                 └──────┬────────────────────────────┬──────┘
                        │                            │
           ┌────────────▼──────────┐    ┌────────────▼──────────┐
           │  MODE A: VPN Exit     │    │  MODE B: P2P Mesh      │
           │  User's self-hosted   │    │  Direct peer ↔ peer    │
           │  VPS/Raspberry Pi     │    │  (STUN hole-punch)     │
           │  ql-server running    │    │  Relay via user's VPS  │
           │  ql-signal + ql-relay │    │  if direct fails       │
           └───────────────────────┘    └───────────────────────┘
```

### Mode A: Self-Hosted VPN Exit
The user's server (VPS or home device) acts as the VPN exit point. Traffic is encrypted end-to-end with hybrid PQC, routed through the user's server, and exits to the internet from the server's IP. The server runs `qls` (QuantumLink Server), which includes `ql-signal` (peer coordination) and `ql-relay` (encrypted packet forwarder for mesh fallback).

### Mode B: P2P Mesh
Devices connect directly to each other. No traffic flows through any server when direct connection succeeds. STUN servers (Google, Cloudflare, Twilio — no QuantumLink servers) assist with NAT traversal and hole punching. When direct connection fails (e.g., both peers behind CGNAT), the user chooses per-connection: fail gracefully, relay through their own VPS, or route through a community-run open-source relay.

Both modes run simultaneously — a device can be connected to its VPS exit while maintaining direct P2P sessions with personal devices in the mesh.

---

## 4. Cryptographic Architecture

### 4.1 Transport Layer
- **Protocol:** WireGuard (unmodified kernel/userspace)
- **Data encryption:** ChaCha20-Poly1305 (quantum-resistant at 256-bit)
- **Data integrity:** Poly1305 MAC
- **Session key rotation:** Every 180 seconds (WireGuard default)

### 4.2 Key Exchange (Hybrid)
- **Classical component:** X25519 (Curve25519 ECDH)
- **Post-quantum component:** ML-KEM-768 (FIPS 203)
- **Hybrid group:** X25519MLKEM768 (aligned with IETF draft-ietf-tls-ecdhe-mlkem)
- **Shared secret derivation:** `HKDF-SHA3-256(classical_ss || pq_ss, salt="QuantumLink-HybridKEM-v1", info=context)`
- **Security guarantee:** Secure if either X25519 or ML-KEM-768 is unbroken

### 4.3 Authentication (Hybrid — Industry First at Consumer Level)
- **Classical component:** Ed25519 (Curve25519 EdDSA)
- **Post-quantum component:** ML-DSA-65 (FIPS 204)
- **Hybrid scheme:** Both signatures produced and verified; connection rejected if either fails
- **Certificates:** Hybrid X.509 containing both Ed25519 and ML-DSA-65 public keys
- **Rationale:** Closes the authentication gap present in every competing consumer product — protects against active quantum adversaries, not just passive eavesdroppers

### 4.4 Post-Quantum PSK Layer (Rosenpass)
- **Protocol:** Rosenpass (formally verified, ProVerif)
- **Algorithms:** Classic McEliece (authentication) + ML-KEM/Kyber 512 (forward secrecy)
- **Function:** Injects a 256-bit PQ-derived Pre-Shared Key into WireGuard every 120 seconds
- **Scope:** All connections — both VPN exit (Mode A) and P2P mesh (Mode B) sessions
- **Architecture:** Rosenpass runs as a sidecar daemon; WireGuard kernel module is untouched
- **Mesh:** Each device maintains independent Rosenpass sessions with each mesh peer simultaneously

### 4.5 Crypto-Agility Modes

| Mode | Key Exchange | Authentication | Use Case |
|------|-------------|----------------|----------|
| **Classical** | X25519 only | Ed25519 only | Legacy compatibility |
| **Hybrid** *(default)* | X25519 + ML-KEM-768 | Ed25519 + ML-DSA-65 | Recommended for all users |
| **PQ-Only** | ML-KEM-768 only | ML-DSA-65 only | Compliance / max assurance |

Mode is negotiated automatically during handshake; user can override per-connection. Server advertises supported modes; client selects strongest mutual option.

### 4.6 Key Rotation Schedule
- WireGuard session keys: every 180 seconds (automatic)
- Rosenpass PQ PSK: every 120 seconds (automatic)
- Long-term identity keys: generated locally, never transmitted in plaintext, stored in OS keychain
- Device certificates: 24-hour validity by default (configurable), renewable by CA

### 4.7 Algorithm Upgrade Path
- ML-KEM-1024 supported as optional parameter set for CNSA 2.0 compliance
- HQC (NIST 5th algorithm, code-based backup) added when FIPS standard finalizes (~2027)
- SLH-DSA (FIPS 205) available as alternative PQ signature scheme
- FN-DSA/FALCON (FIPS 206, pending) added post-finalization

---

## 5. Features & Functions

### 5.1 VPN Exit Features (Mode A)
- **One-click connect** — connect to user's self-hosted server; PQC happens transparently
- **Automatic server setup** — Manager app deploys `qls` to user's VPS via SSH with a single flow; no manual config
- **Kill switch** — hard and soft modes; platform-level firewall rules block all traffic if tunnel drops
- **DNS leak protection** — all DNS through encrypted tunnel; no system resolver fallback
- **IPv6 leak prevention** — dual-stack with leak-proof IPv6 routing
- **Split tunneling** — per-app and per-domain routing rules
- **LAN bypass** — access local devices while VPN is active
- **Auto-connect** — triggers: startup, untrusted Wi-Fi SSIDs, specific network changes
- **Always-on VPN** — device-managed profiles on iOS/Android
- **DDNS integration** — built-in DuckDNS/Cloudflare DDNS updater in server software for dynamic IPs
- **Obfuscation layer** — pluggable transports (obfs4, Shadowsocks) to defeat DPI-based VPN blocking
- **Multi-hop / Double VPN** — route through two sequential nodes; both hops PQC-secured (v0.3)

### 5.2 P2P Mesh Features (Mode B)
- **Direct device-to-device connections** — WireGuard mesh with full hybrid PQC + Rosenpass PSK
- **NAT traversal** — STUN-assisted UDP hole punching using public servers (no QuantumLink servers required)
  - Auto-detects NAT type (Cone vs. Symmetric)
  - Attempts UPnP/NAT-PMP port mapping for home routers
  - Simultaneous UDP send for hole punching
- **Per-connection relay policy** — user configures per peer: Direct only / Use my VPS relay / Use community relay
- **Dumb relay mode** — user's VPS forwards encrypted WireGuard packets without decrypting them; full E2E PQ encryption preserved through relay
- **Connection path indicator** — UI shows whether each peer connection is Direct P2P or Relayed, with latency
- **Automatic path upgrade** — if direct connection becomes available after starting relayed, upgrade silently
- **Mesh status dashboard** — live view of all peers: connection state, path, latency, packet loss, Rosenpass PSK age

### 5.3 Device Pairing Flows

#### In-Person / QR Code Pairing
- Device A displays a QR code encoding `ql://pair?wgkey=BASE64&rpfp=HASH&rendezvous=HOST&ephkey=BASE64&expires=TS`
- QR contains WireGuard public key (32 bytes) + Rosenpass key fingerprint (since full Classic McEliece keys are 261–524 KB and cannot fit in a QR code)
- Device B scans, triggers a two-phase authenticated exchange over the network to transfer full Rosenpass keys
- Optional emoji verification (5 emoji, derived from SPAKE2 session key) confirms no MITM
- Total time: ~10 seconds

#### Remote Pairing (Magic-Wormhole)
- Device A generates a human-readable code: e.g., `7-guitar-nebula`
- User communicates code to remote party (voice, text, any out-of-band channel)
- Device B enters the code in QuantumLink app
- Both devices perform SPAKE2 authenticated key exchange over user's VPS mailbox (or public Nostr relay fallback)
- SPAKE2 guarantees: attacker gets one guess at a ~1-in-4-million chance of success; failure is immediately detectable
- Full WireGuard + Rosenpass keys exchanged over the authenticated channel
- Total time: ~30 seconds

#### LAN Auto-Discovery
- Devices advertise `_quantumlink._udp.local` via mDNS on port 5353
- Discovered peers appear in UI with a "Pair" button
- Short PIN confirmation on both devices prevents LAN spoofing
- Keys exchange over local network; no VPS needed

#### Setup Key (Adding Devices to Existing Mesh)
- Admin generates a time-limited, single-use setup key from VPS admin panel or CLI
- New device enters setup key, connects to VPS, receives mesh config and peer keys
- Best for adding devices to an established mesh

### 5.4 Identity, Trust & Access Control
- **Offline Certificate Authority** — during setup, user generates a CA keypair. CA private key stays on a single trusted device. Each device receives a short-lived certificate (24h default) signed by the CA
- **Certificate fields:** device name, mesh overlay IP, group memberships (e.g., "personal", "friends", "servers"), validity period
- **Group-based access control** — firewall rules reference certificate groups, not individual keys (e.g., group "friends" can reach port 25565 but not SSH)
- **Device revocation** — three mechanisms:
  1. **Short-lived certificates** (primary): lost device's cert expires naturally within 24h; CA refuses renewal
  2. **Signed blocklist**: CA signs a revocation message, propagated to all devices via VPS signaling hub or peer gossip
  3. **Full re-keying**: generate new CA, re-issue certs to all valid devices (automated)
- **WireGuard-level enforcement:** devices with revoked/expired certs are removed from AllowedIPs atomically

### 5.5 PQC-Specific Features
- **PQC status indicator** — real-time display of active algorithm set in system tray / menu bar
- **Algorithm transparency panel** — shows current KEM, signature scheme, key sizes, last key rotation time, Rosenpass PSK age
- **Harvest-Now-Decrypt-Later explainer** — in-app education requiring no cryptography background
- **PQC audit log** — exportable log of all handshakes, key rotations, and algorithm negotiations
- **Mode override** — force PQ-Only mode per-connection; warns if connecting to non-PQ peer
- **Rosenpass interoperability** — compatible with any Rosenpass-enabled WireGuard peer (NetBird, vanilla Rosenpass)

### 5.6 Privacy Features
- **Zero QuantumLink infrastructure** — no accounts, no logging, no telemetry, no analytics; QuantumLink cannot see your traffic because it has no servers
- **RAM-only server option** — server deployment config designed for ephemeral, stateless operation
- **Anonymous VPS provisioning guide** — documentation for setting up a server with payment methods that preserve anonymity
- **Tor over VPN** — optional routing through Tor after VPN tunnel (v0.3)
- **Transparent warrant canary** — published and cryptographically signed, updated monthly (applies to QuantumLink the project, not your traffic — which we cannot access anyway)

### 5.7 Trust & Transparency Features
- **Reproducible builds** — deterministic build pipeline; users can independently verify binary integrity
- **Published audit reports** — PQC protocol audit, infrastructure audit, all publicly available
- **Formal verification summary** — layman-accessible explanation of what has and has not been formally verified
- **Open server software** — `qls` server daemon published under the same Apache 2.0 license
- **Published threat model** — versioned, public document in repository
- **No telemetry, ever** — no crash reports, usage analytics, or phone-home behavior; source-verifiable

### 5.8 Self-Hosting & Deployment
- **One-command VPS setup** — Manager app SSHes into user's VPS and deploys everything via Docker Compose
- **Raspberry Pi installer** — interactive TUI wizard with automated DDNS setup, mDNS discovery, and UPnP port mapping attempt
- **Auto-update** — `unattended-upgrades` for OS, Watchtower for containers, signed release checks from GitHub (no QuantumLink update server)
- **Minimal server footprint** — WireGuard + Rosenpass + ql-signal + ql-relay runs in ~100MB RAM; usable on a $2/month VPS
- **Compatible hardware** — any Linux VPS or ARM device (Raspberry Pi 3/4/5, Orange Pi, etc.)

### 5.9 Performance Features
- **Adaptive MTU management** — auto-detects optimal MTU accounting for PQC handshake overhead
- **Parallel handshake execution** — classical and PQ components computed concurrently
- **Hardware acceleration** — AES-NI, AVX2 (ML-KEM vectorized path), ARM crypto extensions detected and used automatically
- **Connection pre-warming** — tunnel established in background before user-triggered connect

### 5.10 User Experience
- **Onboarding wizard** — plain-language explanations; no cryptography knowledge required
- **Dark / light mode** — follows OS theme
- **System tray / menu bar app** — persistent status with quick-connect toggle
- **Connection health dashboard** — live throughput, latency, packet loss, PQC key rotation timers
- **Diagnostic log export** — redacted (no key material) exportable logs for support

---

## 6. Platform Support

| Platform | Status | Mode A (VPN Exit) | Mode B (Mesh) | Notes |
|----------|--------|------------------|---------------|-------|
| **Linux** | MVP (v0.1) | ✅ | ✅ | CLI + GTK4 GUI; primary dev platform |
| **macOS** | v0.2 | ✅ | ✅ | Native SwiftUI; Network Extension |
| **Windows** | v0.2 | ✅ | ✅ | WinUI 3; WireGuard Windows driver |
| **Android** | v0.3 | ✅ | ✅ | Kotlin; wireguard-android |
| **iOS** | v0.3 | ✅ | ⚠️ | PQC in app-layer; Rosenpass mobile TBD |

**Rosenpass mobile note:** No production VPN has shipped Rosenpass on iOS/Android as of 2026 (NetBird explicitly excludes mobile). QuantumLink targets being the first, but iOS background execution constraints may require Rosenpass to run inside the Network Extension rather than as a separate process. This is a v0.3 research item.

---

## 7. Security Properties & Threat Model

### Protected Against
- **Passive quantum adversary (harvest-now-decrypt-later):** ML-KEM-768 hybrid key exchange
- **Active quantum adversary:** ML-DSA-65 hybrid authentication; cannot impersonate endpoints
- **Classical adversary (present):** X25519 + Ed25519 provide the classical security floor
- **Relay-node compromise:** Dumb relay forwards encrypted ciphertext; relay has no keys and sees no plaintext
- **QuantumLink company compromise:** Company has no servers, no accounts, no keys — nothing to compromise
- **Traffic analysis (partial):** P2P direct connections eliminate server-side metadata; multi-hop available
- **DNS leaks, IPv6 leaks, WebRTC leaks:** Blocked at daemon/firewall level
- **Harvest-now-decrypt-later on mesh traffic:** Rosenpass PSK rotates every 120 seconds; all sessions get PQ forward secrecy

### Not Protected Against (explicit scope)
- Endpoint compromise (malware on user's device or VPS)
- Legal compulsion of user (user holds all key material)
- Novel lattice attacks on ML-KEM before algorithm rotation (HQC backup on roadmap as mitigation)
- Traffic timing correlation at the network level
- A malicious VPS provider with hypervisor-level memory introspection (mitigated by RAM-only config and VPS selection guidance)

### Trust Model Comparison

| Scenario | Commercial VPN | QuantumLink |
|----------|---------------|-------------|
| Provider sees your traffic | Yes (must trust no-logs claim) | **No** (provider has no servers) |
| Provider can be subpoenaed for logs | Yes | **No logs exist anywhere** |
| Provider infrastructure compromised | All users affected | **Only your VPS affected** |
| Cryptographic implementation auditable | No | **Yes (open source)** |
| PQC key exchange | Yes (most providers) | **Yes** |
| PQC authentication | No (industry gap) | **Yes (first consumer product)** |

---

## 8. Server Infrastructure Model

QuantumLink operates under a **fully sovereign model**:

- **QuantumLink Inc operates zero servers** — no relay, no coordination, no update, no telemetry
- Users deploy `qls` on their own VPS or home server
- `qls` includes three services:
  - `ql-server` — WireGuard VPN exit (Mode A)
  - `ql-signal` — peer coordination, pairing mailbox, STUN-assisted hole punch signaling
  - `ql-relay` — dumb UDP packet forwarder for mesh fallback (Mode B, optional)
- Community relay nodes (v0.3) — anyone can run a public `ql-relay` instance; clients choose to trust specific relays per-connection
- Recommended minimum VPS specs: 1 vCPU, 512 MB RAM, any Linux distro — ~$2–4/month (BuyVM, Hetzner)

---

## 9. Pricing Model

| Tier | Price | Features |
|------|-------|---------|
| **Free** | $0 | Full software, unlimited devices, all features. User provides their own server. |

**QuantumLink has no subscription.** The software is free and open source. Users pay only for their own VPS (~$2–4/month to a third-party provider of their choice). QuantumLink generates no revenue from traffic or data.

**Sustainability model (roadmap):** Optional paid support tier, donations, and grants (NLnet/NGI Assure, similar to Rosenpass). Corporate dual-licensing of enterprise features if needed.

---

## 10. Competitive Differentiation Matrix

| Feature | QuantumLink | NordVPN | Mullvad | NetBird | Tailscale | Nebula |
|---------|------------|---------|---------|---------|-----------|--------|
| Zero vendor infrastructure | ✅ | ❌ | ❌ | ⚠️ (self-host servers) | ❌ | ✅ (lighthouse) |
| Open source (full stack) | ✅ | ❌ | Partial | Partial | Partial | ✅ |
| PQC key exchange | ✅ ML-KEM-768 | ✅ | ✅ McEliece+ML-KEM | ✅ Rosenpass | ❌ | ❌ |
| **PQC authentication** | ✅ ML-DSA-65 | 🔜 2026 | ❌ | ❌ | ❌ | ❌ |
| P2P mesh networking | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| Mesh + PQC combined | ✅ | ❌ | ❌ | ✅ (Rosenpass) | ❌ | ❌ |
| No account required | ✅ | ❌ | ✅ (anon) | ❌ | ❌ | ✅ |
| Consumer GUI + mobile | ✅ | ✅ | ✅ | ⚠️ | ✅ | ❌ |
| Magic-wormhole pairing | ✅ | N/A | N/A | ❌ | ❌ | ❌ |
| Dumb relay (E2E preserved) | ✅ | N/A | N/A | ❌ | ❌ | ❌ |
| Short-lived cert revocation | ✅ | N/A | N/A | ❌ | ❌ | ✅ |
| Reproducible builds | ✅ | ❌ | ✅ | ❌ | ❌ | N/A |
| Dedicated PQC audit | ✅ (pre-v1) | ❌ | ❌ | ❌ | ❌ | N/A |
| Free (no subscription) | ✅ | ❌ | ❌ | Freemium | Freemium | ✅ |

---

## 11. Development Roadmap

### v0.1 — Foundation (Target: Q3 2026)
**VPN Exit mode (Mode A) — Linux only**
- Linux CLI daemon (`qld`) + `qls` server daemon
- WireGuard + Rosenpass PSK injection (VPN exit mode)
- Hybrid ML-KEM-768 + X25519 key exchange
- Hybrid ML-DSA-65 + Ed25519 authentication
- Kill switch + DNS leak protection (nftables)
- Manager app: SSH-based VPS deployment wizard
- DDNS integration (DuckDNS + Cloudflare)
- Linux GTK4 GUI: connect/disconnect, PQC status panel
- Basic `ql-signal` server (peer registration, DDNS mailbox)

### v0.2 — Desktop Parity + Mesh Beta (Target: Q1 2027)
- macOS and Windows GUI apps
- **Mesh P2P (Mode B) — desktop platforms**
  - `ql-stun` NAT traversal (STUN + UPnP/NAT-PMP + hole punching)
  - `ql-mesh` daemon for peer lifecycle management
  - `ql-pair` with QR code and magic-wormhole pairing flows
  - `ql-relay` dumb UDP forwarder on VPS
  - LAN mDNS auto-discovery
  - Per-connection relay policy (fail / self-hosted / community)
- Split tunneling
- Device certificate CA + offline cert generation
- Published third-party PQC security audit
- Mesh connection dashboard

### v0.3 — Mobile + Advanced Features (Target: Q3 2027)
- **iOS and Android apps**
  - Rosenpass on mobile (Network Extension integration, research item)
  - QR code pairing on mobile
  - Always-on VPN profiles
- Multi-hop / Double VPN
- Tor over VPN integration
- Obfuscation layer (obfs4 + Shadowsocks)
- Group-based access control (certificate groups + firewall rules)
- Device revocation (signed blocklist + gossip propagation)
- Formal verification of core protocol (published)
- Community relay node support (opt-in per-connection)

### v1.0 — Production Release (Target: Q1 2028)
- Reproducible builds for all platforms
- Full published audit suite (PQC protocol, infrastructure, threat model)
- HQC backup KEM integration (NIST 5th algorithm)
- PQ-Only mode for CNSA 2.0 compliance
- Hardware security key support (YubiKey, FIDO2)
- Signed relay registry (community-contributed relay nodes with reputation)
- Formal verification published and independently reviewed

---

## 12. Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Core daemon (`qld`, `qls`) | **Rust** | Memory safety, performance, Rosenpass/WireGuard ecosystem alignment |
| PQC primitives | **liboqs** + **wolfSSL** | Dual-library: liboqs for breadth, wolfSSL for FIPS-validated path |
| WireGuard integration | **boringtun** (userspace Rust) | Cross-platform, no kernel module required, mobile-compatible |
| Rosenpass | **rosenpass** crate + **go-rosenpass** (mobile) | Formally verified; go-rosenpass for iOS/Android integration |
| STUN/NAT traversal | **stun_rs** + custom socket-sharing | Must share WireGuard's UDP socket for correct NAT mapping |
| Pairing (SPAKE2) | **spake2** Rust crate | Magic-wormhole-style PAKE; proven low-entropy key exchange |
| mDNS discovery | **mdns-sd** Rust crate | LAN peer discovery |
| Signaling server | **Rust async** (tokio) | Lightweight; stateless per-session; same codebase as client |
| Relay server | **wpex-style UDP forwarder** (Rust) | Dumb forwarder; no decryption; zero MTU overhead |
| GUI — Linux | **GTK4 + Relm4** | Native, lightweight |
| GUI — macOS | **SwiftUI** | Required for Network Extension integration |
| GUI — Windows | **WinUI 3** (windows-rs bindings) | WireGuard Windows driver compatibility |
| GUI — Mobile | **Flutter** (Dart + Rust FFI) | Code sharing between iOS and Android |
| Build system | **Cargo + Nix flakes** | Reproducible builds |
| CI/CD | **GitHub Actions + Sigstore/cosign** | Signed, attestable release artifacts |
| Containers | **Docker Compose** | Single-command server deployment |

---

## 13. Key Design Decisions & Rationale

### Why Rosenpass over building our own PQC WireGuard extension?
Rosenpass is formally verified (ProVerif), EU-funded, actively maintained, and already proven in production (NetBird ships it). Re-implementing is unjustifiable risk for a security-critical component. We add value by building the consumer layer on top, not the cryptographic protocol underneath.

### Why Classic McEliece in Rosenpass despite 261–524 KB public keys?
McEliece has 50+ years of cryptanalytic scrutiny — the longest track record of any PQC candidate. The large key sizes are a one-time exchange cost during pairing (handled by our two-phase protocol), not a per-handshake cost. This is Rosenpass's design choice and we inherit it deliberately.

### Why dumb relay instead of hub-and-spoke WireGuard for mesh fallback?
Hub-and-spoke relay decrypts and re-encrypts at the relay node — the relay operator sees all plaintext. A dumb UDP forwarder (wpex-style) relays already-encrypted WireGuard ciphertext without any keys. The relay is blind. This is the only relay architecture compatible with our zero-trust threat model. The user's VPS acting as a dumb relay still cannot read their mesh traffic.

### Why SPAKE2 for magic-wormhole pairing?
SPAKE2 provides cryptographic authentication from low-entropy shared secrets (a short human-readable code). An attacker performing MITM gets one guess with a ~1-in-4-million success probability. Failure is immediately detectable by both parties. This is exactly the right primitive for a pairing code that users communicate verbally or over an insecure channel.

### Why short-lived certificates (24h) for device revocation?
In a serverless mesh, there is no online authority to check revocation status in real time. Short certificate lifetimes bound the worst case: a compromised device loses access within 24 hours without any explicit revocation action, as long as the CA (user's phone or VPS) refuses renewal. This mirrors Nebula's recommended revocation strategy and eliminates the need for a real-time CRL/OCSP infrastructure.

### Why no QuantumLink subscription or hosted tier?
The privacy guarantee is unambiguous only when QuantumLink has zero access to user traffic. Any hosted tier creates the possibility of logging. The zero-infrastructure model is the product's core trust claim — a hosted tier would contradict it. Revenue comes from optional support, donations, and grants.

---

## 14. Open Source & Governance

- **License:** Apache 2.0 (permissive; encourages adoption without copyleft friction)
- **Governance:** BDFL during development → Steering Committee at v1.0
- **Security disclosures:** Responsible disclosure policy; HackerOne program at v0.2
- **Funding:** Donations + NLnet/NGI grant applications + optional corporate support tiers
- **Contributor agreement:** DCO (Developer Certificate of Origin), not CLA
- **Telemetry:** None, ever. Source-verifiable.
