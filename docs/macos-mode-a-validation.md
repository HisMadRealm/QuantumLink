# macOS Mode A Validation

## Purpose

Validate the real macOS Mode A runtime path against a self-hosted server using:

- the Xcode-built `QuantumLinkMacApp` container app and `QuantumLinkPacketTunnelProvider` extension
- the Rust `ql-macos-app` localhost service
- the Swift `QuantumLinkTunnelController`
- the macOS PF-backed `ql-macos-helper`

## Prerequisites

1. Install full Xcode and make it active with `sudo xcode-select -s /Applications/Xcode.app/Contents/Developer`.
2. Open `macos/QuantumLinkMacApp/QuantumLinkMacApp.xcodeproj` and set your signing team for:
   - `QuantumLinkMacApp`
   - `QuantumLinkPacketTunnelProvider`
   - or export `QUANTUMLINK_DEVELOPMENT_TEAM=<team_id>` and use `macos/QuantumLinkMacApp/Scripts/archive_release.sh` for the archive path
3. Build and run the app target once from Xcode so the packet tunnel extension is installed and authorized by macOS.
4. Build the Rust runtime binaries:
   - `cargo build -p ql-macos-app -p ql-macos-helper`
5. Build the Swift tunnel controller:
   - `cd macos/QuantumLinkMacApp && swift build`

## Tunnel Config

Export `QL_MODE_A_TUNNEL_CONFIG_JSON` with a real tunnel configuration, or point `QL_MODE_A_TUNNEL_CONFIG_FILE` at a JSON file with the same shape:

```json
{
  "interface_name": "ql0",
  "interface_addresses": ["10.0.0.2/32"],
  "private_key": [1, 2, 3],
  "listen_port": 51820,
  "peer_public_key": [4, 5, 6],
  "peer_endpoint": "198.51.100.8:51820",
  "allowed_ips": ["0.0.0.0/0"],
  "persistent_keepalive": 25,
  "dns_servers": ["10.0.0.1"],
  "mtu": 1420
}
```

Notes:

- `interface_addresses` is required for the real WireGuardKit path.
- `private_key` and `peer_public_key` are raw 32-byte arrays to match the current Rust bridge contract.
- `peer_endpoint` should point at the real self-hosted server.

## Validation Script

Run:

```bash
./macos/QuantumLinkMacApp/Scripts/mode_a_validate.sh
```

Default environment assumptions:

- `QL_MACOS_APP_MODE=network-extension`
- `QL_MACOS_TUNNEL_CONTROLLER=macos/QuantumLinkMacApp/.build/debug/QuantumLinkTunnelController`
- `QL_MACOS_FIREWALL_HELPER=target/debug/ql-macos-helper`
- `QL_MACOS_TUNNEL_EXTENSION_BUNDLE_ID=com.quantumlink.macos.PacketTunnelProvider`
- `QL_MACOS_HELPER_BACKEND=pf`
- `QL_MODE_A_PROBE_URL=https://api.ipify.org`

Optional overrides:

- `SKIP_BUILD=1` if all binaries are already built
- `QL_MACOS_APP_BINARY` to point at a non-default `ql-macos-app`
- `QL_MODE_A_CONNECT_WAIT_SECS` to allow a slower tunnel handshake window
- `QL_MACOS_APP_SERVICE_PORT` to avoid port collisions
- `QL_MODE_A_TUNNEL_CONFIG_FILE` to load the tunnel JSON from disk instead of the environment

## What The Script Verifies

1. The localhost runtime service becomes healthy.
2. `/status` starts disconnected.
3. `/mode-a/connect` drives the native tunnel controller and PF helper.
4. `/status` reports `tunnel_active=true` and `firewall_active=true`.
5. The PF anchor `com.apple/250.QuantumLink.<interface>` contains rules while connected.
6. `/mode-a/disconnect` tears down the session.
7. `/status` returns to a disconnected and firewall-inactive state.
8. The PF anchor is empty after disconnect.

## Current Limits

- This repository now contains the real Xcode app+extension project path and a WireGuardKit-backed provider implementation, but this environment still does not have full Xcode available, so `xcodebuild` validation was not run here.
- The validation flow depends on a signed and installed packet tunnel extension. The SwiftPM build alone is not sufficient for that path.
- The WireGuardKit data plane now requires `interface_addresses` in the bridge contract. Any older config payload without that field will fail validation.
