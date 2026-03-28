# macOS Distribution Path

## Purpose

Document the signed archive and notarization-ready path for the generated macOS app plus Packet Tunnel Provider product.

## Prerequisites

1. Install full Xcode and make it active:
   - `sudo xcode-select -s /Applications/Xcode.app/Contents/Developer`
2. Install the Ruby `xcodeproj` gem if it is not already present:
   - `gem install --user-install xcodeproj --no-document`
3. Set an Apple signing team:
   - `export QUANTUMLINK_DEVELOPMENT_TEAM=<team_id>`
4. If you want the script to submit for notarization, create a notarytool keychain profile first and export:
   - `export QL_NOTARY_KEYCHAIN_PROFILE=<profile_name>`

## Archive And Export

Run:

```bash
./macos/QuantumLinkMacApp/Scripts/archive_release.sh
```

What the script does:

1. Regenerates `macos/QuantumLinkMacApp/QuantumLinkMacApp.xcodeproj`.
2. Archives the `QuantumLinkMacApp` scheme in `Release`.
3. Exports a signed `.app` using automatic signing and the configured team ID.
4. If `QL_NOTARY_KEYCHAIN_PROFILE` is set, zips the exported `.app` and submits it with `notarytool`.

Default paths:

- archive: `build/QuantumLinkMacApp.xcarchive`
- export: `build/export`
- derived data: `build/DerivedData`

Optional overrides:

- `QL_MACOS_XCODE_SCHEME`
- `QL_MACOS_XCODE_CONFIGURATION`
- `QL_MACOS_ARCHIVE_PATH`
- `QL_MACOS_EXPORT_PATH`
- `QL_MACOS_DERIVED_DATA_PATH`
- `QL_MACOS_EXPORT_METHOD`

## Project Settings Used

The generated project now centralizes signing and release behavior in:

- `macos/QuantumLinkMacApp/Config/Signing.xcconfig`
- `macos/QuantumLinkMacApp/Config/QuantumLinkMacApp.xcconfig`
- `macos/QuantumLinkMacApp/Config/QuantumLinkPacketTunnelProvider.xcconfig`

Important defaults:

- automatic signing through `QUANTUMLINK_DEVELOPMENT_TEAM`
- hardened runtime enabled
- release builds emit dSYMs
- release builds strip installed products
- the Packet Tunnel Provider uses the deeper framework runpath needed for an app extension bundled inside a macOS app

## Current Limits

- This path is prepared in-repo, but it has not been exercised in this environment because full Xcode is unavailable here.
- The `QuantumLinkTunnelController` target remains a developer utility target and is not part of the signed release archive path.
