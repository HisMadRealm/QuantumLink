#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
PROJECT_DIR="$ROOT/macos/QuantumLinkMacApp"
PROJECT_PATH="$PROJECT_DIR/QuantumLinkMacApp.xcodeproj"
SCHEME="${QL_MACOS_XCODE_SCHEME:-QuantumLinkMacApp}"
TEAM_ID="${QUANTUMLINK_DEVELOPMENT_TEAM:-${QL_APPLE_TEAM_ID:-}}"
ARCHIVE_PATH="${QL_MACOS_ARCHIVE_PATH:-$ROOT/build/QuantumLinkMacApp.xcarchive}"
EXPORT_PATH="${QL_MACOS_EXPORT_PATH:-$ROOT/build/export}"
DERIVED_DATA_PATH="${QL_MACOS_DERIVED_DATA_PATH:-$ROOT/build/DerivedData}"
CONFIGURATION="${QL_MACOS_XCODE_CONFIGURATION:-Release}"
EXPORT_METHOD="${QL_MACOS_EXPORT_METHOD:-developer-id}"
NOTARY_PROFILE="${QL_NOTARY_KEYCHAIN_PROFILE:-}"

if [[ -z "$TEAM_ID" ]]; then
  echo "error: set QUANTUMLINK_DEVELOPMENT_TEAM or QL_APPLE_TEAM_ID before archiving" >&2
  exit 1
fi

if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "error: xcodebuild is unavailable; install full Xcode and select it with xcode-select" >&2
  exit 1
fi

if ! command -v ruby >/dev/null 2>&1; then
  echo "error: ruby is required to generate the Xcode project" >&2
  exit 1
fi

ruby "$PROJECT_DIR/Scripts/generate_xcodeproj.rb" >/dev/null

mkdir -p "$(dirname "$ARCHIVE_PATH")" "$EXPORT_PATH" "$DERIVED_DATA_PATH"

TMP_EXPORT_OPTIONS="$(mktemp "${TMPDIR:-/tmp}/quantumlink-export-options.XXXXXX.plist")"
cleanup() {
  rm -f "$TMP_EXPORT_OPTIONS"
}
trap cleanup EXIT

cat >"$TMP_EXPORT_OPTIONS" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>method</key>
	<string>$EXPORT_METHOD</string>
	<key>signingStyle</key>
	<string>automatic</string>
	<key>teamID</key>
	<string>$TEAM_ID</string>
</dict>
</plist>
PLIST

xcodebuild \
  -project "$PROJECT_PATH" \
  -scheme "$SCHEME" \
  -configuration "$CONFIGURATION" \
  -destination "platform=macOS" \
  -derivedDataPath "$DERIVED_DATA_PATH" \
  -archivePath "$ARCHIVE_PATH" \
  QUANTUMLINK_DEVELOPMENT_TEAM="$TEAM_ID" \
  archive

xcodebuild \
  -exportArchive \
  -archivePath "$ARCHIVE_PATH" \
  -exportPath "$EXPORT_PATH" \
  -exportOptionsPlist "$TMP_EXPORT_OPTIONS" \
  QUANTUMLINK_DEVELOPMENT_TEAM="$TEAM_ID"

APP_PATH="$(find "$EXPORT_PATH" -maxdepth 1 -name '*.app' -print -quit)"
if [[ -z "$APP_PATH" ]]; then
  echo "error: no exported .app was found under $EXPORT_PATH" >&2
  exit 1
fi

echo "Exported app: $APP_PATH"

if [[ -n "$NOTARY_PROFILE" ]]; then
  if ! command -v xcrun >/dev/null 2>&1; then
    echo "error: xcrun is unavailable; cannot notarize" >&2
    exit 1
  fi

  ZIP_PATH="$EXPORT_PATH/$(basename "${APP_PATH%.app}").zip"
  rm -f "$ZIP_PATH"
  ditto -c -k --keepParent "$APP_PATH" "$ZIP_PATH"
  xcrun notarytool submit "$ZIP_PATH" --keychain-profile "$NOTARY_PROFILE" --wait
  echo "Notary submission completed for $ZIP_PATH"
fi
