#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
PORT="${QL_MACOS_APP_SERVICE_PORT:-58421}"
APP_BINARY="${QL_MACOS_APP_BINARY:-$ROOT/target/debug/ql-macos-app}"
CONTROLLER_BINARY="${QL_MACOS_TUNNEL_CONTROLLER:-$ROOT/macos/QuantumLinkMacApp/.build/debug/QuantumLinkTunnelController}"
FIREWALL_HELPER_BINARY="${QL_MACOS_FIREWALL_HELPER:-$ROOT/target/debug/ql-macos-helper}"
PROBE_URL="${QL_MODE_A_PROBE_URL:-https://api.ipify.org}"
CONNECT_WAIT_SECS="${QL_MODE_A_CONNECT_WAIT_SECS:-5}"
STATE_FILE="${QL_MACOS_HELPER_STATE:-$ROOT/target/macos-mode-a-helper-state.json}"

export QL_MACOS_APP_MODE="${QL_MACOS_APP_MODE:-network-extension}"
export QL_MACOS_APP_SERVICE_PORT="$PORT"
export QL_MACOS_TUNNEL_CONTROLLER="$CONTROLLER_BINARY"
export QL_MACOS_FIREWALL_HELPER="$FIREWALL_HELPER_BINARY"
export QL_MACOS_TUNNEL_EXTENSION_BUNDLE_ID="${QL_MACOS_TUNNEL_EXTENSION_BUNDLE_ID:-com.quantumlink.macos.PacketTunnelProvider}"
export QL_MACOS_HELPER_BACKEND="${QL_MACOS_HELPER_BACKEND:-pf}"
export QL_MACOS_HELPER_STATE="$STATE_FILE"

if [[ -z "${QL_MODE_A_TUNNEL_CONFIG_JSON:-}" && -n "${QL_MODE_A_TUNNEL_CONFIG_FILE:-}" ]]; then
  if [[ ! -f "$QL_MODE_A_TUNNEL_CONFIG_FILE" ]]; then
    echo "error: QL_MODE_A_TUNNEL_CONFIG_FILE does not exist: $QL_MODE_A_TUNNEL_CONFIG_FILE" >&2
    exit 1
  fi
  export QL_MODE_A_TUNNEL_CONFIG_JSON="$(cat "$QL_MODE_A_TUNNEL_CONFIG_FILE")"
fi

if [[ -z "${QL_MODE_A_TUNNEL_CONFIG_JSON:-}" ]]; then
  echo "error: set QL_MODE_A_TUNNEL_CONFIG_JSON or QL_MODE_A_TUNNEL_CONFIG_FILE with the real Mode A tunnel config" >&2
  exit 1
fi

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  cargo build -p ql-macos-app -p ql-macos-helper >/dev/null
  (cd "$ROOT/macos/QuantumLinkMacApp" && swift build >/dev/null)
fi

for path in "$APP_BINARY" "$CONTROLLER_BINARY" "$FIREWALL_HELPER_BINARY"; do
  if [[ ! -x "$path" ]]; then
    echo "error: expected executable at $path" >&2
    exit 1
  fi
done

ANCHOR_NAME="$(python3 - <<'PY'
import json, os
cfg = json.loads(os.environ['QL_MODE_A_TUNNEL_CONFIG_JSON'])
interface_name = cfg.get('interface_name') or 'ql0'
print(f'com.apple/250.QuantumLink.{interface_name}')
PY
)"

APP_PID=""
cleanup() {
  set +e
  if [[ -n "$APP_PID" ]]; then
    curl -fsS -X POST "http://127.0.0.1:$PORT/mode-a/disconnect" >/dev/null 2>&1 || true
    kill "$APP_PID" >/dev/null 2>&1 || true
    wait "$APP_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_for_health() {
  for _ in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "error: runtime service did not become healthy on port $PORT" >&2
  exit 1
}

assert_status() {
  local expected_tunnel="$1"
  local expected_firewall="$2"
  local payload
  payload="$(curl -fsS "http://127.0.0.1:$PORT/status")"
  echo "$payload"
  python3 - <<'PY' "$expected_tunnel" "$expected_firewall" "$payload"
import json, sys
expected_tunnel = sys.argv[1].lower() == 'true'
expected_firewall = sys.argv[2].lower() == 'true'
payload = json.loads(sys.argv[3])
session = payload.get('session') or {}
actual_tunnel = bool(session.get('tunnel_active', False))
actual_firewall = bool(session.get('firewall_active', False))
if actual_tunnel != expected_tunnel:
    raise SystemExit(f'expected tunnel_active={expected_tunnel}, got {actual_tunnel}')
if actual_firewall != expected_firewall:
    raise SystemExit(f'expected firewall_active={expected_firewall}, got {actual_firewall}')
PY
}

"$APP_BINARY" serve "$PORT" >/tmp/quantumlink-mode-a-validate.stdout 2>/tmp/quantumlink-mode-a-validate.stderr &
APP_PID="$!"
wait_for_health

echo "== Initial status =="
assert_status false false

echo "== Connect =="
CONNECT_PAYLOAD="$(curl -fsS -X POST "http://127.0.0.1:$PORT/mode-a/connect")"
echo "$CONNECT_PAYLOAD"

sleep "$CONNECT_WAIT_SECS"

if [[ -n "$PROBE_URL" ]]; then
  echo "== Probe traffic =="
  curl -fsS "$PROBE_URL" || true
  echo
fi

echo "== Connected status =="
assert_status true true

if [[ "$QL_MACOS_HELPER_BACKEND" == "pf" ]]; then
  echo "== PF rules =="
  pfctl -a "$ANCHOR_NAME" -s rules
fi

echo "== Disconnect =="
DISCONNECT_PAYLOAD="$(curl -fsS -X POST "http://127.0.0.1:$PORT/mode-a/disconnect")"
echo "$DISCONNECT_PAYLOAD"

echo "== Final status =="
assert_status false false

if [[ "$QL_MACOS_HELPER_BACKEND" == "pf" ]]; then
  RULES_AFTER_DISCONNECT="$(pfctl -a "$ANCHOR_NAME" -s rules || true)"
  if [[ -n "$RULES_AFTER_DISCONNECT" ]]; then
    echo "error: PF anchor $ANCHOR_NAME still has rules after disconnect" >&2
    exit 1
  fi
fi

echo "Mode A validation completed"
