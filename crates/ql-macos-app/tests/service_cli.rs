use std::io::Read;
use std::net::TcpListener;
#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

#[cfg(target_os = "macos")]
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    time::{SystemTime, UNIX_EPOCH},
};

struct ServiceProcess {
    child: Child,
}

impl Drop for ServiceProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl ServiceProcess {
    fn exit_error(&mut self) -> Option<String> {
        match self.child.try_wait() {
            Ok(Some(status)) => {
                let mut stderr = String::new();
                if let Some(stderr_pipe) = self.child.stderr.as_mut() {
                    let _ = stderr_pipe.read_to_string(&mut stderr);
                }
                Some(format!("service exited with status {status}: {stderr}"))
            }
            Ok(None) => None,
            Err(error) => Some(format!("failed to inspect service process: {error}")),
        }
    }
}

#[test]
fn serve_command_exposes_health_and_status_endpoints() {
    let port = free_port();
    let mut service = spawn_service(port);
    wait_for_service(&mut service, port);

    let (health_status, health_body) = http_request(port, "GET", "/health");
    assert_eq!(health_status, 200);
    let health_json: serde_json::Value = serde_json::from_str(&health_body).unwrap();
    assert_eq!(health_json["status"], "ok");

    let (status_code, status_body) = http_request(port, "GET", "/status");
    assert_eq!(status_code, 200);
    let status_json: serde_json::Value = serde_json::from_str(&status_body).unwrap();
    assert_eq!(status_json["adapter_mode"], "stub");
    assert_eq!(status_json["connection_state"], "disconnected");

    #[cfg(target_os = "macos")]
    {
        let (connect_status, connect_body) =
            http_request(port, "POST", "/mode-a/connect?server=203.0.113.10:51820");
        assert_eq!(connect_status, 200);
        let connect_json: serde_json::Value = serde_json::from_str(&connect_body).unwrap();
        assert_eq!(connect_json["adapter_mode"], "stub");
        assert_eq!(connect_json["operations"].as_array().unwrap().len(), 2);

        let (bad_status, bad_body) =
            http_request(port, "POST", "/mode-a/connect?server=bad-endpoint");
        assert_eq!(bad_status, 400);
        assert!(bad_body.contains("invalid server socket address"));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn serve_command_supports_network_extension_tunnel_mode_without_firewall_bridge() {
    let port = free_port();
    let temp_root = unique_temp_path("ql-network-extension-service-cli");
    fs::create_dir_all(&temp_root).unwrap();
    let controller_path = temp_root.join("mock-tunnel-controller.sh");
    let state_path = temp_root.join("controller-state.json");
    write_mock_tunnel_controller(&controller_path);

    let mut service = spawn_service_with_env(
        port,
        &[
            ("QL_MACOS_APP_MODE", "network-extension"),
            (
                "QL_MACOS_TUNNEL_CONTROLLER",
                controller_path
                    .to_str()
                    .expect("controller path should be valid UTF-8"),
            ),
            (
                "QL_MACOS_TUNNEL_CONTROLLER_STATE",
                state_path
                    .to_str()
                    .expect("state path should be valid UTF-8"),
            ),
        ],
    );
    wait_for_service(&mut service, port);

    let (initial_status, initial_body) = http_request(port, "GET", "/status");
    assert_eq!(initial_status, 200);
    let initial_json: serde_json::Value = serde_json::from_str(&initial_body).unwrap();
    assert_eq!(initial_json["adapter_mode"], "network-extension");
    assert_eq!(initial_json["connection_state"], "disconnected");

    let (connect_status, connect_body) =
        http_request(port, "POST", "/mode-a/connect?server=203.0.113.10:51820");
    assert_eq!(connect_status, 200);
    let connect_json: serde_json::Value = serde_json::from_str(&connect_body).unwrap();
    assert_eq!(connect_json["adapter_mode"], "network-extension");
    assert_eq!(connect_json["operations"].as_array().unwrap().len(), 1);
    assert_eq!(connect_json["operations"][0]["target"], "tunnel");

    let (connected_status, connected_body) = http_request(port, "GET", "/status");
    assert_eq!(connected_status, 200);
    let connected_json: serde_json::Value = serde_json::from_str(&connected_body).unwrap();
    assert_eq!(connected_json["connection_state"], "connected");
    assert_eq!(
        connected_json["tray_status"],
        "connected:mode-a-network-extension"
    );
    assert_eq!(connected_json["session"]["tunnel_active"], true);
    assert_eq!(connected_json["session"]["firewall_active"], false);

    let (disconnect_status, disconnect_body) = http_request(port, "POST", "/mode-a/disconnect");
    assert_eq!(disconnect_status, 200);
    let disconnect_json: serde_json::Value = serde_json::from_str(&disconnect_body).unwrap();
    assert_eq!(disconnect_json["adapter_mode"], "network-extension");
    assert_eq!(disconnect_json["operations"].as_array().unwrap().len(), 1);
    assert_eq!(disconnect_json["operations"][0]["target"], "tunnel");

    let (final_status, final_body) = http_request(port, "GET", "/status");
    assert_eq!(final_status, 200);
    let final_json: serde_json::Value = serde_json::from_str(&final_body).unwrap();
    assert_eq!(final_json["connection_state"], "disconnected");
    assert_eq!(final_json["session"]["tunnel_active"], false);

    let _ = fs::remove_file(controller_path);
    let _ = fs::remove_file(state_path);
    let _ = fs::remove_dir(temp_root);
}

fn spawn_service(port: u16) -> ServiceProcess {
    spawn_service_with_env(port, &[("QL_MACOS_APP_MODE", "stub")])
}

fn spawn_service_with_env(port: u16, envs: &[(&str, &str)]) -> ServiceProcess {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ql-macos-app"));
    command.arg("serve");
    command.arg(port.to_string());
    for (key, value) in envs {
        command.env(key, value);
    }

    let child = command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn ql-macos-app serve process");

    ServiceProcess { child }
}

#[cfg(target_os = "macos")]
fn unique_temp_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nanos}"))
}

#[cfg(target_os = "macos")]
fn write_mock_tunnel_controller(path: &Path) {
    let script = r#"#!/bin/sh
set -eu

target="$1"
operation="$2"
payload="$3"
state_path="${QL_MACOS_TUNNEL_CONTROLLER_STATE:?missing controller state path}"

if [ "$target" != "tunnel" ]; then
  echo "unsupported target: $target" >&2
  exit 1
fi

active=false
if [ -f "$state_path" ] && grep -q '"tunnel_active":true' "$state_path"; then
  active=true
fi

case "$operation" in
  activate)
    active=true
    ;;
  deactivate)
    active=false
    ;;
  update-endpoint|inject-psk|read-stats)
    ;;
  *)
    echo "unsupported operation: $operation" >&2
    exit 1
    ;;
esac

if [ "$active" = true ]; then
  stats='{"bytes_sent":512,"bytes_received":1024,"last_handshake_secs":0}'
else
  stats='{"bytes_sent":0,"bytes_received":0,"last_handshake_secs":null}'
fi

mkdir -p "$(dirname "$state_path")"
printf '{"tunnel_active":%s}\n' "$active" > "$state_path"
printf '{"target":"tunnel","operation":"%s","accepted":true,"message":"mock native tunnel controller","state":{"tunnel_active":%s},"tunnel_stats":%s}\n' "$operation" "$active" "$stats"

case "$payload" in
  *'"driver":"network-extension"'*)
    ;;
  *)
    echo "missing network-extension driver" >&2
    exit 1
    ;;
esac
"#;
    fs::write(path, script).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn wait_for_service(service: &mut ServiceProcess, port: u16) {
    for _ in 0..40 {
        if let Some(error) = service.exit_error() {
            panic!("service failed before health check: {error}");
        }
        if let Ok((status, _)) = try_http_request(port, "GET", "/health") {
            if status == 200 {
                return;
            }
        }
        thread::sleep(Duration::from_millis(150));
    }

    panic!(
        "timed out waiting for ql-macos-app service on port {port}: {}",
        service
            .exit_error()
            .unwrap_or_else(|| "service still running without health response".to_owned())
    );
}

fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("failed to allocate test port");
    listener.local_addr().unwrap().port()
}

fn http_request(port: u16, method: &str, path: &str) -> (u16, String) {
    try_http_request(port, method, path)
        .unwrap_or_else(|error| panic!("http request failed: {error}"))
}

fn try_http_request(port: u16, method: &str, path: &str) -> Result<(u16, String), String> {
    let output = Command::new("curl")
        .args([
            "-sS",
            "-X",
            method,
            "-o",
            "-",
            "-w",
            "\n%{http_code}",
            &format!("http://127.0.0.1:{port}{path}"),
        ])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }

    let response = String::from_utf8(output.stdout).map_err(|error| error.to_string())?;
    let (body, status) = response
        .rsplit_once('\n')
        .ok_or_else(|| "missing curl status output".to_owned())?;
    Ok((
        status
            .trim()
            .parse::<u16>()
            .map_err(|error| error.to_string())?,
        body.to_owned(),
    ))
}
