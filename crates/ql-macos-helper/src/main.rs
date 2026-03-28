//! Stateful helper contract for the macOS runtime adapter.

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::{self, Command, Stdio};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, PartialEq, Eq)]
struct HelperAck {
    target: String,
    operation: String,
    accepted: bool,
    message: String,
    state: HelperState,
    query_active: Option<bool>,
    tunnel_stats: Option<HelperTunnelStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
struct HelperState {
    tunnel_active: bool,
    firewall_active: bool,
    last_tunnel_operation: Option<String>,
    last_firewall_operation: Option<String>,
    last_tunnel_payload: Option<String>,
    last_firewall_payload: Option<String>,
    tunnel_stats: HelperTunnelStats,
    pf_enable_token: Option<String>,
    active_pf_anchor_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
struct HelperTunnelStats {
    bytes_sent: u64,
    bytes_received: u64,
    last_handshake_secs: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirewallBackendMode {
    Statefile,
    PacketFilter,
}

#[derive(Debug, Deserialize)]
struct FirewallEnvelope {
    operation: String,
    request: FirewallRequest,
}

#[derive(Debug, Deserialize)]
struct FirewallRequest {
    anchor_name: String,
    interface_name: String,
    driver: String,
    operation: String,
    dns_server: Option<IpAddr>,
    peer_endpoint: Option<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PfctlOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

trait PfctlRunner {
    fn run(&self, args: &[String], stdin: Option<&str>) -> Result<PfctlOutput, String>;
}

#[derive(Debug, Default)]
struct SystemPfctlRunner;

impl PfctlRunner for SystemPfctlRunner {
    fn run(&self, args: &[String], stdin: Option<&str>) -> Result<PfctlOutput, String> {
        let mut command = Command::new("pfctl");
        command.args(args);
        if stdin.is_some() {
            command.stdin(Stdio::piped());
        }
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|error| error.to_string())?;
        if let Some(input) = stdin {
            use std::io::Write as _;
            let mut child_stdin = child
                .stdin
                .take()
                .ok_or_else(|| "pfctl stdin pipe was not available".to_owned())?;
            child_stdin
                .write_all(input.as_bytes())
                .map_err(|error| error.to_string())?;
        }
        let output = child
            .wait_with_output()
            .map_err(|error| error.to_string())?;
        Ok(PfctlOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let target = args.next().ok_or_else(usage)?;
    let operation = args.next().ok_or_else(usage)?;
    let payload = args.next().ok_or_else(usage)?;
    if args.next().is_some() {
        return Err(usage());
    }

    let state_path = helper_state_path();
    let mut state = load_state(&state_path)?;
    let firewall_backend = firewall_backend_mode_from_env()?;
    let pfctl_runner = SystemPfctlRunner;
    let response = apply_invocation(
        &target,
        &operation,
        &payload,
        &mut state,
        firewall_backend,
        &pfctl_runner,
    )?;
    save_state(&state_path, &state)?;
    println!(
        "{}",
        serde_json::to_string(&response).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn firewall_backend_mode_from_env() -> Result<FirewallBackendMode, String> {
    match env::var("QL_MACOS_HELPER_BACKEND") {
        Ok(raw) => match raw.as_str() {
            "statefile" => Ok(FirewallBackendMode::Statefile),
            "pf" | "packet-filter" => Ok(FirewallBackendMode::PacketFilter),
            other => Err(format!("unsupported QL_MACOS_HELPER_BACKEND: {other}")),
        },
        Err(_) => Ok(FirewallBackendMode::Statefile),
    }
}

fn apply_invocation<R: PfctlRunner>(
    target: &str,
    operation: &str,
    payload: &str,
    state: &mut HelperState,
    firewall_backend: FirewallBackendMode,
    pfctl_runner: &R,
) -> Result<HelperAck, String> {
    validate_invocation(target, operation, payload)?;

    match target {
        "tunnel" => apply_tunnel_invocation(operation, payload, state),
        "firewall" => {
            apply_firewall_invocation(operation, payload, state, firewall_backend, pfctl_runner)
        }
        other => Err(format!("unsupported helper target: {other}")),
    }
}

fn apply_tunnel_invocation(
    operation: &str,
    payload: &str,
    state: &mut HelperState,
) -> Result<HelperAck, String> {
    state.last_tunnel_operation = Some(operation.to_owned());
    state.last_tunnel_payload = Some(redact_sensitive_tunnel_payload(payload)?);
    let mut tunnel_stats = None;

    match operation {
        "activate" => {
            state.tunnel_active = true;
            state.tunnel_stats.bytes_sent += 256;
            state.tunnel_stats.bytes_received += 512;
            state.tunnel_stats.last_handshake_secs = Some(0);
        }
        "deactivate" => {
            state.tunnel_active = false;
        }
        "update-endpoint" => {
            state.tunnel_stats.bytes_sent += 32;
        }
        "inject-psk" => {
            state.tunnel_stats.bytes_sent += 16;
        }
        "read-stats" => {
            tunnel_stats = Some(state.tunnel_stats.clone());
        }
        other => return Err(format!("unsupported tunnel operation: {other}")),
    }

    Ok(HelperAck {
        target: "tunnel".to_owned(),
        operation: operation.to_owned(),
        accepted: true,
        message: format!("applied tunnel operation {operation}"),
        state: state.clone(),
        query_active: None,
        tunnel_stats,
    })
}

fn apply_firewall_invocation<R: PfctlRunner>(
    operation: &str,
    payload: &str,
    state: &mut HelperState,
    firewall_backend: FirewallBackendMode,
    pfctl_runner: &R,
) -> Result<HelperAck, String> {
    state.last_firewall_operation = Some(operation.to_owned());
    state.last_firewall_payload = Some(payload.to_owned());

    match firewall_backend {
        FirewallBackendMode::Statefile => apply_statefile_firewall_invocation(operation, state),
        FirewallBackendMode::PacketFilter => {
            apply_packet_filter_firewall_invocation(operation, payload, state, pfctl_runner)
        }
    }
}

fn apply_statefile_firewall_invocation(
    operation: &str,
    state: &mut HelperState,
) -> Result<HelperAck, String> {
    let mut query_active = None;

    match operation {
        "kill-switch" | "dns-only" => {
            state.firewall_active = true;
        }
        "disable-all" => {
            state.firewall_active = false;
        }
        "query-active" => {
            query_active = Some(state.firewall_active);
        }
        other => return Err(format!("unsupported firewall operation: {other}")),
    }

    Ok(HelperAck {
        target: "firewall".to_owned(),
        operation: operation.to_owned(),
        accepted: true,
        message: format!("applied firewall operation {operation}"),
        state: state.clone(),
        query_active,
        tunnel_stats: None,
    })
}

fn apply_packet_filter_firewall_invocation<R: PfctlRunner>(
    operation: &str,
    payload: &str,
    state: &mut HelperState,
    pfctl_runner: &R,
) -> Result<HelperAck, String> {
    let envelope: FirewallEnvelope = serde_json::from_str(payload)
        .map_err(|error| format!("invalid firewall payload JSON: {error}"))?;
    if envelope.request.driver != "packet-filter" {
        return Err(format!(
            "unsupported firewall driver for packet-filter backend: {}",
            envelope.request.driver
        ));
    }
    if envelope.operation != operation {
        return Err(format!(
            "firewall envelope operation mismatch: expected {operation}, got {}",
            envelope.operation
        ));
    }
    if envelope.request.operation != operation_mode_label(operation) {
        return Err(format!(
            "firewall request operation mismatch: expected {}, got {}",
            operation_mode_label(operation),
            envelope.request.operation
        ));
    }

    let mut query_active = None;
    let message = match operation {
        "kill-switch" => {
            reconcile_firewall_anchor(&envelope.request.anchor_name, state, pfctl_runner)?;
            ensure_pf_reference(state, pfctl_runner)?;
            let rules = build_kill_switch_rules(&envelope.request)?;
            load_anchor_rules(&envelope.request.anchor_name, &rules, pfctl_runner)?;
            state.firewall_active = true;
            state.active_pf_anchor_name = Some(envelope.request.anchor_name.clone());
            "applied firewall operation kill-switch via packet filter".to_owned()
        }
        "dns-only" => {
            reconcile_firewall_anchor(&envelope.request.anchor_name, state, pfctl_runner)?;
            ensure_pf_reference(state, pfctl_runner)?;
            let rules = build_dns_only_rules(&envelope.request)?;
            load_anchor_rules(&envelope.request.anchor_name, &rules, pfctl_runner)?;
            state.firewall_active = true;
            state.active_pf_anchor_name = Some(envelope.request.anchor_name.clone());
            "applied firewall operation dns-only via packet filter".to_owned()
        }
        "disable-all" => {
            disable_known_firewall_anchors(&envelope.request.anchor_name, state, pfctl_runner)?;
            release_pf_reference(state, pfctl_runner)?;
            clear_packet_filter_state(state);
            "applied firewall operation disable-all via packet filter".to_owned()
        }
        "query-active" => {
            let active = query_firewall_active(&envelope.request.anchor_name, state, pfctl_runner)?;
            state.firewall_active = active;
            query_active = Some(active);
            if !active {
                release_pf_reference(state, pfctl_runner)?;
                clear_packet_filter_state(state);
            }
            "applied firewall operation query-active via packet filter".to_owned()
        }
        other => return Err(format!("unsupported firewall operation: {other}")),
    };

    Ok(HelperAck {
        target: "firewall".to_owned(),
        operation: operation.to_owned(),
        accepted: true,
        message,
        state: state.clone(),
        query_active,
        tunnel_stats: None,
    })
}

fn ensure_pf_reference<R: PfctlRunner>(
    state: &mut HelperState,
    pfctl_runner: &R,
) -> Result<(), String> {
    if state.pf_enable_token.is_some() && pf_is_enabled(pfctl_runner)? {
        return Ok(());
    }
    if state.pf_enable_token.is_some() {
        state.pf_enable_token = None;
    }

    let output = run_pfctl(pfctl_runner, &["-E"], None)?;
    let token = extract_pf_enable_token(&output.stdout)
        .or_else(|| extract_pf_enable_token(&output.stderr))
        .ok_or_else(|| "pfctl -E succeeded but did not return a reference token".to_owned())?;
    state.pf_enable_token = Some(token);
    Ok(())
}

fn release_pf_reference<R: PfctlRunner>(
    state: &mut HelperState,
    pfctl_runner: &R,
) -> Result<(), String> {
    let Some(token) = state.pf_enable_token.clone() else {
        return Ok(());
    };
    let token_arg = token.clone();
    if let Err(error) = run_pfctl(pfctl_runner, &["-X", &token_arg], None) {
        if is_stale_pf_reference_error(&error) {
            state.pf_enable_token = None;
            return Ok(());
        }
        return Err(error);
    }
    state.pf_enable_token = None;
    Ok(())
}

fn clear_packet_filter_state(state: &mut HelperState) {
    state.firewall_active = false;
    state.pf_enable_token = None;
    state.active_pf_anchor_name = None;
}

fn reconcile_firewall_anchor<R: PfctlRunner>(
    requested_anchor_name: &str,
    state: &mut HelperState,
    pfctl_runner: &R,
) -> Result<(), String> {
    let Some(existing_anchor_name) = state.active_pf_anchor_name.clone() else {
        return Ok(());
    };
    if existing_anchor_name == requested_anchor_name {
        return Ok(());
    }
    flush_anchor_rules_if_present(&existing_anchor_name, pfctl_runner)?;
    state.firewall_active = false;
    state.active_pf_anchor_name = None;
    Ok(())
}

fn load_anchor_rules<R: PfctlRunner>(
    anchor_name: &str,
    rules: &str,
    pfctl_runner: &R,
) -> Result<(), String> {
    run_pfctl(
        pfctl_runner,
        &["-n", "-a", anchor_name, "-f", "-"],
        Some(rules),
    )?;
    run_pfctl(pfctl_runner, &["-a", anchor_name, "-f", "-"], Some(rules))?;
    Ok(())
}

fn flush_anchor_rules<R: PfctlRunner>(anchor_name: &str, pfctl_runner: &R) -> Result<(), String> {
    run_pfctl(pfctl_runner, &["-a", anchor_name, "-F", "rules"], None)?;
    Ok(())
}

fn flush_anchor_rules_if_present<R: PfctlRunner>(
    anchor_name: &str,
    pfctl_runner: &R,
) -> Result<(), String> {
    if let Err(error) = flush_anchor_rules(anchor_name, pfctl_runner) {
        if is_missing_anchor_error(&error) {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}

fn disable_known_firewall_anchors<R: PfctlRunner>(
    requested_anchor_name: &str,
    state: &mut HelperState,
    pfctl_runner: &R,
) -> Result<(), String> {
    flush_anchor_rules_if_present(requested_anchor_name, pfctl_runner)?;
    if let Some(existing_anchor_name) = state.active_pf_anchor_name.clone() {
        if existing_anchor_name != requested_anchor_name {
            flush_anchor_rules_if_present(&existing_anchor_name, pfctl_runner)?;
        }
    }
    Ok(())
}

fn query_anchor_active<R: PfctlRunner>(
    anchor_name: &str,
    pfctl_runner: &R,
) -> Result<bool, String> {
    let output = run_pfctl(pfctl_runner, &["-a", anchor_name, "-s", "rules"], None)?;
    Ok(output.stdout.lines().any(|line| !line.trim().is_empty()))
}

fn query_firewall_active<R: PfctlRunner>(
    requested_anchor_name: &str,
    state: &mut HelperState,
    pfctl_runner: &R,
) -> Result<bool, String> {
    let requested_active = query_anchor_active(requested_anchor_name, pfctl_runner)?;
    if requested_active {
        state.active_pf_anchor_name = Some(requested_anchor_name.to_owned());
        return Ok(true);
    }

    let Some(existing_anchor_name) = state.active_pf_anchor_name.clone() else {
        return Ok(false);
    };
    if existing_anchor_name == requested_anchor_name {
        state.active_pf_anchor_name = None;
        return Ok(false);
    }

    let existing_active = query_anchor_active(&existing_anchor_name, pfctl_runner)?;
    if existing_active {
        return Ok(true);
    }

    state.active_pf_anchor_name = None;
    Ok(false)
}

fn pf_is_enabled<R: PfctlRunner>(pfctl_runner: &R) -> Result<bool, String> {
    let output = run_pfctl(pfctl_runner, &["-s", "info"], None)?;
    Ok(output
        .stdout
        .lines()
        .chain(output.stderr.lines())
        .any(|line| line.trim() == "Status: Enabled"))
}

fn run_pfctl<R: PfctlRunner>(
    pfctl_runner: &R,
    args: &[&str],
    stdin: Option<&str>,
) -> Result<PfctlOutput, String> {
    let args = args
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let output = pfctl_runner.run(&args, stdin)?;
    if output.success {
        return Ok(output);
    }
    Err(format!(
        "pfctl {} failed: {}",
        args.join(" "),
        command_error_summary(&output)
    ))
}

fn command_error_summary(output: &PfctlOutput) -> String {
    let stderr = output.stderr.trim();
    let stdout = output.stdout.trim();
    if !stderr.is_empty() {
        stderr.to_owned()
    } else if !stdout.is_empty() {
        stdout.to_owned()
    } else {
        "pfctl exited unsuccessfully without output".to_owned()
    }
}

fn extract_pf_enable_token(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let token_field = line
            .split_once(':')
            .and_then(|(label, value)| label.contains("Token").then_some(value.trim()));
        if let Some(token) = token_field {
            if !token.is_empty() {
                return Some(token.to_owned());
            }
        }
        line.split_whitespace().find_map(|part| {
            let token = part.trim_matches(|ch: char| !ch.is_ascii_alphanumeric());
            (token.chars().all(|ch| ch.is_ascii_alphanumeric()) && token.len() >= 6)
                .then(|| token.to_owned())
        })
    })
}

fn is_missing_anchor_error(error: &str) -> bool {
    let normalized = error.to_ascii_lowercase();
    normalized.contains("anchor")
        && (normalized.contains("does not exist")
            || normalized.contains("not found")
            || normalized.contains("no such file"))
}

fn is_stale_pf_reference_error(error: &str) -> bool {
    let normalized = error.to_ascii_lowercase();
    normalized.contains("token")
        && (normalized.contains("does not exist")
            || normalized.contains("not found")
            || normalized.contains("invalid"))
}

fn build_kill_switch_rules(request: &FirewallRequest) -> Result<String, String> {
    let peer_endpoint = request
        .peer_endpoint
        .ok_or_else(|| "kill-switch firewall request missing peer_endpoint".to_owned())?;
    let peer_rule = peer_endpoint_rule(peer_endpoint);
    Ok(format!(
        "pass out quick on lo0 all keep state\n\
pass out quick on {interface} all keep state\n\
{peer_rule}\n\
block drop out quick all\n",
        interface = request.interface_name,
        peer_rule = peer_rule,
    ))
}

fn build_dns_only_rules(request: &FirewallRequest) -> Result<String, String> {
    let dns_server = request
        .dns_server
        .ok_or_else(|| "dns-only firewall request missing dns_server".to_owned())?;
    let dns_family = address_family_label(dns_server);
    Ok(format!(
        "pass out quick on lo0 all keep state\n\
pass out quick on {interface} all keep state\n\
pass out quick {dns_family} proto {{ tcp, udp }} from any to {dns_server} port 53 keep state\n\
pass out quick {dns_family} proto tcp from any to {dns_server} port 853 keep state\n\
block drop out quick proto {{ tcp, udp }} from any to any port 53\n\
block drop out quick proto tcp from any to any port 853\n",
        interface = request.interface_name,
        dns_family = dns_family,
        dns_server = dns_server,
    ))
}

fn peer_endpoint_rule(peer_endpoint: SocketAddr) -> String {
    match peer_endpoint {
        SocketAddr::V4(endpoint) => format!(
            "pass out quick inet proto udp from any to {} port {} keep state",
            endpoint.ip(),
            endpoint.port()
        ),
        SocketAddr::V6(endpoint) => format!(
            "pass out quick inet6 proto udp from any to {} port {} keep state",
            endpoint.ip(),
            endpoint.port()
        ),
    }
}

fn address_family_label(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "inet",
        IpAddr::V6(_) => "inet6",
    }
}

fn operation_mode_label(operation: &str) -> &'static str {
    match operation {
        "kill-switch" => "KillSwitch",
        "dns-only" => "DnsOnly",
        "disable-all" => "DisableAll",
        "query-active" => "QueryActive",
        _ => "",
    }
}

fn validate_invocation(target: &str, operation: &str, payload: &str) -> Result<(), String> {
    let envelope: Value = serde_json::from_str(payload)
        .map_err(|error| format!("invalid helper payload JSON: {error}"))?;

    match target {
        "tunnel" => validate_tunnel_payload(operation, &envelope),
        "firewall" => validate_firewall_payload(operation, &envelope),
        other => Err(format!("unsupported helper target: {other}")),
    }
}

fn validate_tunnel_payload(operation: &str, envelope: &Value) -> Result<(), String> {
    let request = envelope
        .get("request")
        .ok_or_else(|| "tunnel payload missing request object".to_owned())?;
    for field in [
        "provider_bundle_identifier",
        "driver",
        "interface_name",
        "interface_addresses",
        "private_key",
        "listen_port",
        "peer_public_key",
        "allowed_ips",
        "dns_servers",
        "mtu",
    ] {
        if request.get(field).is_none() {
            return Err(format!("tunnel request missing field: {field}"));
        }
    }

    if operation != "inject-psk" {
        let actual = envelope
            .get("operation")
            .and_then(Value::as_str)
            .ok_or_else(|| "tunnel envelope missing operation".to_owned())?;
        if actual != operation {
            return Err(format!(
                "tunnel operation mismatch: expected {operation}, got {actual}"
            ));
        }
    } else if envelope.get("psk").is_none() {
        return Err("tunnel PSK payload missing psk field".to_owned());
    }

    Ok(())
}

fn redact_sensitive_tunnel_payload(payload: &str) -> Result<String, String> {
    let mut json: Value = serde_json::from_str(payload)
        .map_err(|error| format!("invalid helper payload JSON: {error}"))?;
    redact_field_path(&mut json, &["request", "private_key"]);
    redact_field_path(&mut json, &["psk"]);
    serde_json::to_string(&json).map_err(|error| error.to_string())
}

fn redact_field_path(root: &mut Value, path: &[&str]) {
    let Some((field, parents)) = path.split_last() else {
        return;
    };
    let mut cursor = root;
    for parent in parents {
        let Some(next) = cursor.get_mut(*parent) else {
            return;
        };
        cursor = next;
    }
    if let Some(value) = cursor.get_mut(*field) {
        *value = redacted_value(value);
    }
}

fn redacted_value(original: &Value) -> Value {
    match original {
        Value::Array(values) => Value::Array(values.iter().map(|_| Value::from(0_u8)).collect()),
        _ => Value::String("<redacted>".to_owned()),
    }
}

fn validate_firewall_payload(operation: &str, envelope: &Value) -> Result<(), String> {
    let request = envelope
        .get("request")
        .ok_or_else(|| "firewall payload missing request object".to_owned())?;
    for field in ["anchor_name", "interface_name", "driver", "operation"] {
        if request.get(field).is_none() {
            return Err(format!("firewall request missing field: {field}"));
        }
    }

    let actual = envelope
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| "firewall envelope missing operation".to_owned())?;
    if actual != operation {
        return Err(format!(
            "firewall operation mismatch: expected {operation}, got {actual}"
        ));
    }

    Ok(())
}

fn helper_state_path() -> PathBuf {
    env::var_os("QL_MACOS_HELPER_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::temp_dir().join("quantumlink-macos-helper-state.json"))
}

fn load_state(path: &PathBuf) -> Result<HelperState, String> {
    if !path.exists() {
        return Ok(HelperState::default());
    }
    let contents = fs::read_to_string(path).map_err(|error| error.to_string())?;
    serde_json::from_str(&contents).map_err(|error| error.to_string())
}

fn save_state(path: &PathBuf, state: &HelperState) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let contents = serde_json::to_string_pretty(state).map_err(|error| error.to_string())?;
    fs::write(path, contents).map_err(|error| error.to_string())
}

fn usage() -> String {
    "usage: ql-macos-helper <tunnel|firewall> <operation> <payload-json>".to_owned()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::path::PathBuf;

    use super::{
        apply_invocation, load_state, save_state, validate_invocation, FirewallBackendMode,
        HelperAck, HelperState, PfctlOutput, PfctlRunner,
    };

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedPfctlCall {
        args: Vec<String>,
        stdin: Option<String>,
    }

    #[derive(Debug, Default)]
    struct RecordingPfctlRunner {
        calls: RefCell<Vec<RecordedPfctlCall>>,
        responses: RefCell<VecDeque<Result<PfctlOutput, String>>>,
    }

    impl RecordingPfctlRunner {
        fn with_responses(responses: Vec<Result<PfctlOutput, String>>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                responses: RefCell::new(VecDeque::from(responses)),
            }
        }
    }

    impl PfctlRunner for RecordingPfctlRunner {
        fn run(&self, args: &[String], stdin: Option<&str>) -> Result<PfctlOutput, String> {
            self.calls.borrow_mut().push(RecordedPfctlCall {
                args: args.to_vec(),
                stdin: stdin.map(str::to_owned),
            });
            self.responses.borrow_mut().pop_front().unwrap_or_else(|| {
                Ok(PfctlOutput {
                    success: true,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            })
        }
    }

    #[test]
    fn validates_tunnel_payload() {
        let payload = r#"{"operation":"activate","request":{"provider_bundle_identifier":"com.quantumlink.macos.PacketTunnelProvider","driver":"network-extension","interface_name":"ql0","interface_addresses":["10.0.0.2/32"],"private_key":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"listen_port":51820,"peer_public_key":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"peer_endpoint":null,"allowed_ips":["10.0.0.1/32"],"persistent_keepalive":25,"dns_servers":["10.0.0.1"],"mtu":1420}}"#;
        validate_invocation("tunnel", "activate", payload).unwrap();
    }

    #[test]
    fn validates_firewall_payload() {
        let payload = r#"{"operation":"kill-switch","request":{"anchor_name":"com.apple/250.QuantumLink.ql0","interface_name":"ql0","driver":"packet-filter","operation":"KillSwitch","dns_server":"10.0.0.1","peer_endpoint":"198.51.100.8:51820"}}"#;
        validate_invocation("firewall", "kill-switch", payload).unwrap();
    }

    #[test]
    fn helper_ack_serializes() {
        let ack = HelperAck {
            target: "tunnel".to_owned(),
            operation: "activate".to_owned(),
            accepted: true,
            message: "applied tunnel operation activate".to_owned(),
            state: HelperState::default(),
            query_active: None,
            tunnel_stats: None,
        };
        assert!(serde_json::to_string(&ack)
            .unwrap()
            .contains("applied tunnel operation activate"));
    }

    #[test]
    fn stateful_firewall_query_reflects_previous_operation() {
        let mut state = HelperState::default();
        let runner = RecordingPfctlRunner::default();
        let enable_payload = r#"{"operation":"kill-switch","request":{"anchor_name":"com.apple/250.QuantumLink.ql0","interface_name":"ql0","driver":"packet-filter","operation":"KillSwitch","dns_server":"10.0.0.1","peer_endpoint":"198.51.100.8:51820"}}"#;
        apply_invocation(
            "firewall",
            "kill-switch",
            enable_payload,
            &mut state,
            FirewallBackendMode::Statefile,
            &runner,
        )
        .unwrap();

        let query_payload = r#"{"operation":"query-active","request":{"anchor_name":"com.apple/250.QuantumLink.ql0","interface_name":"ql0","driver":"packet-filter","operation":"QueryActive","dns_server":null,"peer_endpoint":null}}"#;
        let response = apply_invocation(
            "firewall",
            "query-active",
            query_payload,
            &mut state,
            FirewallBackendMode::Statefile,
            &runner,
        )
        .unwrap();
        assert_eq!(response.query_active, Some(true));
    }

    #[test]
    fn packet_filter_backend_loads_anchor_rules_and_tracks_token() {
        let mut state = HelperState::default();
        let runner = RecordingPfctlRunner::with_responses(vec![
            Ok(PfctlOutput {
                success: true,
                stdout: "Token : 123456\n".to_owned(),
                stderr: String::new(),
            }),
            Ok(PfctlOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }),
            Ok(PfctlOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }),
        ]);
        let payload = r#"{"operation":"kill-switch","request":{"anchor_name":"com.apple/250.QuantumLink.ql0","interface_name":"ql0","driver":"packet-filter","operation":"KillSwitch","dns_server":"10.0.0.1","peer_endpoint":"198.51.100.8:51820"}}"#;

        let response = apply_invocation(
            "firewall",
            "kill-switch",
            payload,
            &mut state,
            FirewallBackendMode::PacketFilter,
            &runner,
        )
        .unwrap();

        assert!(response.accepted);
        assert!(state.firewall_active);
        assert_eq!(state.pf_enable_token.as_deref(), Some("123456"));
        assert_eq!(
            state.active_pf_anchor_name.as_deref(),
            Some("com.apple/250.QuantumLink.ql0")
        );
        let calls = runner.calls.borrow();
        assert_eq!(calls[0].args, vec!["-E"]);
        assert_eq!(
            calls[1].args,
            vec!["-n", "-a", "com.apple/250.QuantumLink.ql0", "-f", "-"]
        );
        assert_eq!(
            calls[2].args,
            vec!["-a", "com.apple/250.QuantumLink.ql0", "-f", "-"]
        );
        let loaded_rules = calls[2].stdin.as_deref().unwrap();
        assert!(loaded_rules.contains("pass out quick on ql0 all keep state"));
        assert!(loaded_rules.contains("198.51.100.8 port 51820"));
    }

    #[test]
    fn packet_filter_backend_queries_anchor_state() {
        let mut state = HelperState::default();
        let runner = RecordingPfctlRunner::with_responses(vec![Ok(PfctlOutput {
            success: true,
            stdout: "pass out quick on ql0 all keep state\n".to_owned(),
            stderr: String::new(),
        })]);
        let payload = r#"{"operation":"query-active","request":{"anchor_name":"com.apple/250.QuantumLink.ql0","interface_name":"ql0","driver":"packet-filter","operation":"QueryActive","dns_server":null,"peer_endpoint":null}}"#;

        let response = apply_invocation(
            "firewall",
            "query-active",
            payload,
            &mut state,
            FirewallBackendMode::PacketFilter,
            &runner,
        )
        .unwrap();

        assert_eq!(response.query_active, Some(true));
        assert!(state.firewall_active);
        assert_eq!(
            state.active_pf_anchor_name.as_deref(),
            Some("com.apple/250.QuantumLink.ql0")
        );
        assert_eq!(
            runner.calls.borrow()[0].args,
            vec!["-a", "com.apple/250.QuantumLink.ql0", "-s", "rules"]
        );
    }

    #[test]
    fn packet_filter_backend_releases_token_on_disable() {
        let mut state = HelperState {
            pf_enable_token: Some("123456".to_owned()),
            firewall_active: true,
            ..HelperState::default()
        };
        let runner = RecordingPfctlRunner::with_responses(vec![
            Ok(PfctlOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }),
            Ok(PfctlOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }),
        ]);
        let payload = r#"{"operation":"disable-all","request":{"anchor_name":"com.apple/250.QuantumLink.ql0","interface_name":"ql0","driver":"packet-filter","operation":"DisableAll","dns_server":null,"peer_endpoint":null}}"#;

        apply_invocation(
            "firewall",
            "disable-all",
            payload,
            &mut state,
            FirewallBackendMode::PacketFilter,
            &runner,
        )
        .unwrap();

        assert!(!state.firewall_active);
        assert!(state.pf_enable_token.is_none());
        assert!(state.active_pf_anchor_name.is_none());
        let calls = runner.calls.borrow();
        assert_eq!(
            calls[0].args,
            vec!["-a", "com.apple/250.QuantumLink.ql0", "-F", "rules"]
        );
        assert_eq!(calls[1].args, vec!["-X", "123456"]);
    }

    #[test]
    fn packet_filter_backend_recovers_disabled_pf_before_loading_rules() {
        let mut state = HelperState {
            pf_enable_token: Some("stale-token".to_owned()),
            ..HelperState::default()
        };
        let runner = RecordingPfctlRunner::with_responses(vec![
            Ok(PfctlOutput {
                success: true,
                stdout: "Status: Disabled\n".to_owned(),
                stderr: String::new(),
            }),
            Ok(PfctlOutput {
                success: true,
                stdout: "Token : 654321\n".to_owned(),
                stderr: String::new(),
            }),
            Ok(PfctlOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }),
            Ok(PfctlOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }),
        ]);
        let payload = r#"{"operation":"kill-switch","request":{"anchor_name":"com.apple/250.QuantumLink.ql0","interface_name":"ql0","driver":"packet-filter","operation":"KillSwitch","dns_server":"10.0.0.1","peer_endpoint":"198.51.100.8:51820"}}"#;

        apply_invocation(
            "firewall",
            "kill-switch",
            payload,
            &mut state,
            FirewallBackendMode::PacketFilter,
            &runner,
        )
        .unwrap();

        assert_eq!(state.pf_enable_token.as_deref(), Some("654321"));
        let calls = runner.calls.borrow();
        assert_eq!(calls[0].args, vec!["-s", "info"]);
        assert_eq!(calls[1].args, vec!["-E"]);
    }

    #[test]
    fn packet_filter_backend_flushes_previous_anchor_before_switching() {
        let mut state = HelperState {
            firewall_active: true,
            pf_enable_token: Some("123456".to_owned()),
            active_pf_anchor_name: Some("com.apple/250.QuantumLink.ql0".to_owned()),
            ..HelperState::default()
        };
        let runner = RecordingPfctlRunner::with_responses(vec![
            Ok(PfctlOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }),
            Ok(PfctlOutput {
                success: true,
                stdout: "Status: Enabled\n".to_owned(),
                stderr: String::new(),
            }),
            Ok(PfctlOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }),
            Ok(PfctlOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }),
        ]);
        let payload = r#"{"operation":"dns-only","request":{"anchor_name":"com.apple/250.QuantumLink.ql1","interface_name":"ql1","driver":"packet-filter","operation":"DnsOnly","dns_server":"10.0.0.1","peer_endpoint":null}}"#;

        apply_invocation(
            "firewall",
            "dns-only",
            payload,
            &mut state,
            FirewallBackendMode::PacketFilter,
            &runner,
        )
        .unwrap();

        assert_eq!(
            state.active_pf_anchor_name.as_deref(),
            Some("com.apple/250.QuantumLink.ql1")
        );
        let calls = runner.calls.borrow();
        assert_eq!(
            calls[0].args,
            vec!["-a", "com.apple/250.QuantumLink.ql0", "-F", "rules"]
        );
        assert_eq!(calls[1].args, vec!["-s", "info"]);
        assert_eq!(
            calls[2].args,
            vec!["-n", "-a", "com.apple/250.QuantumLink.ql1", "-f", "-"]
        );
        assert_eq!(
            calls[3].args,
            vec!["-a", "com.apple/250.QuantumLink.ql1", "-f", "-"]
        );
    }

    #[test]
    fn packet_filter_backend_disable_flushes_stored_anchor_on_mismatch() {
        let mut state = HelperState {
            firewall_active: true,
            pf_enable_token: Some("123456".to_owned()),
            active_pf_anchor_name: Some("com.apple/250.QuantumLink.ql0".to_owned()),
            ..HelperState::default()
        };
        let runner = RecordingPfctlRunner::with_responses(vec![
            Ok(PfctlOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }),
            Ok(PfctlOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }),
            Ok(PfctlOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }),
        ]);
        let payload = r#"{"operation":"disable-all","request":{"anchor_name":"com.apple/250.QuantumLink.ql1","interface_name":"ql1","driver":"packet-filter","operation":"DisableAll","dns_server":null,"peer_endpoint":null}}"#;

        apply_invocation(
            "firewall",
            "disable-all",
            payload,
            &mut state,
            FirewallBackendMode::PacketFilter,
            &runner,
        )
        .unwrap();

        let calls = runner.calls.borrow();
        assert_eq!(
            calls[0].args,
            vec!["-a", "com.apple/250.QuantumLink.ql1", "-F", "rules"]
        );
        assert_eq!(
            calls[1].args,
            vec!["-a", "com.apple/250.QuantumLink.ql0", "-F", "rules"]
        );
        assert_eq!(calls[2].args, vec!["-X", "123456"]);
    }

    #[test]
    fn packet_filter_backend_query_clears_stale_reference_state() {
        let mut state = HelperState {
            firewall_active: true,
            pf_enable_token: Some("123456".to_owned()),
            active_pf_anchor_name: Some("com.apple/250.QuantumLink.ql0".to_owned()),
            ..HelperState::default()
        };
        let runner = RecordingPfctlRunner::with_responses(vec![
            Ok(PfctlOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }),
            Ok(PfctlOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }),
        ]);
        let payload = r#"{"operation":"query-active","request":{"anchor_name":"com.apple/250.QuantumLink.ql0","interface_name":"ql0","driver":"packet-filter","operation":"QueryActive","dns_server":null,"peer_endpoint":null}}"#;

        let response = apply_invocation(
            "firewall",
            "query-active",
            payload,
            &mut state,
            FirewallBackendMode::PacketFilter,
            &runner,
        )
        .unwrap();

        assert_eq!(response.query_active, Some(false));
        assert!(!state.firewall_active);
        assert!(state.pf_enable_token.is_none());
        assert!(state.active_pf_anchor_name.is_none());
        let calls = runner.calls.borrow();
        assert_eq!(
            calls[0].args,
            vec!["-a", "com.apple/250.QuantumLink.ql0", "-s", "rules"]
        );
        assert_eq!(calls[1].args, vec!["-X", "123456"]);
    }

    #[test]
    fn redacts_tunnel_secrets_in_stored_state() {
        let mut state = HelperState::default();
        let runner = RecordingPfctlRunner::default();
        let payload = r#"{"operation":"inject-psk","request":{"provider_bundle_identifier":"com.quantumlink.macos.PacketTunnelProvider","driver":"network-extension","interface_name":"ql0","interface_addresses":["10.0.0.2/32"],"private_key":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"listen_port":51820,"peer_public_key":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"peer_endpoint":null,"allowed_ips":["10.0.0.1/32"],"persistent_keepalive":25,"dns_servers":["10.0.0.1"],"mtu":1420},"psk":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9]}"#;

        apply_invocation(
            "tunnel",
            "inject-psk",
            payload,
            &mut state,
            FirewallBackendMode::Statefile,
            &runner,
        )
        .unwrap();

        let stored = state.last_tunnel_payload.unwrap();
        assert!(stored.contains("\"private_key\":[0,0,0,0"));
        assert!(stored.contains("\"psk\":[0,0,0,0"));
        assert!(!stored.contains("\"private_key\":[1,1,1,1"));
        assert!(!stored.contains("\"psk\":[9,9,9,9"));
    }

    #[test]
    fn state_roundtrips_to_disk() {
        let path = std::env::temp_dir().join("quantumlink-helper-test-state.json");
        let state = HelperState {
            tunnel_active: true,
            ..HelperState::default()
        };
        save_state(&path, &state).unwrap();
        assert_eq!(load_state(&path).unwrap(), state);
        let _ = std::fs::remove_file(PathBuf::from(&path));
    }
}
