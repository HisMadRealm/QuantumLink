//! macOS runtime adapter target for QuantumLink.

#![forbid(unsafe_code)]

use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "macos")]
use std::time::Duration;

use ql_core::{QuantumLinkError, QuantumLinkResult};
#[cfg(target_os = "macos")]
use ql_firewall::{
    MacOsFirewallBridgeExecutor, MacOsFirewallBridgeRequest, MacOsFirewallOperationMode,
};
#[cfg(target_os = "macos")]
use ql_wireguard::{MacOsTunnelBridgeExecutor, MacOsTunnelBridgeRequest, TunnelStats};
use serde::{Deserialize, Serialize};

/// Execution mode for the macOS runtime adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacOsAdapterMode {
    /// Record and validate requests without invoking a native helper.
    Stub,
    /// Invoke an external native helper executable.
    ExternalProcess,
    /// Invoke a dedicated native tunnel controller intended to front a Network Extension path.
    NetworkExtension,
}

/// Configuration for the macOS runtime adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOsRuntimeAdapterConfig {
    /// Execution mode used by the adapter.
    pub mode: MacOsAdapterMode,
    /// Optional Packet Tunnel Provider extension bundle identifier override.
    pub tunnel_extension_bundle_identifier: Option<String>,
    /// Optional native controller executable used for tunnel operations in Network Extension mode.
    pub tunnel_controller_path: Option<PathBuf>,
    /// Optional helper executable used for tunnel operations.
    pub tunnel_helper_path: Option<PathBuf>,
    /// Optional helper executable used for firewall operations.
    pub firewall_helper_path: Option<PathBuf>,
}

impl Default for MacOsRuntimeAdapterConfig {
    fn default() -> Self {
        Self {
            mode: MacOsAdapterMode::Stub,
            tunnel_extension_bundle_identifier: None,
            tunnel_controller_path: None,
            tunnel_helper_path: None,
            firewall_helper_path: None,
        }
    }
}

/// Result of adapter execution, useful for host-side diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MacOsAdapterExecution {
    /// Logical helper target that handled the request.
    pub target: &'static str,
    /// Operation name provided to the helper.
    pub operation: &'static str,
    /// Serialized payload emitted by the adapter.
    pub payload: String,
    /// Optional JSON emitted by a native bridge executable on success.
    pub helper_response: Option<String>,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Deserialize)]
struct HelperResponse {
    query_active: Option<bool>,
    tunnel_stats: Option<HelperTunnelStats>,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Deserialize)]
struct HelperTunnelStats {
    bytes_sent: u64,
    bytes_received: u64,
    last_handshake_secs: Option<u64>,
}

/// Concrete macOS adapter target that implements the runtime executor interfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOsRuntimeAdapter {
    config: MacOsRuntimeAdapterConfig,
}

impl MacOsRuntimeAdapter {
    /// Creates a macOS runtime adapter from the supplied config.
    #[must_use]
    pub fn new(config: MacOsRuntimeAdapterConfig) -> Self {
        Self { config }
    }

    /// Returns the configured adapter mode.
    #[must_use]
    pub fn mode(&self) -> &MacOsAdapterMode {
        &self.config.mode
    }

    /// Returns whether a firewall bridge executable is configured.
    #[must_use]
    pub fn has_firewall_bridge(&self) -> bool {
        match self.config.mode {
            MacOsAdapterMode::Stub => true,
            MacOsAdapterMode::ExternalProcess | MacOsAdapterMode::NetworkExtension => {
                self.config.firewall_helper_path.is_some()
            }
        }
    }

    /// Serializes and optionally dispatches a tunnel operation.
    #[cfg(target_os = "macos")]
    pub fn execute_tunnel_operation(
        &self,
        operation: &'static str,
        request: &MacOsTunnelBridgeRequest,
    ) -> QuantumLinkResult<MacOsAdapterExecution> {
        let request = self.effective_tunnel_request(request);
        let raw_payload = serialize_payload(&TunnelEnvelope {
            operation,
            request: &request,
        })?;
        let diagnostic_payload = redact_sensitive_tunnel_payload(&raw_payload)?;
        match self.config.mode {
            MacOsAdapterMode::Stub => {
                Ok(self.stub_execution("tunnel", operation, diagnostic_payload))
            }
            MacOsAdapterMode::ExternalProcess => self.dispatch_external(
                "tunnel",
                operation,
                raw_payload,
                diagnostic_payload,
                self.config.tunnel_helper_path.as_ref(),
                "macOS tunnel helper path is not configured",
            ),
            MacOsAdapterMode::NetworkExtension => self.dispatch_external(
                "tunnel",
                operation,
                raw_payload,
                diagnostic_payload,
                self.config.tunnel_controller_path.as_ref(),
                "macOS tunnel controller path is not configured for Network Extension mode",
            ),
        }
    }

    #[cfg(target_os = "macos")]
    fn effective_tunnel_request(
        &self,
        request: &MacOsTunnelBridgeRequest,
    ) -> MacOsTunnelBridgeRequest {
        let mut effective = request.clone();
        if let Some(bundle_identifier) = &self.config.tunnel_extension_bundle_identifier {
            effective.provider_bundle_identifier = bundle_identifier.clone();
        }
        effective
    }

    /// Serializes and optionally dispatches a firewall operation.
    #[cfg(target_os = "macos")]
    pub fn execute_firewall_operation(
        &self,
        operation: &'static str,
        request: &MacOsFirewallBridgeRequest,
    ) -> QuantumLinkResult<MacOsAdapterExecution> {
        let payload = serialize_payload(&FirewallEnvelope { operation, request })?;
        match self.config.mode {
            MacOsAdapterMode::Stub => Ok(self.stub_execution("firewall", operation, payload)),
            MacOsAdapterMode::ExternalProcess | MacOsAdapterMode::NetworkExtension => self
                .dispatch_external(
                    "firewall",
                    operation,
                    payload.clone(),
                    payload,
                    self.config.firewall_helper_path.as_ref(),
                    "macOS firewall helper path is not configured",
                ),
        }
    }

    #[cfg(target_os = "macos")]
    fn stub_execution(
        &self,
        target: &'static str,
        operation: &'static str,
        payload: String,
    ) -> MacOsAdapterExecution {
        let _ = &self.config;
        MacOsAdapterExecution {
            target,
            operation,
            payload,
            helper_response: None,
        }
    }

    #[cfg(target_os = "macos")]
    fn dispatch_external(
        &self,
        target: &'static str,
        operation: &'static str,
        raw_payload: String,
        diagnostic_payload: String,
        helper_path: Option<&PathBuf>,
        missing_path_message: &'static str,
    ) -> QuantumLinkResult<MacOsAdapterExecution> {
        let helper_path = helper_path
            .ok_or_else(|| QuantumLinkError::NotImplemented(missing_path_message.to_owned()))?;

        let output = Command::new(helper_path)
            .arg(target)
            .arg(operation)
            .arg(&raw_payload)
            .output()
            .map_err(QuantumLinkError::Io)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Err(QuantumLinkError::NotImplemented(format!(
                "macOS {target} bridge failed for operation {operation}: {stderr}"
            )));
        }

        let helper_response = {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if stdout.is_empty() {
                None
            } else {
                Some(stdout)
            }
        };

        Ok(MacOsAdapterExecution {
            target,
            operation,
            payload: diagnostic_payload,
            helper_response,
        })
    }
}

#[cfg(target_os = "macos")]
impl MacOsTunnelBridgeExecutor for MacOsRuntimeAdapter {
    fn activate_tunnel(&self, request: &MacOsTunnelBridgeRequest) -> QuantumLinkResult<()> {
        self.execute_tunnel_operation("activate", request)
            .map(|_| ())
    }

    fn deactivate_tunnel(&self, request: &MacOsTunnelBridgeRequest) -> QuantumLinkResult<()> {
        self.execute_tunnel_operation("deactivate", request)
            .map(|_| ())
    }

    fn update_tunnel_endpoint(
        &self,
        request: &MacOsTunnelBridgeRequest,
        endpoint: std::net::SocketAddr,
    ) -> QuantumLinkResult<()> {
        let mut updated = request.clone();
        updated.peer_endpoint = Some(endpoint);
        self.execute_tunnel_operation("update-endpoint", &updated)
            .map(|_| ())
    }

    fn inject_tunnel_psk(
        &self,
        request: &MacOsTunnelBridgeRequest,
        psk: [u8; 32],
    ) -> QuantumLinkResult<()> {
        let request = self.effective_tunnel_request(request);
        let envelope = TunnelPskEnvelope {
            request: &request,
            psk,
        };
        let raw_payload = serialize_payload(&envelope)?;
        let diagnostic_payload = redact_sensitive_tunnel_payload(&raw_payload)?;
        match self.config.mode {
            MacOsAdapterMode::Stub => Ok(()),
            MacOsAdapterMode::ExternalProcess => self
                .dispatch_external(
                    "tunnel",
                    "inject-psk",
                    raw_payload,
                    diagnostic_payload,
                    self.config.tunnel_helper_path.as_ref(),
                    "macOS tunnel helper path is not configured",
                )
                .map(|_| ()),
            MacOsAdapterMode::NetworkExtension => self
                .dispatch_external(
                    "tunnel",
                    "inject-psk",
                    raw_payload,
                    diagnostic_payload,
                    self.config.tunnel_controller_path.as_ref(),
                    "macOS tunnel controller path is not configured for Network Extension mode",
                )
                .map(|_| ()),
        }
    }

    fn read_tunnel_stats(
        &self,
        request: &MacOsTunnelBridgeRequest,
    ) -> QuantumLinkResult<TunnelStats> {
        let execution = self.execute_tunnel_operation("read-stats", request)?;
        let helper_response = parse_helper_response(execution.helper_response.as_deref())?;
        Ok(helper_response
            .and_then(|response| response.tunnel_stats)
            .map(Into::into)
            .unwrap_or_default())
    }
}

#[cfg(target_os = "macos")]
impl MacOsFirewallBridgeExecutor for MacOsRuntimeAdapter {
    fn execute_firewall_request(
        &self,
        request: &MacOsFirewallBridgeRequest,
    ) -> QuantumLinkResult<Option<bool>> {
        let operation = match request.operation {
            MacOsFirewallOperationMode::KillSwitch => "kill-switch",
            MacOsFirewallOperationMode::DnsOnly => "dns-only",
            MacOsFirewallOperationMode::DisableAll => "disable-all",
            MacOsFirewallOperationMode::QueryActive => "query-active",
        };
        let execution = self.execute_firewall_operation(operation, request)?;
        if matches!(request.operation, MacOsFirewallOperationMode::QueryActive) {
            let helper_response = parse_helper_response(execution.helper_response.as_deref())?;
            return Ok(Some(
                helper_response
                    .and_then(|response| response.query_active)
                    .unwrap_or(false),
            ));
        }

        Ok(None)
    }
}

#[cfg(target_os = "macos")]
#[derive(Serialize)]
struct TunnelEnvelope<'a> {
    operation: &'static str,
    request: &'a MacOsTunnelBridgeRequest,
}

#[cfg(target_os = "macos")]
#[derive(Serialize)]
struct TunnelPskEnvelope<'a> {
    request: &'a MacOsTunnelBridgeRequest,
    psk: [u8; 32],
}

#[cfg(target_os = "macos")]
#[derive(Serialize)]
struct FirewallEnvelope<'a> {
    operation: &'static str,
    request: &'a MacOsFirewallBridgeRequest,
}

#[cfg(target_os = "macos")]
fn serialize_payload<T: Serialize>(value: &T) -> QuantumLinkResult<String> {
    serde_json::to_string(value).map_err(|error| QuantumLinkError::Config(error.to_string()))
}

#[cfg(target_os = "macos")]
fn redact_sensitive_tunnel_payload(payload: &str) -> QuantumLinkResult<String> {
    let mut json: serde_json::Value = serde_json::from_str(payload)
        .map_err(|error| QuantumLinkError::Config(error.to_string()))?;
    redact_field_path(&mut json, &["request", "private_key"]);
    redact_field_path(&mut json, &["psk"]);
    serde_json::to_string(&json).map_err(|error| QuantumLinkError::Config(error.to_string()))
}

#[cfg(target_os = "macos")]
fn redact_field_path(root: &mut serde_json::Value, path: &[&str]) {
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

#[cfg(target_os = "macos")]
fn redacted_value(original: &serde_json::Value) -> serde_json::Value {
    match original {
        serde_json::Value::Array(values) => serde_json::Value::Array(
            values
                .iter()
                .map(|_| serde_json::Value::from(0_u8))
                .collect(),
        ),
        _ => serde_json::Value::String("<redacted>".to_owned()),
    }
}

#[cfg(target_os = "macos")]
fn parse_helper_response(payload: Option<&str>) -> QuantumLinkResult<Option<HelperResponse>> {
    match payload {
        Some(raw) => serde_json::from_str(raw).map(Some).map_err(|error| {
            QuantumLinkError::Config(format!("invalid macOS helper response: {error}"))
        }),
        None => Ok(None),
    }
}

#[cfg(target_os = "macos")]
impl From<HelperTunnelStats> for TunnelStats {
    fn from(value: HelperTunnelStats) -> Self {
        Self {
            bytes_sent: value.bytes_sent,
            bytes_received: value.bytes_received,
            last_handshake: value.last_handshake_secs.map(Duration::from_secs),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use super::MacOsAdapterExecution;
    #[cfg(target_os = "macos")]
    use super::{parse_helper_response, HelperTunnelStats};
    use super::{
        redact_sensitive_tunnel_payload, serialize_payload, MacOsAdapterMode, MacOsRuntimeAdapter,
        MacOsRuntimeAdapterConfig, TunnelPskEnvelope,
    };
    #[cfg(target_os = "macos")]
    use ipnetwork::IpNetwork;
    #[cfg(target_os = "macos")]
    use ql_firewall::{MacOsFirewallOperationMode, PlatformFirewall};
    #[cfg(target_os = "macos")]
    use ql_wireguard::{MacOsTunnelBridgeExecutor, PlatformTunnel, TunnelConfig};
    #[cfg(target_os = "macos")]
    use std::net::{IpAddr, Ipv4Addr};
    #[cfg(target_os = "macos")]
    use std::time::Duration;

    #[test]
    fn default_adapter_uses_stub_mode() {
        let adapter = MacOsRuntimeAdapter::new(MacOsRuntimeAdapterConfig::default());
        assert_eq!(adapter.mode(), &MacOsAdapterMode::Stub);
    }

    #[test]
    fn runtime_config_defaults_to_no_native_bridge_paths() {
        let config = MacOsRuntimeAdapterConfig::default();
        assert!(config.tunnel_extension_bundle_identifier.is_none());
        assert!(config.tunnel_controller_path.is_none());
        assert!(config.tunnel_helper_path.is_none());
        assert!(config.firewall_helper_path.is_none());
    }

    #[test]
    fn runtime_adapter_reports_missing_firewall_bridge() {
        let adapter = MacOsRuntimeAdapter::new(MacOsRuntimeAdapterConfig::default());
        assert!(adapter.has_firewall_bridge());
    }

    #[test]
    fn network_extension_adapter_reports_missing_firewall_bridge_without_helper() {
        let adapter = MacOsRuntimeAdapter::new(MacOsRuntimeAdapterConfig {
            mode: MacOsAdapterMode::NetworkExtension,
            ..MacOsRuntimeAdapterConfig::default()
        });
        assert!(!adapter.has_firewall_bridge());
    }

    #[cfg(target_os = "macos")]
    fn sample_tunnel() -> PlatformTunnel {
        PlatformTunnel::new(TunnelConfig {
            interface_name: "ql0".to_owned(),
            interface_addresses: vec![IpNetwork::V4("10.0.0.2/32".parse().unwrap())],
            private_key: [7_u8; 32],
            listen_port: 51_820,
            peer_public_key: [8_u8; 32],
            peer_endpoint: None,
            allowed_ips: vec![IpNetwork::V4("10.0.0.1/32".parse().unwrap())],
            persistent_keepalive: Some(25),
            dns_servers: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
            mtu: 1_420,
        })
        .unwrap()
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stub_adapter_serializes_tunnel_execution() {
        let adapter = MacOsRuntimeAdapter::new(MacOsRuntimeAdapterConfig::default());
        let tunnel = sample_tunnel();
        let execution: MacOsAdapterExecution = adapter
            .execute_tunnel_operation("activate", &tunnel.macos_bridge_request())
            .unwrap();

        assert_eq!(execution.target, "tunnel");
        assert_eq!(execution.operation, "activate");
        assert!(execution.payload.contains("network-extension"));
        assert!(execution
            .payload
            .contains("com.quantumlink.macos.PacketTunnelProvider"));
        assert!(execution.payload.contains("\"private_key\":[0,0,0,0"));
        assert!(!execution.payload.contains("\"private_key\":[7,7,7,7"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn adapter_overrides_tunnel_extension_bundle_identifier() {
        let adapter = MacOsRuntimeAdapter::new(MacOsRuntimeAdapterConfig {
            tunnel_extension_bundle_identifier: Some("com.example.PacketTunnelProvider".to_owned()),
            ..MacOsRuntimeAdapterConfig::default()
        });
        let tunnel = sample_tunnel();
        let execution = adapter
            .execute_tunnel_operation("activate", &tunnel.macos_bridge_request())
            .unwrap();

        assert!(execution
            .payload
            .contains("com.example.PacketTunnelProvider"));
        assert!(!execution
            .payload
            .contains("com.quantumlink.macos.PacketTunnelProvider"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn psk_injection_payload_is_redacted_for_diagnostics() {
        let tunnel = sample_tunnel();
        let payload = serialize_payload(&TunnelPskEnvelope {
            request: &tunnel.macos_bridge_request(),
            psk: [9_u8; 32],
        })
        .unwrap();
        let redacted = redact_sensitive_tunnel_payload(&payload).unwrap();

        assert!(redacted.contains("\"psk\":[0,0,0,0"));
        assert!(!redacted.contains("\"psk\":[9,9,9,9"));
        assert!(redacted.contains("\"private_key\":[0,0,0,0"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stub_adapter_serializes_firewall_execution() {
        let adapter = MacOsRuntimeAdapter::new(MacOsRuntimeAdapterConfig::default());
        let firewall = PlatformFirewall::new("ql0");
        let execution: MacOsAdapterExecution = adapter
            .execute_firewall_operation(
                "kill-switch",
                &firewall.macos_kill_switch_request(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    Some("198.51.100.8:51820".parse().unwrap()),
                ),
            )
            .unwrap();

        assert_eq!(execution.target, "firewall");
        assert_eq!(execution.operation, "kill-switch");
        assert!(execution.payload.contains("packet-filter"));
        assert!(execution.payload.contains("com.apple/250.QuantumLink.ql0"));
        assert!(execution
            .payload
            .contains("\"peer_endpoint\":\"198.51.100.8:51820\""));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn executor_impl_reports_firewall_query_as_inactive() {
        let adapter = MacOsRuntimeAdapter::new(MacOsRuntimeAdapterConfig::default());
        let firewall = PlatformFirewall::new("ql0");
        let result = ql_firewall::MacOsFirewallBridgeExecutor::execute_firewall_request(
            &adapter,
            &firewall.macos_query_request(),
        )
        .unwrap();

        assert_eq!(result, Some(false));
        assert_eq!(
            firewall.macos_query_request().operation,
            MacOsFirewallOperationMode::QueryActive
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn helper_response_parses_query_and_stats() {
        let response = parse_helper_response(Some(
			r#"{"query_active":true,"tunnel_stats":{"bytes_sent":256,"bytes_received":512,"last_handshake_secs":3}}"#,
		))
		.unwrap()
		.unwrap();

        assert_eq!(response.query_active, Some(true));
        assert_eq!(response.tunnel_stats.unwrap().bytes_received, 512);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn helper_stats_convert_into_tunnel_stats() {
        let stats: ql_wireguard::TunnelStats = HelperTunnelStats {
            bytes_sent: 11,
            bytes_received: 22,
            last_handshake_secs: Some(7),
        }
        .into();

        assert_eq!(stats.bytes_sent, 11);
        assert_eq!(stats.bytes_received, 22);
        assert_eq!(stats.last_handshake, Some(Duration::from_secs(7)));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stub_tunnel_stats_default_without_helper_response() {
        let adapter = MacOsRuntimeAdapter::new(MacOsRuntimeAdapterConfig::default());
        let tunnel = sample_tunnel();
        let stats =
            MacOsTunnelBridgeExecutor::read_tunnel_stats(&adapter, &tunnel.macos_bridge_request())
                .unwrap();

        assert_eq!(stats, ql_wireguard::TunnelStats::default());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn network_extension_mode_requires_controller_path() {
        let adapter = MacOsRuntimeAdapter::new(MacOsRuntimeAdapterConfig {
            mode: MacOsAdapterMode::NetworkExtension,
            ..MacOsRuntimeAdapterConfig::default()
        });
        let tunnel = sample_tunnel();
        let error = adapter
            .execute_tunnel_operation("activate", &tunnel.macos_bridge_request())
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("macOS tunnel controller path is not configured for Network Extension mode"));
    }
}
