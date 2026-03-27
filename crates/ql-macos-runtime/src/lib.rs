//! macOS runtime adapter target for QuantumLink.

#![forbid(unsafe_code)]

use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;

use ql_core::{QuantumLinkError, QuantumLinkResult};
#[cfg(target_os = "macos")]
use ql_firewall::{
	MacOsFirewallBridgeExecutor, MacOsFirewallBridgeRequest, MacOsFirewallOperationMode,
};
#[cfg(target_os = "macos")]
use ql_wireguard::{MacOsTunnelBridgeExecutor, MacOsTunnelBridgeRequest, TunnelStats};
use serde::Serialize;

/// Execution mode for the macOS runtime adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacOsAdapterMode {
	/// Record and validate requests without invoking a native helper.
	Stub,
	/// Invoke an external native helper executable.
	ExternalProcess,
}

/// Configuration for the macOS runtime adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOsRuntimeAdapterConfig {
	/// Execution mode used by the adapter.
	pub mode: MacOsAdapterMode,
	/// Optional helper executable used for tunnel operations.
	pub tunnel_helper_path: Option<PathBuf>,
	/// Optional helper executable used for firewall operations.
	pub firewall_helper_path: Option<PathBuf>,
}

impl Default for MacOsRuntimeAdapterConfig {
	fn default() -> Self {
		Self {
			mode: MacOsAdapterMode::Stub,
			tunnel_helper_path: None,
			firewall_helper_path: None,
		}
	}
}

/// Result of adapter execution, useful for host-side diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOsAdapterExecution {
	/// Logical helper target that handled the request.
	pub target: &'static str,
	/// Operation name provided to the helper.
	pub operation: &'static str,
	/// Serialized payload emitted by the adapter.
	pub payload: String,
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

	/// Serializes and optionally dispatches a tunnel operation.
	#[cfg(target_os = "macos")]
	pub fn execute_tunnel_operation(
		&self,
		operation: &'static str,
		request: &MacOsTunnelBridgeRequest,
	) -> QuantumLinkResult<MacOsAdapterExecution> {
		let payload = serialize_payload(&TunnelEnvelope { operation, request })?;
		self.dispatch("tunnel", operation, payload, self.config.tunnel_helper_path.as_ref())
	}

	/// Serializes and optionally dispatches a firewall operation.
	#[cfg(target_os = "macos")]
	pub fn execute_firewall_operation(
		&self,
		operation: &'static str,
		request: &MacOsFirewallBridgeRequest,
	) -> QuantumLinkResult<MacOsAdapterExecution> {
		let payload = serialize_payload(&FirewallEnvelope { operation, request })?;
		self.dispatch("firewall", operation, payload, self.config.firewall_helper_path.as_ref())
	}

	#[cfg(target_os = "macos")]
	fn dispatch(
		&self,
		target: &'static str,
		operation: &'static str,
		payload: String,
		helper_path: Option<&PathBuf>,
	) -> QuantumLinkResult<MacOsAdapterExecution> {
		match self.config.mode {
			MacOsAdapterMode::Stub => Ok(MacOsAdapterExecution {
				target,
				operation,
				payload,
			}),
			MacOsAdapterMode::ExternalProcess => {
				let helper_path = helper_path.ok_or_else(|| {
					QuantumLinkError::NotImplemented(format!(
						"macOS {target} helper path is not configured"
					))
				})?;

				let status = Command::new(helper_path)
					.arg(operation)
					.arg(&payload)
					.status()
					.map_err(QuantumLinkError::Io)?;
				if !status.success() {
					return Err(QuantumLinkError::NotImplemented(format!(
						"macOS {target} helper failed for operation {operation}"
					)));
				}

				Ok(MacOsAdapterExecution {
					target,
					operation,
					payload,
				})
			}
		}
	}
}

#[cfg(target_os = "macos")]
impl MacOsTunnelBridgeExecutor for MacOsRuntimeAdapter {
	fn activate_tunnel(&self, request: &MacOsTunnelBridgeRequest) -> QuantumLinkResult<()> {
		self.execute_tunnel_operation("activate", request).map(|_| ())
	}

	fn deactivate_tunnel(&self, request: &MacOsTunnelBridgeRequest) -> QuantumLinkResult<()> {
		self.execute_tunnel_operation("deactivate", request).map(|_| ())
	}

	fn update_tunnel_endpoint(
		&self,
		request: &MacOsTunnelBridgeRequest,
		endpoint: std::net::SocketAddr,
	) -> QuantumLinkResult<()> {
		let mut updated = request.clone();
		updated.peer_endpoint = Some(endpoint);
		self.execute_tunnel_operation("update-endpoint", &updated).map(|_| ())
	}

	fn inject_tunnel_psk(
		&self,
		request: &MacOsTunnelBridgeRequest,
		psk: [u8; 32],
	) -> QuantumLinkResult<()> {
		let envelope = TunnelPskEnvelope { request, psk };
		let payload = serialize_payload(&envelope)?;
		self.dispatch("tunnel", "inject-psk", payload, self.config.tunnel_helper_path.as_ref())
			.map(|_| ())
	}

	fn read_tunnel_stats(&self, request: &MacOsTunnelBridgeRequest) -> QuantumLinkResult<TunnelStats> {
		let _ = self.execute_tunnel_operation("read-stats", request)?;
		Ok(TunnelStats::default())
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
		let _ = self.execute_firewall_operation(operation, request)?;
		Ok(matches!(request.operation, MacOsFirewallOperationMode::QueryActive).then_some(false))
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

#[cfg(test)]
mod tests {
	use super::{MacOsAdapterMode, MacOsRuntimeAdapter, MacOsRuntimeAdapterConfig};
	#[cfg(target_os = "macos")]
	use super::MacOsAdapterExecution;
	#[cfg(target_os = "macos")]
	use ql_firewall::{MacOsFirewallOperationMode, PlatformFirewall};
	#[cfg(target_os = "macos")]
	use ql_wireguard::{PlatformTunnel, TunnelConfig};
	#[cfg(target_os = "macos")]
	use ipnetwork::IpNetwork;
	#[cfg(target_os = "macos")]
	use std::net::{IpAddr, Ipv4Addr};

	#[test]
	fn default_adapter_uses_stub_mode() {
		let adapter = MacOsRuntimeAdapter::new(MacOsRuntimeAdapterConfig::default());
		assert_eq!(adapter.mode(), &MacOsAdapterMode::Stub);
	}

	#[cfg(target_os = "macos")]
	fn sample_tunnel() -> PlatformTunnel {
		PlatformTunnel::new(TunnelConfig {
			interface_name: "ql0".to_owned(),
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
		assert!(execution.payload.contains("com.quantumlink.tunnel.ql0"));
	}

	#[cfg(target_os = "macos")]
	#[test]
	fn stub_adapter_serializes_firewall_execution() {
		let adapter = MacOsRuntimeAdapter::new(MacOsRuntimeAdapterConfig::default());
		let firewall = PlatformFirewall::new("ql0");
		let execution: MacOsAdapterExecution = adapter
			.execute_firewall_operation(
				"kill-switch",
				&firewall.macos_kill_switch_request(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
			)
			.unwrap();

		assert_eq!(execution.target, "firewall");
		assert_eq!(execution.operation, "kill-switch");
		assert!(execution.payload.contains("packet-filter"));
		assert!(execution.payload.contains("com.quantumlink.ql0"));
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
		assert_eq!(firewall.macos_query_request().operation, MacOsFirewallOperationMode::QueryActive);
	}
}