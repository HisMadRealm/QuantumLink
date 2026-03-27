//! Native macOS app-shell host model for QuantumLink.

#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};

use ql_core::{DaemonCommand, DaemonEvent, QuantumLinkResult};
use ql_gui::GuiModel;
use ql_macos_runtime::{
	MacOsAdapterExecution, MacOsRuntimeAdapter, MacOsRuntimeAdapterConfig,
};

#[cfg(target_os = "macos")]
use ql_firewall::PlatformFirewall;
#[cfg(target_os = "macos")]
use ql_wireguard::PlatformTunnel;

/// Firewall behavior requested by the macOS host for a connection session.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacOsHostFirewallPolicy {
	KillSwitch { dns_server: IpAddr },
	DnsOnly { dns_server: IpAddr },
	None,
}

/// Host-side operation emitted by the macOS app shell.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacOsHostOperation {
	Tunnel(MacOsAdapterExecution),
	Firewall(MacOsAdapterExecution),
}

/// Native macOS app-shell host state.
#[derive(Debug, Clone)]
pub struct MacOsAppShell {
	gui: GuiModel,
	adapter: MacOsRuntimeAdapter,
}

impl MacOsAppShell {
	/// Creates a macOS app shell using the supplied runtime adapter config.
	#[must_use]
	pub fn new(adapter_config: MacOsRuntimeAdapterConfig) -> Self {
		Self {
			gui: GuiModel::default(),
			adapter: MacOsRuntimeAdapter::new(adapter_config),
		}
	}

	/// Returns an immutable view of the shared GUI model.
	#[must_use]
	pub fn gui(&self) -> &GuiModel {
		&self.gui
	}

	/// Returns a mutable view of the shared GUI model.
	#[must_use]
	pub fn gui_mut(&mut self) -> &mut GuiModel {
		&mut self.gui
	}

	/// Returns the runtime adapter owned by the host shell.
	#[must_use]
	pub fn adapter(&self) -> &MacOsRuntimeAdapter {
		&self.adapter
	}

	/// Queues a connect request through the shared GUI model.
	pub fn request_connect(&mut self, server: Option<SocketAddr>) {
		self.gui.request_connect(server);
	}

	/// Queues a disconnect request through the shared GUI model.
	pub fn request_disconnect(&mut self) {
		self.gui.request_disconnect();
	}

	/// Queues a status refresh through the shared GUI model.
	pub fn request_status_refresh(&mut self) {
		self.gui.request_status_refresh();
	}

	/// Applies a daemon event to the shared GUI model.
	pub fn apply_daemon_event(&mut self, event: DaemonEvent) {
		self.gui.apply_event(event);
	}

	/// Drains the next pending daemon command.
	pub fn take_pending_command(&mut self) -> Option<DaemonCommand> {
		self.gui.take_pending_command()
	}

	/// Plans host-side connect operations for the macOS runtime.
	#[cfg(target_os = "macos")]
	pub fn plan_connect_operations(
		&self,
		tunnel: &PlatformTunnel,
		firewall: &PlatformFirewall,
		firewall_policy: MacOsHostFirewallPolicy,
	) -> QuantumLinkResult<Vec<MacOsHostOperation>> {
		let mut operations = vec![MacOsHostOperation::Tunnel(
			self.adapter
				.execute_tunnel_operation("activate", &tunnel.macos_bridge_request())?,
		)];

		match firewall_policy {
			MacOsHostFirewallPolicy::KillSwitch { dns_server } => operations.push(
				MacOsHostOperation::Firewall(self.adapter.execute_firewall_operation(
					"kill-switch",
					&firewall.macos_kill_switch_request(dns_server),
				)?),
			),
			MacOsHostFirewallPolicy::DnsOnly { dns_server } => operations.push(
				MacOsHostOperation::Firewall(self.adapter.execute_firewall_operation(
					"dns-only",
					&firewall.macos_dns_request(dns_server),
				)?),
			),
			MacOsHostFirewallPolicy::None => {}
		}

		Ok(operations)
	}

	/// Plans host-side disconnect operations for the macOS runtime.
	#[cfg(target_os = "macos")]
	pub fn plan_disconnect_operations(
		&self,
		tunnel: &PlatformTunnel,
		firewall: &PlatformFirewall,
	) -> QuantumLinkResult<Vec<MacOsHostOperation>> {
		Ok(vec![
			MacOsHostOperation::Firewall(
				self.adapter.execute_firewall_operation("disable-all", &firewall.macos_disable_request())?,
			),
			MacOsHostOperation::Tunnel(
				self.adapter.execute_tunnel_operation("deactivate", &tunnel.macos_bridge_request())?,
			),
		])
	}
}

#[cfg(test)]
mod tests {
	use super::MacOsAppShell;
	use ql_core::{DaemonEvent, TunnelState};
	use ql_macos_runtime::{MacOsAdapterMode, MacOsRuntimeAdapterConfig};

	#[cfg(target_os = "macos")]
	use super::{MacOsHostFirewallPolicy, MacOsHostOperation};
	#[cfg(target_os = "macos")]
	use ipnetwork::IpNetwork;
	#[cfg(target_os = "macos")]
	use ql_firewall::PlatformFirewall;
	#[cfg(target_os = "macos")]
	use ql_wireguard::{PlatformTunnel, TunnelConfig};
	#[cfg(target_os = "macos")]
	use std::net::{IpAddr, Ipv4Addr};

	fn sample_shell() -> MacOsAppShell {
		MacOsAppShell::new(MacOsRuntimeAdapterConfig {
			mode: MacOsAdapterMode::Stub,
			..MacOsRuntimeAdapterConfig::default()
		})
	}

	#[test]
	fn shell_queues_and_drains_gui_commands() {
		let mut shell = sample_shell();
		shell.request_status_refresh();

		assert!(shell.take_pending_command().is_some());
		assert!(shell.take_pending_command().is_none());
	}

	#[test]
	fn shell_applies_daemon_events_to_gui_model() {
		let mut shell = sample_shell();
		shell.apply_daemon_event(DaemonEvent::StateChanged(TunnelState::Connecting));

		assert_eq!(shell.gui().connection.state, TunnelState::Connecting);
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
	fn shell_plans_connect_operations() {
		let shell = sample_shell();
		let tunnel = sample_tunnel();
		let firewall = PlatformFirewall::new("ql0");
		let operations = shell
			.plan_connect_operations(
				&tunnel,
				&firewall,
				MacOsHostFirewallPolicy::KillSwitch {
					dns_server: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
				},
			)
			.unwrap();

		assert_eq!(operations.len(), 2);
		assert!(matches!(&operations[0], MacOsHostOperation::Tunnel(_)));
		assert!(matches!(&operations[1], MacOsHostOperation::Firewall(_)));
	}

	#[cfg(target_os = "macos")]
	#[test]
	fn shell_plans_disconnect_operations() {
		let shell = sample_shell();
		let tunnel = sample_tunnel();
		let firewall = PlatformFirewall::new("ql0");
		let operations = shell.plan_disconnect_operations(&tunnel, &firewall).unwrap();

		assert_eq!(operations.len(), 2);
		assert!(matches!(&operations[0], MacOsHostOperation::Firewall(_)));
		assert!(matches!(&operations[1], MacOsHostOperation::Tunnel(_)));
	}
}