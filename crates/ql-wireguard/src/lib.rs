//! WireGuard tunnel management for QuantumLink.

use std::net::{IpAddr, SocketAddr};
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::time::Duration;

use ipnetwork::IpNetwork;
use ql_core::{QuantumLinkError, QuantumLinkResult};
use zeroize::Zeroize;

/// Configuration used to create and manage a WireGuard tunnel.
#[derive(Clone, Debug)]
pub struct TunnelConfig {
	/// WireGuard interface name.
	pub interface_name: String,
	/// WireGuard private key bytes.
	pub private_key: [u8; 32],
	/// Local WireGuard listen port.
	pub listen_port: u16,
	/// Remote peer public key.
	pub peer_public_key: [u8; 32],
	/// Remote peer endpoint.
	pub peer_endpoint: Option<SocketAddr>,
	/// Allowed IPs routed through the interface.
	pub allowed_ips: Vec<IpNetwork>,
	/// Persistent keepalive interval in seconds.
	pub persistent_keepalive: Option<u16>,
	/// DNS servers configured while the tunnel is active.
	pub dns_servers: Vec<IpAddr>,
	/// MTU applied to the interface.
	pub mtu: u16,
}

impl Zeroize for TunnelConfig {
	fn zeroize(&mut self) {
		self.private_key.zeroize();
	}
}

impl Drop for TunnelConfig {
	fn drop(&mut self) {
		self.zeroize();
	}
}

/// Runtime tunnel statistics for the active peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TunnelStats {
	/// Bytes sent to the peer.
	pub bytes_sent: u64,
	/// Bytes received from the peer.
	pub bytes_received: u64,
	/// Time since the last successful WireGuard handshake.
	pub last_handshake: Option<Duration>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
enum DnsState {
	Unconfigured,
	Resolved,
	ResolvConfBackup { backup_path: PathBuf },
}

/// Managed WireGuard tunnel state.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct WireGuardTunnel {
	config: TunnelConfig,
	dns_state: Mutex<DnsState>,
}

/// Managed WireGuard tunnel state.
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct WireGuardTunnel {
	config: TunnelConfig,
}

#[cfg(target_os = "linux")]
impl WireGuardTunnel {
	/// Creates and configures a WireGuard interface without bringing it up.
	///
	/// # Errors
	///
	/// Returns an error if interface creation or peer configuration fails.
	#[must_use]
	pub fn new(config: TunnelConfig) -> QuantumLinkResult<Self> {
		validate_config(&config)?;
		ensure_root()?;

		let mut route_socket = wireguard_uapi::RouteSocket::connect().map_err(|error| {
			QuantumLinkError::WireGuard(format!("failed to connect route socket: {error}"))
		})?;

		let existing_devices = route_socket.list_device_names().map_err(|error| {
			QuantumLinkError::WireGuard(format!("failed to enumerate WireGuard devices: {error}"))
		})?;
		if existing_devices.iter().any(|name| name == &config.interface_name) {
			return Err(QuantumLinkError::WireGuard(format!(
				"interface {} already exists",
				config.interface_name
			)));
		}

		route_socket.add_device(&config.interface_name).map_err(|error| {
			QuantumLinkError::WireGuard(format!("failed to create interface: {error}"))
		})?;

		apply_device_config(&config)?;
		run_command("ip", ["link", "set", "dev", &config.interface_name, "mtu", &config.mtu.to_string()])?;

		Ok(Self {
			config,
			dns_state: Mutex::new(DnsState::Unconfigured),
		})
	}

	/// Brings the interface up, installs routes, and configures DNS.
	///
	/// # Errors
	///
	/// Returns an error if interface activation, route installation, or DNS setup fails.
	#[must_use]
	pub fn bring_up(&self) -> QuantumLinkResult<()> {
		ensure_root()?;

		run_command("ip", ["link", "set", "up", "dev", &self.config.interface_name])?;
		for network in &self.config.allowed_ips {
			let network_cidr = network.to_string();
			run_command("ip", ["route", "replace", network_cidr.as_str(), "dev", &self.config.interface_name])?;
		}

		self.configure_dns()
	}

	/// Tears down the interface, routes, and any DNS changes.
	///
	/// # Errors
	///
	/// Returns an error if cleanup fails.
	#[must_use]
	pub fn tear_down(self) -> QuantumLinkResult<()> {
		ensure_root()?;

		let _ = self.restore_dns();
		for network in &self.config.allowed_ips {
			let network_cidr = network.to_string();
			let _ = run_command("ip", ["route", "del", network_cidr.as_str(), "dev", &self.config.interface_name]);
		}

		let mut route_socket = wireguard_uapi::RouteSocket::connect().map_err(|error| {
			QuantumLinkError::WireGuard(format!("failed to connect route socket: {error}"))
		})?;
		route_socket.del_device(&self.config.interface_name).map_err(|error| {
			QuantumLinkError::WireGuard(format!("failed to delete interface: {error}"))
		})
	}

	/// Updates the peer endpoint for roaming or re-resolution.
	///
	/// # Errors
	///
	/// Returns an error if the peer endpoint cannot be updated.
	#[must_use]
	pub fn update_peer_endpoint(&self, endpoint: SocketAddr) -> QuantumLinkResult<()> {
		ensure_root()?;

		let peer = wireguard_uapi::set::Peer::from_public_key(&self.config.peer_public_key)
			.flags(vec![wireguard_uapi::set::WgPeerF::UpdateOnly])
			.endpoint(&endpoint);
		let device = wireguard_uapi::set::Device::from_ifname(self.config.interface_name.as_str())
			.peers(vec![peer]);

		let mut socket = wireguard_uapi::WgSocket::connect().map_err(|error| {
			QuantumLinkError::WireGuard(format!("failed to connect WireGuard socket: {error}"))
		})?;
		socket.set_device(device).map_err(|error| {
			QuantumLinkError::WireGuard(format!("failed to update peer endpoint: {error}"))
		})
	}

	/// Injects a fresh preshared key for the active peer.
	///
	/// # Errors
	///
	/// Returns an error if the PSK cannot be applied.
	#[must_use]
	pub fn inject_psk(&self, psk: [u8; 32]) -> QuantumLinkResult<()> {
		ensure_root()?;

		let peer = wireguard_uapi::set::Peer::from_public_key(&self.config.peer_public_key)
			.flags(vec![wireguard_uapi::set::WgPeerF::UpdateOnly])
			.preshared_key(&psk);
		let device = wireguard_uapi::set::Device::from_ifname(self.config.interface_name.as_str())
			.peers(vec![peer]);

		let mut socket = wireguard_uapi::WgSocket::connect().map_err(|error| {
			QuantumLinkError::WireGuard(format!("failed to connect WireGuard socket: {error}"))
		})?;
		socket.set_device(device).map_err(|error| {
			QuantumLinkError::WireGuard(format!("failed to inject peer PSK: {error}"))
		})
	}

	/// Reads current interface statistics.
	///
	/// # Errors
	///
	/// Returns an error if the interface state cannot be queried.
	#[must_use]
	pub fn stats(&self) -> QuantumLinkResult<TunnelStats> {
		let mut socket = wireguard_uapi::WgSocket::connect().map_err(|error| {
			QuantumLinkError::WireGuard(format!("failed to connect WireGuard socket: {error}"))
		})?;
		let device = socket
			.get_device(wireguard_uapi::DeviceInterface::from_name(self.config.interface_name.as_str()))
			.map_err(|error| QuantumLinkError::WireGuard(format!("failed to fetch interface state: {error}")))?;

		let peer = device
			.peers
			.into_iter()
			.find(|peer| peer.public_key == self.config.peer_public_key)
			.ok_or_else(|| {
				QuantumLinkError::WireGuard("configured peer not present on interface".to_owned())
			})?;

		Ok(TunnelStats {
			bytes_sent: peer.tx_bytes,
			bytes_received: peer.rx_bytes,
			last_handshake: Some(peer.last_handshake_time).filter(|duration| !duration.is_zero()),
		})
	}

	fn configure_dns(&self) -> QuantumLinkResult<()> {
		if self.config.dns_servers.is_empty() {
			return Ok(());
		}

		if has_command("resolvectl") {
			let mut args = vec!["dns".to_owned(), self.config.interface_name.clone()];
			args.extend(self.config.dns_servers.iter().map(ToString::to_string));
			run_command_owned("resolvectl", args)?;
			run_command("resolvectl", ["domain", &self.config.interface_name, "~."])?;
			*self.dns_state.lock().map_err(|_| {
				QuantumLinkError::WireGuard("dns state mutex poisoned".to_owned())
			})? = DnsState::Resolved;
			return Ok(());
		}

		let resolv_conf = PathBuf::from("/etc/resolv.conf");
		let backup_path = PathBuf::from(format!(
			"/tmp/quantumlink-{}-resolv.conf.bak",
			self.config.interface_name
		));
		if !backup_path.exists() {
			std::fs::copy(&resolv_conf, &backup_path).map_err(QuantumLinkError::Io)?;
		}

		let content = self
			.config
			.dns_servers
			.iter()
			.map(|server| format!("nameserver {server}\n"))
			.collect::<String>();
		std::fs::write(&resolv_conf, content).map_err(QuantumLinkError::Io)?;

		*self.dns_state.lock().map_err(|_| {
			QuantumLinkError::WireGuard("dns state mutex poisoned".to_owned())
		})? = DnsState::ResolvConfBackup { backup_path };
		Ok(())
	}

	fn restore_dns(&self) -> QuantumLinkResult<()> {
		let mut state = self.dns_state.lock().map_err(|_| {
			QuantumLinkError::WireGuard("dns state mutex poisoned".to_owned())
		})?;

		match &*state {
			DnsState::Unconfigured => Ok(()),
			DnsState::Resolved => {
				if has_command("resolvectl") {
					run_command("resolvectl", ["revert", &self.config.interface_name])?;
				}
				*state = DnsState::Unconfigured;
				Ok(())
			}
			DnsState::ResolvConfBackup { backup_path } => {
				std::fs::copy(backup_path, "/etc/resolv.conf").map_err(QuantumLinkError::Io)?;
				let _ = std::fs::remove_file(backup_path);
				*state = DnsState::Unconfigured;
				Ok(())
			}
		}
	}
}

#[cfg(not(target_os = "linux"))]
impl WireGuardTunnel {
	/// Creates a non-Linux stub tunnel implementation.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` on non-Linux targets.
	#[must_use]
	pub fn new(config: TunnelConfig) -> QuantumLinkResult<Self> {
		let _ = config;
		Err(QuantumLinkError::NotImplemented(
			"WireGuard tunnel management is implemented for Linux only in v0.1".to_owned(),
		))
	}

	/// Brings the interface up.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` on non-Linux targets.
	#[must_use]
	pub fn bring_up(&self) -> QuantumLinkResult<()> {
		let _ = &self.config;
		Err(QuantumLinkError::NotImplemented(
			"WireGuard tunnel management is implemented for Linux only in v0.1".to_owned(),
		))
	}

	/// Tears the interface down.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` on non-Linux targets.
	#[must_use]
	pub fn tear_down(self) -> QuantumLinkResult<()> {
		let _ = self;
		Err(QuantumLinkError::NotImplemented(
			"WireGuard tunnel management is implemented for Linux only in v0.1".to_owned(),
		))
	}

	/// Updates the peer endpoint.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` on non-Linux targets.
	#[must_use]
	pub fn update_peer_endpoint(&self, endpoint: SocketAddr) -> QuantumLinkResult<()> {
		let _ = (&self.config, endpoint);
		Err(QuantumLinkError::NotImplemented(
			"WireGuard tunnel management is implemented for Linux only in v0.1".to_owned(),
		))
	}

	/// Injects a preshared key for the peer.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` on non-Linux targets.
	#[must_use]
	pub fn inject_psk(&self, psk: [u8; 32]) -> QuantumLinkResult<()> {
		let _ = (&self.config, psk);
		Err(QuantumLinkError::NotImplemented(
			"WireGuard tunnel management is implemented for Linux only in v0.1".to_owned(),
		))
	}

	/// Reads tunnel statistics.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` on non-Linux targets.
	#[must_use]
	pub fn stats(&self) -> QuantumLinkResult<TunnelStats> {
		let _ = &self.config;
		Err(QuantumLinkError::NotImplemented(
			"WireGuard tunnel management is implemented for Linux only in v0.1".to_owned(),
		))
	}
}

#[cfg(target_os = "linux")]
fn validate_config(config: &TunnelConfig) -> QuantumLinkResult<()> {
	if config.interface_name.is_empty() || config.interface_name.len() > 15 {
		return Err(QuantumLinkError::WireGuard(
			"interface name must be between 1 and 15 characters".to_owned(),
		));
	}
	if !config
		.interface_name
		.bytes()
		.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
	{
		return Err(QuantumLinkError::WireGuard(
			"interface name contains unsupported characters".to_owned(),
		));
	}
	if config.allowed_ips.is_empty() {
		return Err(QuantumLinkError::WireGuard(
			"at least one allowed IP is required".to_owned(),
		));
	}

	Ok(())
}

#[cfg(target_os = "linux")]
fn apply_device_config(config: &TunnelConfig) -> QuantumLinkResult<()> {
	let allowed_ips = config
		.allowed_ips
		.iter()
		.map(|network| {
			wireguard_uapi::set::AllowedIp::from_ipaddr(&network.ip()).cidr_mask(network.prefix())
		})
		.collect::<Vec<_>>();

	let mut peer = wireguard_uapi::set::Peer::from_public_key(&config.peer_public_key)
		.flags(vec![wireguard_uapi::set::WgPeerF::ReplaceAllowedIps])
		.allowed_ips(allowed_ips);
	if let Some(endpoint) = &config.peer_endpoint {
		peer = peer.endpoint(endpoint);
	}
	if let Some(keepalive) = config.persistent_keepalive {
		peer = peer.persistent_keepalive_interval(keepalive);
	}

	let device = wireguard_uapi::set::Device::from_ifname(config.interface_name.as_str())
		.private_key(&config.private_key)
		.listen_port(config.listen_port)
		.peers(vec![peer]);

	let mut socket = wireguard_uapi::WgSocket::connect().map_err(|error| {
		QuantumLinkError::WireGuard(format!("failed to connect WireGuard socket: {error}"))
	})?;
	socket.set_device(device).map_err(|error| {
		QuantumLinkError::WireGuard(format!("failed to configure interface: {error}"))
	})
}

#[cfg(target_os = "linux")]
fn ensure_root() -> QuantumLinkResult<()> {
	use nix::unistd::Uid;

	if Uid::effective().is_root() {
		Ok(())
	} else {
		Err(QuantumLinkError::WireGuard(
			"CAP_NET_ADMIN or root privileges are required".to_owned(),
		))
	}
}

#[cfg(target_os = "linux")]
fn has_command(command: &str) -> bool {
	std::env::var_os("PATH")
		.map(|paths| std::env::split_paths(&paths).any(|path| path.join(command).exists()))
		.unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn run_command<const N: usize>(program: &str, args: [&str; N]) -> QuantumLinkResult<()> {
	let status = std::process::Command::new(program)
		.args(args)
		.status()
		.map_err(QuantumLinkError::Io)?;
	if status.success() {
		Ok(())
	} else {
		Err(QuantumLinkError::WireGuard(format!(
			"command failed: {program} {}",
			args.join(" ")
		)))
	}
}

#[cfg(target_os = "linux")]
fn run_command_owned(program: &str, args: Vec<String>) -> QuantumLinkResult<()> {
	let status = std::process::Command::new(program)
		.args(args.as_slice())
		.status()
		.map_err(QuantumLinkError::Io)?;
	if status.success() {
		Ok(())
	} else {
		Err(QuantumLinkError::WireGuard(format!(
			"command failed: {program} {}",
			args.join(" ")
		)))
	}
}

#[cfg(test)]
mod tests {
	use super::TunnelConfig;
	use ipnetwork::IpNetwork;
	use zeroize::Zeroize;

	#[test]
	fn tunnel_config_zeroizes_private_key() {
		let mut config = TunnelConfig {
			interface_name: "ql0".to_owned(),
			private_key: [7_u8; 32],
			listen_port: 51_820,
			peer_public_key: [8_u8; 32],
			peer_endpoint: None,
			allowed_ips: vec![IpNetwork::V4("10.0.0.1/32".parse().unwrap())],
			persistent_keepalive: Some(25),
			dns_servers: Vec::new(),
			mtu: 1_420,
		};

		config.zeroize();

		assert!(config.private_key.iter().all(|byte| *byte == 0));
	}
}
