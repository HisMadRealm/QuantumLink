//! WireGuard tunnel management for QuantumLink.

use std::net::{IpAddr, SocketAddr};
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::time::Duration;

use ipnetwork::IpNetwork;
use ql_core::{QuantumLinkError, QuantumLinkResult};
#[cfg(target_os = "macos")]
use serde::Serialize;
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

/// Describes the runtime tunnel backend selected for the current target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelBackendDescriptor {
	/// Stable backend identifier.
	pub name: &'static str,
	/// Whether this backend is meant to become a native product path.
	pub product_target: bool,
	/// Whether this backend currently performs native execution.
	pub native_execution: bool,
	/// Short note describing the backend state.
	pub note: &'static str,
}

/// Native bridge request handed to a future macOS tunnel extension layer.
#[cfg(target_os = "macos")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MacOsTunnelBridgeRequest {
	/// Provider bundle identifier expected by the native tunnel layer.
	pub provider_bundle_identifier: String,
	/// Runtime driver name.
	pub driver: &'static str,
	/// WireGuard interface name represented by the session.
	pub interface_name: String,
	/// Local listen port.
	pub listen_port: u16,
	/// Remote peer public key.
	pub peer_public_key: [u8; 32],
	/// Remote peer endpoint.
	pub peer_endpoint: Option<SocketAddr>,
	/// Allowed IPs routed through the tunnel.
	pub allowed_ips: Vec<IpNetwork>,
	/// Persistent keepalive interval.
	pub persistent_keepalive: Option<u16>,
	/// DNS servers associated with the session.
	pub dns_servers: Vec<IpAddr>,
	/// Requested tunnel MTU.
	pub mtu: u16,
}

/// Native executor interface for macOS tunnel bridge requests.
#[cfg(target_os = "macos")]
pub trait MacOsTunnelBridgeExecutor {
	/// Activates a tunnel session using the supplied bridge request.
	fn activate_tunnel(&self, request: &MacOsTunnelBridgeRequest) -> QuantumLinkResult<()>;

	/// Deactivates a tunnel session using the supplied bridge request.
	fn deactivate_tunnel(&self, request: &MacOsTunnelBridgeRequest) -> QuantumLinkResult<()>;

	/// Updates the peer endpoint for a tunnel session.
	fn update_tunnel_endpoint(
		&self,
		request: &MacOsTunnelBridgeRequest,
		endpoint: SocketAddr,
	) -> QuantumLinkResult<()>;

	/// Injects a preshared key for a tunnel session.
	fn inject_tunnel_psk(
		&self,
		request: &MacOsTunnelBridgeRequest,
		psk: [u8; 32],
	) -> QuantumLinkResult<()>;

	/// Reads tunnel statistics for a session.
	fn read_tunnel_stats(&self, request: &MacOsTunnelBridgeRequest) -> QuantumLinkResult<TunnelStats>;
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
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct WireGuardTunnel {
	backend: MacOsTunnelBackend,
}

/// Managed WireGuard tunnel state.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[derive(Debug)]
pub struct WireGuardTunnel {
	config: TunnelConfig,
}

/// Platform-selected tunnel facade used by higher layers.
#[derive(Debug)]
pub struct PlatformTunnel {
	backend: WireGuardTunnel,
}

impl PlatformTunnel {
	/// Creates the platform-selected tunnel backend.
	///
	/// # Errors
	///
	/// Returns an error if the active platform backend cannot be created.
	#[must_use]
	pub fn new(config: TunnelConfig) -> QuantumLinkResult<Self> {
		Ok(Self {
			backend: WireGuardTunnel::new(config)?,
		})
	}

	/// Returns the logical backend name selected for the current target.
	#[must_use]
	pub fn backend_name() -> &'static str {
		platform_backend_name()
	}

	/// Returns the backend descriptor selected for the current target.
	#[must_use]
	pub fn backend_descriptor() -> TunnelBackendDescriptor {
		tunnel_backend_descriptor()
	}

	/// Brings the platform tunnel up.
	///
	/// # Errors
	///
	/// Returns an error if the active backend cannot be activated.
	#[must_use]
	pub fn bring_up(&self) -> QuantumLinkResult<()> {
		self.backend.bring_up()
	}

	/// Tears the platform tunnel down.
	///
	/// # Errors
	///
	/// Returns an error if the active backend cannot be removed cleanly.
	#[must_use]
	pub fn tear_down(self) -> QuantumLinkResult<()> {
		self.backend.tear_down()
	}

	/// Updates the peer endpoint for the active backend.
	///
	/// # Errors
	///
	/// Returns an error if the active backend cannot apply the update.
	#[must_use]
	pub fn update_peer_endpoint(&self, endpoint: SocketAddr) -> QuantumLinkResult<()> {
		self.backend.update_peer_endpoint(endpoint)
	}

	/// Injects a preshared key through the active backend.
	///
	/// # Errors
	///
	/// Returns an error if the active backend cannot apply the PSK.
	#[must_use]
	pub fn inject_psk(&self, psk: [u8; 32]) -> QuantumLinkResult<()> {
		self.backend.inject_psk(psk)
	}

	/// Reads platform tunnel statistics.
	///
	/// # Errors
	///
	/// Returns an error if the active backend cannot provide stats.
	#[must_use]
	pub fn stats(&self) -> QuantumLinkResult<TunnelStats> {
		self.backend.stats()
	}

	/// Builds the macOS native bridge request for the active tunnel backend.
	#[cfg(target_os = "macos")]
	#[must_use]
	pub fn macos_bridge_request(&self) -> MacOsTunnelBridgeRequest {
		self.backend.macos_bridge_request()
	}

	/// Activates the tunnel through a supplied macOS executor.
	#[cfg(target_os = "macos")]
	pub fn bring_up_with_executor<E: MacOsTunnelBridgeExecutor>(
		&self,
		executor: &E,
	) -> QuantumLinkResult<()> {
		executor.activate_tunnel(&self.macos_bridge_request())
	}

	/// Tears down the tunnel through a supplied macOS executor.
	#[cfg(target_os = "macos")]
	pub fn tear_down_with_executor<E: MacOsTunnelBridgeExecutor>(
		&self,
		executor: &E,
	) -> QuantumLinkResult<()> {
		executor.deactivate_tunnel(&self.macos_bridge_request())
	}

	/// Updates the tunnel endpoint through a supplied macOS executor.
	#[cfg(target_os = "macos")]
	pub fn update_peer_endpoint_with_executor<E: MacOsTunnelBridgeExecutor>(
		&self,
		executor: &E,
		endpoint: SocketAddr,
	) -> QuantumLinkResult<()> {
		executor.update_tunnel_endpoint(&self.macos_bridge_request(), endpoint)
	}

	/// Injects a PSK through a supplied macOS executor.
	#[cfg(target_os = "macos")]
	pub fn inject_psk_with_executor<E: MacOsTunnelBridgeExecutor>(
		&self,
		executor: &E,
		psk: [u8; 32],
	) -> QuantumLinkResult<()> {
		executor.inject_tunnel_psk(&self.macos_bridge_request(), psk)
	}

	/// Reads tunnel statistics through a supplied macOS executor.
	#[cfg(target_os = "macos")]
	pub fn stats_with_executor<E: MacOsTunnelBridgeExecutor>(
		&self,
		executor: &E,
	) -> QuantumLinkResult<TunnelStats> {
		executor.read_tunnel_stats(&self.macos_bridge_request())
	}
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum MacOsTunnelDriver {
	NetworkExtension,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum MacOsTunnelState {
	Prepared,
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct MacOsTunnelBackend {
	config: TunnelConfig,
	driver: MacOsTunnelDriver,
	state: MacOsTunnelState,
	provider_bundle_identifier: String,
}

#[cfg(target_os = "macos")]
impl MacOsTunnelBackend {
	fn new(config: TunnelConfig) -> QuantumLinkResult<Self> {
		validate_stub_config(&config)?;
		Ok(Self {
			provider_bundle_identifier: format!("com.quantumlink.tunnel.{}", config.interface_name),
			config,
			driver: MacOsTunnelDriver::NetworkExtension,
			state: MacOsTunnelState::Prepared,
		})
	}

	fn bring_up(&self) -> QuantumLinkResult<()> {
		let _ = (&self.config, &self.driver, &self.state, &self.provider_bundle_identifier);
		Err(QuantumLinkError::NotImplemented(
			"macOS tunnel backend shape is defined but native Network Extension execution is not implemented yet"
				.to_owned(),
		))
	}

	fn tear_down(self) -> QuantumLinkResult<()> {
		let _ = self;
		Err(QuantumLinkError::NotImplemented(
			"macOS tunnel backend shape is defined but native Network Extension execution is not implemented yet"
				.to_owned(),
		))
	}

	fn update_peer_endpoint(&self, endpoint: SocketAddr) -> QuantumLinkResult<()> {
		let _ = (&self.config, &self.driver, endpoint);
		Err(QuantumLinkError::NotImplemented(
			"macOS tunnel backend shape is defined but native endpoint management is not implemented yet"
				.to_owned(),
		))
	}

	fn inject_psk(&self, psk: [u8; 32]) -> QuantumLinkResult<()> {
		let _ = (&self.config, &self.driver, psk);
		Err(QuantumLinkError::NotImplemented(
			"macOS tunnel backend shape is defined but native PSK injection is not implemented yet"
				.to_owned(),
		))
	}

	fn stats(&self) -> QuantumLinkResult<TunnelStats> {
		let _ = (&self.config, &self.state);
		Err(QuantumLinkError::NotImplemented(
			"macOS tunnel backend shape is defined but native tunnel statistics are not implemented yet"
				.to_owned(),
		))
	}

	fn bridge_request(&self) -> MacOsTunnelBridgeRequest {
		MacOsTunnelBridgeRequest {
			provider_bundle_identifier: self.provider_bundle_identifier.clone(),
			driver: "network-extension",
			interface_name: self.config.interface_name.clone(),
			listen_port: self.config.listen_port,
			peer_public_key: self.config.peer_public_key,
			peer_endpoint: self.config.peer_endpoint,
			allowed_ips: self.config.allowed_ips.clone(),
			persistent_keepalive: self.config.persistent_keepalive,
			dns_servers: self.config.dns_servers.clone(),
			mtu: self.config.mtu,
		}
	}
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

#[cfg(target_os = "macos")]
impl WireGuardTunnel {
	/// Creates a macOS tunnel scaffold implementation.
	///
	/// # Errors
	///
	/// Returns an error if the shared tunnel configuration is invalid.
	#[must_use]
	pub fn new(config: TunnelConfig) -> QuantumLinkResult<Self> {
		Ok(Self {
			backend: MacOsTunnelBackend::new(config)?,
		})
	}

	/// Brings the interface up.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` until the native macOS backend lands.
	#[must_use]
	pub fn bring_up(&self) -> QuantumLinkResult<()> {
		self.backend.bring_up()
	}

	/// Tears the interface down.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` until the native macOS backend lands.
	#[must_use]
	pub fn tear_down(self) -> QuantumLinkResult<()> {
		self.backend.tear_down()
	}

	/// Updates the peer endpoint.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` until the native macOS backend lands.
	#[must_use]
	pub fn update_peer_endpoint(&self, endpoint: SocketAddr) -> QuantumLinkResult<()> {
		self.backend.update_peer_endpoint(endpoint)
	}

	/// Injects a preshared key for the peer.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` until the native macOS backend lands.
	#[must_use]
	pub fn inject_psk(&self, psk: [u8; 32]) -> QuantumLinkResult<()> {
		self.backend.inject_psk(psk)
	}

	/// Reads tunnel statistics.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` until the native macOS backend lands.
	#[must_use]
	pub fn stats(&self) -> QuantumLinkResult<TunnelStats> {
		self.backend.stats()
	}

	/// Builds the native bridge request for the current macOS tunnel backend.
	#[must_use]
	pub fn macos_bridge_request(&self) -> MacOsTunnelBridgeRequest {
		self.backend.bridge_request()
	}
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl WireGuardTunnel {
	/// Creates a non-Linux stub tunnel implementation.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` on non-Linux targets.
	#[must_use]
	pub fn new(config: TunnelConfig) -> QuantumLinkResult<Self> {
		validate_stub_config(&config)?;
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

#[cfg(any(target_os = "macos", not(target_os = "linux")))]
fn validate_stub_config(config: &TunnelConfig) -> QuantumLinkResult<()> {
	if config.allowed_ips.is_empty() {
		return Err(QuantumLinkError::WireGuard(
			"at least one allowed IP is required".to_owned(),
		));
	}

	Ok(())
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
fn platform_backend_name() -> &'static str {
	"linux-reference"
}

#[cfg(target_os = "macos")]
fn platform_backend_name() -> &'static str {
	"macos-scaffold"
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_backend_name() -> &'static str {
	"stub"
}

#[cfg(target_os = "linux")]
fn tunnel_backend_descriptor() -> TunnelBackendDescriptor {
	TunnelBackendDescriptor {
		name: "linux-reference",
		product_target: false,
		native_execution: true,
		note: "reference runtime backend used while the macOS product path is built",
	}
}

#[cfg(target_os = "macos")]
fn tunnel_backend_descriptor() -> TunnelBackendDescriptor {
	TunnelBackendDescriptor {
		name: "macos-scaffold",
		product_target: true,
		native_execution: false,
		note: "typed macOS Network Extension backend shape without native execution yet",
	}
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn tunnel_backend_descriptor() -> TunnelBackendDescriptor {
	TunnelBackendDescriptor {
		name: "stub",
		product_target: false,
		native_execution: false,
		note: "unsupported-target placeholder backend",
	}
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
	use super::PlatformTunnel;
	use super::TunnelBackendDescriptor;
	use super::TunnelConfig;
	#[cfg(target_os = "macos")]
	use super::{
		MacOsTunnelBackend, MacOsTunnelBridgeExecutor, MacOsTunnelBridgeRequest,
		MacOsTunnelDriver, MacOsTunnelState, TunnelStats,
	};
	use ipnetwork::IpNetwork;
	#[cfg(target_os = "macos")]
	use std::cell::RefCell;
	#[cfg(target_os = "macos")]
	use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
	#[cfg(target_os = "macos")]
	use ql_core::QuantumLinkResult;
	use zeroize::Zeroize;

	fn sample_config() -> TunnelConfig {
		TunnelConfig {
			interface_name: "ql0".to_owned(),
			private_key: [7_u8; 32],
			listen_port: 51_820,
			peer_public_key: [8_u8; 32],
			peer_endpoint: None,
			allowed_ips: vec![IpNetwork::V4("10.0.0.1/32".parse().unwrap())],
			persistent_keepalive: Some(25),
			dns_servers: Vec::new(),
			mtu: 1_420,
		}
	}

	#[test]
	fn tunnel_config_zeroizes_private_key() {
		let mut config = sample_config();

		config.zeroize();

		assert!(config.private_key.iter().all(|byte| *byte == 0));
	}

	#[cfg(target_os = "macos")]
	#[test]
	fn macos_backend_name_reports_scaffold() {
		assert_eq!(PlatformTunnel::backend_name(), "macos-scaffold");
	}

	#[test]
	fn backend_descriptor_exposes_target_state() {
		let descriptor: TunnelBackendDescriptor = PlatformTunnel::backend_descriptor();
		assert_eq!(descriptor.name, PlatformTunnel::backend_name());
	}

	#[cfg(target_os = "macos")]
	#[test]
	fn macos_backend_initializes_native_shape() {
		let backend = MacOsTunnelBackend::new(sample_config()).unwrap();

		assert_eq!(backend.driver, MacOsTunnelDriver::NetworkExtension);
		assert_eq!(backend.state, MacOsTunnelState::Prepared);
		assert_eq!(backend.provider_bundle_identifier, "com.quantumlink.tunnel.ql0");
	}

	#[cfg(target_os = "macos")]
	#[test]
	fn macos_bridge_request_carries_tunnel_configuration() {
		let tunnel = PlatformTunnel::new(sample_config()).unwrap();
		let request = tunnel.macos_bridge_request();

		assert_eq!(request.driver, "network-extension");
		assert_eq!(request.interface_name, "ql0");
		assert_eq!(request.provider_bundle_identifier, "com.quantumlink.tunnel.ql0");
		assert_eq!(request.listen_port, 51_820);
		assert_eq!(request.allowed_ips.len(), 1);
	}

	#[cfg(target_os = "macos")]
	#[derive(Default)]
	struct RecordingTunnelExecutor {
		operations: RefCell<Vec<String>>,
	}

	#[cfg(target_os = "macos")]
	impl MacOsTunnelBridgeExecutor for RecordingTunnelExecutor {
		fn activate_tunnel(&self, request: &MacOsTunnelBridgeRequest) -> QuantumLinkResult<()> {
			self.operations.borrow_mut().push(format!("activate:{}", request.interface_name));
			Ok(())
		}

		fn deactivate_tunnel(&self, request: &MacOsTunnelBridgeRequest) -> QuantumLinkResult<()> {
			self.operations.borrow_mut().push(format!("deactivate:{}", request.interface_name));
			Ok(())
		}

		fn update_tunnel_endpoint(
			&self,
			request: &MacOsTunnelBridgeRequest,
			endpoint: SocketAddr,
		) -> QuantumLinkResult<()> {
			self.operations.borrow_mut().push(format!("endpoint:{}:{}", request.interface_name, endpoint));
			Ok(())
		}

		fn inject_tunnel_psk(
			&self,
			request: &MacOsTunnelBridgeRequest,
			psk: [u8; 32],
		) -> QuantumLinkResult<()> {
			self.operations.borrow_mut().push(format!("psk:{}:{}", request.interface_name, psk[0]));
			Ok(())
		}

		fn read_tunnel_stats(&self, request: &MacOsTunnelBridgeRequest) -> QuantumLinkResult<TunnelStats> {
			self.operations.borrow_mut().push(format!("stats:{}", request.interface_name));
			Ok(TunnelStats {
				bytes_sent: 11,
				bytes_received: 22,
				last_handshake: None,
			})
		}
	}

	#[cfg(target_os = "macos")]
	#[test]
	fn macos_executor_methods_consume_bridge_requests() {
		let tunnel = PlatformTunnel::new(sample_config()).unwrap();
		executor_assertions(tunnel);
	}

	#[cfg(target_os = "macos")]
	fn executor_assertions(tunnel: PlatformTunnel) {
		let executor = RecordingTunnelExecutor::default();
		let endpoint = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 51820));

		tunnel.bring_up_with_executor(&executor).unwrap();
		tunnel.update_peer_endpoint_with_executor(&executor, endpoint).unwrap();
		tunnel.inject_psk_with_executor(&executor, [9_u8; 32]).unwrap();
		let stats = tunnel.stats_with_executor(&executor).unwrap();
		tunnel.tear_down_with_executor(&executor).unwrap();

		assert_eq!(stats.bytes_sent, 11);
		assert_eq!(stats.bytes_received, 22);
		assert_eq!(
			executor.operations.borrow().as_slice(),
			[
				"activate:ql0",
				"endpoint:ql0:10.0.0.2:51820",
				"psk:ql0:9",
				"stats:ql0",
				"deactivate:ql0",
			]
		);
	}
}
