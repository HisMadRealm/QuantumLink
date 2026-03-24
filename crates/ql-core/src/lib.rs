//! Shared types, configuration, and IPC definitions for QuantumLink.

#![forbid(unsafe_code)]

use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A `Result` alias used across QuantumLink crates.
pub type QuantumLinkResult<T> = Result<T, QuantumLinkError>;

/// Runtime configuration loaded from `~/.config/quantumlink/config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct QuantumLinkConfig {
	/// Server-side connection parameters for VPN exit mode.
	pub server: ServerConfig,
	/// Active cryptographic mode and algorithm preferences.
	pub crypto: CryptoConfig,
	/// Network-level protections and tunnel settings.
	pub network: NetworkConfig,
	/// Split-tunnel configuration.
	pub split_tunnel: SplitTunnelConfig,
	/// Mesh-mode settings reserved for the v0.2 API surface.
	pub mesh: MeshSettings,
}

impl Default for QuantumLinkConfig {
	fn default() -> Self {
		Self {
			server: ServerConfig::default(),
			crypto: CryptoConfig::default(),
			network: NetworkConfig::default(),
			split_tunnel: SplitTunnelConfig::default(),
			mesh: MeshSettings::default(),
		}
	}
}

impl QuantumLinkConfig {
	/// Returns the default client configuration path.
	#[must_use]
	pub fn default_path() -> PathBuf {
		PathBuf::from("~/.config/quantumlink/config.toml")
	}

	/// Loads the default client configuration file.
	pub fn load_default() -> QuantumLinkResult<Self> {
		let home = env::var_os("HOME")
			.map(PathBuf::from)
			.ok_or_else(|| QuantumLinkError::Config("HOME is not set".to_owned()))?;
		let path = home.join(".config/quantumlink/config.toml");
		Self::from_file(&path)
	}

	/// Loads configuration from a TOML file.
	pub fn from_file(path: &Path) -> QuantumLinkResult<Self> {
		let contents = std::fs::read_to_string(path).map_err(QuantumLinkError::Io)?;
		toml::from_str(&contents)
			.map_err(|error| QuantumLinkError::Config(format!("failed to parse config: {error}")))
	}
}

/// Server endpoint settings used by the client daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerConfig {
	/// Host and port for the user-controlled server daemon.
	pub endpoint: String,
	/// UDP port used by the Rosenpass sidecar.
	pub rosenpass_port: u16,
}

impl Default for ServerConfig {
	fn default() -> Self {
		Self {
			endpoint: "vpn.example.com:51820".to_owned(),
			rosenpass_port: 9_999,
		}
	}
}

/// Cryptographic policy settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CryptoConfig {
	/// Requested crypto mode.
	pub mode: CryptoMode,
	/// Requested KEM name.
	pub kem: String,
	/// Requested signature scheme name.
	pub signature: String,
}

impl Default for CryptoConfig {
	fn default() -> Self {
		Self {
			mode: CryptoMode::Hybrid,
			kem: "ML-KEM-768".to_owned(),
			signature: "ML-DSA-65".to_owned(),
		}
	}
}

/// Network policy settings for the tunnel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkConfig {
	/// Enables a hard kill switch when the tunnel is active.
	pub kill_switch: bool,
	/// Forces DNS resolution through the tunnel.
	pub dns_leak_protection: bool,
	/// WireGuard MTU.
	pub mtu: u16,
	/// DNS servers to use while connected.
	pub dns_servers: Vec<IpAddr>,
}

impl Default for NetworkConfig {
	fn default() -> Self {
		Self {
			kill_switch: true,
			dns_leak_protection: true,
			mtu: 1_420,
			dns_servers: vec![IpAddr::from([10, 0, 0, 1])],
		}
	}
}

/// Split-tunnel configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SplitTunnelConfig {
	/// Enables split tunneling.
	pub enabled: bool,
	/// Applications excluded from the tunnel.
	pub excluded_apps: Vec<String>,
}

/// Mesh-specific settings reserved for the v0.2 surface area.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshSettings {
	/// Enables mesh functionality.
	pub enabled: bool,
	/// Default relay policy for mesh sessions.
	pub relay_policy: RelayPolicy,
}

impl Default for MeshSettings {
	fn default() -> Self {
		Self {
			enabled: false,
			relay_policy: RelayPolicy::SelfHosted,
		}
	}
}

/// Crypto mode selection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CryptoMode {
	/// Classical algorithms only.
	Classical,
	/// Hybrid classical plus post-quantum operation.
	Hybrid,
	/// Post-quantum algorithms only.
	PQOnly,
}

/// Active algorithm set displayed to users and reported over IPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlgorithmSet {
	/// Active KEM display string.
	pub kem: String,
	/// Active signature display string.
	pub signature: String,
	/// Indicates whether Rosenpass is actively rotating PSKs.
	pub rosenpass_active: bool,
	/// Current PQ-derived PSK age.
	pub psk_age_seconds: u64,
}

/// Tunnel lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TunnelState {
	/// No active tunnel.
	Disconnected,
	/// Connection establishment is in progress.
	Connecting,
	/// The tunnel is established and the active peer IP is known.
	Connected {
		/// The negotiated algorithm set.
		algo: AlgorithmSet,
		/// The peer IP currently in use.
		peer_ip: IpAddr,
	},
	/// Connection establishment or runtime operation failed.
	Error(String),
}

/// Connection path for a mesh peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectionPath {
	/// Direct peer-to-peer path.
	DirectP2P {
		/// Measured latency for the direct path.
		latency_ms: u32,
	},
	/// Relayed path via a dumb UDP forwarder.
	Relayed {
		/// Relay endpoint currently forwarding packets.
		relay_endpoint: SocketAddr,
		/// Measured latency for the relayed path.
		latency_ms: u32,
	},
	/// No viable connection path exists.
	Unavailable,
}

/// Relay policy for a peer connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelayPolicy {
	/// Never relay.
	None,
	/// Relay only through the user's own infrastructure.
	SelfHosted,
	/// Relay through an approved community relay.
	Community,
	/// Ask the user before relaying.
	Ask,
}

/// Commands sent from the GUI to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DaemonCommand {
	/// Establish a tunnel to the configured or overridden server endpoint.
	Connect {
		/// Optional explicit server endpoint override.
		server: Option<SocketAddr>,
	},
	/// Disconnect the active tunnel.
	Disconnect,
	/// Request daemon status.
	GetStatus,
	/// Update the crypto mode.
	SetMode(CryptoMode),
	/// Generate client key material.
	GenerateKeys,
	/// Enable mesh mode.
	MeshEnable,
	/// Disable mesh mode.
	MeshDisable,
	/// Start QR pairing.
	MeshPairQr,
	/// Start wormhole pairing with a code.
	MeshPairWormhole {
		/// Human-readable pairing code.
		code: String,
	},
	/// Update relay policy for a specific peer.
	MeshSetRelayPolicy {
		/// WireGuard public key for the peer.
		peer_key: [u8; 32],
		/// New relay policy.
		policy: RelayPolicy,
	},
}

/// Events sent from the daemon to GUI subscribers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DaemonEvent {
	/// Tunnel state changed.
	StateChanged(TunnelState),
	/// Algorithm negotiation completed.
	AlgorithmNegotiated(AlgorithmSet),
	/// Rosenpass rotated a PSK for a peer.
	PskRotated {
		/// Peer WireGuard public key.
		peer_key: [u8; 32],
		/// Current PSK age in seconds.
		age_seconds: u64,
	},
	/// An error occurred.
	Error(String),
	/// A mesh peer connected.
	MeshPeerConnected {
		/// Peer WireGuard public key.
		peer_key: [u8; 32],
		/// Active connection path.
		path: ConnectionPath,
	},
	/// A mesh peer disconnected.
	MeshPeerDisconnected {
		/// Peer WireGuard public key.
		peer_key: [u8; 32],
	},
	/// A mesh path improved or changed.
	MeshPathUpgraded {
		/// Peer WireGuard public key.
		peer_key: [u8; 32],
		/// New active path.
		new_path: ConnectionPath,
	},
	/// A wormhole pairing code was generated.
	MeshPairingCode {
		/// Human-readable code for pairing.
		code: String,
	},
}

/// Unified QuantumLink error type.
#[derive(Debug, Error)]
pub enum QuantumLinkError {
	/// Cryptographic failure.
	#[error("crypto error: {0}")]
	Crypto(String),
	/// WireGuard integration failure.
	#[error("wireguard error: {0}")]
	WireGuard(String),
	/// Rosenpass integration failure.
	#[error("rosenpass error: {0}")]
	Rosenpass(String),
	/// Configuration load or validation failure.
	#[error("config error: {0}")]
	Config(String),
	/// I/O failure.
	#[error("io error: {0}")]
	Io(std::io::Error),
	/// Authentication or certificate failure.
	#[error("auth error: {0}")]
	Auth(String),
	/// Pairing failure.
	#[error("pairing error: {0}")]
	Pairing(String),
	/// Reserved for forward-compatible v0.2 stubs.
	#[error("not implemented: {0}")]
	NotImplemented(String),
}

impl Clone for QuantumLinkError {
	fn clone(&self) -> Self {
		match self {
			Self::Crypto(message) => Self::Crypto(message.clone()),
			Self::WireGuard(message) => Self::WireGuard(message.clone()),
			Self::Rosenpass(message) => Self::Rosenpass(message.clone()),
			Self::Config(message) => Self::Config(message.clone()),
			Self::Io(error) => Self::Io(std::io::Error::new(error.kind(), error.to_string())),
			Self::Auth(message) => Self::Auth(message.clone()),
			Self::Pairing(message) => Self::Pairing(message.clone()),
			Self::NotImplemented(message) => Self::NotImplemented(message.clone()),
		}
	}
}

/// Step-local placeholder retained for scaffold continuity.
pub fn placeholder() {}

#[cfg(test)]
mod tests {
	use super::{CryptoMode, QuantumLinkConfig, QuantumLinkError, RelayPolicy};

	#[test]
	fn parses_reference_config_shape() {
		let config = toml::from_str::<QuantumLinkConfig>(
			r#"
			[server]
			endpoint = "vpn.example.com:51820"
			rosenpass_port = 9999

			[crypto]
			mode = "Hybrid"
			kem = "ML-KEM-768"
			signature = "ML-DSA-65"

			[network]
			kill_switch = true
			dns_leak_protection = true
			mtu = 1420
			dns_servers = ["10.0.0.1"]

			[split_tunnel]
			enabled = false
			excluded_apps = []

			[mesh]
			enabled = false
			relay_policy = "SelfHosted"
			"#,
		)
		.unwrap();

		assert_eq!(config.crypto.mode, CryptoMode::Hybrid);
		assert_eq!(config.mesh.relay_policy, RelayPolicy::SelfHosted);
		assert_eq!(config.network.mtu, 1_420);
	}

	#[test]
	fn clones_io_error_variant() {
		let original = QuantumLinkError::Io(std::io::Error::other("disk unavailable"));
		let cloned = original.clone();

		assert_eq!(original.to_string(), cloned.to_string());
	}
}
