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

/// Certificate authority metadata for a self-hosted QuantumLink mesh.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateAuthority {
    /// User-facing CA label.
    pub name: String,
    /// Hex or base64 fingerprint identifying the CA.
    pub fingerprint: String,
    /// Unix timestamp when the CA was created.
    pub created_at: u64,
}

/// Certificate enrollment request submitted to the offline CA workflow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateRequest {
    /// Human-readable device name.
    pub device_name: String,
    /// Mesh overlay IP requested for the device.
    pub overlay_ip: IpAddr,
    /// Requested certificate groups.
    pub groups: Vec<String>,
    /// Embedded WireGuard public key.
    pub wg_public_key: [u8; 32],
    /// Embedded Rosenpass public-key fingerprint.
    pub rosenpass_fingerprint: String,
    /// Unix timestamp when the request was created.
    pub requested_at: u64,
}

/// A short-lived device certificate issued by the user's offline CA.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceCertificate {
    /// Stable certificate serial identifier.
    pub serial: String,
    /// Human-readable device name.
    pub device_name: String,
    /// Mesh overlay IP assigned to the device.
    pub overlay_ip: IpAddr,
    /// Certificate groups used for policy and firewall rules.
    pub groups: Vec<String>,
    /// Embedded WireGuard public key.
    pub wg_public_key: [u8; 32],
    /// Embedded Rosenpass public key fingerprint.
    pub rosenpass_fingerprint: String,
    /// Issuer fingerprint.
    pub issuer_fingerprint: String,
    /// Certificate validity start timestamp.
    pub valid_from: u64,
    /// Certificate expiry timestamp.
    pub valid_until: u64,
}

impl DeviceCertificate {
    /// Returns whether the certificate is currently valid and not expired.
    #[must_use]
    pub fn is_valid_at(&self, now_unix: u64) -> bool {
        self.valid_from <= now_unix && now_unix < self.valid_until
    }

    /// Returns whether the certificate grants membership in the named group.
    #[must_use]
    pub fn has_group(&self, group: &str) -> bool {
        self.groups.iter().any(|member| member == group)
    }
}

/// Signed or locally distributed device revocation record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationRecord {
    /// Revoked certificate serial.
    pub certificate_serial: String,
    /// Human-readable revocation reason.
    pub reason: String,
    /// Unix timestamp when revocation was issued.
    pub revoked_at: u64,
}

/// Revocation list distributed through the signaling hub or peer gossip.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RevocationList {
    /// Monotonic issue time for the current blocklist.
    pub issued_at: u64,
    /// Revoked certificate entries.
    pub entries: Vec<RevocationRecord>,
}

impl RevocationList {
    /// Returns whether the certificate serial has been revoked.
    #[must_use]
    pub fn is_revoked(&self, certificate_serial: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.certificate_serial == certificate_serial)
    }

    /// Returns a new revocation list with a record inserted or replaced.
    #[must_use]
    pub fn with_record(mut self, record: RevocationRecord) -> Self {
        self.entries
            .retain(|entry| entry.certificate_serial != record.certificate_serial);
        self.entries.push(record);
        self
    }
}

/// Audit record for identity lifecycle operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityAuditEvent {
    /// Event timestamp.
    pub recorded_at: u64,
    /// High-level action name.
    pub action: String,
    /// Certificate serial or CA fingerprint associated with the action.
    pub subject: String,
    /// Optional freeform detail.
    pub detail: Option<String>,
}

/// Filesystem layout used by the daemon for local key material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyStorageLayout {
    /// Root directory containing all QuantumLink key material.
    pub root_dir: PathBuf,
    /// Offline CA metadata or key material directory.
    pub ca_dir: PathBuf,
    /// Device identity bundle directory.
    pub device_dir: PathBuf,
    /// Audit-log directory for handshake and rotation history.
    pub audit_dir: PathBuf,
}

impl KeyStorageLayout {
    /// Returns the default key-storage layout beneath the user's home directory.
    #[must_use]
    pub fn default_layout() -> Self {
        let root_dir = env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".local/share/quantumlink"))
            .unwrap_or_else(|| PathBuf::from("~/.local/share/quantumlink"));
        Self::from_root(root_dir)
    }

    /// Returns a storage layout rooted at the provided path.
    #[must_use]
    pub fn from_root(root_dir: PathBuf) -> Self {
        Self {
            ca_dir: root_dir.join("ca"),
            device_dir: root_dir.join("device"),
            audit_dir: root_dir.join("audit"),
            root_dir,
        }
    }

    /// Ensures all key-storage directories exist.
    pub fn ensure_directories(&self) -> QuantumLinkResult<()> {
        std::fs::create_dir_all(&self.ca_dir).map_err(QuantumLinkError::Io)?;
        std::fs::create_dir_all(&self.device_dir).map_err(QuantumLinkError::Io)?;
        std::fs::create_dir_all(&self.audit_dir).map_err(QuantumLinkError::Io)?;
        Ok(())
    }

    /// Path to the CA metadata file.
    #[must_use]
    pub fn ca_metadata_path(&self) -> PathBuf {
        self.ca_dir.join("authority.json")
    }

    /// Path to the serialized CA signing key.
    #[must_use]
    pub fn ca_signing_key_path(&self) -> PathBuf {
        self.ca_dir.join("signing-key.json")
    }

    /// Path to the serialized CA verifying key.
    #[must_use]
    pub fn ca_verifying_key_path(&self) -> PathBuf {
        self.ca_dir.join("verifying-key.json")
    }

    /// Path to the revocation list.
    #[must_use]
    pub fn revocations_path(&self) -> PathBuf {
        self.ca_dir.join("revocations.json")
    }

    /// Path to a signed device certificate bundle.
    #[must_use]
    pub fn device_certificate_path(&self, serial: &str) -> PathBuf {
        self.device_dir.join(format!("{serial}.json"))
    }

    /// Path to the identity audit log.
    #[must_use]
    pub fn audit_log_path(&self) -> PathBuf {
        self.audit_dir.join("identity-events.jsonl")
    }
}

/// Device identity bundle tying together certificate metadata and local paths.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceIdentity {
    /// Device certificate metadata.
    pub certificate: DeviceCertificate,
    /// Local storage layout for this device.
    pub storage: KeyStorageLayout,
}

impl DeviceIdentity {
    /// Returns whether the device should still be trusted at `now_unix`.
    #[must_use]
    pub fn is_active(&self, now_unix: u64, revocations: &RevocationList) -> bool {
        self.certificate.is_valid_at(now_unix) && !revocations.is_revoked(&self.certificate.serial)
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

/// Role of the local participant in a pairing workflow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PairingRole {
    /// Device initiating the pairing flow.
    Initiator,
    /// Device accepting the pairing flow.
    Responder,
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
    /// Start the high-level initiator pairing workflow.
    MeshPairInitiate {
        /// Signal server URL used for pairing mailbox transport.
        signal_url: String,
        /// Shared rendezvous identifier for the pairing session.
        pairing_id: String,
        /// Human-readable wormhole code.
        code: String,
        /// Local certificate path to export after pairing succeeds.
        certificate_path: PathBuf,
    },
    /// Start the high-level responder pairing workflow.
    MeshPairAccept {
        /// Signal server URL used for pairing mailbox transport.
        signal_url: String,
        /// Shared rendezvous identifier for the pairing session.
        pairing_id: String,
        /// Human-readable wormhole code.
        code: String,
        /// Mailbox identifier created by the initiator.
        mailbox_id: String,
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
    /// A high-level pairing workflow has started.
    MeshPairingStarted {
        /// Local role in the pairing flow.
        role: PairingRole,
        /// Shared rendezvous identifier.
        pairing_id: String,
        /// Mailbox identifier once one exists.
        mailbox_id: Option<String>,
    },
    /// Five-word verification phrase for user confirmation.
    MeshPairingVerification {
        /// Shared five-word verification phrase.
        words: [String; 5],
    },
    /// A pairing workflow completed and imported peer trust.
    MeshPairingComplete {
        /// Shared rendezvous identifier.
        pairing_id: String,
        /// Human-readable imported or enrolled device label.
        device_name: String,
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
    use std::path::PathBuf;

    use super::{
        CertificateAuthority, CertificateRequest, CryptoMode, DeviceCertificate, DeviceIdentity,
        IdentityAuditEvent, KeyStorageLayout, PairingRole, QuantumLinkConfig, QuantumLinkError,
        RelayPolicy, RevocationList, RevocationRecord,
    };

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

    #[test]
    fn device_certificate_reports_validity_and_groups() {
        let certificate = DeviceCertificate {
            serial: "cert-001".to_owned(),
            device_name: "Laptop".to_owned(),
            overlay_ip: "10.42.0.2".parse().unwrap(),
            groups: vec!["personal".to_owned(), "servers".to_owned()],
            wg_public_key: [7_u8; 32],
            rosenpass_fingerprint: "rp-fingerprint".to_owned(),
            issuer_fingerprint: "ca-fingerprint".to_owned(),
            valid_from: 1_700_000_000,
            valid_until: 1_700_086_400,
        };

        assert!(certificate.is_valid_at(1_700_010_000));
        assert!(certificate.has_group("personal"));
        assert!(!certificate.has_group("friends"));
    }

    #[test]
    fn revocation_list_tracks_serials() {
        let revocations = RevocationList::default().with_record(RevocationRecord {
            certificate_serial: "cert-001".to_owned(),
            reason: "device lost".to_owned(),
            revoked_at: 1_700_020_000,
        });

        assert!(revocations.is_revoked("cert-001"));
        assert!(!revocations.is_revoked("cert-002"));
    }

    #[test]
    fn device_identity_is_inactive_when_revoked() {
        let identity = DeviceIdentity {
            certificate: DeviceCertificate {
                serial: "cert-001".to_owned(),
                device_name: "Phone".to_owned(),
                overlay_ip: "10.42.0.3".parse().unwrap(),
                groups: vec!["personal".to_owned()],
                wg_public_key: [3_u8; 32],
                rosenpass_fingerprint: "rp".to_owned(),
                issuer_fingerprint: "ca".to_owned(),
                valid_from: 1_700_000_000,
                valid_until: 1_700_086_400,
            },
            storage: KeyStorageLayout {
                root_dir: PathBuf::from("/tmp/quantumlink"),
                ca_dir: PathBuf::from("/tmp/quantumlink/ca"),
                device_dir: PathBuf::from("/tmp/quantumlink/device"),
                audit_dir: PathBuf::from("/tmp/quantumlink/audit"),
            },
        };
        let revocations = RevocationList::default().with_record(RevocationRecord {
            certificate_serial: "cert-001".to_owned(),
            reason: "rotated out".to_owned(),
            revoked_at: 1_700_010_000,
        });

        assert!(!identity.is_active(1_700_020_000, &revocations));
    }

    #[test]
    fn key_storage_layout_uses_expected_default_paths() {
        let layout = KeyStorageLayout::default_layout();
        assert!(layout.root_dir.ends_with(".local/share/quantumlink"));
        assert_eq!(layout.ca_dir, layout.root_dir.join("ca"));
        assert_eq!(
            layout.device_certificate_path("cert-001"),
            layout.device_dir.join("cert-001.json")
        );
    }

    #[test]
    fn certificate_request_roundtrips() {
        let request = CertificateRequest {
            device_name: "Laptop".to_owned(),
            overlay_ip: "10.42.0.20".parse().unwrap(),
            groups: vec!["personal".to_owned()],
            wg_public_key: [9_u8; 32],
            rosenpass_fingerprint: "rp-fp".to_owned(),
            requested_at: 1_700_000_000,
        };

        let encoded = serde_json::to_string(&request).unwrap();
        let decoded: CertificateRequest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn identity_audit_event_allows_optional_details() {
        let event = IdentityAuditEvent {
            recorded_at: 1_700_000_100,
            action: "issue-certificate".to_owned(),
            subject: "cert-001".to_owned(),
            detail: Some("Laptop".to_owned()),
        };

        let encoded = serde_json::to_string(&event).unwrap();
        let decoded: IdentityAuditEvent = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, event);
    }

    #[test]
    fn certificate_authority_metadata_roundtrips() {
        let authority = CertificateAuthority {
            name: "Rick CA".to_owned(),
            fingerprint: "ca-fingerprint".to_owned(),
            created_at: 1_700_000_000,
        };

        let encoded = serde_json::to_string(&authority).unwrap();
        let decoded: CertificateAuthority = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, authority);
    }

    #[test]
    fn pairing_role_roundtrips() {
        let encoded = serde_json::to_string(&PairingRole::Initiator).unwrap();
        let decoded: PairingRole = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, PairingRole::Initiator);
    }
}
