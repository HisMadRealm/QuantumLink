//! GUI integration points for QuantumLink.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;

use ql_core::{
	AlgorithmSet, ConnectionPath, DaemonCommand, DaemonEvent, PairingRole, TunnelState,
};
use ql_mesh::MeshPeerStatus;

/// Top-level GUI state consumed by a future platform frontend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuiModel {
	/// Main connection summary card.
	pub connection: ConnectionCard,
	/// PQC transparency panel state.
	pub pqc_panel: PqcStatusPanel,
	/// Pairing workflow panel state.
	pub pairing: PairingPanel,
	/// Mesh status dashboard rows.
	pub mesh_dashboard: Vec<MeshPeerCard>,
	/// System tray or menu bar summary state.
	pub tray: TrayStatus,
	pending_command: Option<DaemonCommand>,
}

impl Default for GuiModel {
	fn default() -> Self {
		Self {
			connection: ConnectionCard::default(),
			pqc_panel: PqcStatusPanel::default(),
			pairing: PairingPanel::default(),
			mesh_dashboard: Vec::new(),
			tray: TrayStatus::Disconnected,
			pending_command: None,
		}
	}
}

/// Connection summary shown in the main window and tray popover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionCard {
	/// Current tunnel state.
	pub state: TunnelState,
	/// Human-readable primary status line.
	pub headline: String,
	/// Human-readable supporting detail.
	pub detail: String,
}

impl Default for ConnectionCard {
	fn default() -> Self {
		Self {
			state: TunnelState::Disconnected,
			headline: "Disconnected".to_owned(),
			detail: "QuantumLink is idle".to_owned(),
		}
	}
}

/// PQC transparency panel content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqcStatusPanel {
	/// Active KEM name.
	pub kem: Option<String>,
	/// Active signature scheme name.
	pub signature: Option<String>,
	/// Whether Rosenpass is active.
	pub rosenpass_active: bool,
	/// Latest PSK age in seconds.
	pub psk_age_seconds: u64,
	/// Fingerprint or status summary line.
	pub summary: String,
}

impl Default for PqcStatusPanel {
	fn default() -> Self {
		Self {
			kem: None,
			signature: None,
			rosenpass_active: false,
			psk_age_seconds: 0,
			summary: "No active QuantumLink session".to_owned(),
		}
	}
}

/// Compact connection indicator for tray or menu bar presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayStatus {
	/// No active tunnel.
	Disconnected,
	/// Active connection is being established.
	Connecting,
	/// Connected with the currently active PQC stack label.
	Connected { label: String },
	/// Error state with short message.
	Error { message: String },
}

/// Mesh peer row for the connection dashboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshPeerCard {
	/// Peer display label.
	pub label: String,
	/// Connection path description.
	pub path_label: String,
	/// Packet loss in percent with one decimal place scaled into string form.
	pub packet_loss_label: String,
	/// Rosenpass PSK age label.
	pub psk_age_label: String,
	/// Optional relay endpoint currently used.
	pub relay_endpoint: Option<SocketAddr>,
}

/// GUI-facing summary of the current pairing workflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingPanel {
	/// High-level state of the pairing flow.
	pub state: PairingState,
	/// Human-readable headline.
	pub headline: String,
	/// Human-readable supporting detail.
	pub detail: String,
	/// Current rendezvous identifier, if one exists.
	pub pairing_id: Option<String>,
	/// Current mailbox identifier, if one exists.
	pub mailbox_id: Option<String>,
	/// Derived verification words, when available.
	pub verification_words: Option<[String; 5]>,
}

impl Default for PairingPanel {
	fn default() -> Self {
		Self {
			state: PairingState::Idle,
			headline: "Pairing Idle".to_owned(),
			detail: "No pairing flow in progress".to_owned(),
			pairing_id: None,
			mailbox_id: None,
			verification_words: None,
		}
	}
}

/// State machine projection for the pairing workflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingState {
	/// No active pairing flow.
	Idle,
	/// Waiting for the remote peer to continue the exchange.
	InProgress { role: PairingRole },
	/// Waiting for the user to confirm verification words.
	AwaitingVerification,
	/// Pairing and enrollment completed.
	Complete,
}

impl GuiModel {
	/// Queues a connect command for the GUI frontend to submit to the daemon.
	pub fn request_connect(&mut self, server: Option<SocketAddr>) {
		self.pending_command = Some(DaemonCommand::Connect { server });
	}

	/// Queues a disconnect command.
	pub fn request_disconnect(&mut self) {
		self.pending_command = Some(DaemonCommand::Disconnect);
	}

	/// Queues a status refresh command.
	pub fn request_status_refresh(&mut self) {
		self.pending_command = Some(DaemonCommand::GetStatus);
	}

	/// Queues a wormhole pairing command for the provided code.
	pub fn request_wormhole_pair(&mut self, code: String) {
		self.pending_command = Some(DaemonCommand::MeshPairWormhole { code });
	}

	/// Queues the high-level initiator pairing workflow.
	pub fn request_pair_initiate(
		&mut self,
		signal_url: String,
		pairing_id: String,
		code: String,
		certificate_path: PathBuf,
	) {
		self.pending_command = Some(DaemonCommand::MeshPairInitiate {
			signal_url,
			pairing_id,
			code,
			certificate_path,
		});
	}

	/// Queues the high-level responder pairing workflow.
	pub fn request_pair_accept(
		&mut self,
		signal_url: String,
		pairing_id: String,
		code: String,
		mailbox_id: String,
	) {
		self.pending_command = Some(DaemonCommand::MeshPairAccept {
			signal_url,
			pairing_id,
			code,
			mailbox_id,
		});
	}

	/// Queues a QR pairing flow command.
	pub fn request_qr_pair(&mut self) {
		self.pending_command = Some(DaemonCommand::MeshPairQr);
	}

	/// Drains the next pending command for daemon submission.
	pub fn take_pending_command(&mut self) -> Option<DaemonCommand> {
		self.pending_command.take()
	}

	/// Applies a daemon event to the GUI state.
	pub fn apply_event(&mut self, event: DaemonEvent) {
		match event {
			DaemonEvent::StateChanged(state) => self.apply_tunnel_state(state),
			DaemonEvent::AlgorithmNegotiated(algo) => self.apply_algorithm_set(algo),
			DaemonEvent::PskRotated { age_seconds, .. } => {
				self.pqc_panel.psk_age_seconds = age_seconds;
				self.update_pqc_summary();
			}
			DaemonEvent::Error(message) => {
				self.connection.detail = message.clone();
				self.tray = TrayStatus::Error { message };
			}
			DaemonEvent::MeshPeerConnected { peer_key, path } => {
				self.upsert_mesh_path(peer_key, path);
			}
			DaemonEvent::MeshPeerDisconnected { peer_key } => {
				self.mesh_dashboard.retain(|peer| peer.label != mesh_label(peer_key));
			}
			DaemonEvent::MeshPathUpgraded { peer_key, new_path } => {
				self.upsert_mesh_path(peer_key, new_path);
			}
			DaemonEvent::MeshPairingCode { code } => {
				self.connection.detail = format!("Pairing code ready: {code}");
			}
			DaemonEvent::MeshPairingStarted {
				role,
				pairing_id,
				mailbox_id,
			} => {
				self.pairing.state = PairingState::InProgress { role: role.clone() };
				self.pairing.headline = match role {
					PairingRole::Initiator => "Initiating Pairing".to_owned(),
					PairingRole::Responder => "Accepting Pairing".to_owned(),
				};
				self.pairing.detail = "Authenticated pairing exchange in progress".to_owned();
				self.pairing.pairing_id = Some(pairing_id);
				self.pairing.mailbox_id = mailbox_id;
				self.pairing.verification_words = None;
			}
			DaemonEvent::MeshPairingVerification { words } => {
				self.pairing.state = PairingState::AwaitingVerification;
				self.pairing.headline = "Confirm Verification Words".to_owned();
				self.pairing.detail = words.join(" ");
				self.pairing.verification_words = Some(words);
			}
			DaemonEvent::MeshPairingComplete {
				pairing_id,
				device_name,
			} => {
				self.pairing.state = PairingState::Complete;
				self.pairing.headline = "Pairing Complete".to_owned();
				self.pairing.detail = format!("Imported trust for {device_name}");
				self.pairing.pairing_id = Some(pairing_id);
			}
		}
	}

	/// Replaces the mesh dashboard projection from current daemon mesh status.
	pub fn replace_mesh_dashboard(&mut self, peers: &[MeshPeerStatus]) {
		self.mesh_dashboard = peers.iter().map(MeshPeerCard::from_status).collect();
	}

	fn apply_tunnel_state(&mut self, state: TunnelState) {
		self.connection.state = state.clone();
		match state {
			TunnelState::Disconnected => {
				self.connection.headline = "Disconnected".to_owned();
				self.connection.detail = "QuantumLink is idle".to_owned();
				self.tray = TrayStatus::Disconnected;
				self.pqc_panel = PqcStatusPanel::default();
				self.pairing = PairingPanel::default();
			}
			TunnelState::Connecting => {
				self.connection.headline = "Connecting".to_owned();
				self.connection.detail = "Establishing WireGuard and Rosenpass".to_owned();
				self.tray = TrayStatus::Connecting;
			}
			TunnelState::Connected { algo, peer_ip } => {
				self.connection.headline = "Connected".to_owned();
				self.connection.detail = format!("Peer endpoint active via {peer_ip}");
				self.apply_algorithm_set(algo.clone());
				self.tray = TrayStatus::Connected {
					label: format!("{} / {}", algo.kem, algo.signature),
				};
			}
			TunnelState::Error(message) => {
				self.connection.headline = "Connection Error".to_owned();
				self.connection.detail = message.clone();
				self.tray = TrayStatus::Error { message };
			}
		}
	}

	fn apply_algorithm_set(&mut self, algo: AlgorithmSet) {
		self.pqc_panel.kem = Some(algo.kem.clone());
		self.pqc_panel.signature = Some(algo.signature.clone());
		self.pqc_panel.rosenpass_active = algo.rosenpass_active;
		self.pqc_panel.psk_age_seconds = algo.psk_age_seconds;
		self.update_pqc_summary();
	}

	fn update_pqc_summary(&mut self) {
		self.pqc_panel.summary = match (&self.pqc_panel.kem, &self.pqc_panel.signature) {
			(Some(kem), Some(signature)) => format!(
				"{kem} with {signature}; Rosenpass {} (PSK age {}s)",
				if self.pqc_panel.rosenpass_active {
					"active"
				} else {
					"inactive"
				},
				self.pqc_panel.psk_age_seconds,
			),
			_ => "No active QuantumLink session".to_owned(),
		};
	}

	fn upsert_mesh_path(&mut self, peer_key: [u8; 32], path: ConnectionPath) {
		let label = mesh_label(peer_key);
		let new_card = MeshPeerCard {
			label: label.clone(),
			path_label: path_label(&path),
			packet_loss_label: "0.0% loss".to_owned(),
			psk_age_label: "PSK age unknown".to_owned(),
			relay_endpoint: relay_endpoint(&path),
		};

		if let Some(existing) = self.mesh_dashboard.iter_mut().find(|peer| peer.label == label) {
			*existing = new_card;
		} else {
			self.mesh_dashboard.push(new_card);
			self.mesh_dashboard.sort_by(|left, right| left.label.cmp(&right.label));
		}
	}
}

impl MeshPeerCard {
	fn from_status(status: &MeshPeerStatus) -> Self {
		Self {
			label: status.display_name.clone(),
			path_label: path_label(&status.path),
			packet_loss_label: format!("{:.1}% loss", f32::from(status.packet_loss_bps) / 100.0),
			psk_age_label: format!("PSK age {}s", status.psk_age_seconds),
			relay_endpoint: relay_endpoint(&status.path),
		}
	}
}

fn mesh_label(peer_key: [u8; 32]) -> String {
	format!("peer-{:02x}{:02x}{:02x}{:02x}", peer_key[0], peer_key[1], peer_key[2], peer_key[3])
}

fn path_label(path: &ConnectionPath) -> String {
	match path {
		ConnectionPath::DirectP2P { latency_ms } => format!("Direct P2P ({latency_ms} ms)"),
		ConnectionPath::Relayed {
			relay_endpoint,
			latency_ms,
		} => format!("Relayed via {relay_endpoint} ({latency_ms} ms)"),
		ConnectionPath::Unavailable => "Unavailable".to_owned(),
	}
}

fn relay_endpoint(path: &ConnectionPath) -> Option<SocketAddr> {
	match path {
		ConnectionPath::Relayed { relay_endpoint, .. } => Some(*relay_endpoint),
		_ => None,
	}
}

#[cfg(test)]
mod tests {
	use std::path::PathBuf;

	use ql_core::{AlgorithmSet, ConnectionPath, DaemonCommand, DaemonEvent, RelayPolicy, TunnelState};
	use ql_mesh::MeshPeerStatus;

	use super::{GuiModel, PairingState, TrayStatus};

	#[test]
	fn queues_and_drains_commands() {
		let mut model = GuiModel::default();
		model.request_disconnect();
		assert_eq!(model.take_pending_command(), Some(DaemonCommand::Disconnect));
		assert_eq!(model.take_pending_command(), None);
	}

	#[test]
	fn applies_connection_and_algorithm_events() {
		let mut model = GuiModel::default();
		let algo = AlgorithmSet {
			kem: "ML-KEM-768".to_owned(),
			signature: "ML-DSA-65".to_owned(),
			rosenpass_active: true,
			psk_age_seconds: 12,
		};

		model.apply_event(DaemonEvent::StateChanged(TunnelState::Connecting));
		model.apply_event(DaemonEvent::AlgorithmNegotiated(algo.clone()));
		model.apply_event(DaemonEvent::StateChanged(TunnelState::Connected {
			algo,
			peer_ip: "203.0.113.10".parse().unwrap(),
		}));

		assert_eq!(model.connection.headline, "Connected");
		assert!(matches!(model.tray, TrayStatus::Connected { .. }));
		assert_eq!(model.pqc_panel.kem.as_deref(), Some("ML-KEM-768"));
		assert_eq!(model.pqc_panel.psk_age_seconds, 12);
	}

	#[test]
	fn projects_mesh_dashboard_from_status() {
		let mut model = GuiModel::default();
		model.replace_mesh_dashboard(&[MeshPeerStatus {
			peer_key: [7_u8; 32],
			display_name: "Laptop".to_owned(),
			relay_policy: RelayPolicy::SelfHosted,
			path: ConnectionPath::Relayed {
				relay_endpoint: "198.51.100.20:51821".parse().unwrap(),
				latency_ms: 82,
			},
			packet_loss_bps: 135,
			psk_age_seconds: 44,
			direct_candidate: Some("10.0.0.4:51820".parse().unwrap()),
			relay_candidate: Some("198.51.100.20:51821".parse().unwrap()),
		}]);

		assert_eq!(model.mesh_dashboard.len(), 1);
		assert_eq!(model.mesh_dashboard[0].label, "Laptop");
		assert_eq!(model.mesh_dashboard[0].packet_loss_label, "1.4% loss");
	}

	#[test]
	fn updates_mesh_rows_from_events() {
		let mut model = GuiModel::default();
		model.apply_event(DaemonEvent::MeshPeerConnected {
			peer_key: [1_u8; 32],
			path: ConnectionPath::DirectP2P { latency_ms: 17 },
		});

		assert_eq!(model.mesh_dashboard.len(), 1);
		assert!(model.mesh_dashboard[0].path_label.contains("Direct P2P"));
	}

	#[test]
	fn queues_high_level_pairing_commands() {
		let mut model = GuiModel::default();
		model.request_pair_initiate(
			"http://127.0.0.1:8443".to_owned(),
			"session-42".to_owned(),
			"42-garden-nebula".to_owned(),
			PathBuf::from("/tmp/cert.json"),
		);
		assert!(matches!(
			model.take_pending_command(),
			Some(DaemonCommand::MeshPairInitiate { .. })
		));

		model.request_pair_accept(
			"http://127.0.0.1:8443".to_owned(),
			"session-42".to_owned(),
			"42-garden-nebula".to_owned(),
			"mailbox-1".to_owned(),
		);
		assert!(matches!(
			model.take_pending_command(),
			Some(DaemonCommand::MeshPairAccept { .. })
		));
	}

	#[test]
	fn projects_pairing_workflow_events() {
		let mut model = GuiModel::default();
		model.apply_event(DaemonEvent::MeshPairingStarted {
			role: ql_core::PairingRole::Initiator,
			pairing_id: "session-42".to_owned(),
			mailbox_id: Some("mailbox-1".to_owned()),
		});
		assert!(matches!(model.pairing.state, PairingState::InProgress { .. }));
		assert_eq!(model.pairing.mailbox_id.as_deref(), Some("mailbox-1"));

		model.apply_event(DaemonEvent::MeshPairingVerification {
			words: [
				"amber".to_owned(),
				"cabin".to_owned(),
				"forest".to_owned(),
				"orbit".to_owned(),
				"trail".to_owned(),
			],
		});
		assert!(matches!(model.pairing.state, PairingState::AwaitingVerification));
		assert!(model.pairing.detail.contains("amber"));

		model.apply_event(DaemonEvent::MeshPairingComplete {
			pairing_id: "session-42".to_owned(),
			device_name: "Office Laptop".to_owned(),
		});
		assert!(matches!(model.pairing.state, PairingState::Complete));
		assert!(model.pairing.detail.contains("Office Laptop"));
	}
}
