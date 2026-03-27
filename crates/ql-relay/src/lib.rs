//! Blind UDP relay services for QuantumLink mesh fallback.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ql_core::{QuantumLinkError, QuantumLinkResult};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, RwLock};
use tokio::task::JoinHandle;
use tracing::warn;
use uuid::Uuid;

const DEFAULT_IDLE_SESSION_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_MAX_PACKET_SIZE: usize = 65_535;
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);

/// Runtime configuration for the blind UDP relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConfig {
	/// Socket address to bind for incoming mesh relay traffic.
	pub bind_addr: SocketAddr,
	/// Idle timeout after which an inactive relay session is discarded.
	pub idle_session_timeout: Duration,
	/// Maximum datagram size accepted by the socket loop.
	pub max_packet_size: usize,
}

impl Default for RelayConfig {
	fn default() -> Self {
		Self {
			bind_addr: SocketAddr::from(([0, 0, 0, 0], 51_821)),
			idle_session_timeout: DEFAULT_IDLE_SESSION_TIMEOUT,
			max_packet_size: DEFAULT_MAX_PACKET_SIZE,
		}
	}
}

/// Static session registration supplied by the control plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySessionRegistration {
	/// Stable identifier for the relay session.
	pub session_id: Uuid,
	/// First peer endpoint.
	pub initiator: SocketAddr,
	/// Second peer endpoint.
	pub responder: SocketAddr,
}

/// Runtime relay statistics exposed to the server daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStats {
	/// Number of currently active registered sessions.
	pub active_sessions: usize,
	/// Total number of forwarded datagrams.
	pub packets_forwarded: u64,
	/// Total number of forwarded payload bytes.
	pub bytes_forwarded: u64,
}

/// Running blind UDP relay instance.
#[derive(Debug)]
pub struct RelayServer {
	local_addr: SocketAddr,
	state: Arc<SharedState>,
	shutdown: Arc<Notify>,
	task: JoinHandle<()>,
}

#[derive(Debug)]
struct SharedState {
	config: RelayConfig,
	sessions: RwLock<HashMap<Uuid, RelaySession>>,
	endpoint_index: RwLock<HashMap<SocketAddr, Uuid>>,
	packets_forwarded: AtomicU64,
	bytes_forwarded: AtomicU64,
}

#[derive(Debug, Clone)]
struct RelaySession {
	initiator: SocketAddr,
	responder: SocketAddr,
	last_activity: Instant,
}

impl RelaySession {
	fn new(initiator: SocketAddr, responder: SocketAddr) -> Self {
		Self {
			initiator,
			responder,
			last_activity: Instant::now(),
		}
	}

	fn destination_for(&self, source: SocketAddr) -> Option<SocketAddr> {
		if source == self.initiator {
			Some(self.responder)
		} else if source == self.responder {
			Some(self.initiator)
		} else {
			None
		}
	}
}

impl RelayServer {
	/// Starts the blind UDP relay service.
	///
	/// # Errors
	///
	/// Returns an error if the socket cannot be bound or the configuration is invalid.
	#[must_use]
	pub async fn start(config: RelayConfig) -> QuantumLinkResult<Self> {
		validate_config(&config)?;

		let socket = UdpSocket::bind(config.bind_addr)
			.await
			.map_err(|error| QuantumLinkError::Io(std::io::Error::other(error)))?;
		let local_addr = socket
			.local_addr()
			.map_err(|error| QuantumLinkError::Io(std::io::Error::other(error)))?;

		let state = Arc::new(SharedState {
			config,
			sessions: RwLock::new(HashMap::new()),
			endpoint_index: RwLock::new(HashMap::new()),
			packets_forwarded: AtomicU64::new(0),
			bytes_forwarded: AtomicU64::new(0),
		});
		let shutdown = Arc::new(Notify::new());

		let task = tokio::spawn(run_relay_loop(
			Arc::new(socket),
			Arc::clone(&state),
			Arc::clone(&shutdown),
		));

		Ok(Self {
			local_addr,
			state,
			shutdown,
			task,
		})
	}

	/// Stops the relay service gracefully.
	///
	/// # Errors
	///
	/// Returns an error if the relay task cannot be joined.
	#[must_use]
	pub async fn stop(self) -> QuantumLinkResult<()> {
		self.shutdown.notify_one();
		let abort_handle = self.task.abort_handle();
		match tokio::time::timeout(Duration::from_secs(2), self.task).await {
			Ok(join_result) => {
				join_result.map_err(|error| {
					QuantumLinkError::Io(std::io::Error::other(format!(
						"ql-relay join error: {error}"
					)))
				})?;
			}
			Err(_) => {
				abort_handle.abort();
			}
		}
		Ok(())
	}

	/// Returns the socket address currently bound by the relay.
	#[must_use]
	pub fn local_addr(&self) -> SocketAddr {
		self.local_addr
	}

	/// Registers or replaces a two-peer blind relay session.
	///
	/// # Errors
	///
	/// Returns an error if the session endpoints are invalid or already claimed by another session.
	#[must_use]
	pub async fn register_session(
		&self,
		registration: RelaySessionRegistration,
	) -> QuantumLinkResult<()> {
		if registration.initiator == registration.responder {
			return Err(QuantumLinkError::Config(
				"relay session peers must use distinct endpoints".to_owned(),
			));
		}

		let mut sessions = self.state.sessions.write().await;
		let mut endpoint_index = self.state.endpoint_index.write().await;

		if let Some(existing) = sessions.remove(&registration.session_id) {
			endpoint_index.remove(&existing.initiator);
			endpoint_index.remove(&existing.responder);
		}

		for endpoint in [registration.initiator, registration.responder] {
			if let Some(existing_session) = endpoint_index.get(&endpoint) {
				return Err(QuantumLinkError::Config(format!(
					"relay endpoint {endpoint} is already assigned to session {existing_session}"
				)));
			}
		}

		endpoint_index.insert(registration.initiator, registration.session_id);
		endpoint_index.insert(registration.responder, registration.session_id);
		sessions.insert(
			registration.session_id,
			RelaySession::new(registration.initiator, registration.responder),
		);

		Ok(())
	}

	/// Removes a relay session if it exists.
	#[must_use]
	pub async fn remove_session(&self, session_id: Uuid) -> bool {
		remove_session(&self.state, session_id).await
	}

	/// Prunes sessions that have been idle for longer than the configured timeout.
	#[must_use]
	pub async fn purge_idle_sessions(&self) -> usize {
		purge_idle_sessions(&self.state).await
	}

	/// Returns current relay statistics.
	#[must_use]
	pub async fn stats(&self) -> RelayStats {
		RelayStats {
			active_sessions: self.state.sessions.read().await.len(),
			packets_forwarded: self.state.packets_forwarded.load(Ordering::Relaxed),
			bytes_forwarded: self.state.bytes_forwarded.load(Ordering::Relaxed),
		}
	}
}

async fn run_relay_loop(socket: Arc<UdpSocket>, state: Arc<SharedState>, shutdown: Arc<Notify>) {
	let mut maintenance = tokio::time::interval(MAINTENANCE_INTERVAL);
	let mut buffer = vec![0_u8; state.config.max_packet_size];

	loop {
		tokio::select! {
			_ = shutdown.notified() => {
				break;
			}
			_ = maintenance.tick() => {
				let _ = purge_idle_sessions(&state).await;
			}
			result = socket.recv_from(&mut buffer) => {
				match result {
					Ok((bytes_read, source)) => {
						forward_datagram(&socket, &state, &buffer[..bytes_read], source).await;
					}
					Err(error) => {
						warn!("ql-relay socket receive error: {error}");
					}
				}
			}
		}
	}
}

async fn forward_datagram(
	socket: &UdpSocket,
	state: &SharedState,
	payload: &[u8],
	source: SocketAddr,
) {
	let session_id = {
		let endpoint_index = state.endpoint_index.read().await;
		endpoint_index.get(&source).copied()
	};

	let Some(session_id) = session_id else {
		return;
	};

	let destination = {
		let mut sessions = state.sessions.write().await;
		let Some(session) = sessions.get_mut(&session_id) else {
			return;
		};
		let destination = session.destination_for(source);
		if destination.is_some() {
			session.last_activity = Instant::now();
		}
		destination
	};

	let Some(destination) = destination else {
		return;
	};

	if let Err(error) = socket.send_to(payload, destination).await {
		warn!("ql-relay socket send error to {destination}: {error}");
		return;
	}

	state.packets_forwarded.fetch_add(1, Ordering::Relaxed);
	state
		.bytes_forwarded
		.fetch_add(payload.len() as u64, Ordering::Relaxed);
}

async fn purge_idle_sessions(state: &SharedState) -> usize {
	if state.config.idle_session_timeout.is_zero() {
		return 0;
	}

	let expired_session_ids = {
		let sessions = state.sessions.read().await;
		let now = Instant::now();
		sessions
			.iter()
			.filter_map(|(session_id, session)| {
				(now.duration_since(session.last_activity) >= state.config.idle_session_timeout)
					.then_some(*session_id)
			})
			.collect::<Vec<_>>()
	};

	let mut removed = 0_usize;
	for session_id in expired_session_ids {
		if remove_session(state, session_id).await {
			removed += 1;
		}
	}

	removed
}

async fn remove_session(state: &SharedState, session_id: Uuid) -> bool {
	let mut sessions = state.sessions.write().await;
	let Some(session) = sessions.remove(&session_id) else {
		return false;
	};
	drop(sessions);

	let mut endpoint_index = state.endpoint_index.write().await;
	endpoint_index.remove(&session.initiator);
	endpoint_index.remove(&session.responder);
	true
}

fn validate_config(config: &RelayConfig) -> QuantumLinkResult<()> {
	if config.max_packet_size == 0 {
		return Err(QuantumLinkError::Config(
			"relay max_packet_size must be greater than zero".to_owned(),
		));
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use tokio::net::UdpSocket;
	use tokio::time::timeout;
	use uuid::Uuid;

	use super::{RelayConfig, RelayServer, RelaySessionRegistration};

	#[tokio::test]
	async fn forwards_packets_between_registered_peers() {
		let relay = RelayServer::start(RelayConfig {
			bind_addr: "127.0.0.1:0".parse().unwrap(),
			..RelayConfig::default()
		})
		.await
		.unwrap();

		let initiator = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		let responder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		let session_id = Uuid::new_v4();
		relay
			.register_session(RelaySessionRegistration {
				session_id,
				initiator: initiator.local_addr().unwrap(),
				responder: responder.local_addr().unwrap(),
			})
			.await
			.unwrap();

		initiator
			.send_to(b"opaque-wireguard-ciphertext", relay.local_addr())
			.await
			.unwrap();

		let mut buffer = [0_u8; 128];
		let (bytes_read, source) = timeout(
			Duration::from_secs(1),
			responder.recv_from(&mut buffer),
		)
		.await
		.unwrap()
		.unwrap();

		assert_eq!(&buffer[..bytes_read], b"opaque-wireguard-ciphertext");
		assert_eq!(source, relay.local_addr());

		responder
			.send_to(b"return-path-ciphertext", relay.local_addr())
			.await
			.unwrap();
		let (bytes_read, _) = timeout(
			Duration::from_secs(1),
			initiator.recv_from(&mut buffer),
		)
		.await
		.unwrap()
		.unwrap();

		assert_eq!(&buffer[..bytes_read], b"return-path-ciphertext");

		let stats = relay.stats().await;
		assert_eq!(stats.active_sessions, 1);
		assert_eq!(stats.packets_forwarded, 2);
		assert_eq!(
			stats.bytes_forwarded,
			(b"opaque-wireguard-ciphertext".len() + b"return-path-ciphertext".len()) as u64
		);

		relay.stop().await.unwrap();
	}

	#[tokio::test]
	async fn ignores_unregistered_sources() {
		let relay = RelayServer::start(RelayConfig {
			bind_addr: "127.0.0.1:0".parse().unwrap(),
			..RelayConfig::default()
		})
		.await
		.unwrap();

		let unknown = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();

		unknown.send_to(b"ignored", relay.local_addr()).await.unwrap();

		let mut buffer = [0_u8; 32];
		let recv_result = timeout(Duration::from_millis(200), receiver.recv_from(&mut buffer)).await;
		assert!(recv_result.is_err());

		let stats = relay.stats().await;
		assert_eq!(stats.packets_forwarded, 0);

		relay.stop().await.unwrap();
	}

	#[tokio::test]
	async fn purges_idle_sessions() {
		let relay = RelayServer::start(RelayConfig {
			bind_addr: "127.0.0.1:0".parse().unwrap(),
			idle_session_timeout: Duration::from_millis(10),
			..RelayConfig::default()
		})
		.await
		.unwrap();

		let initiator = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		let responder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		relay
			.register_session(RelaySessionRegistration {
				session_id: Uuid::new_v4(),
				initiator: initiator.local_addr().unwrap(),
				responder: responder.local_addr().unwrap(),
			})
			.await
			.unwrap();

		tokio::time::sleep(Duration::from_millis(20)).await;
		assert_eq!(relay.purge_idle_sessions().await, 1);
		assert_eq!(relay.stats().await.active_sessions, 0);

		relay.stop().await.unwrap();
	}
}
