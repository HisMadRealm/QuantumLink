//! Signaling services for peer registration and pairing mailboxes.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use ql_core::{QuantumLinkError, QuantumLinkResult};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify, RwLock};
use tokio::task::JoinHandle;
use tracing::info;
use uuid::Uuid;

const DEFAULT_MAILBOX_TTL: Duration = Duration::from_secs(600);
const DEFAULT_PEER_TTL: Duration = Duration::from_secs(120);
const MAILBOX_CREATIONS_PER_HOUR: usize = 5;
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(30);
const DEVICE_CERT_HEADER: &str = "x-quantumlink-device-cert";
const PAIRING_ID_HEADER: &str = "x-quantumlink-pairing-id";

/// Runtime configuration for the signaling server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalConfig {
	/// Socket address to bind.
	pub bind_addr: SocketAddr,
	/// How long peer registrations stay live without refresh.
	pub peer_ttl: Duration,
	/// How long pairing mailboxes remain valid.
	pub mailbox_ttl: Duration,
}

impl Default for SignalConfig {
	fn default() -> Self {
		Self {
			bind_addr: SocketAddr::from(([0, 0, 0, 0], 8_443)),
			peer_ttl: DEFAULT_PEER_TTL,
			mailbox_ttl: DEFAULT_MAILBOX_TTL,
		}
	}
}

/// Registration payload for a device endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterRequest {
	/// Device WireGuard public key.
	pub wg_public_key: [u8; 32],
	/// Current reachable endpoint.
	pub endpoint: SocketAddr,
}

/// Registered peer snapshot returned to authenticated devices.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisteredPeer {
	/// Device WireGuard public key.
	pub wg_public_key: [u8; 32],
	/// Current endpoint registered for the device.
	pub endpoint: SocketAddr,
	/// Certificate fingerprint associated with the device.
	pub cert_fingerprint: String,
	/// Last registration update in unix seconds.
	pub updated_at: u64,
}

/// Request to place an encrypted payload into a mailbox.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxSendRequest {
	/// Opaque encrypted message bytes.
	#[serde(with = "serde_bytes")]
	pub payload: Vec<u8>,
}

/// Opaque encrypted mailbox message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxMessage {
	/// Sender certificate fingerprint.
	pub sender: String,
	/// Opaque encrypted message bytes.
	#[serde(with = "serde_bytes")]
	pub payload: Vec<u8>,
	/// Unix timestamp when the server accepted the message.
	pub created_at: u64,
}

/// Response returned when a mailbox is created.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxCreateResponse {
	/// Server-generated mailbox identifier.
	pub mailbox_id: Uuid,
}

/// Authentication material used by the signal mailbox client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalMailboxAuth {
	/// Device certificate header used for authenticated devices.
	DeviceCertificate(String),
	/// Pairing-token header used during enrollment handoff.
	PairingId(String),
}

/// Small HTTP client for QuantumLink signal operations.
#[derive(Debug, Clone)]
pub struct SignalClient {
	base_url: String,
	auth: SignalMailboxAuth,
	http: HttpClient,
}

impl SignalClient {
	/// Creates a signal client for the given base URL and auth material.
	pub fn new(base_url: impl Into<String>, auth: SignalMailboxAuth) -> QuantumLinkResult<Self> {
		let base_url = base_url.into().trim_end_matches('/').to_owned();
		if base_url.is_empty() {
			return Err(QuantumLinkError::Config(
				"signal base URL must not be empty".to_owned(),
			));
		}

		Ok(Self {
			base_url,
			auth,
			http: HttpClient::new(),
		})
	}

	/// Creates a mailbox on the signal server.
	pub async fn create_mailbox(&self) -> QuantumLinkResult<MailboxCreateResponse> {
		self.send_request(self.http.post(self.url("/mailbox/create")))
			.await?
			.error_for_status()
			.map_err(http_error)?
			.json::<MailboxCreateResponse>()
			.await
			.map_err(http_error)
	}

	/// Sends an opaque mailbox payload.
	pub async fn send_mailbox_payload(&self, mailbox_id: Uuid, payload: Vec<u8>) -> QuantumLinkResult<()> {
		self.send_request(
			self.http
				.post(self.url(&format!("/mailbox/{mailbox_id}/send")))
				.json(&MailboxSendRequest { payload }),
		)
		.await?
		.error_for_status()
		.map_err(http_error)?;
		Ok(())
	}

	/// Receives the next mailbox payload not sent by this client identity.
	pub async fn receive_mailbox_payload(
		&self,
		mailbox_id: Uuid,
	) -> QuantumLinkResult<Option<MailboxMessage>> {
		let response = self
			.send_request(self.http.post(self.url(&format!("/mailbox/{mailbox_id}/recv"))))
			.await?;
		if response.status() == reqwest::StatusCode::NO_CONTENT {
			return Ok(None);
		}
		response
			.error_for_status()
			.map_err(http_error)?
			.json::<MailboxMessage>()
			.await
			.map(Some)
			.map_err(http_error)
	}

	/// Deletes the mailbox on the signal server.
	pub async fn delete_mailbox(&self, mailbox_id: Uuid) -> QuantumLinkResult<()> {
		self.send_request(self.http.post(self.url(&format!("/mailbox/{mailbox_id}/delete"))))
			.await?
			.error_for_status()
			.map_err(http_error)?;
		Ok(())
	}

	fn url(&self, path: &str) -> String {
		format!("{}{}", self.base_url, path)
	}

	async fn send_request(
		&self,
		request: reqwest::RequestBuilder,
	) -> QuantumLinkResult<reqwest::Response> {
		let request = match &self.auth {
			SignalMailboxAuth::DeviceCertificate(cert) => request.header(DEVICE_CERT_HEADER, cert),
			SignalMailboxAuth::PairingId(pairing_id) => request.header(PAIRING_ID_HEADER, pairing_id),
		};
		request.send().await.map_err(http_error)
	}
}

/// Running signaling service instance.
#[derive(Debug)]
pub struct SignalServer {
	local_addr: SocketAddr,
	shutdown: Arc<Notify>,
	task: JoinHandle<()>,
}

impl SignalServer {
	/// Starts the HTTP signaling service.
	///
	/// # Errors
	///
	/// Returns an error if the listening socket cannot be bound.
	#[must_use]
	pub async fn start(config: SignalConfig) -> QuantumLinkResult<Self> {
		let state = Arc::new(AppState::new(config.clone()));
		let listener = TcpListener::bind(config.bind_addr)
			.await
			.map_err(|error| QuantumLinkError::Io(std::io::Error::other(error)))?;
		let local_addr = listener
			.local_addr()
			.map_err(|error| QuantumLinkError::Io(std::io::Error::other(error)))?;
		let shutdown = Arc::new(Notify::new());
		let shutdown_task = Arc::clone(&shutdown);

		let app = router(state);
		let task = tokio::spawn(async move {
			let server = axum::serve(
				listener,
				app.into_make_service_with_connect_info::<SocketAddr>(),
			)
			.with_graceful_shutdown(async move {
				shutdown_task.notified().await;
			});

			if let Err(error) = server.await {
				tracing::error!("ql-signal server terminated with error: {error}");
			}
		});

		Ok(Self {
			local_addr,
			shutdown,
			task,
		})
	}

	/// Stops the signaling service gracefully.
	///
	/// # Errors
	///
	/// Returns an error if the server task fails to join.
	#[must_use]
	pub async fn stop(self) -> QuantumLinkResult<()> {
		self.shutdown.notify_one();
		let abort_handle = self.task.abort_handle();
		match tokio::time::timeout(Duration::from_secs(2), self.task).await {
			Ok(join_result) => {
				join_result.map_err(|error| {
					QuantumLinkError::Io(std::io::Error::other(format!(
						"ql-signal join error: {error}"
					)))
				})?;
			}
			Err(_) => {
				abort_handle.abort();
			}
		}
		Ok(())
	}

	/// Returns the socket address currently bound by the service.
	#[must_use]
	pub fn local_addr(&self) -> SocketAddr {
		self.local_addr
	}
}

fn router(state: Arc<AppState>) -> Router {
	let routes = Router::new()
		.route("/register", post(register_peer))
		.route("/peers", post(list_peers))
		.route("/mailbox/create", post(create_mailbox))
		.route("/mailbox/{id}/send", post(send_mailbox_message))
		.route("/mailbox/{id}/recv", post(receive_mailbox_message))
		.route("/mailbox/{id}/delete", post(delete_mailbox))
		.route("/health", get(health))
		.with_state(state);

	#[cfg(feature = "metrics")]
	let routes = routes.route("/metrics", get(metrics));

	routes
}

#[derive(Debug)]
struct AppState {
	config: SignalConfig,
	peers: RwLock<HashMap<String, PeerRecord>>,
	mailboxes: RwLock<HashMap<Uuid, Arc<MailboxEntry>>>,
	mailbox_rate_limits: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl AppState {
	fn new(config: SignalConfig) -> Self {
		Self {
			config,
			peers: RwLock::new(HashMap::new()),
			mailboxes: RwLock::new(HashMap::new()),
			mailbox_rate_limits: Mutex::new(HashMap::new()),
		}
	}
}

#[derive(Debug, Clone)]
struct PeerRecord {
	wg_public_key: [u8; 32],
	endpoint: SocketAddr,
	cert_fingerprint: String,
	updated_at: Instant,
}

#[derive(Debug)]
struct MailboxEntry {
	created_at: Instant,
	messages: Mutex<VecDeque<MailboxMessage>>,
	participants: Mutex<Vec<String>>,
	notify: Notify,
}

impl MailboxEntry {
	fn new() -> Self {
		Self {
			created_at: Instant::now(),
			messages: Mutex::new(VecDeque::new()),
			participants: Mutex::new(Vec::new()),
			notify: Notify::new(),
		}
	}
}

#[derive(Debug)]
struct AuthIdentity {
	fingerprint: String,
}

async fn register_peer(
	State(state): State<Arc<AppState>>,
	ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
	headers: HeaderMap,
	Json(request): Json<RegisterRequest>,
) -> impl IntoResponse {
	let identity = match auth_identity(&headers) {
		Ok(identity) => identity,
		Err(response) => return response,
	};

	purge_expired_peers(&state).await;
	let record = PeerRecord {
		wg_public_key: request.wg_public_key,
		endpoint: request.endpoint,
		cert_fingerprint: identity.fingerprint.clone(),
		updated_at: Instant::now(),
	};

	state
		.peers
		.write()
		.await
		.insert(identity.fingerprint, record);
	info!("registered peer from {}", remote_addr.ip());
	StatusCode::NO_CONTENT.into_response()
}

async fn list_peers(
	State(state): State<Arc<AppState>>,
	headers: HeaderMap,
) -> impl IntoResponse {
	let identity = match auth_identity(&headers) {
		Ok(identity) => identity,
		Err(response) => return response,
	};

	purge_expired_peers(&state).await;
	let peers = state
		.peers
		.read()
		.await
		.values()
		.filter(|peer| peer.cert_fingerprint != identity.fingerprint)
		.map(peer_snapshot)
		.collect::<Vec<_>>();

	Json(peers).into_response()
}

async fn create_mailbox(
	State(state): State<Arc<AppState>>,
	ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
	headers: HeaderMap,
) -> impl IntoResponse {
	let _identity = match auth_identity(&headers) {
		Ok(identity) => identity,
		Err(response) => return response,
	};

	if let Err(response) = enforce_mailbox_rate_limit(&state, remote_addr.ip()).await {
		return response;
	}

	purge_expired_mailboxes(&state).await;
	let mailbox_id = Uuid::new_v4();
	state
		.mailboxes
		.write()
		.await
		.insert(mailbox_id, Arc::new(MailboxEntry::new()));

	Json(MailboxCreateResponse { mailbox_id }).into_response()
}

async fn send_mailbox_message(
	State(state): State<Arc<AppState>>,
	Path(mailbox_id): Path<Uuid>,
	headers: HeaderMap,
	Json(request): Json<MailboxSendRequest>,
) -> impl IntoResponse {
	let identity = match auth_identity(&headers) {
		Ok(identity) => identity,
		Err(response) => return response,
	};

	purge_expired_mailboxes(&state).await;
	let Some(mailbox) = state.mailboxes.read().await.get(&mailbox_id).cloned() else {
		return StatusCode::NOT_FOUND.into_response();
	};

	let mut participants = mailbox.participants.lock().await;
	if !participants.contains(&identity.fingerprint) {
		participants.push(identity.fingerprint.clone());
	}
	drop(participants);

	let mut messages = mailbox.messages.lock().await;
	messages.push_back(MailboxMessage {
		sender: identity.fingerprint,
		payload: request.payload,
		created_at: unix_timestamp(),
	});
	if messages.len() > 2 {
		messages.pop_front();
	}
	drop(messages);
	mailbox.notify.notify_waiters();

	StatusCode::NO_CONTENT.into_response()
}

async fn receive_mailbox_message(
	State(state): State<Arc<AppState>>,
	Path(mailbox_id): Path<Uuid>,
	headers: HeaderMap,
) -> impl IntoResponse {
	let identity = match auth_identity(&headers) {
		Ok(identity) => identity,
		Err(response) => return response,
	};

	purge_expired_mailboxes(&state).await;
	let Some(mailbox) = state.mailboxes.read().await.get(&mailbox_id).cloned() else {
		return StatusCode::NOT_FOUND.into_response();
	};

	if let Some(message) = pop_message_for_recipient(&mailbox, &identity.fingerprint).await {
		cleanup_mailbox_if_complete(&state, mailbox_id, &mailbox).await;
		return Json(message).into_response();
	}

	let timeout = tokio::time::timeout(RECEIVE_TIMEOUT, mailbox.notify.notified()).await;
	if timeout.is_err() {
		return StatusCode::NO_CONTENT.into_response();
	}

	match pop_message_for_recipient(&mailbox, &identity.fingerprint).await {
		Some(message) => {
			cleanup_mailbox_if_complete(&state, mailbox_id, &mailbox).await;
			Json(message).into_response()
		}
		None => StatusCode::NO_CONTENT.into_response(),
	}
}

async fn delete_mailbox(
	State(state): State<Arc<AppState>>,
	Path(mailbox_id): Path<Uuid>,
	headers: HeaderMap,
) -> impl IntoResponse {
	let _identity = match auth_identity(&headers) {
		Ok(identity) => identity,
		Err(response) => return response,
	};

	state.mailboxes.write().await.remove(&mailbox_id);
	StatusCode::NO_CONTENT.into_response()
}

async fn health() -> impl IntoResponse {
	Json(serde_json::json!({ "status": "ok" })).into_response()
}

#[cfg(feature = "metrics")]
async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
	let peer_count = state.peers.read().await.len();
	let mailbox_count = state.mailboxes.read().await.len();
	format!(
		"# TYPE ql_signal_peers gauge\nql_signal_peers {}\n# TYPE ql_signal_mailboxes gauge\nql_signal_mailboxes {}\n",
		peer_count, mailbox_count
	)
}

fn auth_identity(headers: &HeaderMap) -> Result<AuthIdentity, axum::response::Response> {
	let Some(raw_identity) = headers
		.get(DEVICE_CERT_HEADER)
		.or_else(|| headers.get(PAIRING_ID_HEADER))
	else {
		return Err(StatusCode::UNAUTHORIZED.into_response());
	};
	let mut hasher = Sha256::new();
	hasher.update(raw_identity.as_bytes());
	Ok(AuthIdentity {
		fingerprint: format!("{:x}", hasher.finalize()),
	})
}

fn http_error(error: reqwest::Error) -> QuantumLinkError {
	QuantumLinkError::Io(std::io::Error::other(format!("signal HTTP error: {error}")))
}

async fn purge_expired_peers(state: &Arc<AppState>) {
	let peer_ttl = state.config.peer_ttl;
	state.peers.write().await.retain(|_, peer| peer.updated_at.elapsed() <= peer_ttl);
}

async fn purge_expired_mailboxes(state: &Arc<AppState>) {
	let mailbox_ttl = state.config.mailbox_ttl;
	state
		.mailboxes
		.write()
		.await
		.retain(|_, mailbox| mailbox.created_at.elapsed() <= mailbox_ttl);
}

async fn enforce_mailbox_rate_limit(
	state: &Arc<AppState>,
	ip: IpAddr,
) -> Result<(), axum::response::Response> {
	let mut limits = state.mailbox_rate_limits.lock().await;
	let history = limits.entry(ip).or_default();
	let cutoff = Instant::now() - Duration::from_secs(3_600);
	while history.front().is_some_and(|instant| *instant < cutoff) {
		history.pop_front();
	}
	if history.len() >= MAILBOX_CREATIONS_PER_HOUR {
		return Err(StatusCode::TOO_MANY_REQUESTS.into_response());
	}

	history.push_back(Instant::now());
	Ok(())
}

async fn pop_message_for_recipient(mailbox: &Arc<MailboxEntry>, recipient: &str) -> Option<MailboxMessage> {
	let mut messages = mailbox.messages.lock().await;
	let index = messages.iter().position(|message| message.sender != recipient)?;
	messages.remove(index)
}

async fn cleanup_mailbox_if_complete(state: &Arc<AppState>, mailbox_id: Uuid, mailbox: &Arc<MailboxEntry>) {
	let _ = (state, mailbox_id, mailbox);
}

fn peer_snapshot(peer: &PeerRecord) -> RegisteredPeer {
	RegisteredPeer {
		wg_public_key: peer.wg_public_key,
		endpoint: peer.endpoint,
		cert_fingerprint: peer.cert_fingerprint.clone(),
		updated_at: unix_timestamp(),
	}
}

fn unix_timestamp() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_secs()
}

#[cfg(test)]
mod tests {
	use super::{
		peer_snapshot, PeerRecord, SignalClient, SignalConfig, SignalMailboxAuth, SignalServer,
		DEFAULT_MAILBOX_TTL,
	};
	use std::time::{Duration, Instant};

	#[test]
	fn default_signal_config_matches_spec_defaults() {
		let config = SignalConfig::default();

		assert_eq!(config.bind_addr.port(), 8_443);
		assert_eq!(config.mailbox_ttl, DEFAULT_MAILBOX_TTL);
	}

	#[test]
	fn peer_snapshot_preserves_registration_fields() {
		let peer = PeerRecord {
			wg_public_key: [4_u8; 32],
			endpoint: "198.51.100.11:51820".parse().unwrap(),
			cert_fingerprint: "fingerprint".to_owned(),
			updated_at: Instant::now() - Duration::from_secs(5),
		};

		let snapshot = peer_snapshot(&peer);

		assert_eq!(snapshot.wg_public_key, [4_u8; 32]);
		assert_eq!(snapshot.endpoint.port(), 51_820);
		assert_eq!(snapshot.cert_fingerprint, "fingerprint");
	}

	#[tokio::test]
	async fn signal_client_roundtrips_mailbox_message_with_pairing_auth() {
		let server = SignalServer::start(SignalConfig {
			bind_addr: "127.0.0.1:0".parse().unwrap(),
			..SignalConfig::default()
		})
		.await
		.unwrap();
		let base_url = format!("http://{}", server.local_addr());
		let initiator = SignalClient::new(
			base_url.clone(),
			SignalMailboxAuth::PairingId("rendezvous-1:initiator".to_owned()),
		)
		.unwrap();
		let responder = SignalClient::new(
			base_url,
			SignalMailboxAuth::PairingId("rendezvous-1:responder".to_owned()),
		)
		.unwrap();

		let mailbox = initiator.create_mailbox().await.unwrap();
		initiator
			.send_mailbox_payload(mailbox.mailbox_id, b"enrollment".to_vec())
			.await
			.unwrap();

		let message = responder
			.receive_mailbox_payload(mailbox.mailbox_id)
			.await
			.unwrap()
			.unwrap();
		assert_eq!(message.payload, b"enrollment".to_vec());

		server.stop().await.unwrap();
	}
}
