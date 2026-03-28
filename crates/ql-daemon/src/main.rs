//! Client daemon binary for QuantumLink.

#![forbid(unsafe_code)]

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ipnetwork::IpNetwork;
use ql_core::{
    AlgorithmSet, CertificateAuthority, CertificateRequest, CryptoMode, DaemonEvent,
    DeviceCertificate, IdentityAuditEvent, KeyStorageLayout, QuantumLinkConfig, QuantumLinkError,
    QuantumLinkResult, RelayPolicy, RevocationList, RevocationRecord, TunnelState,
};
use ql_crypto::{HybridSigningKey, HybridSigningKeyFile, HybridVerifyingKey};
use ql_firewall::PlatformFirewall;
use ql_mesh::{MeshConfig, MeshManager};
use ql_pair::{
    EnrollmentBundle, PairingMailboxIdentity, PairingMailboxPayload, PairingRole,
    SignedDeviceCertificate, WormholeCode, WormholePairingSession,
};
use ql_rosenpass::{RosenpassConfig, RosenpassManager};
use ql_signal::{SignalClient, SignalMailboxAuth};
use ql_wireguard::{PlatformTunnel, TunnelConfig};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeArgs {
    config_path: Option<PathBuf>,
    interface_name: String,
    interface_addresses: Vec<IpNetwork>,
    private_key: [u8; 32],
    peer_public_key: [u8; 32],
    peer_endpoint: SocketAddr,
    allowed_ips: Vec<IpNetwork>,
    listen_port: u16,
    persistent_keepalive: Option<u16>,
    rosenpass_keys: Option<RosenpassKeyPaths>,
    dry_run: bool,
    shutdown_after: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RosenpassKeyPaths {
    own_secret_key: PathBuf,
    own_public_key: PathBuf,
    peer_public_key: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityInitCaArgs {
    root_dir: Option<PathBuf>,
    name: String,
    created_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityIssueArgs {
    root_dir: Option<PathBuf>,
    device_name: String,
    overlay_ip: IpAddr,
    groups: Vec<String>,
    wg_public_key: [u8; 32],
    rosenpass_fingerprint: String,
    valid_for: u64,
    valid_from: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityVerifyArgs {
    root_dir: Option<PathBuf>,
    certificate_path: PathBuf,
    now: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityRenewArgs {
    root_dir: Option<PathBuf>,
    certificate_path: PathBuf,
    valid_for: u64,
    valid_from: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityRevokeArgs {
    root_dir: Option<PathBuf>,
    serial: String,
    reason: String,
    revoked_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityExportEnrollmentArgs {
    root_dir: Option<PathBuf>,
    certificate_path: PathBuf,
    exported_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentityImportEnrollmentArgs {
    root_dir: Option<PathBuf>,
    bundle_path: PathBuf,
    now: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PairMailboxCreateArgs {
    signal_url: String,
    pairing_id: String,
    role: PairingRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PairSendEnrollmentArgs {
    root_dir: Option<PathBuf>,
    signal_url: String,
    pairing_id: String,
    role: PairingRole,
    mailbox_id: Uuid,
    certificate_path: PathBuf,
    exported_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PairReceiveEnrollmentArgs {
    root_dir: Option<PathBuf>,
    signal_url: String,
    pairing_id: String,
    role: PairingRole,
    mailbox_id: Uuid,
    now: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PairInitiateArgs {
    root_dir: Option<PathBuf>,
    signal_url: String,
    pairing_id: String,
    code: String,
    certificate_path: PathBuf,
    exported_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PairAcceptArgs {
    root_dir: Option<PathBuf>,
    signal_url: String,
    pairing_id: String,
    code: String,
    mailbox_id: Uuid,
    now: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IdentityCommand {
    InitCa(IdentityInitCaArgs),
    Issue(IdentityIssueArgs),
    Verify(IdentityVerifyArgs),
    Renew(IdentityRenewArgs),
    Revoke(IdentityRevokeArgs),
    ExportEnrollment(IdentityExportEnrollmentArgs),
    ImportEnrollment(IdentityImportEnrollmentArgs),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliCommand {
    Status { config_path: Option<PathBuf> },
    PairCode,
    PairMailboxCreate(PairMailboxCreateArgs),
    PairSendEnrollment(PairSendEnrollmentArgs),
    PairReceiveEnrollment(PairReceiveEnrollmentArgs),
    PairInitiate(PairInitiateArgs),
    PairAccept(PairAcceptArgs),
    Plan(RuntimeArgs),
    Connect(RuntimeArgs),
    Identity(IdentityCommand),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ConnectPlan {
    interface_name: String,
    interface_addresses: Vec<String>,
    peer_endpoint: SocketAddr,
    allowed_ips: Vec<String>,
    listen_port: u16,
    kill_switch: bool,
    dns_leak_protection: bool,
    dns_servers: Vec<IpAddr>,
    crypto_mode: CryptoMode,
    rosenpass_enabled: bool,
    mesh_enabled: bool,
    relay_policy: RelayPolicy,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct DaemonStatusSnapshot {
    state: TunnelState,
    plan: Option<ConnectPlan>,
    psk_age_seconds: Option<u64>,
    mesh_enabled: bool,
    managed_mesh_peers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredCertificateAuthority {
    authority: CertificateAuthority,
    verifying_key: HybridVerifyingKey,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct StoredCertificateResult {
    path: PathBuf,
    bundle: SignedDeviceCertificate,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct CaInitResult {
    root_dir: PathBuf,
    authority: StoredCertificateAuthority,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct RevocationResult {
    path: PathBuf,
    revocations: RevocationList,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct EnrollmentExportResult {
    path: PathBuf,
    bundle: EnrollmentBundle,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct EnrollmentImportResult {
    root_dir: PathBuf,
    certificate_path: PathBuf,
    verification: CertificateVerificationReport,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PairMailboxCreateResult {
    mailbox_id: Uuid,
    pairing_id: String,
    role: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PairMailboxSendResult {
    mailbox_id: Uuid,
    serial: String,
    exported_at: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PairMailboxReceiveResult {
    mailbox_id: Uuid,
    sender: String,
    certificate_path: PathBuf,
    verification: CertificateVerificationReport,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PairInitiateResult {
    mailbox_id: Uuid,
    pairing_id: String,
    verification_words: [String; 5],
    serial: String,
    exported_at: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PairAcceptResult {
    mailbox_id: Uuid,
    verification_words: [String; 5],
    sender: String,
    certificate_path: PathBuf,
    verification: CertificateVerificationReport,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct CertificateVerificationReport {
    certificate_path: PathBuf,
    serial: String,
    device_name: String,
    issuer_fingerprint: String,
    valid_signature: bool,
    valid_at_time: bool,
    revoked: bool,
    expires_at: u64,
}

#[derive(Debug)]
struct ClientDaemon {
    config: QuantumLinkConfig,
    runtime: RuntimeArgs,
    mesh: MeshManager,
    state: TunnelState,
    tunnel: Option<PlatformTunnel>,
    rosenpass: Option<RosenpassManager>,
}

impl ClientDaemon {
    fn new(config: QuantumLinkConfig, runtime: RuntimeArgs) -> Self {
        Self {
            mesh: MeshManager::new(MeshConfig::default()),
            config,
            runtime,
            state: TunnelState::Disconnected,
            tunnel: None,
            rosenpass: None,
        }
    }

    fn plan(&self) -> ConnectPlan {
        ConnectPlan {
            interface_name: self.runtime.interface_name.clone(),
            interface_addresses: self
                .runtime
                .interface_addresses
                .iter()
                .map(ToString::to_string)
                .collect(),
            peer_endpoint: self.runtime.peer_endpoint,
            allowed_ips: self
                .runtime
                .allowed_ips
                .iter()
                .map(ToString::to_string)
                .collect(),
            listen_port: self.runtime.listen_port,
            kill_switch: self.config.network.kill_switch,
            dns_leak_protection: self.config.network.dns_leak_protection,
            dns_servers: self.config.network.dns_servers.clone(),
            crypto_mode: self.config.crypto.mode.clone(),
            rosenpass_enabled: self.runtime.rosenpass_keys.is_some(),
            mesh_enabled: self.config.mesh.enabled,
            relay_policy: self.config.mesh.relay_policy.clone(),
        }
    }

    fn status_snapshot(&self) -> DaemonStatusSnapshot {
        DaemonStatusSnapshot {
            state: self.state.clone(),
            plan: Some(self.plan()),
            psk_age_seconds: self
                .rosenpass
                .as_ref()
                .map(|manager| manager.psk_age().as_secs()),
            mesh_enabled: self.config.mesh.enabled,
            managed_mesh_peers: self.mesh.dashboard().len(),
        }
    }

    async fn connect(&mut self) -> QuantumLinkResult<Vec<DaemonEvent>> {
        if matches!(
            self.state,
            TunnelState::Connected { .. } | TunnelState::Connecting
        ) {
            return Err(QuantumLinkError::Config(
                "daemon is already connecting or connected".to_owned(),
            ));
        }

        self.state = TunnelState::Connecting;
        let mut events = vec![DaemonEvent::StateChanged(self.state.clone())];
        let tunnel_config = self.build_tunnel_config();
        let tunnel = PlatformTunnel::new(tunnel_config)?;
        tunnel.bring_up()?;

        let firewall = PlatformFirewall::new(&self.runtime.interface_name);
        if self.config.network.kill_switch {
            let dns_server = self
                .config
                .network
                .dns_servers
                .first()
                .copied()
                .unwrap_or(IpAddr::from([10, 0, 0, 1]));
            firewall.enable_kill_switch(dns_server)?;
        } else if self.config.network.dns_leak_protection {
            let dns_server = self
                .config
                .network
                .dns_servers
                .first()
                .copied()
                .unwrap_or(IpAddr::from([10, 0, 0, 1]));
            firewall.enable_dns_protection(dns_server)?;
        }

        let rosenpass = if let Some(paths) = &self.runtime.rosenpass_keys {
            Some(
                RosenpassManager::start(RosenpassConfig {
                    own_sk_path: paths.own_secret_key.clone(),
                    own_pk_path: paths.own_public_key.clone(),
                    peer_pk_path: paths.peer_public_key.clone(),
                    interface_name: self.runtime.interface_name.clone(),
                    peer_wg_pubkey: self.runtime.peer_public_key,
                    listen_port: self.config.server.rosenpass_port,
                    peer_endpoint: Some(self.runtime.peer_endpoint),
                })
                .await?,
            )
        } else {
            None
        };

        let algo = AlgorithmSet {
            kem: self.config.crypto.kem.clone(),
            signature: self.config.crypto.signature.clone(),
            rosenpass_active: rosenpass.is_some(),
            psk_age_seconds: rosenpass
                .as_ref()
                .map(|manager| manager.psk_age().as_secs())
                .unwrap_or(0),
        };

        self.tunnel = Some(tunnel);
        self.rosenpass = rosenpass;
        self.state = TunnelState::Connected {
            algo: algo.clone(),
            peer_ip: self.runtime.peer_endpoint.ip(),
        };
        events.push(DaemonEvent::AlgorithmNegotiated(algo));
        events.push(DaemonEvent::StateChanged(self.state.clone()));
        Ok(events)
    }

    async fn disconnect(&mut self) -> QuantumLinkResult<Vec<DaemonEvent>> {
        if let Some(rosenpass) = self.rosenpass.take() {
            rosenpass.stop().await?;
        }

        let firewall = PlatformFirewall::new(&self.runtime.interface_name);
        let _ = firewall.disable_all();

        if let Some(tunnel) = self.tunnel.take() {
            tunnel.tear_down()?;
        }

        self.state = TunnelState::Disconnected;
        Ok(vec![DaemonEvent::StateChanged(self.state.clone())])
    }

    fn build_tunnel_config(&self) -> TunnelConfig {
        TunnelConfig {
            interface_name: self.runtime.interface_name.clone(),
            interface_addresses: self.runtime.interface_addresses.clone(),
            private_key: self.runtime.private_key,
            listen_port: self.runtime.listen_port,
            peer_public_key: self.runtime.peer_public_key,
            peer_endpoint: Some(self.runtime.peer_endpoint),
            allowed_ips: self.runtime.allowed_ips.clone(),
            persistent_keepalive: self.runtime.persistent_keepalive,
            dns_servers: self.config.network.dns_servers.clone(),
            mtu: self.config.network.mtu,
        }
    }
}

#[tokio::main]
async fn main() {
    match run().await {
        Ok(()) => {}
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

async fn run() -> QuantumLinkResult<()> {
    let command = parse_cli(env::args()).map_err(QuantumLinkError::Config)?;

    match command {
        CliCommand::Status { config_path } => {
            let config = load_config(config_path.as_deref())?;
            let status = DaemonStatusSnapshot {
                state: TunnelState::Disconnected,
                plan: None,
                psk_age_seconds: None,
                mesh_enabled: config.mesh.enabled,
                managed_mesh_peers: 0,
            };
            print_json(&status)
        }
        CliCommand::PairCode => {
            println!("{}", WormholeCode::generate().as_str());
            Ok(())
        }
        CliCommand::PairMailboxCreate(args) => handle_pair_mailbox_create(args).await,
        CliCommand::PairSendEnrollment(args) => handle_pair_send_enrollment(args).await,
        CliCommand::PairReceiveEnrollment(args) => handle_pair_receive_enrollment(args).await,
        CliCommand::PairInitiate(args) => handle_pair_initiate(args).await,
        CliCommand::PairAccept(args) => handle_pair_accept(args).await,
        CliCommand::Plan(runtime) => {
            let config = load_config(runtime.config_path.as_deref())?;
            let daemon = ClientDaemon::new(config, runtime);
            print_json(&daemon.plan())
        }
        CliCommand::Connect(runtime) => {
            let config = load_config(runtime.config_path.as_deref())?;
            let dry_run = runtime.dry_run;
            let shutdown_after = runtime.shutdown_after;
            let mut daemon = ClientDaemon::new(config, runtime);

            if dry_run {
                return print_json(&daemon.status_snapshot());
            }

            let _ = daemon.connect().await?;
            print_json(&daemon.status_snapshot())?;

            if let Some(duration) = shutdown_after {
                tokio::time::sleep(duration).await;
            } else {
                tokio::signal::ctrl_c().await.map_err(|error| {
                    QuantumLinkError::Io(std::io::Error::other(format!(
                        "failed waiting for Ctrl-C: {error}"
                    )))
                })?;
            }

            let _ = daemon.disconnect().await?;
            print_json(&daemon.status_snapshot())
        }
        CliCommand::Identity(identity_command) => handle_identity_command(identity_command),
    }
}

async fn handle_pair_mailbox_create(args: PairMailboxCreateArgs) -> QuantumLinkResult<()> {
    let client = pairing_signal_client(&args.signal_url, &args.pairing_id, args.role)?;
    let response = client.create_mailbox().await?;
    print_json(&PairMailboxCreateResult {
        mailbox_id: response.mailbox_id,
        pairing_id: args.pairing_id,
        role: args.role.as_str().to_owned(),
    })
}

async fn handle_pair_send_enrollment(args: PairSendEnrollmentArgs) -> QuantumLinkResult<()> {
    let layout = storage_layout(args.root_dir);
    let exported_at = args.exported_at.unwrap_or(current_unix_timestamp()?);
    let result = send_enrollment_via_mailbox(
        &layout,
        &args.signal_url,
        &args.pairing_id,
        args.role,
        args.mailbox_id,
        &args.certificate_path,
        exported_at,
    )
    .await?;
    print_json(&result)
}

async fn handle_pair_receive_enrollment(args: PairReceiveEnrollmentArgs) -> QuantumLinkResult<()> {
    let layout = storage_layout(args.root_dir);
    let now = args.now.unwrap_or(current_unix_timestamp()?);
    let result = receive_enrollment_via_mailbox(
        &layout,
        &args.signal_url,
        &args.pairing_id,
        args.role,
        args.mailbox_id,
        now,
    )
    .await?;
    print_json(&result)
}

async fn handle_pair_initiate(args: PairInitiateArgs) -> QuantumLinkResult<()> {
    let layout = storage_layout(args.root_dir);
    let exported_at = args.exported_at.unwrap_or(current_unix_timestamp()?);
    let result = initiate_pairing_enrollment(
        &layout,
        &args.signal_url,
        &args.pairing_id,
        &args.code,
        &args.certificate_path,
        exported_at,
    )
    .await?;
    print_json(&result)
}

async fn handle_pair_accept(args: PairAcceptArgs) -> QuantumLinkResult<()> {
    let layout = storage_layout(args.root_dir);
    let now = args.now.unwrap_or(current_unix_timestamp()?);
    let result = accept_pairing_enrollment(
        &layout,
        &args.signal_url,
        &args.pairing_id,
        &args.code,
        args.mailbox_id,
        now,
    )
    .await?;
    print_json(&result)
}

async fn send_enrollment_via_mailbox(
    layout: &KeyStorageLayout,
    signal_url: &str,
    pairing_id: &str,
    role: PairingRole,
    mailbox_id: Uuid,
    certificate_path: &Path,
    exported_at: u64,
) -> QuantumLinkResult<PairMailboxSendResult> {
    let (_, bundle) = export_enrollment_bundle(layout, certificate_path, exported_at)?;
    let payload = PairingMailboxPayload::EnrollmentBundle(bundle.clone()).encode()?;
    let client = pairing_signal_client(signal_url, pairing_id, role)?;
    client.send_mailbox_payload(mailbox_id, payload).await?;
    Ok(PairMailboxSendResult {
        mailbox_id,
        serial: bundle.device.certificate.serial,
        exported_at,
    })
}

async fn receive_enrollment_via_mailbox(
    layout: &KeyStorageLayout,
    signal_url: &str,
    pairing_id: &str,
    role: PairingRole,
    mailbox_id: Uuid,
    now: u64,
) -> QuantumLinkResult<PairMailboxReceiveResult> {
    let client = pairing_signal_client(signal_url, pairing_id, role)?;
    let message = client
        .receive_mailbox_payload(mailbox_id)
        .await?
        .ok_or_else(|| {
            QuantumLinkError::Pairing("no enrollment payload available in mailbox".to_owned())
        })?;
    let bundle = PairingMailboxPayload::decode(&message.payload)?.into_enrollment_bundle()?;
    let (certificate_path, verification) = import_enrollment_bundle_value(layout, bundle, now)?;
    Ok(PairMailboxReceiveResult {
        mailbox_id,
        sender: message.sender,
        certificate_path,
        verification,
    })
}

async fn initiate_pairing_enrollment(
    layout: &KeyStorageLayout,
    signal_url: &str,
    pairing_id: &str,
    code: &str,
    certificate_path: &Path,
    exported_at: u64,
) -> QuantumLinkResult<PairInitiateResult> {
    let client = pairing_signal_client(signal_url, pairing_id, PairingRole::Initiator)?;
    let mailbox = client.create_mailbox().await?;
    initiate_pairing_enrollment_on_mailbox(
        layout,
        signal_url,
        pairing_id,
        code,
        mailbox.mailbox_id,
        certificate_path,
        exported_at,
    )
    .await
}

async fn initiate_pairing_enrollment_on_mailbox(
    layout: &KeyStorageLayout,
    signal_url: &str,
    pairing_id: &str,
    code: &str,
    mailbox_id: Uuid,
    certificate_path: &Path,
    exported_at: u64,
) -> QuantumLinkResult<PairInitiateResult> {
    let client = pairing_signal_client(signal_url, pairing_id, PairingRole::Initiator)?;
    let (session, outbound_message) = WormholePairingSession::start(code, pairing_id)?;
    client
        .send_mailbox_payload(
            mailbox_id,
            PairingMailboxPayload::Spake2Message(outbound_message).encode()?,
        )
        .await?;
    let message = client
        .receive_mailbox_payload(mailbox_id)
        .await?
        .ok_or_else(|| {
            QuantumLinkError::Pairing("no SPAKE2 response received from the responder".to_owned())
        })?;
    let response = expect_spake2_message(&message.payload)?;
    let shared_secret = session.finish(&response)?;
    let sent = send_enrollment_via_mailbox(
        layout,
        signal_url,
        pairing_id,
        PairingRole::Initiator,
        mailbox_id,
        certificate_path,
        exported_at,
    )
    .await?;

    Ok(PairInitiateResult {
        mailbox_id,
        pairing_id: pairing_id.to_owned(),
        verification_words: shared_secret.emoji_verification(),
        serial: sent.serial,
        exported_at,
    })
}

async fn accept_pairing_enrollment(
    layout: &KeyStorageLayout,
    signal_url: &str,
    pairing_id: &str,
    code: &str,
    mailbox_id: Uuid,
    now: u64,
) -> QuantumLinkResult<PairAcceptResult> {
    let client = pairing_signal_client(signal_url, pairing_id, PairingRole::Responder)?;
    let inbound = client
        .receive_mailbox_payload(mailbox_id)
        .await?
        .ok_or_else(|| {
            QuantumLinkError::Pairing("no SPAKE2 message received from the initiator".to_owned())
        })?;
    let request = expect_spake2_message(&inbound.payload)?;
    let (session, outbound_message) = WormholePairingSession::start(code, pairing_id)?;
    let shared_secret = session.finish(&request)?;
    client
        .send_mailbox_payload(
            mailbox_id,
            PairingMailboxPayload::Spake2Message(outbound_message).encode()?,
        )
        .await?;
    let received = receive_enrollment_via_mailbox(
        layout,
        signal_url,
        pairing_id,
        PairingRole::Responder,
        mailbox_id,
        now,
    )
    .await?;
    client.delete_mailbox(mailbox_id).await?;

    Ok(PairAcceptResult {
        mailbox_id,
        verification_words: shared_secret.emoji_verification(),
        sender: received.sender,
        certificate_path: received.certificate_path,
        verification: received.verification,
    })
}

fn expect_spake2_message(payload: &[u8]) -> QuantumLinkResult<Vec<u8>> {
    match PairingMailboxPayload::decode(payload)? {
        PairingMailboxPayload::Spake2Message(message) => Ok(message),
        PairingMailboxPayload::EnrollmentBundle(_) => Err(QuantumLinkError::Pairing(
            "expected a SPAKE2 mailbox payload but received an enrollment bundle".to_owned(),
        )),
    }
}

fn handle_identity_command(command: IdentityCommand) -> QuantumLinkResult<()> {
    match command {
        IdentityCommand::InitCa(args) => {
            let layout = storage_layout(args.root_dir);
            let created_at = args.created_at.unwrap_or(current_unix_timestamp()?);
            let result = initialize_certificate_authority(&layout, &args.name, created_at)?;
            print_json(&CaInitResult {
                root_dir: layout.root_dir.clone(),
                authority: result,
            })
        }
        IdentityCommand::Issue(args) => {
            let layout = storage_layout(args.root_dir);
            let valid_from = args.valid_from.unwrap_or(current_unix_timestamp()?);
            let request = CertificateRequest {
                device_name: args.device_name,
                overlay_ip: args.overlay_ip,
                groups: args.groups,
                wg_public_key: args.wg_public_key,
                rosenpass_fingerprint: args.rosenpass_fingerprint,
                requested_at: valid_from,
            };
            let (path, bundle) = issue_certificate(&layout, request, valid_from, args.valid_for)?;
            print_json(&StoredCertificateResult { path, bundle })
        }
        IdentityCommand::Verify(args) => {
            let layout = storage_layout(args.root_dir);
            let now = args.now.unwrap_or(current_unix_timestamp()?);
            let report = verify_certificate(&layout, &args.certificate_path, now)?;
            print_json(&report)
        }
        IdentityCommand::Renew(args) => {
            let layout = storage_layout(args.root_dir);
            let valid_from = args.valid_from.unwrap_or(current_unix_timestamp()?);
            let existing: SignedDeviceCertificate = read_json_file(&args.certificate_path)?;
            let request = CertificateRequest {
                device_name: existing.certificate.device_name.clone(),
                overlay_ip: existing.certificate.overlay_ip,
                groups: existing.certificate.groups.clone(),
                wg_public_key: existing.certificate.wg_public_key,
                rosenpass_fingerprint: existing.certificate.rosenpass_fingerprint.clone(),
                requested_at: valid_from,
            };
            let (path, bundle) = issue_certificate(&layout, request, valid_from, args.valid_for)?;
            print_json(&StoredCertificateResult { path, bundle })
        }
        IdentityCommand::Revoke(args) => {
            let layout = storage_layout(args.root_dir);
            let revoked_at = args.revoked_at.unwrap_or(current_unix_timestamp()?);
            let result = revoke_certificate(&layout, &args.serial, &args.reason, revoked_at)?;
            print_json(&result)
        }
        IdentityCommand::ExportEnrollment(args) => {
            let layout = storage_layout(args.root_dir);
            let exported_at = args.exported_at.unwrap_or(current_unix_timestamp()?);
            let (path, bundle) =
                export_enrollment_bundle(&layout, &args.certificate_path, exported_at)?;
            print_json(&EnrollmentExportResult { path, bundle })
        }
        IdentityCommand::ImportEnrollment(args) => {
            let layout = storage_layout(args.root_dir);
            let now = args.now.unwrap_or(current_unix_timestamp()?);
            let (certificate_path, verification) =
                import_enrollment_bundle(&layout, &args.bundle_path, now)?;
            print_json(&EnrollmentImportResult {
                root_dir: layout.root_dir.clone(),
                certificate_path,
                verification,
            })
        }
    }
}

fn initialize_certificate_authority(
    layout: &KeyStorageLayout,
    name: &str,
    created_at: u64,
) -> QuantumLinkResult<StoredCertificateAuthority> {
    layout.ensure_directories()?;

    let signing_key = HybridSigningKey::generate()?;
    let verifying_key = signing_key.verifying_key();
    let authority = CertificateAuthority {
        name: name.to_owned(),
        fingerprint: encode_fingerprint(&verifying_key.fingerprint()),
        created_at,
    };
    let stored = StoredCertificateAuthority {
        authority: authority.clone(),
        verifying_key: verifying_key.clone(),
    };

    write_json_file(&layout.ca_metadata_path(), &authority)?;
    write_json_file(&layout.ca_verifying_key_path(), &verifying_key)?;
    write_json_file(&layout.ca_signing_key_path(), &signing_key.export_secret())?;
    append_identity_audit_event(
        layout,
        IdentityAuditEvent {
            recorded_at: created_at,
            action: "init-ca".to_owned(),
            subject: authority.fingerprint.clone(),
            detail: Some(name.to_owned()),
        },
    )?;

    Ok(stored)
}

fn issue_certificate(
    layout: &KeyStorageLayout,
    request: CertificateRequest,
    valid_from: u64,
    valid_for: u64,
) -> QuantumLinkResult<(PathBuf, SignedDeviceCertificate)> {
    layout.ensure_directories()?;
    let ca = load_certificate_authority(layout)?;
    let signing_key = load_ca_signing_key(layout)?;

    if signing_key.verifying_key() != ca.verifying_key {
        return Err(QuantumLinkError::Auth(
            "stored CA signing key does not match the stored verifying key".to_owned(),
        ));
    }

    let serial = certificate_serial(valid_from, &request.wg_public_key);
    let certificate = DeviceCertificate {
        serial: serial.clone(),
        device_name: request.device_name.clone(),
        overlay_ip: request.overlay_ip,
        groups: request.groups.clone(),
        wg_public_key: request.wg_public_key,
        rosenpass_fingerprint: request.rosenpass_fingerprint.clone(),
        issuer_fingerprint: ca.authority.fingerprint.clone(),
        valid_from,
        valid_until: valid_from.saturating_add(valid_for),
    };
    let signature = signing_key.sign(&certificate_signing_message(&certificate)?)?;
    let bundle = SignedDeviceCertificate {
        certificate,
        issuer_name: ca.authority.name.clone(),
        issued_at: valid_from,
        signature,
    };
    let path = layout.device_certificate_path(&serial);
    write_json_file(&path, &bundle)?;
    append_identity_audit_event(
        layout,
        IdentityAuditEvent {
            recorded_at: valid_from,
            action: "issue-certificate".to_owned(),
            subject: serial,
            detail: Some(request.device_name),
        },
    )?;

    Ok((path, bundle))
}

fn verify_certificate(
    layout: &KeyStorageLayout,
    certificate_path: &Path,
    now: u64,
) -> QuantumLinkResult<CertificateVerificationReport> {
    let ca = load_certificate_authority(layout)?;
    let revocations = load_revocations(layout)?;
    let bundle: SignedDeviceCertificate = read_json_file(certificate_path)?;
    let verification = bundle.verify(&ca.authority, &ca.verifying_key, &revocations, now)?;

    Ok(CertificateVerificationReport {
        certificate_path: certificate_path.to_path_buf(),
        serial: verification.serial,
        device_name: verification.device_name,
        issuer_fingerprint: verification.issuer_fingerprint,
        valid_signature: verification.valid_signature,
        valid_at_time: verification.valid_at_time,
        revoked: verification.revoked,
        expires_at: verification.expires_at,
    })
}

fn revoke_certificate(
    layout: &KeyStorageLayout,
    serial: &str,
    reason: &str,
    revoked_at: u64,
) -> QuantumLinkResult<RevocationResult> {
    layout.ensure_directories()?;
    let revocations = load_revocations(layout)?.with_record(RevocationRecord {
        certificate_serial: serial.to_owned(),
        reason: reason.to_owned(),
        revoked_at,
    });
    let updated = RevocationList {
        issued_at: revoked_at,
        entries: revocations.entries,
    };
    let path = layout.revocations_path();
    write_json_file(&path, &updated)?;
    append_identity_audit_event(
        layout,
        IdentityAuditEvent {
            recorded_at: revoked_at,
            action: "revoke-certificate".to_owned(),
            subject: serial.to_owned(),
            detail: Some(reason.to_owned()),
        },
    )?;
    Ok(RevocationResult {
        path,
        revocations: updated,
    })
}

fn export_enrollment_bundle(
    layout: &KeyStorageLayout,
    certificate_path: &Path,
    exported_at: u64,
) -> QuantumLinkResult<(PathBuf, EnrollmentBundle)> {
    layout.ensure_directories()?;
    let ca = load_certificate_authority(layout)?;
    let revocations = load_revocations(layout)?;
    let device: SignedDeviceCertificate = read_json_file(certificate_path)?;
    let verification =
        device.verify(&ca.authority, &ca.verifying_key, &revocations, exported_at)?;
    if !verification.valid_at_time {
        return Err(QuantumLinkError::Auth(
            "cannot export an expired or not-yet-valid enrollment bundle".to_owned(),
        ));
    }
    if verification.revoked {
        return Err(QuantumLinkError::Auth(
            "cannot export an enrollment bundle for a revoked certificate".to_owned(),
        ));
    }

    let bundle = EnrollmentBundle {
        authority: ca.authority,
        verifying_key: ca.verifying_key,
        device,
        revocations,
        exported_at,
    };
    let path = layout.device_dir.join(format!(
        "enrollment-{}.json",
        bundle.device.certificate.serial
    ));
    write_json_file(&path, &bundle)?;
    append_identity_audit_event(
        layout,
        IdentityAuditEvent {
            recorded_at: exported_at,
            action: "export-enrollment".to_owned(),
            subject: bundle.device.certificate.serial.clone(),
            detail: Some(path.display().to_string()),
        },
    )?;

    Ok((path, bundle))
}

fn import_enrollment_bundle(
    layout: &KeyStorageLayout,
    bundle_path: &Path,
    now: u64,
) -> QuantumLinkResult<(PathBuf, CertificateVerificationReport)> {
    let bundle: EnrollmentBundle = read_json_file(bundle_path)?;
    import_enrollment_bundle_value(layout, bundle, now)
}

fn import_enrollment_bundle_value(
    layout: &KeyStorageLayout,
    bundle: EnrollmentBundle,
    now: u64,
) -> QuantumLinkResult<(PathBuf, CertificateVerificationReport)> {
    layout.ensure_directories()?;
    let verification = bundle.verify(now)?;
    if !verification.valid_at_time {
        return Err(QuantumLinkError::Auth(
            "cannot import an expired or not-yet-valid enrollment bundle".to_owned(),
        ));
    }
    if verification.revoked {
        return Err(QuantumLinkError::Auth(
            "cannot import a revoked enrollment bundle".to_owned(),
        ));
    }

    write_json_file(&layout.ca_metadata_path(), &bundle.authority)?;
    write_json_file(&layout.ca_verifying_key_path(), &bundle.verifying_key)?;
    write_json_file(&layout.revocations_path(), &bundle.revocations)?;
    let certificate_path = layout.device_certificate_path(&bundle.device.certificate.serial);
    write_json_file(&certificate_path, &bundle.device)?;
    append_identity_audit_event(
        layout,
        IdentityAuditEvent {
            recorded_at: now,
            action: "import-enrollment".to_owned(),
            subject: bundle.device.certificate.serial.clone(),
            detail: Some(bundle.authority.name.clone()),
        },
    )?;

    Ok((
        certificate_path.clone(),
        CertificateVerificationReport {
            certificate_path,
            serial: verification.serial,
            device_name: verification.device_name,
            issuer_fingerprint: verification.issuer_fingerprint,
            valid_signature: verification.valid_signature,
            valid_at_time: verification.valid_at_time,
            revoked: verification.revoked,
            expires_at: verification.expires_at,
        },
    ))
}

fn pairing_signal_client(
    signal_url: &str,
    pairing_id: &str,
    role: PairingRole,
) -> QuantumLinkResult<SignalClient> {
    let identity = PairingMailboxIdentity::new(pairing_id.to_owned(), role)?;
    SignalClient::new(
        signal_url.to_owned(),
        SignalMailboxAuth::PairingId(identity.token()),
    )
}

fn load_certificate_authority(
    layout: &KeyStorageLayout,
) -> QuantumLinkResult<StoredCertificateAuthority> {
    let authority: CertificateAuthority = read_json_file(&layout.ca_metadata_path())?;
    let verifying_key: HybridVerifyingKey = read_json_file(&layout.ca_verifying_key_path())?;
    Ok(StoredCertificateAuthority {
        authority,
        verifying_key,
    })
}

fn load_ca_signing_key(layout: &KeyStorageLayout) -> QuantumLinkResult<HybridSigningKey> {
    let key_file: HybridSigningKeyFile = read_json_file(&layout.ca_signing_key_path())?;
    HybridSigningKey::import_secret(key_file)
}

fn load_revocations(layout: &KeyStorageLayout) -> QuantumLinkResult<RevocationList> {
    if layout.revocations_path().exists() {
        read_json_file(&layout.revocations_path())
    } else {
        Ok(RevocationList::default())
    }
}

fn append_identity_audit_event(
    layout: &KeyStorageLayout,
    event: IdentityAuditEvent,
) -> QuantumLinkResult<()> {
    layout.ensure_directories()?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(layout.audit_log_path())
        .map_err(QuantumLinkError::Io)?;
    let line = serde_json::to_string(&event).map_err(|error| {
        QuantumLinkError::Config(format!("failed to serialize audit event: {error}"))
    })?;
    writeln!(file, "{line}").map_err(QuantumLinkError::Io)
}

fn storage_layout(root_dir: Option<PathBuf>) -> KeyStorageLayout {
    root_dir
        .map(KeyStorageLayout::from_root)
        .unwrap_or_else(KeyStorageLayout::default_layout)
}

fn certificate_serial(issued_at: u64, wg_public_key: &[u8; 32]) -> String {
    format!(
        "cert-{issued_at}-{}",
        URL_SAFE_NO_PAD.encode(&wg_public_key[..6])
    )
}

fn certificate_signing_message(certificate: &DeviceCertificate) -> QuantumLinkResult<Vec<u8>> {
    serde_json::to_vec(certificate).map_err(|error| {
        QuantumLinkError::Config(format!("failed to serialize certificate: {error}"))
    })
}

fn encode_fingerprint(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn read_json_file<T>(path: &Path) -> QuantumLinkResult<T>
where
    T: DeserializeOwned,
{
    let contents = fs::read_to_string(path).map_err(QuantumLinkError::Io)?;
    serde_json::from_str(&contents).map_err(|error| {
        QuantumLinkError::Config(format!("failed to parse {}: {error}", path.display()))
    })
}

fn write_json_file<T>(path: &Path, value: &T) -> QuantumLinkResult<()>
where
    T: Serialize,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(QuantumLinkError::Io)?;
    }
    let json = serde_json::to_string_pretty(value).map_err(|error| {
        QuantumLinkError::Config(format!("failed to serialize {}: {error}", path.display()))
    })?;
    fs::write(path, json).map_err(QuantumLinkError::Io)
}

fn current_unix_timestamp() -> QuantumLinkResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| {
            QuantumLinkError::Config(format!("system clock before unix epoch: {error}"))
        })
}

fn load_config(path: Option<&Path>) -> QuantumLinkResult<QuantumLinkConfig> {
    match path {
        Some(path) => QuantumLinkConfig::from_file(path),
        None => QuantumLinkConfig::load_default(),
    }
}

fn print_json<T>(value: &T) -> QuantumLinkResult<()>
where
    T: Serialize,
{
    let json = serde_json::to_string_pretty(value).map_err(|error| {
        QuantumLinkError::Config(format!("failed to serialize output: {error}"))
    })?;
    println!("{json}");
    Ok(())
}

fn parse_cli<I>(args: I) -> Result<CliCommand, String>
where
    I: IntoIterator<Item = String>,
{
    let arguments = args.into_iter().skip(1).collect::<Vec<_>>();
    let Some(command) = arguments.first().map(String::as_str) else {
        return Err(usage().to_owned());
    };

    match command {
        "status" => parse_status_args(&arguments[1..]),
        "pair-code" => Ok(CliCommand::PairCode),
        "pair-mailbox-create" => parse_pair_mailbox_create_args(&arguments[1..]),
        "pair-send-enrollment" => parse_pair_send_enrollment_args(&arguments[1..]),
        "pair-recv-enrollment" => parse_pair_receive_enrollment_args(&arguments[1..]),
        "pair-initiate" => parse_pair_initiate_args(&arguments[1..]),
        "pair-accept" => parse_pair_accept_args(&arguments[1..]),
        "plan" => parse_runtime_command(&arguments[1..], true),
        "connect" => parse_runtime_command(&arguments[1..], false),
        "identity" => parse_identity_command(&arguments[1..]),
        _ => Err(usage().to_owned()),
    }
}

fn parse_status_args(arguments: &[String]) -> Result<CliCommand, String> {
    let mut config_path = None;
    let mut index = 0_usize;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--config" => {
                config_path = Some(PathBuf::from(next_value(
                    arguments, &mut index, "--config",
                )?));
            }
            other => return Err(format!("unknown status argument: {other}")),
        }
        index += 1;
    }
    Ok(CliCommand::Status { config_path })
}

fn parse_runtime_command(arguments: &[String], plan_only: bool) -> Result<CliCommand, String> {
    let mut config_path = None;
    let mut interface_name = "ql0".to_owned();
    let mut interface_addresses = Vec::new();
    let mut private_key = None;
    let mut peer_public_key = None;
    let mut peer_endpoint = None;
    let mut allowed_ips = Vec::new();
    let mut listen_port = 51_820_u16;
    let mut persistent_keepalive = Some(25_u16);
    let mut rosenpass_secret = None;
    let mut rosenpass_public = None;
    let mut rosenpass_peer_public = None;
    let mut dry_run = false;
    let mut shutdown_after = None;

    let mut index = 0_usize;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--config" => {
                config_path = Some(PathBuf::from(next_value(
                    arguments, &mut index, "--config",
                )?))
            }
            "--interface" => {
                interface_name = next_value(arguments, &mut index, "--interface")?.to_owned()
            }
            "--interface-address" => interface_addresses.push(
                next_value(arguments, &mut index, "--interface-address")?
                    .parse()
                    .map_err(|error| format!("invalid --interface-address CIDR: {error}"))?,
            ),
            "--private-key" => {
                private_key = Some(decode_key32(next_value(
                    arguments,
                    &mut index,
                    "--private-key",
                )?)?)
            }
            "--peer-public-key" => {
                peer_public_key = Some(decode_key32(next_value(
                    arguments,
                    &mut index,
                    "--peer-public-key",
                )?)?)
            }
            "--peer-endpoint" => {
                peer_endpoint = Some(
                    next_value(arguments, &mut index, "--peer-endpoint")?
                        .parse()
                        .map_err(|error| {
                            format!("invalid --peer-endpoint socket address: {error}")
                        })?,
                )
            }
            "--allowed-ip" => allowed_ips.push(
                next_value(arguments, &mut index, "--allowed-ip")?
                    .parse()
                    .map_err(|error| format!("invalid --allowed-ip CIDR: {error}"))?,
            ),
            "--listen-port" => {
                listen_port = next_value(arguments, &mut index, "--listen-port")?
                    .parse()
                    .map_err(|error| format!("invalid --listen-port value: {error}"))?
            }
            "--keepalive" => {
                persistent_keepalive = Some(
                    next_value(arguments, &mut index, "--keepalive")?
                        .parse()
                        .map_err(|error| format!("invalid --keepalive value: {error}"))?,
                )
            }
            "--no-keepalive" => persistent_keepalive = None,
            "--rp-secret-key" => {
                rosenpass_secret = Some(PathBuf::from(next_value(
                    arguments,
                    &mut index,
                    "--rp-secret-key",
                )?))
            }
            "--rp-public-key" => {
                rosenpass_public = Some(PathBuf::from(next_value(
                    arguments,
                    &mut index,
                    "--rp-public-key",
                )?))
            }
            "--rp-peer-public-key" => {
                rosenpass_peer_public = Some(PathBuf::from(next_value(
                    arguments,
                    &mut index,
                    "--rp-peer-public-key",
                )?))
            }
            "--dry-run" => dry_run = true,
            "--shutdown-after" => {
                let secs = next_value(arguments, &mut index, "--shutdown-after")?
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --shutdown-after value: {error}"))?;
                shutdown_after = Some(Duration::from_secs(secs));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        index += 1;
    }

    let private_key = private_key.ok_or_else(|| "missing required --private-key".to_owned())?;
    let peer_public_key =
        peer_public_key.ok_or_else(|| "missing required --peer-public-key".to_owned())?;
    let peer_endpoint =
        peer_endpoint.ok_or_else(|| "missing required --peer-endpoint".to_owned())?;
    if interface_addresses.is_empty() {
        return Err("missing required --interface-address".to_owned());
    }
    if allowed_ips.is_empty() {
        allowed_ips.push("0.0.0.0/0".parse().unwrap());
        allowed_ips.push("::/0".parse().unwrap());
    }

    let rosenpass_keys = match (rosenpass_secret, rosenpass_public, rosenpass_peer_public) {
        (Some(own_secret_key), Some(own_public_key), Some(peer_public_key)) => Some(RosenpassKeyPaths {
            own_secret_key,
            own_public_key,
            peer_public_key,
        }),
        (None, None, None) => None,
        _ => {
            return Err(
                "rosenpass configuration requires --rp-secret-key, --rp-public-key, and --rp-peer-public-key together"
                    .to_owned(),
            )
        }
    };

    let runtime = RuntimeArgs {
        config_path,
        interface_name,
        interface_addresses,
        private_key,
        peer_public_key,
        peer_endpoint,
        allowed_ips,
        listen_port,
        persistent_keepalive,
        rosenpass_keys,
        dry_run,
        shutdown_after,
    };

    Ok(if plan_only {
        CliCommand::Plan(runtime)
    } else {
        CliCommand::Connect(runtime)
    })
}

fn parse_identity_command(arguments: &[String]) -> Result<CliCommand, String> {
    let Some(subcommand) = arguments.first().map(String::as_str) else {
        return Err(
            "usage: qld identity <init-ca|issue|verify|renew|revoke|export-enrollment|import-enrollment> [options]"
                .to_owned(),
        );
    };

    let identity = match subcommand {
        "init-ca" => IdentityCommand::InitCa(parse_identity_init_ca_args(&arguments[1..])?),
        "issue" => IdentityCommand::Issue(parse_identity_issue_args(&arguments[1..])?),
        "verify" => IdentityCommand::Verify(parse_identity_verify_args(&arguments[1..])?),
        "renew" => IdentityCommand::Renew(parse_identity_renew_args(&arguments[1..])?),
        "revoke" => IdentityCommand::Revoke(parse_identity_revoke_args(&arguments[1..])?),
        "export-enrollment" => IdentityCommand::ExportEnrollment(
            parse_identity_export_enrollment_args(&arguments[1..])?,
        ),
        "import-enrollment" => IdentityCommand::ImportEnrollment(
            parse_identity_import_enrollment_args(&arguments[1..])?,
        ),
        other => return Err(format!("unknown identity subcommand: {other}")),
    };

    Ok(CliCommand::Identity(identity))
}

fn parse_identity_init_ca_args(arguments: &[String]) -> Result<IdentityInitCaArgs, String> {
    let mut root_dir = None;
    let mut name = None;
    let mut created_at = None;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--root" => {
                root_dir = Some(PathBuf::from(next_value(arguments, &mut index, "--root")?))
            }
            "--name" => name = Some(next_value(arguments, &mut index, "--name")?.to_owned()),
            "--created-at" => {
                created_at = Some(
                    next_value(arguments, &mut index, "--created-at")?
                        .parse()
                        .map_err(|error| format!("invalid --created-at value: {error}"))?,
                )
            }
            other => return Err(format!("unknown identity init-ca argument: {other}")),
        }
        index += 1;
    }

    Ok(IdentityInitCaArgs {
        root_dir,
        name: name.ok_or_else(|| "missing required --name".to_owned())?,
        created_at,
    })
}

fn parse_identity_issue_args(arguments: &[String]) -> Result<IdentityIssueArgs, String> {
    let mut root_dir = None;
    let mut device_name = None;
    let mut overlay_ip = None;
    let mut groups = Vec::new();
    let mut wg_public_key = None;
    let mut rosenpass_fingerprint = None;
    let mut valid_for = 86_400_u64;
    let mut valid_from = None;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--root" => {
                root_dir = Some(PathBuf::from(next_value(arguments, &mut index, "--root")?))
            }
            "--device-name" => {
                device_name = Some(next_value(arguments, &mut index, "--device-name")?.to_owned())
            }
            "--overlay-ip" => {
                overlay_ip = Some(
                    next_value(arguments, &mut index, "--overlay-ip")?
                        .parse()
                        .map_err(|error| format!("invalid --overlay-ip value: {error}"))?,
                )
            }
            "--group" => groups.push(next_value(arguments, &mut index, "--group")?.to_owned()),
            "--wg-public-key" => {
                wg_public_key = Some(decode_key32(next_value(
                    arguments,
                    &mut index,
                    "--wg-public-key",
                )?)?)
            }
            "--rp-fingerprint" => {
                rosenpass_fingerprint =
                    Some(next_value(arguments, &mut index, "--rp-fingerprint")?.to_owned())
            }
            "--valid-for" => {
                valid_for = next_value(arguments, &mut index, "--valid-for")?
                    .parse()
                    .map_err(|error| format!("invalid --valid-for value: {error}"))?
            }
            "--valid-from" => {
                valid_from = Some(
                    next_value(arguments, &mut index, "--valid-from")?
                        .parse()
                        .map_err(|error| format!("invalid --valid-from value: {error}"))?,
                )
            }
            other => return Err(format!("unknown identity issue argument: {other}")),
        }
        index += 1;
    }

    Ok(IdentityIssueArgs {
        root_dir,
        device_name: device_name.ok_or_else(|| "missing required --device-name".to_owned())?,
        overlay_ip: overlay_ip.ok_or_else(|| "missing required --overlay-ip".to_owned())?,
        groups,
        wg_public_key: wg_public_key
            .ok_or_else(|| "missing required --wg-public-key".to_owned())?,
        rosenpass_fingerprint: rosenpass_fingerprint
            .ok_or_else(|| "missing required --rp-fingerprint".to_owned())?,
        valid_for,
        valid_from,
    })
}

fn parse_identity_verify_args(arguments: &[String]) -> Result<IdentityVerifyArgs, String> {
    let mut root_dir = None;
    let mut certificate_path = None;
    let mut now = None;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--root" => {
                root_dir = Some(PathBuf::from(next_value(arguments, &mut index, "--root")?))
            }
            "--certificate" => {
                certificate_path = Some(PathBuf::from(next_value(
                    arguments,
                    &mut index,
                    "--certificate",
                )?))
            }
            "--now" => {
                now = Some(
                    next_value(arguments, &mut index, "--now")?
                        .parse()
                        .map_err(|error| format!("invalid --now value: {error}"))?,
                )
            }
            other => return Err(format!("unknown identity verify argument: {other}")),
        }
        index += 1;
    }

    Ok(IdentityVerifyArgs {
        root_dir,
        certificate_path: certificate_path
            .ok_or_else(|| "missing required --certificate".to_owned())?,
        now,
    })
}

fn parse_identity_renew_args(arguments: &[String]) -> Result<IdentityRenewArgs, String> {
    let mut root_dir = None;
    let mut certificate_path = None;
    let mut valid_for = 86_400_u64;
    let mut valid_from = None;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--root" => {
                root_dir = Some(PathBuf::from(next_value(arguments, &mut index, "--root")?))
            }
            "--certificate" => {
                certificate_path = Some(PathBuf::from(next_value(
                    arguments,
                    &mut index,
                    "--certificate",
                )?))
            }
            "--valid-for" => {
                valid_for = next_value(arguments, &mut index, "--valid-for")?
                    .parse()
                    .map_err(|error| format!("invalid --valid-for value: {error}"))?
            }
            "--valid-from" => {
                valid_from = Some(
                    next_value(arguments, &mut index, "--valid-from")?
                        .parse()
                        .map_err(|error| format!("invalid --valid-from value: {error}"))?,
                )
            }
            other => return Err(format!("unknown identity renew argument: {other}")),
        }
        index += 1;
    }

    Ok(IdentityRenewArgs {
        root_dir,
        certificate_path: certificate_path
            .ok_or_else(|| "missing required --certificate".to_owned())?,
        valid_for,
        valid_from,
    })
}

fn parse_identity_revoke_args(arguments: &[String]) -> Result<IdentityRevokeArgs, String> {
    let mut root_dir = None;
    let mut serial = None;
    let mut reason = None;
    let mut revoked_at = None;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--root" => {
                root_dir = Some(PathBuf::from(next_value(arguments, &mut index, "--root")?))
            }
            "--serial" => serial = Some(next_value(arguments, &mut index, "--serial")?.to_owned()),
            "--reason" => reason = Some(next_value(arguments, &mut index, "--reason")?.to_owned()),
            "--revoked-at" => {
                revoked_at = Some(
                    next_value(arguments, &mut index, "--revoked-at")?
                        .parse()
                        .map_err(|error| format!("invalid --revoked-at value: {error}"))?,
                )
            }
            other => return Err(format!("unknown identity revoke argument: {other}")),
        }
        index += 1;
    }

    Ok(IdentityRevokeArgs {
        root_dir,
        serial: serial.ok_or_else(|| "missing required --serial".to_owned())?,
        reason: reason.ok_or_else(|| "missing required --reason".to_owned())?,
        revoked_at,
    })
}

fn parse_identity_export_enrollment_args(
    arguments: &[String],
) -> Result<IdentityExportEnrollmentArgs, String> {
    let mut root_dir = None;
    let mut certificate_path = None;
    let mut exported_at = None;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--root" => {
                root_dir = Some(PathBuf::from(next_value(arguments, &mut index, "--root")?))
            }
            "--certificate" => {
                certificate_path = Some(PathBuf::from(next_value(
                    arguments,
                    &mut index,
                    "--certificate",
                )?))
            }
            "--exported-at" => {
                exported_at = Some(
                    next_value(arguments, &mut index, "--exported-at")?
                        .parse()
                        .map_err(|error| format!("invalid --exported-at value: {error}"))?,
                )
            }
            other => {
                return Err(format!(
                    "unknown identity export-enrollment argument: {other}"
                ))
            }
        }
        index += 1;
    }

    Ok(IdentityExportEnrollmentArgs {
        root_dir,
        certificate_path: certificate_path
            .ok_or_else(|| "missing required --certificate".to_owned())?,
        exported_at,
    })
}

fn parse_identity_import_enrollment_args(
    arguments: &[String],
) -> Result<IdentityImportEnrollmentArgs, String> {
    let mut root_dir = None;
    let mut bundle_path = None;
    let mut now = None;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--root" => {
                root_dir = Some(PathBuf::from(next_value(arguments, &mut index, "--root")?))
            }
            "--bundle" => {
                bundle_path = Some(PathBuf::from(next_value(
                    arguments, &mut index, "--bundle",
                )?))
            }
            "--now" => {
                now = Some(
                    next_value(arguments, &mut index, "--now")?
                        .parse()
                        .map_err(|error| format!("invalid --now value: {error}"))?,
                )
            }
            other => {
                return Err(format!(
                    "unknown identity import-enrollment argument: {other}"
                ))
            }
        }
        index += 1;
    }

    Ok(IdentityImportEnrollmentArgs {
        root_dir,
        bundle_path: bundle_path.ok_or_else(|| "missing required --bundle".to_owned())?,
        now,
    })
}

fn parse_pair_mailbox_create_args(arguments: &[String]) -> Result<CliCommand, String> {
    let mut signal_url = None;
    let mut pairing_id = None;
    let mut role = PairingRole::Initiator;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--signal-url" => {
                signal_url = Some(next_value(arguments, &mut index, "--signal-url")?.to_owned())
            }
            "--pairing-id" => {
                pairing_id = Some(next_value(arguments, &mut index, "--pairing-id")?.to_owned())
            }
            "--role" => {
                role = PairingRole::parse(next_value(arguments, &mut index, "--role")?)
                    .map_err(|error| error.to_string())?
            }
            other => return Err(format!("unknown pair-mailbox-create argument: {other}")),
        }
        index += 1;
    }

    Ok(CliCommand::PairMailboxCreate(PairMailboxCreateArgs {
        signal_url: signal_url.ok_or_else(|| "missing required --signal-url".to_owned())?,
        pairing_id: pairing_id.ok_or_else(|| "missing required --pairing-id".to_owned())?,
        role,
    }))
}

fn parse_pair_send_enrollment_args(arguments: &[String]) -> Result<CliCommand, String> {
    let mut root_dir = None;
    let mut signal_url = None;
    let mut pairing_id = None;
    let mut role = PairingRole::Initiator;
    let mut mailbox_id = None;
    let mut certificate_path = None;
    let mut exported_at = None;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--root" => {
                root_dir = Some(PathBuf::from(next_value(arguments, &mut index, "--root")?))
            }
            "--signal-url" => {
                signal_url = Some(next_value(arguments, &mut index, "--signal-url")?.to_owned())
            }
            "--pairing-id" => {
                pairing_id = Some(next_value(arguments, &mut index, "--pairing-id")?.to_owned())
            }
            "--role" => {
                role = PairingRole::parse(next_value(arguments, &mut index, "--role")?)
                    .map_err(|error| error.to_string())?
            }
            "--mailbox" => {
                mailbox_id = Some(
                    next_value(arguments, &mut index, "--mailbox")?
                        .parse()
                        .map_err(|error| format!("invalid --mailbox UUID: {error}"))?,
                )
            }
            "--certificate" => {
                certificate_path = Some(PathBuf::from(next_value(
                    arguments,
                    &mut index,
                    "--certificate",
                )?))
            }
            "--exported-at" => {
                exported_at = Some(
                    next_value(arguments, &mut index, "--exported-at")?
                        .parse()
                        .map_err(|error| format!("invalid --exported-at value: {error}"))?,
                )
            }
            other => return Err(format!("unknown pair-send-enrollment argument: {other}")),
        }
        index += 1;
    }

    Ok(CliCommand::PairSendEnrollment(PairSendEnrollmentArgs {
        root_dir,
        signal_url: signal_url.ok_or_else(|| "missing required --signal-url".to_owned())?,
        pairing_id: pairing_id.ok_or_else(|| "missing required --pairing-id".to_owned())?,
        role,
        mailbox_id: mailbox_id.ok_or_else(|| "missing required --mailbox".to_owned())?,
        certificate_path: certificate_path
            .ok_or_else(|| "missing required --certificate".to_owned())?,
        exported_at,
    }))
}

fn parse_pair_receive_enrollment_args(arguments: &[String]) -> Result<CliCommand, String> {
    let mut root_dir = None;
    let mut signal_url = None;
    let mut pairing_id = None;
    let mut role = PairingRole::Responder;
    let mut mailbox_id = None;
    let mut now = None;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--root" => {
                root_dir = Some(PathBuf::from(next_value(arguments, &mut index, "--root")?))
            }
            "--signal-url" => {
                signal_url = Some(next_value(arguments, &mut index, "--signal-url")?.to_owned())
            }
            "--pairing-id" => {
                pairing_id = Some(next_value(arguments, &mut index, "--pairing-id")?.to_owned())
            }
            "--role" => {
                role = PairingRole::parse(next_value(arguments, &mut index, "--role")?)
                    .map_err(|error| error.to_string())?
            }
            "--mailbox" => {
                mailbox_id = Some(
                    next_value(arguments, &mut index, "--mailbox")?
                        .parse()
                        .map_err(|error| format!("invalid --mailbox UUID: {error}"))?,
                )
            }
            "--now" => {
                now = Some(
                    next_value(arguments, &mut index, "--now")?
                        .parse()
                        .map_err(|error| format!("invalid --now value: {error}"))?,
                )
            }
            other => return Err(format!("unknown pair-recv-enrollment argument: {other}")),
        }
        index += 1;
    }

    Ok(CliCommand::PairReceiveEnrollment(
        PairReceiveEnrollmentArgs {
            root_dir,
            signal_url: signal_url.ok_or_else(|| "missing required --signal-url".to_owned())?,
            pairing_id: pairing_id.ok_or_else(|| "missing required --pairing-id".to_owned())?,
            role,
            mailbox_id: mailbox_id.ok_or_else(|| "missing required --mailbox".to_owned())?,
            now,
        },
    ))
}

fn parse_pair_initiate_args(arguments: &[String]) -> Result<CliCommand, String> {
    let mut root_dir = None;
    let mut signal_url = None;
    let mut pairing_id = None;
    let mut code = None;
    let mut certificate_path = None;
    let mut exported_at = None;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--root" => {
                root_dir = Some(PathBuf::from(next_value(arguments, &mut index, "--root")?))
            }
            "--signal-url" => {
                signal_url = Some(next_value(arguments, &mut index, "--signal-url")?.to_owned())
            }
            "--pairing-id" => {
                pairing_id = Some(next_value(arguments, &mut index, "--pairing-id")?.to_owned())
            }
            "--code" => code = Some(next_value(arguments, &mut index, "--code")?.to_owned()),
            "--certificate" => {
                certificate_path = Some(PathBuf::from(next_value(
                    arguments,
                    &mut index,
                    "--certificate",
                )?))
            }
            "--exported-at" => {
                exported_at = Some(
                    next_value(arguments, &mut index, "--exported-at")?
                        .parse()
                        .map_err(|error| format!("invalid --exported-at value: {error}"))?,
                )
            }
            other => return Err(format!("unknown pair-initiate argument: {other}")),
        }
        index += 1;
    }

    Ok(CliCommand::PairInitiate(PairInitiateArgs {
        root_dir,
        signal_url: signal_url.ok_or_else(|| "missing required --signal-url".to_owned())?,
        pairing_id: pairing_id.ok_or_else(|| "missing required --pairing-id".to_owned())?,
        code: code.ok_or_else(|| "missing required --code".to_owned())?,
        certificate_path: certificate_path
            .ok_or_else(|| "missing required --certificate".to_owned())?,
        exported_at,
    }))
}

fn parse_pair_accept_args(arguments: &[String]) -> Result<CliCommand, String> {
    let mut root_dir = None;
    let mut signal_url = None;
    let mut pairing_id = None;
    let mut code = None;
    let mut mailbox_id = None;
    let mut now = None;
    let mut index = 0_usize;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--root" => {
                root_dir = Some(PathBuf::from(next_value(arguments, &mut index, "--root")?))
            }
            "--signal-url" => {
                signal_url = Some(next_value(arguments, &mut index, "--signal-url")?.to_owned())
            }
            "--pairing-id" => {
                pairing_id = Some(next_value(arguments, &mut index, "--pairing-id")?.to_owned())
            }
            "--code" => code = Some(next_value(arguments, &mut index, "--code")?.to_owned()),
            "--mailbox" => {
                mailbox_id = Some(
                    next_value(arguments, &mut index, "--mailbox")?
                        .parse()
                        .map_err(|error| format!("invalid --mailbox UUID: {error}"))?,
                )
            }
            "--now" => {
                now = Some(
                    next_value(arguments, &mut index, "--now")?
                        .parse()
                        .map_err(|error| format!("invalid --now value: {error}"))?,
                )
            }
            other => return Err(format!("unknown pair-accept argument: {other}")),
        }
        index += 1;
    }

    Ok(CliCommand::PairAccept(PairAcceptArgs {
        root_dir,
        signal_url: signal_url.ok_or_else(|| "missing required --signal-url".to_owned())?,
        pairing_id: pairing_id.ok_or_else(|| "missing required --pairing-id".to_owned())?,
        code: code.ok_or_else(|| "missing required --code".to_owned())?,
        mailbox_id: mailbox_id.ok_or_else(|| "missing required --mailbox".to_owned())?,
        now,
    }))
}

fn next_value<'a>(
    arguments: &'a [String],
    index: &mut usize,
    flag: &str,
) -> Result<&'a str, String> {
    *index += 1;
    arguments
        .get(*index)
        .map(String::as_str)
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn decode_key32(encoded: &str) -> Result<[u8; 32], String> {
    let bytes = STANDARD
        .decode(encoded.as_bytes())
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded.as_bytes()))
        .map_err(|error| format!("invalid base64 key: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| "keys must decode to exactly 32 bytes".to_owned())
}

fn usage() -> &'static str {
    "usage: qld <status|pair-code|pair-mailbox-create|pair-send-enrollment|pair-recv-enrollment|pair-initiate|pair-accept|plan|connect|identity> [options]"
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::path::PathBuf;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use ql_core::{
        CertificateRequest, CryptoConfig, MeshSettings, NetworkConfig, QuantumLinkConfig,
        RelayPolicy, ServerConfig, SplitTunnelConfig, TunnelState,
    };
    use ql_pair::PairingRole;
    use ql_signal::{SignalClient, SignalConfig, SignalMailboxAuth, SignalServer};

    use super::{
        accept_pairing_enrollment, decode_key32, export_enrollment_bundle,
        import_enrollment_bundle, initialize_certificate_authority,
        initiate_pairing_enrollment_on_mailbox, issue_certificate, parse_cli,
        receive_enrollment_via_mailbox, revoke_certificate, send_enrollment_via_mailbox,
        storage_layout, verify_certificate, CliCommand, ClientDaemon, IdentityCommand, RuntimeArgs,
    };

    fn sample_runtime_args() -> RuntimeArgs {
        RuntimeArgs {
            config_path: None,
            interface_name: "ql0".to_owned(),
            interface_addresses: vec!["10.0.0.2/32".parse().unwrap()],
            private_key: [1_u8; 32],
            peer_public_key: [2_u8; 32],
            peer_endpoint: "198.51.100.8:51820".parse().unwrap(),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            listen_port: 51820,
            persistent_keepalive: Some(25),
            rosenpass_keys: None,
            dry_run: true,
            shutdown_after: None,
        }
    }

    fn sample_config() -> QuantumLinkConfig {
        QuantumLinkConfig {
            server: ServerConfig {
                endpoint: "vpn.example.com:51820".to_owned(),
                rosenpass_port: 9999,
            },
            crypto: CryptoConfig::default(),
            network: NetworkConfig {
                kill_switch: true,
                dns_leak_protection: true,
                mtu: 1420,
                dns_servers: vec![IpAddr::from([10, 0, 0, 1])],
            },
            split_tunnel: SplitTunnelConfig::default(),
            mesh: MeshSettings {
                enabled: true,
                relay_policy: RelayPolicy::SelfHosted,
            },
        }
    }

    fn unique_test_root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "quantumlink-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn decodes_32_byte_keys() {
        let encoded = STANDARD.encode([9_u8; 32]);
        assert_eq!(decode_key32(&encoded).unwrap(), [9_u8; 32]);
    }

    #[test]
    fn parses_plan_command() {
        let private_key = STANDARD.encode([1_u8; 32]);
        let peer_key = STANDARD.encode([2_u8; 32]);
        let command = parse_cli(vec![
            "qld".to_owned(),
            "plan".to_owned(),
            "--private-key".to_owned(),
            private_key,
            "--peer-public-key".to_owned(),
            peer_key,
            "--interface-address".to_owned(),
            "10.0.0.2/32".to_owned(),
            "--peer-endpoint".to_owned(),
            "198.51.100.8:51820".to_owned(),
        ])
        .unwrap();

        assert!(matches!(command, CliCommand::Plan(_)));
    }

    #[test]
    fn parses_identity_init_ca_command() {
        let command = parse_cli(vec![
            "qld".to_owned(),
            "identity".to_owned(),
            "init-ca".to_owned(),
            "--name".to_owned(),
            "Home Mesh".to_owned(),
        ])
        .unwrap();

        assert!(matches!(
            command,
            CliCommand::Identity(IdentityCommand::InitCa(_))
        ));
    }

    #[test]
    fn parses_pair_mailbox_create_command() {
        let command = parse_cli(vec![
            "qld".to_owned(),
            "pair-mailbox-create".to_owned(),
            "--signal-url".to_owned(),
            "http://127.0.0.1:8443".to_owned(),
            "--pairing-id".to_owned(),
            "session-42".to_owned(),
            "--role".to_owned(),
            "initiator".to_owned(),
        ])
        .unwrap();

        assert!(matches!(command, CliCommand::PairMailboxCreate(_)));
    }

    #[test]
    fn parses_pair_initiate_command() {
        let command = parse_cli(vec![
            "qld".to_owned(),
            "pair-initiate".to_owned(),
            "--signal-url".to_owned(),
            "http://127.0.0.1:8443".to_owned(),
            "--pairing-id".to_owned(),
            "session-42".to_owned(),
            "--code".to_owned(),
            "42-garden-nebula".to_owned(),
            "--certificate".to_owned(),
            "/tmp/cert.json".to_owned(),
        ])
        .unwrap();

        assert!(matches!(command, CliCommand::PairInitiate(_)));
    }

    #[test]
    fn daemon_plan_reflects_config_and_runtime() {
        let daemon = ClientDaemon::new(sample_config(), sample_runtime_args());
        let plan = daemon.plan();

        assert_eq!(plan.interface_name, "ql0");
        assert_eq!(plan.interface_addresses, vec!["10.0.0.2/32".to_owned()]);
        assert_eq!(plan.peer_endpoint, "198.51.100.8:51820".parse().unwrap());
        assert_eq!(plan.allowed_ips, vec!["0.0.0.0/0".to_owned()]);
        assert!(plan.kill_switch);
        assert!(plan.mesh_enabled);
    }

    #[test]
    fn status_snapshot_starts_disconnected() {
        let daemon = ClientDaemon::new(sample_config(), sample_runtime_args());
        assert_eq!(daemon.status_snapshot().state, TunnelState::Disconnected);
    }

    #[test]
    fn identity_lifecycle_roundtrip() {
        let root = unique_test_root("identity-lifecycle");
        let layout = storage_layout(Some(root.clone()));

        let ca = initialize_certificate_authority(&layout, "Home Mesh", 1_700_000_000).unwrap();
        assert_eq!(ca.authority.name, "Home Mesh");

        let request = CertificateRequest {
            device_name: "Laptop".to_owned(),
            overlay_ip: "10.42.0.20".parse().unwrap(),
            groups: vec!["personal".to_owned()],
            wg_public_key: [7_u8; 32],
            rosenpass_fingerprint: "rp-fingerprint".to_owned(),
            requested_at: 1_700_000_100,
        };
        let (path, bundle) = issue_certificate(&layout, request, 1_700_000_100, 86_400).unwrap();
        assert_eq!(bundle.certificate.device_name, "Laptop");

        let verified = verify_certificate(&layout, &path, 1_700_000_200).unwrap();
        assert!(verified.valid_signature);
        assert!(verified.valid_at_time);
        assert!(!verified.revoked);

        let revoked = revoke_certificate(
            &layout,
            &bundle.certificate.serial,
            "lost device",
            1_700_000_300,
        )
        .unwrap();
        assert!(revoked.revocations.is_revoked(&bundle.certificate.serial));

        let verified_after_revoke = verify_certificate(&layout, &path, 1_700_000_400).unwrap();
        assert!(verified_after_revoke.revoked);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn enrollment_bundle_exports_and_imports() {
        let authority_root = unique_test_root("enrollment-authority");
        let authority_layout = storage_layout(Some(authority_root.clone()));
        initialize_certificate_authority(&authority_layout, "Home Mesh", 1_700_000_000).unwrap();

        let request = CertificateRequest {
            device_name: "Travel Laptop".to_owned(),
            overlay_ip: "10.42.0.21".parse().unwrap(),
            groups: vec!["travel".to_owned()],
            wg_public_key: [8_u8; 32],
            rosenpass_fingerprint: "rp-travel".to_owned(),
            requested_at: 1_700_000_100,
        };
        let (certificate_path, _) =
            issue_certificate(&authority_layout, request, 1_700_000_100, 86_400).unwrap();

        let (bundle_path, _) =
            export_enrollment_bundle(&authority_layout, &certificate_path, 1_700_000_200).unwrap();

        let device_root = unique_test_root("enrollment-device");
        let device_layout = storage_layout(Some(device_root.clone()));
        let (imported_certificate_path, verification) =
            import_enrollment_bundle(&device_layout, &bundle_path, 1_700_000_300).unwrap();

        assert!(verification.valid_signature);
        assert!(verification.valid_at_time);
        assert_eq!(verification.device_name, "Travel Laptop");
        assert!(imported_certificate_path.exists());
        assert!(device_layout.ca_metadata_path().exists());
        assert!(device_layout.ca_verifying_key_path().exists());

        std::fs::remove_dir_all(authority_root).unwrap();
        std::fs::remove_dir_all(device_root).unwrap();
    }

    #[tokio::test]
    async fn enrollment_bundle_roundtrips_over_signal_mailbox() {
        let server = SignalServer::start(SignalConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..SignalConfig::default()
        })
        .await
        .unwrap();
        let signal_url = format!("http://{}", server.local_addr());
        let mailbox = SignalClient::new(
            signal_url.clone(),
            SignalMailboxAuth::PairingId("session-99:initiator".to_owned()),
        )
        .unwrap()
        .create_mailbox()
        .await
        .unwrap();

        let authority_root = unique_test_root("mailbox-enrollment-authority");
        let authority_layout = storage_layout(Some(authority_root.clone()));
        initialize_certificate_authority(&authority_layout, "Home Mesh", 1_700_000_000).unwrap();

        let request = CertificateRequest {
            device_name: "Field Laptop".to_owned(),
            overlay_ip: "10.42.0.22".parse().unwrap(),
            groups: vec!["ops".to_owned()],
            wg_public_key: [9_u8; 32],
            rosenpass_fingerprint: "rp-ops".to_owned(),
            requested_at: 1_700_000_100,
        };
        let (certificate_path, _) =
            issue_certificate(&authority_layout, request, 1_700_000_100, 86_400).unwrap();

        let sent = send_enrollment_via_mailbox(
            &authority_layout,
            &signal_url,
            "session-99",
            PairingRole::Initiator,
            mailbox.mailbox_id,
            &certificate_path,
            1_700_000_200,
        )
        .await
        .unwrap();
        assert!(sent.serial.starts_with("cert-"));

        let device_root = unique_test_root("mailbox-enrollment-device");
        let device_layout = storage_layout(Some(device_root.clone()));
        let received = receive_enrollment_via_mailbox(
            &device_layout,
            &signal_url,
            "session-99",
            PairingRole::Responder,
            mailbox.mailbox_id,
            1_700_000_300,
        )
        .await
        .unwrap();

        assert!(received.verification.valid_signature);
        assert!(received.verification.valid_at_time);
        assert_eq!(received.verification.device_name, "Field Laptop");
        assert!(received.certificate_path.exists());

        std::fs::remove_dir_all(authority_root).unwrap();
        std::fs::remove_dir_all(device_root).unwrap();
        server.stop().await.unwrap();
    }

    #[tokio::test]
    async fn high_level_pairing_flow_roundtrips_enrollment() {
        let server = SignalServer::start(SignalConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..SignalConfig::default()
        })
        .await
        .unwrap();
        let signal_url = format!("http://{}", server.local_addr());
        let mailbox = SignalClient::new(
            signal_url.clone(),
            SignalMailboxAuth::PairingId("session-123:initiator".to_owned()),
        )
        .unwrap()
        .create_mailbox()
        .await
        .unwrap();

        let authority_root = unique_test_root("high-level-pair-authority");
        let authority_layout = storage_layout(Some(authority_root.clone()));
        initialize_certificate_authority(&authority_layout, "Home Mesh", 1_700_000_000).unwrap();
        let request = CertificateRequest {
            device_name: "Office Laptop".to_owned(),
            overlay_ip: "10.42.0.23".parse().unwrap(),
            groups: vec!["office".to_owned()],
            wg_public_key: [10_u8; 32],
            rosenpass_fingerprint: "rp-office".to_owned(),
            requested_at: 1_700_000_100,
        };
        let (certificate_path, _) =
            issue_certificate(&authority_layout, request, 1_700_000_100, 86_400).unwrap();

        let device_root = unique_test_root("high-level-pair-device");
        let device_layout = storage_layout(Some(device_root.clone()));

        let initiator = initiate_pairing_enrollment_on_mailbox(
            &authority_layout,
            &signal_url,
            "session-123",
            "42-garden-nebula",
            mailbox.mailbox_id,
            &certificate_path,
            1_700_000_200,
        );
        let acceptor = accept_pairing_enrollment(
            &device_layout,
            &signal_url,
            "session-123",
            "42-garden-nebula",
            mailbox.mailbox_id,
            1_700_000_300,
        );

        let (initiate, accept) = tokio::join!(initiator, acceptor);
        let initiate = initiate.unwrap();
        let accept = accept.unwrap();
        assert_eq!(initiate.mailbox_id, mailbox.mailbox_id);
        assert_eq!(initiate.verification_words, accept.verification_words);
        assert!(accept.verification.valid_signature);
        assert!(accept.verification.valid_at_time);
        assert_eq!(accept.verification.device_name, "Office Laptop");

        std::fs::remove_dir_all(authority_root).unwrap();
        std::fs::remove_dir_all(device_root).unwrap();
        server.stop().await.unwrap();
    }
}
