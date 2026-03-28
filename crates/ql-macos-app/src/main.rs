//! Minimal macOS app-shell bootstrap for QuantumLink.

#![forbid(unsafe_code)]

use std::env;
use std::net::SocketAddr;
#[cfg(target_os = "macos")]
use std::net::{IpAddr, Ipv4Addr};
use std::process;

use axum::{
    body::Body,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
#[cfg(target_os = "macos")]
use ipnetwork::IpNetwork;
use ql_core::TunnelState;
#[cfg(target_os = "macos")]
use ql_firewall::{MacOsFirewallBridgeExecutor, PlatformFirewall};
use ql_gui::TrayStatus;
use ql_macos_app::MacOsAppShell;
#[cfg(target_os = "macos")]
use ql_macos_app::{MacOsHostFirewallPolicy, MacOsHostOperation};
use ql_macos_runtime::{MacOsAdapterMode, MacOsRuntimeAdapterConfig};
use ql_wireguard::DEFAULT_MACOS_TUNNEL_PROVIDER_BUNDLE_IDENTIFIER;
#[cfg(target_os = "macos")]
use ql_wireguard::{PlatformTunnel, TunnelConfig, TunnelStats};
#[cfg(target_os = "macos")]
use serde::Deserialize;
use serde::Serialize;
use tokio::net::TcpListener;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return Ok(());
    };

    let adapter_config = adapter_config_from_env()?;

    match command.as_str() {
        "serve" => {
            let port = args
                .next()
                .map(|raw| raw.parse::<u16>())
                .transpose()
                .map_err(|error| format!("invalid service port: {error}"))?;
            run_service(adapter_config, port)
        }
        "status" => {
            let mut shell = MacOsAppShell::new(adapter_config);
            shell.request_status_refresh();
            println!("adapter_mode={:?}", shell.adapter().mode());
            println!("pending_command={:?}", shell.take_pending_command());
            println!("gui_state={:#?}", shell.gui());
            Ok(())
        }
        "status-json" => run_status_json(MacOsAppShell::new(adapter_config)),
        "connect" => {
            let mut shell = MacOsAppShell::new(adapter_config);
            let server = args
                .next()
                .map(|raw| raw.parse())
                .transpose()
                .map_err(|error| format!("invalid server socket address: {error}"))?;
            shell.request_connect(server);
            println!("adapter_mode={:?}", shell.adapter().mode());
            println!("pending_command={:?}", shell.take_pending_command());
            Ok(())
        }
        "disconnect" => {
            let mut shell = MacOsAppShell::new(adapter_config);
            shell.request_disconnect();
            println!("adapter_mode={:?}", shell.adapter().mode());
            println!("pending_command={:?}", shell.take_pending_command());
            Ok(())
        }
        #[cfg(target_os = "macos")]
        "mode-a-connect" | "mode-a-demo-connect" => {
            run_mode_a_connect(MacOsAppShell::new(adapter_config))
        }
        #[cfg(target_os = "macos")]
        "mode-a-connect-json" | "mode-a-demo-connect-json" => {
            let server = args
                .next()
                .map(|raw| raw.parse())
                .transpose()
                .map_err(|error| format!("invalid server socket address: {error}"))?;
            run_mode_a_connect_json(MacOsAppShell::new(adapter_config), server)
        }
        #[cfg(target_os = "macos")]
        "mode-a-disconnect" | "mode-a-demo-disconnect" => {
            run_mode_a_disconnect(MacOsAppShell::new(adapter_config))
        }
        #[cfg(target_os = "macos")]
        "mode-a-disconnect-json" | "mode-a-demo-disconnect-json" => {
            run_mode_a_disconnect_json(MacOsAppShell::new(adapter_config))
        }
        _ => {
            print_usage();
            Err(format!("unknown command: {command}"))
        }
    }
}

fn run_status_json(mut shell: MacOsAppShell) -> Result<(), String> {
    let response = build_status_response(&mut shell)?;
    print_json(&response)
}

fn build_status_response(shell: &mut MacOsAppShell) -> Result<StatusResponse, String> {
    shell.request_status_refresh();
    let pending_command = shell
        .take_pending_command()
        .map(|command| format!("{command:?}"));
    let mut connection_state = tunnel_state_label(&shell.gui().connection.state);
    let mut connection_headline = shell.gui().connection.headline.clone();
    let mut connection_detail = shell.gui().connection.detail.clone();
    let mut tray_status = tray_status_label(&shell.gui().tray);
    #[cfg(target_os = "macos")]
    let session = {
        let session = mode_a_session_status(shell.adapter())?;
        if session.tunnel_active {
            connection_state = "connected";
            connection_headline = "Connected".to_owned();
            connection_detail =
                connected_detail_label(shell.adapter().mode(), session.firewall_active).to_owned();
            tray_status = connected_tray_status(shell.adapter().mode(), session.firewall_active);
        }
        session
    };
    Ok(StatusResponse {
        adapter_mode: adapter_mode_label(shell.adapter().mode()),
        pending_command,
        connection_state,
        connection_headline,
        connection_detail,
        tray_status,
        #[cfg(target_os = "macos")]
        session,
    })
}

#[cfg(target_os = "macos")]
fn run_mode_a_connect(shell: MacOsAppShell) -> Result<(), String> {
    let tunnel = sample_tunnel(None)?;
    let firewall = PlatformFirewall::new("ql0");
    let operations = shell
        .plan_connect_operations(
            &tunnel,
            &firewall,
            MacOsHostFirewallPolicy::KillSwitch {
                dns_server: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            },
        )
        .map_err(|error| error.to_string())?;

    println!("adapter_mode={:?}", shell.adapter().mode());
    for operation in operations {
        println!("planned_operation={operation:?}");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_mode_a_connect_json(
    shell: MacOsAppShell,
    server: Option<std::net::SocketAddr>,
) -> Result<(), String> {
    let response = build_connect_operations_response(shell, server)?;
    print_json(&response)
}

#[cfg(target_os = "macos")]
fn build_connect_operations_response(
    shell: MacOsAppShell,
    server: Option<std::net::SocketAddr>,
) -> Result<OperationsResponse, String> {
    let tunnel = sample_tunnel(server)?;
    let firewall = PlatformFirewall::new("ql0");
    let firewall_policy = default_firewall_policy(&shell);
    let operations = shell
        .plan_connect_operations(&tunnel, &firewall, firewall_policy)
        .map_err(|error| error.to_string())?;

    Ok(OperationsResponse {
        adapter_mode: adapter_mode_label(shell.adapter().mode()),
        operations: operations.into_iter().map(host_operation_json).collect(),
    })
}

#[cfg(target_os = "macos")]
fn run_mode_a_disconnect(shell: MacOsAppShell) -> Result<(), String> {
    let tunnel = sample_tunnel(None)?;
    let firewall = PlatformFirewall::new("ql0");
    let operations = shell
        .plan_disconnect_operations(&tunnel, &firewall)
        .map_err(|error| error.to_string())?;

    println!("adapter_mode={:?}", shell.adapter().mode());
    for operation in operations {
        println!("planned_operation={operation:?}");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_mode_a_disconnect_json(shell: MacOsAppShell) -> Result<(), String> {
    let response = build_disconnect_operations_response(shell)?;
    print_json(&response)
}

#[cfg(target_os = "macos")]
fn build_disconnect_operations_response(
    shell: MacOsAppShell,
) -> Result<OperationsResponse, String> {
    let tunnel = sample_tunnel(None)?;
    let firewall = PlatformFirewall::new("ql0");
    let operations = if shell.adapter().has_firewall_bridge() {
        shell
            .plan_disconnect_operations(&tunnel, &firewall)
            .map_err(|error| error.to_string())?
    } else {
        vec![MacOsHostOperation::Tunnel(
            shell
                .adapter()
                .execute_tunnel_operation("deactivate", &tunnel.macos_bridge_request())
                .map_err(|error| error.to_string())?,
        )]
    };

    Ok(OperationsResponse {
        adapter_mode: adapter_mode_label(shell.adapter().mode()),
        operations: operations.into_iter().map(host_operation_json).collect(),
    })
}

fn run_service(adapter_config: MacOsRuntimeAdapterConfig, port: Option<u16>) -> Result<(), String> {
    let port = port
        .or_else(|| {
            env::var("QL_MACOS_APP_SERVICE_PORT")
                .ok()
                .and_then(|raw| raw.parse().ok())
        })
        .unwrap_or(58_421);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(async move {
        let bind_addr = SocketAddr::from(([127, 0, 0, 1], port));
        let app = build_service_router(ServiceState { adapter_config });
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|error| error.to_string())?;
        axum::serve(listener, app)
            .await
            .map_err(|error| error.to_string())
    })
}

#[derive(Clone)]
struct ServiceState {
    adapter_config: MacOsRuntimeAdapterConfig,
}

fn build_service_router(state: ServiceState) -> Router {
    Router::new()
        .route("/health", get(service_health))
        .route("/status", get(service_status))
        .route("/mode-a/connect", post(service_mode_a_connect))
        .route("/mode-a/disconnect", post(service_mode_a_disconnect))
        .with_state(state)
}

struct ServiceError {
    status: StatusCode,
    message: String,
}

impl ServiceError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn not_implemented(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_IMPLEMENTED,
            message: message.into(),
        }
    }
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response<Body> {
        (self.status, self.message).into_response()
    }
}

#[derive(Serialize)]
struct ServiceHealthResponse {
    status: &'static str,
}

#[derive(Deserialize)]
struct ModeAConnectParams {
    server: Option<String>,
}

async fn service_health() -> Json<ServiceHealthResponse> {
    Json(ServiceHealthResponse { status: "ok" })
}

async fn service_status(
    State(state): State<ServiceState>,
) -> Result<Json<StatusResponse>, ServiceError> {
    let mut shell = MacOsAppShell::new(state.adapter_config);
    build_status_response(&mut shell)
        .map(Json)
        .map_err(ServiceError::internal)
}

async fn service_mode_a_connect(
    State(state): State<ServiceState>,
    Query(params): Query<ModeAConnectParams>,
) -> Result<Json<OperationsResponse>, ServiceError> {
    #[cfg(target_os = "macos")]
    {
        let server = params
            .server
            .as_deref()
            .map(str::parse::<SocketAddr>)
            .transpose()
            .map_err(|error| {
                ServiceError::bad_request(format!("invalid server socket address: {error}"))
            })?;
        return build_connect_operations_response(MacOsAppShell::new(state.adapter_config), server)
            .map(Json)
            .map_err(ServiceError::internal);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = state;
        let _ = params;
        Err(ServiceError::not_implemented(
            "mode-a connect service is only available on macOS",
        ))
    }
}

async fn service_mode_a_disconnect(
    State(state): State<ServiceState>,
) -> Result<Json<OperationsResponse>, ServiceError> {
    #[cfg(target_os = "macos")]
    {
        return build_disconnect_operations_response(MacOsAppShell::new(state.adapter_config))
            .map(Json)
            .map_err(ServiceError::internal);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = state;
        Err(ServiceError::not_implemented(
            "mode-a disconnect service is only available on macOS",
        ))
    }
}

#[cfg(target_os = "macos")]
fn mode_a_session_status(
    adapter: &ql_macos_runtime::MacOsRuntimeAdapter,
) -> Result<ModeASessionStatus, String> {
    let tunnel = sample_tunnel(None)?;
    let firewall = PlatformFirewall::new("ql0");
    let tunnel_execution = adapter
        .execute_tunnel_operation("read-stats", &tunnel.macos_bridge_request())
        .map_err(|error| error.to_string())?;
    let helper_snapshot = tunnel_execution
        .helper_response
        .as_deref()
        .map(parse_tunnel_status_helper_response)
        .transpose()?;
    let tunnel_stats = helper_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.tunnel_stats.as_ref())
        .map(|stats| TunnelStats {
            bytes_sent: stats.bytes_sent,
            bytes_received: stats.bytes_received,
            last_handshake: stats
                .last_handshake_secs
                .map(std::time::Duration::from_secs),
        })
        .unwrap_or_else(TunnelStats::default);
    let firewall_active = if adapter.has_firewall_bridge() {
        MacOsFirewallBridgeExecutor::execute_firewall_request(
            adapter,
            &firewall.macos_query_request(),
        )
        .map_err(|error| error.to_string())?
        .unwrap_or(false)
    } else {
        false
    };
    let tunnel_active = helper_snapshot
        .and_then(|snapshot| snapshot.state.map(|state| state.tunnel_active))
        .unwrap_or(false);

    Ok(ModeASessionStatus {
        tunnel_active,
        firewall_active,
        tunnel_stats: TunnelStatsResponse::from(tunnel_stats),
    })
}

#[cfg(target_os = "macos")]
#[derive(Deserialize)]
struct ModeATunnelConfigOverride {
    interface_name: Option<String>,
    interface_addresses: Vec<String>,
    private_key: Option<[u8; 32]>,
    listen_port: Option<u16>,
    peer_public_key: Option<[u8; 32]>,
    peer_endpoint: Option<String>,
    allowed_ips: Vec<String>,
    persistent_keepalive: Option<u16>,
    dns_servers: Vec<String>,
    mtu: Option<u16>,
}

#[cfg(target_os = "macos")]
fn sample_tunnel(server: Option<std::net::SocketAddr>) -> Result<PlatformTunnel, String> {
    if let Some(raw) = env::var_os("QL_MODE_A_TUNNEL_CONFIG_JSON") {
        let mut config: ModeATunnelConfigOverride = serde_json::from_str(
            raw.to_str()
                .ok_or_else(|| "QL_MODE_A_TUNNEL_CONFIG_JSON is not valid UTF-8".to_owned())?,
        )
        .map_err(|error| format!("invalid QL_MODE_A_TUNNEL_CONFIG_JSON: {error}"))?;
        if let Some(server) = server {
            config.peer_endpoint = Some(server.to_string());
        }
        return tunnel_from_override(config);
    }

    PlatformTunnel::new(TunnelConfig {
        interface_name: "ql0".to_owned(),
        interface_addresses: vec![IpNetwork::V4(
            "10.0.0.2/32"
                .parse::<ipnetwork::Ipv4Network>()
                .map_err(|error| error.to_string())?,
        )],
        private_key: [7_u8; 32],
        listen_port: 51_820,
        peer_public_key: [8_u8; 32],
        peer_endpoint: Some(match server {
            Some(server) => server,
            None => "198.51.100.8:51820"
                .parse::<std::net::SocketAddr>()
                .map_err(|error| error.to_string())?,
        }),
        allowed_ips: vec![IpNetwork::V4(
            "0.0.0.0/0"
                .parse::<ipnetwork::Ipv4Network>()
                .map_err(|error| error.to_string())?,
        )],
        persistent_keepalive: Some(25),
        dns_servers: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
        mtu: 1_420,
    })
    .map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn tunnel_from_override(config: ModeATunnelConfigOverride) -> Result<PlatformTunnel, String> {
    let interface_addresses = config
        .interface_addresses
        .iter()
        .map(|cidr| {
            cidr.parse::<IpNetwork>()
                .map_err(|error| format!("invalid interface_addresses CIDR {cidr}: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if interface_addresses.is_empty() {
        return Err(
            "QL_MODE_A_TUNNEL_CONFIG_JSON.interface_addresses must not be empty".to_owned(),
        );
    }

    let allowed_ips = if config.allowed_ips.is_empty() {
        vec!["0.0.0.0/0".parse().unwrap()]
    } else {
        config
            .allowed_ips
            .iter()
            .map(|cidr| {
                cidr.parse::<IpNetwork>()
                    .map_err(|error| format!("invalid allowed_ips CIDR {cidr}: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    let dns_servers = if config.dns_servers.is_empty() {
        vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]
    } else {
        config
            .dns_servers
            .iter()
            .map(|address| {
                address
                    .parse::<IpAddr>()
                    .map_err(|error| format!("invalid dns_servers address {address}: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    let peer_endpoint = config
        .peer_endpoint
        .ok_or_else(|| "QL_MODE_A_TUNNEL_CONFIG_JSON.peer_endpoint is required".to_owned())?
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid peer_endpoint socket address: {error}"))?;

    PlatformTunnel::new(TunnelConfig {
        interface_name: config.interface_name.unwrap_or_else(|| "ql0".to_owned()),
        interface_addresses,
        private_key: config.private_key.unwrap_or([7_u8; 32]),
        listen_port: config.listen_port.unwrap_or(51_820),
        peer_public_key: config.peer_public_key.unwrap_or([8_u8; 32]),
        peer_endpoint: Some(peer_endpoint),
        allowed_ips,
        persistent_keepalive: config.persistent_keepalive.or(Some(25)),
        dns_servers,
        mtu: config.mtu.unwrap_or(1_420),
    })
    .map_err(|error| error.to_string())
}

fn adapter_config_from_env() -> Result<MacOsRuntimeAdapterConfig, String> {
    let mode = match env::var("QL_MACOS_APP_MODE") {
        Ok(raw) => match raw.as_str() {
            "stub" => MacOsAdapterMode::Stub,
            "external" => MacOsAdapterMode::ExternalProcess,
            "network-extension" => MacOsAdapterMode::NetworkExtension,
            other => return Err(format!("unsupported QL_MACOS_APP_MODE: {other}")),
        },
        Err(_) => MacOsAdapterMode::Stub,
    };
    let tunnel_controller_path = env::var_os("QL_MACOS_TUNNEL_CONTROLLER").map(Into::into);
    if matches!(mode, MacOsAdapterMode::NetworkExtension) && tunnel_controller_path.is_none() {
        return Err(
            "QL_MACOS_TUNNEL_CONTROLLER is required when QL_MACOS_APP_MODE=network-extension"
                .to_owned(),
        );
    }
    let tunnel_extension_bundle_identifier = env::var("QL_MACOS_TUNNEL_EXTENSION_BUNDLE_ID")
        .ok()
        .or_else(|| {
            matches!(mode, MacOsAdapterMode::NetworkExtension)
                .then(|| DEFAULT_MACOS_TUNNEL_PROVIDER_BUNDLE_IDENTIFIER.to_owned())
        });

    Ok(MacOsRuntimeAdapterConfig {
        mode,
        tunnel_extension_bundle_identifier,
        tunnel_controller_path,
        tunnel_helper_path: env::var_os("QL_MACOS_TUNNEL_HELPER").map(Into::into),
        firewall_helper_path: env::var_os("QL_MACOS_FIREWALL_HELPER").map(Into::into),
    })
}

fn adapter_mode_label(mode: &MacOsAdapterMode) -> &'static str {
    match mode {
        MacOsAdapterMode::Stub => "stub",
        MacOsAdapterMode::ExternalProcess => "external",
        MacOsAdapterMode::NetworkExtension => "network-extension",
    }
}

#[cfg(target_os = "macos")]
fn default_firewall_policy(shell: &MacOsAppShell) -> MacOsHostFirewallPolicy {
    if shell.adapter().has_firewall_bridge() {
        MacOsHostFirewallPolicy::KillSwitch {
            dns_server: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        }
    } else {
        MacOsHostFirewallPolicy::None
    }
}

#[cfg(target_os = "macos")]
fn connected_detail_label(mode: &MacOsAdapterMode, firewall_active: bool) -> &'static str {
    match (mode, firewall_active) {
        (MacOsAdapterMode::Stub, true) => "Mode A session active with stubbed kill switch",
        (MacOsAdapterMode::Stub, false) => "Mode A session active with stubbed runtime",
        (MacOsAdapterMode::ExternalProcess, true) => {
            "Mode A session active with helper-backed kill switch"
        }
        (MacOsAdapterMode::ExternalProcess, false) => {
            "Mode A session active with helper-backed runtime"
        }
        (MacOsAdapterMode::NetworkExtension, true) => {
            "Mode A session active with native tunnel controller and kill switch"
        }
        (MacOsAdapterMode::NetworkExtension, false) => {
            "Mode A session active with native tunnel controller"
        }
    }
}

#[cfg(target_os = "macos")]
fn connected_tray_status(mode: &MacOsAdapterMode, firewall_active: bool) -> String {
    match (mode, firewall_active) {
        (MacOsAdapterMode::Stub, true) => "connected:mode-a-stub+killswitch".to_owned(),
        (MacOsAdapterMode::Stub, false) => "connected:mode-a-stub".to_owned(),
        (MacOsAdapterMode::ExternalProcess, true) => {
            "connected:mode-a-helper+killswitch".to_owned()
        }
        (MacOsAdapterMode::ExternalProcess, false) => "connected:mode-a-helper".to_owned(),
        (MacOsAdapterMode::NetworkExtension, true) => {
            "connected:mode-a-network-extension+killswitch".to_owned()
        }
        (MacOsAdapterMode::NetworkExtension, false) => {
            "connected:mode-a-network-extension".to_owned()
        }
    }
}

fn tunnel_state_label(state: &TunnelState) -> &'static str {
    match state {
        TunnelState::Disconnected => "disconnected",
        TunnelState::Connecting => "connecting",
        TunnelState::Connected { .. } => "connected",
        TunnelState::Error(_) => "error",
    }
}

fn tray_status_label(status: &TrayStatus) -> String {
    match status {
        TrayStatus::Disconnected => "disconnected".to_owned(),
        TrayStatus::Connecting => "connecting".to_owned(),
        TrayStatus::Connected { label } => format!("connected:{label}"),
        TrayStatus::Error { message } => format!("error:{message}"),
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|error| error.to_string())?
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn host_operation_json(operation: MacOsHostOperation) -> OperationResponse {
    match operation {
        MacOsHostOperation::Tunnel(execution) => OperationResponse {
            target: "tunnel",
            operation: execution.operation,
            payload: execution.payload,
            helper_response: execution.helper_response,
        },
        MacOsHostOperation::Firewall(execution) => OperationResponse {
            target: "firewall",
            operation: execution.operation,
            payload: execution.payload,
            helper_response: execution.helper_response,
        },
    }
}

#[derive(Serialize)]
struct StatusResponse {
    adapter_mode: &'static str,
    pending_command: Option<String>,
    connection_state: &'static str,
    connection_headline: String,
    connection_detail: String,
    tray_status: String,
    #[cfg(target_os = "macos")]
    session: ModeASessionStatus,
}

#[cfg(target_os = "macos")]
#[derive(Serialize)]
struct OperationsResponse {
    adapter_mode: &'static str,
    operations: Vec<OperationResponse>,
}

#[derive(Serialize)]
struct OperationResponse {
    target: &'static str,
    operation: &'static str,
    payload: String,
    helper_response: Option<String>,
}

#[cfg(target_os = "macos")]
#[derive(Serialize)]
struct ModeASessionStatus {
    tunnel_active: bool,
    firewall_active: bool,
    tunnel_stats: TunnelStatsResponse,
}

#[cfg(target_os = "macos")]
#[derive(Serialize, Deserialize)]
struct TunnelStatsResponse {
    bytes_sent: u64,
    bytes_received: u64,
    last_handshake_secs: Option<u64>,
}

#[cfg(target_os = "macos")]
impl From<TunnelStats> for TunnelStatsResponse {
    fn from(value: TunnelStats) -> Self {
        Self {
            bytes_sent: value.bytes_sent,
            bytes_received: value.bytes_received,
            last_handshake_secs: value.last_handshake.map(|duration| duration.as_secs()),
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Deserialize)]
struct TunnelStatusHelperResponse {
    state: Option<TunnelStatusHelperState>,
    tunnel_stats: Option<TunnelStatsResponse>,
}

#[cfg(target_os = "macos")]
#[derive(Deserialize)]
struct TunnelStatusHelperState {
    tunnel_active: bool,
}

#[cfg(target_os = "macos")]
fn parse_tunnel_status_helper_response(
    payload: &str,
) -> Result<TunnelStatusHelperResponse, String> {
    serde_json::from_str(payload).map_err(|error| error.to_string())
}

fn print_usage() {
    eprintln!("usage: ql-macos-app <serve [port]|status|status-json|connect [host:port]|disconnect|mode-a-connect|mode-a-connect-json [host:port]|mode-a-disconnect|mode-a-disconnect-json>");
    eprintln!("env: QL_MACOS_APP_MODE=stub|external|network-extension");
    eprintln!("env: QL_MACOS_TUNNEL_CONTROLLER=/path/to/native-tunnel-controller");
    eprintln!(
		"env: QL_MACOS_TUNNEL_EXTENSION_BUNDLE_ID={DEFAULT_MACOS_TUNNEL_PROVIDER_BUNDLE_IDENTIFIER}"
	);
    eprintln!("env: QL_MACOS_TUNNEL_HELPER=/path/to/helper");
    eprintln!("env: QL_MACOS_FIREWALL_HELPER=/path/to/helper");
    eprintln!("env: QL_MACOS_APP_SERVICE_PORT=58421");
    eprintln!("env: QL_MODE_A_TUNNEL_CONFIG_JSON='{{...real tunnel config...}}'");
}

#[cfg(test)]
mod tests {
    use super::{adapter_config_from_env, build_service_router, ServiceState};
    use axum::{
        body::to_bytes,
        http::{Request, StatusCode},
    };
    use ql_macos_runtime::MacOsAdapterMode;
    use ql_wireguard::DEFAULT_MACOS_TUNNEL_PROVIDER_BUNDLE_IDENTIFIER;
    use serde::Deserialize;
    use std::sync::Mutex;
    use tower::util::ServiceExt;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Deserialize)]
    struct ServiceHealthPayload {
        status: String,
    }

    #[derive(Deserialize)]
    struct StatusPayload {
        adapter_mode: String,
        connection_state: String,
        tray_status: String,
    }

    #[derive(Deserialize)]
    struct OperationsPayload {
        adapter_mode: String,
        operations: Vec<OperationPayload>,
    }

    #[derive(Deserialize)]
    struct OperationPayload {
        target: String,
    }

    #[test]
    fn default_env_uses_stub_mode() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("QL_MACOS_APP_MODE");
        std::env::remove_var("QL_MACOS_TUNNEL_EXTENSION_BUNDLE_ID");
        std::env::remove_var("QL_MACOS_TUNNEL_CONTROLLER");
        std::env::remove_var("QL_MACOS_TUNNEL_HELPER");
        std::env::remove_var("QL_MACOS_FIREWALL_HELPER");

        let config = adapter_config_from_env().unwrap();
        assert_eq!(config.mode, MacOsAdapterMode::Stub);
        assert!(config.tunnel_extension_bundle_identifier.is_none());
        assert!(config.tunnel_controller_path.is_none());
        assert!(config.tunnel_helper_path.is_none());
        assert!(config.firewall_helper_path.is_none());
    }

    #[test]
    fn network_extension_mode_requires_controller_path() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("QL_MACOS_APP_MODE", "network-extension");
        std::env::remove_var("QL_MACOS_TUNNEL_EXTENSION_BUNDLE_ID");
        std::env::remove_var("QL_MACOS_TUNNEL_CONTROLLER");
        std::env::remove_var("QL_MACOS_TUNNEL_HELPER");
        std::env::remove_var("QL_MACOS_FIREWALL_HELPER");

        let error = adapter_config_from_env().unwrap_err();
        assert!(error.contains("QL_MACOS_TUNNEL_CONTROLLER is required"));

        std::env::remove_var("QL_MACOS_APP_MODE");
    }

    #[test]
    fn network_extension_env_is_parsed() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("QL_MACOS_APP_MODE", "network-extension");
        std::env::set_var("QL_MACOS_TUNNEL_CONTROLLER", "/tmp/ql-tunnel-controller");
        std::env::remove_var("QL_MACOS_TUNNEL_EXTENSION_BUNDLE_ID");
        std::env::remove_var("QL_MACOS_TUNNEL_HELPER");
        std::env::remove_var("QL_MACOS_FIREWALL_HELPER");

        let config = adapter_config_from_env().unwrap();
        assert_eq!(config.mode, MacOsAdapterMode::NetworkExtension);
        assert_eq!(
            config.tunnel_extension_bundle_identifier.as_deref(),
            Some(DEFAULT_MACOS_TUNNEL_PROVIDER_BUNDLE_IDENTIFIER)
        );
        assert_eq!(
            config.tunnel_controller_path.as_deref(),
            Some(std::path::Path::new("/tmp/ql-tunnel-controller"))
        );

        std::env::remove_var("QL_MACOS_APP_MODE");
        std::env::remove_var("QL_MACOS_TUNNEL_CONTROLLER");
    }

    #[test]
    fn explicit_tunnel_extension_bundle_id_is_parsed() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("QL_MACOS_APP_MODE", "network-extension");
        std::env::set_var("QL_MACOS_TUNNEL_CONTROLLER", "/tmp/ql-tunnel-controller");
        std::env::set_var(
            "QL_MACOS_TUNNEL_EXTENSION_BUNDLE_ID",
            "com.example.PacketTunnelProvider",
        );
        std::env::remove_var("QL_MACOS_TUNNEL_HELPER");
        std::env::remove_var("QL_MACOS_FIREWALL_HELPER");

        let config = adapter_config_from_env().unwrap();
        assert_eq!(
            config.tunnel_extension_bundle_identifier.as_deref(),
            Some("com.example.PacketTunnelProvider")
        );

        std::env::remove_var("QL_MACOS_APP_MODE");
        std::env::remove_var("QL_MACOS_TUNNEL_CONTROLLER");
        std::env::remove_var("QL_MACOS_TUNNEL_EXTENSION_BUNDLE_ID");
    }

    #[tokio::test]
    async fn service_health_endpoint_reports_ok() {
        let response = build_service_router(ServiceState {
            adapter_config: ql_macos_runtime::MacOsRuntimeAdapterConfig::default(),
        })
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload: ServiceHealthPayload = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload.status, "ok");
    }

    #[tokio::test]
    async fn service_status_endpoint_reports_stub_disconnected_state() {
        let response = build_service_router(ServiceState {
            adapter_config: ql_macos_runtime::MacOsRuntimeAdapterConfig::default(),
        })
        .oneshot(
            Request::builder()
                .uri("/status")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload: StatusPayload = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload.adapter_mode, "stub");
        assert_eq!(payload.connection_state, "disconnected");
        assert_eq!(payload.tray_status, "disconnected");
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn service_connect_and_disconnect_endpoints_return_operations() {
        let router = build_service_router(ServiceState {
            adapter_config: ql_macos_runtime::MacOsRuntimeAdapterConfig::default(),
        });

        let connect = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mode-a/connect?server=203.0.113.10:51820")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(connect.status(), StatusCode::OK);
        let connect_body = to_bytes(connect.into_body(), usize::MAX).await.unwrap();
        let connect_payload: OperationsPayload = serde_json::from_slice(&connect_body).unwrap();
        assert_eq!(connect_payload.adapter_mode, "stub");
        assert_eq!(connect_payload.operations.len(), 2);
        assert_eq!(connect_payload.operations[0].target, "tunnel");
        assert_eq!(connect_payload.operations[1].target, "firewall");

        let disconnect = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mode-a/disconnect")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disconnect.status(), StatusCode::OK);
        let disconnect_body = to_bytes(disconnect.into_body(), usize::MAX).await.unwrap();
        let disconnect_payload: OperationsPayload =
            serde_json::from_slice(&disconnect_body).unwrap();
        assert_eq!(disconnect_payload.adapter_mode, "stub");
        assert_eq!(disconnect_payload.operations.len(), 2);
        assert_eq!(disconnect_payload.operations[0].target, "firewall");
        assert_eq!(disconnect_payload.operations[1].target, "tunnel");
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn service_connect_endpoint_rejects_invalid_server() {
        let response = build_service_router(ServiceState {
            adapter_config: ql_macos_runtime::MacOsRuntimeAdapterConfig::default(),
        })
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mode-a/connect?server=not-a-socket")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let message = String::from_utf8(body.to_vec()).unwrap();
        assert!(message.contains("invalid server socket address"));
    }
}
