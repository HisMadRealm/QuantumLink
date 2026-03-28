//! Rosenpass sidecar integration for QuantumLink.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ql_core::{QuantumLinkError, QuantumLinkResult};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

const DEFAULT_ROSENPASS_BIN: &str = "rosenpass";
const DEFAULT_LISTEN_IP: &str = "0.0.0.0";
const MAX_RESTART_ATTEMPTS: u8 = 3;

/// Configuration for a managed Rosenpass sidecar process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosenpassConfig {
    /// Path to the local Rosenpass secret key file.
    pub own_sk_path: PathBuf,
    /// Path to the local Rosenpass public key file.
    pub own_pk_path: PathBuf,
    /// Path to the peer Rosenpass public key file.
    pub peer_pk_path: PathBuf,
    /// WireGuard interface that should receive rotated PSKs.
    pub interface_name: String,
    /// WireGuard peer public key bytes.
    pub peer_wg_pubkey: [u8; 32],
    /// Rosenpass UDP listen port.
    pub listen_port: u16,
    /// Optional peer endpoint.
    pub peer_endpoint: Option<std::net::SocketAddr>,
}

/// Managed Rosenpass sidecar process with restart supervision.
#[derive(Debug)]
pub struct RosenpassManager {
    inner: Arc<Inner>,
    supervisor: JoinHandle<()>,
}

#[derive(Debug)]
struct Inner {
    config: RosenpassConfig,
    child: AsyncMutex<Option<Child>>,
    shutdown_requested: AtomicBool,
    last_psk_rotation: Mutex<Instant>,
    last_error: Mutex<Option<String>>,
}

impl RosenpassManager {
    /// Starts the Rosenpass sidecar process and its supervision task.
    ///
    /// # Errors
    ///
    /// Returns an error if the Rosenpass process cannot be spawned.
    #[must_use]
    pub async fn start(config: RosenpassConfig) -> QuantumLinkResult<Self> {
        validate_config(&config)?;

        let inner = Arc::new(Inner {
            config: config.clone(),
            child: AsyncMutex::new(None),
            shutdown_requested: AtomicBool::new(false),
            last_psk_rotation: Mutex::new(Instant::now()),
            last_error: Mutex::new(None),
        });

        spawn_rosenpass_process(&inner).await?;

        let supervisor_inner = Arc::clone(&inner);
        let supervisor = tokio::spawn(async move {
            supervise_process(supervisor_inner).await;
        });

        Ok(Self { inner, supervisor })
    }

    /// Stops the Rosenpass sidecar process and waits for supervision to finish.
    ///
    /// # Errors
    ///
    /// Returns an error if the child process cannot be stopped cleanly.
    #[must_use]
    pub async fn stop(self) -> QuantumLinkResult<()> {
        self.inner.shutdown_requested.store(true, Ordering::SeqCst);

        if let Some(mut child) = self.inner.child.lock().await.take() {
            if let Err(error) = child.start_kill() {
                return Err(QuantumLinkError::Rosenpass(format!(
                    "failed to terminate rosenpass child: {error}"
                )));
            }
            let _ = child.wait().await.map_err(|error| {
                QuantumLinkError::Rosenpass(format!(
                    "failed waiting for rosenpass child exit: {error}"
                ))
            })?;
        }

        self.supervisor.await.map_err(|error| {
            QuantumLinkError::Rosenpass(format!("rosenpass supervisor task failed: {error}"))
        })?;

        Ok(())
    }

    /// Returns the elapsed time since the last observed Rosenpass activity.
    #[must_use]
    pub fn psk_age(&self) -> Duration {
        self.inner
            .last_psk_rotation
            .lock()
            .map(|instant| instant.elapsed())
            .unwrap_or_else(|_| Duration::MAX)
    }

    /// Generates a Rosenpass keypair into `output_dir/sk` and `output_dir/pk`.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    #[must_use]
    pub async fn generate_keypair(output_dir: &Path) -> QuantumLinkResult<()> {
        std::fs::create_dir_all(output_dir).map_err(QuantumLinkError::Io)?;

        let secret_key = output_dir.join("sk");
        let public_key = output_dir.join("pk");
        let status = Command::new(rosenpass_binary())
            .arg("gen-keys")
            .arg("--secret-key")
            .arg(secret_key)
            .arg("--public-key")
            .arg(public_key)
            .status()
            .await
            .map_err(|error| {
                QuantumLinkError::Rosenpass(format!("failed to start key generation: {error}"))
            })?;

        if status.success() {
            Ok(())
        } else {
            Err(QuantumLinkError::Rosenpass(format!(
                "rosenpass gen-keys exited with status {status}"
            )))
        }
    }
}

async fn supervise_process(inner: Arc<Inner>) {
    let mut restart_attempts = 0_u8;

    loop {
        let exit_status = {
            let mut child_guard = inner.child.lock().await;
            match child_guard.as_mut() {
                Some(child) => match child.wait().await {
                    Ok(status) => Some(status),
                    Err(error) => {
                        set_last_error(
                            &inner,
                            format!("failed waiting on rosenpass child: {error}"),
                        );
                        None
                    }
                },
                None => None,
            }
        };

        if inner.shutdown_requested.load(Ordering::SeqCst) {
            break;
        }

        match exit_status {
            Some(status) if status.success() => {
                info!("rosenpass exited cleanly");
                break;
            }
            Some(status) => {
                let message = format!("rosenpass exited unexpectedly with status {status}");
                set_last_error(&inner, message.clone());
                warn!("{message}");
            }
            None => {
                warn!("rosenpass child handle missing during supervision");
            }
        }

        if restart_attempts >= MAX_RESTART_ATTEMPTS {
            error!("rosenpass reached the maximum restart attempts");
            break;
        }

        restart_attempts += 1;
        let backoff = Duration::from_secs(1_u64 << (restart_attempts - 1));
        tokio::time::sleep(backoff).await;
        if let Err(error) = spawn_rosenpass_process(&inner).await {
            set_last_error(&inner, format!("failed to restart rosenpass: {error}"));
            error!("failed to restart rosenpass: {error}");
            if restart_attempts >= MAX_RESTART_ATTEMPTS {
                break;
            }
        }
    }
}

async fn spawn_rosenpass_process(inner: &Arc<Inner>) -> QuantumLinkResult<()> {
    let mut command = Command::new(rosenpass_binary());
    command
        .args(build_exchange_args(&inner.config))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().map_err(|error| {
        QuantumLinkError::Rosenpass(format!("failed to spawn rosenpass exchange: {error}"))
    })?;

    if let Some(stdout) = child.stdout.take() {
        let stdout_inner = Arc::clone(inner);
        tokio::spawn(async move {
            observe_stream(stdout_inner, BufReader::new(stdout)).await;
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let stderr_inner = Arc::clone(inner);
        tokio::spawn(async move {
            observe_stream(stderr_inner, BufReader::new(stderr)).await;
        });
    }

    *inner.child.lock().await = Some(child);
    *inner
        .last_psk_rotation
        .lock()
        .map_err(|_| QuantumLinkError::Rosenpass("psk age mutex poisoned".to_owned()))? =
        Instant::now();
    info!("started rosenpass sidecar process");

    Ok(())
}

async fn observe_stream<R>(inner: Arc<Inner>, reader: BufReader<R>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = reader.lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                let lower = line.to_ascii_lowercase();
                if lower.contains("psk")
                    || lower.contains("key")
                    || lower.contains("handshake")
                    || lower.contains("exchange")
                {
                    if let Ok(mut last_rotation) = inner.last_psk_rotation.lock() {
                        *last_rotation = Instant::now();
                    }
                }
            }
            Ok(None) => break,
            Err(error) => {
                set_last_error(&inner, format!("failed to read rosenpass output: {error}"));
                break;
            }
        }
    }
}

fn build_exchange_args(config: &RosenpassConfig) -> Vec<String> {
    let mut args = vec![
        "exchange".to_owned(),
        "private-key".to_owned(),
        config.own_sk_path.display().to_string(),
        "public-key".to_owned(),
        config.own_pk_path.display().to_string(),
        "listen".to_owned(),
        format!("{DEFAULT_LISTEN_IP}:{}", config.listen_port),
        "peer".to_owned(),
        "public-key".to_owned(),
        config.peer_pk_path.display().to_string(),
    ];

    if let Some(endpoint) = config.peer_endpoint {
        args.push("endpoint".to_owned());
        args.push(endpoint.to_string());
    }

    args.push("wireguard".to_owned());
    args.push(config.interface_name.clone());
    args.push(BASE64_STANDARD.encode(config.peer_wg_pubkey));

    args
}

fn rosenpass_binary() -> String {
    std::env::var("ROSENPASS_BIN").unwrap_or_else(|_| DEFAULT_ROSENPASS_BIN.to_owned())
}

fn validate_config(config: &RosenpassConfig) -> QuantumLinkResult<()> {
    if config.interface_name.is_empty() {
        return Err(QuantumLinkError::Rosenpass(
            "interface_name must not be empty".to_owned(),
        ));
    }
    for path in [
        &config.own_sk_path,
        &config.own_pk_path,
        &config.peer_pk_path,
    ] {
        if path.as_os_str().is_empty() {
            return Err(QuantumLinkError::Rosenpass(
                "rosenpass key paths must not be empty".to_owned(),
            ));
        }
    }
    Ok(())
}

fn set_last_error(inner: &Arc<Inner>, message: String) {
    if let Ok(mut last_error) = inner.last_error.lock() {
        *last_error = Some(message);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};

    use super::{build_exchange_args, RosenpassConfig};

    #[test]
    fn builds_exchange_command_arguments() {
        let config = RosenpassConfig {
            own_sk_path: PathBuf::from("/keys/own.sk"),
            own_pk_path: PathBuf::from("/keys/own.pk"),
            peer_pk_path: PathBuf::from("/keys/peer.pk"),
            interface_name: "ql0".to_owned(),
            peer_wg_pubkey: [9_u8; 32],
            listen_port: 9_999,
            peer_endpoint: Some("198.51.100.10:9999".parse().unwrap()),
        };

        let args = build_exchange_args(&config);

        assert_eq!(args[0], "exchange");
        assert!(args.contains(&"wireguard".to_owned()));
        assert!(args.contains(&"198.51.100.10:9999".to_owned()));
        assert_eq!(
            args.last().unwrap(),
            &BASE64_STANDARD.encode(config.peer_wg_pubkey)
        );
    }
}
