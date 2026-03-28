//! Server daemon binary for QuantumLink.

#![forbid(unsafe_code)]

use std::env;
use std::net::SocketAddr;
use std::time::Duration;

use ql_core::{QuantumLinkError, QuantumLinkResult};
use ql_relay::{RelayConfig, RelayServer};
use ql_signal::{SignalConfig, SignalServer};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliCommand {
    Plan(ServerRuntimeConfig),
    Run(ServerRuntimeConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServerRuntimeConfig {
    signal_bind_addr: SocketAddr,
    relay_bind_addr: SocketAddr,
    shutdown_after: Option<Duration>,
}

impl Default for ServerRuntimeConfig {
    fn default() -> Self {
        Self {
            signal_bind_addr: SocketAddr::from(([0, 0, 0, 0], 8_443)),
            relay_bind_addr: SocketAddr::from(([0, 0, 0, 0], 51_821)),
            shutdown_after: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ServerPlan {
    signal_bind_addr: SocketAddr,
    relay_bind_addr: SocketAddr,
    shutdown_after_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ServerStatus {
    signal_addr: SocketAddr,
    relay_addr: SocketAddr,
    active_sessions: usize,
    packets_forwarded: u64,
    bytes_forwarded: u64,
}

#[derive(Debug)]
struct QuantumLinkServer {
    signal: SignalServer,
    relay: RelayServer,
}

impl QuantumLinkServer {
    async fn start(config: ServerRuntimeConfig) -> QuantumLinkResult<Self> {
        let signal = SignalServer::start(SignalConfig {
            bind_addr: config.signal_bind_addr,
            ..SignalConfig::default()
        })
        .await?;
        let relay = RelayServer::start(RelayConfig {
            bind_addr: config.relay_bind_addr,
            ..RelayConfig::default()
        })
        .await?;

        Ok(Self { signal, relay })
    }

    async fn stop(self) -> QuantumLinkResult<()> {
        self.signal.stop().await?;
        self.relay.stop().await
    }

    async fn status(&self) -> ServerStatus {
        let relay_stats = self.relay.stats().await;
        ServerStatus {
            signal_addr: self.signal.local_addr(),
            relay_addr: self.relay.local_addr(),
            active_sessions: relay_stats.active_sessions,
            packets_forwarded: relay_stats.packets_forwarded,
            bytes_forwarded: relay_stats.bytes_forwarded,
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
        CliCommand::Plan(config) => print_json(&ServerPlan {
            signal_bind_addr: config.signal_bind_addr,
            relay_bind_addr: config.relay_bind_addr,
            shutdown_after_seconds: config.shutdown_after.map(|duration| duration.as_secs()),
        }),
        CliCommand::Run(config) => {
            let shutdown_after = config.shutdown_after;
            let server = QuantumLinkServer::start(config).await?;
            print_json(&server.status().await)?;

            if let Some(duration) = shutdown_after {
                tokio::time::sleep(duration).await;
            } else {
                tokio::signal::ctrl_c().await.map_err(|error| {
                    QuantumLinkError::Io(std::io::Error::other(format!(
                        "failed waiting for Ctrl-C: {error}"
                    )))
                })?;
            }

            server.stop().await
        }
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

    let mut config = ServerRuntimeConfig::default();
    let mut index = 1_usize;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--signal-bind" => {
                index += 1;
                config.signal_bind_addr = arguments
                    .get(index)
                    .ok_or_else(|| "missing value for --signal-bind".to_owned())?
                    .parse()
                    .map_err(|error| format!("invalid --signal-bind socket address: {error}"))?;
            }
            "--relay-bind" => {
                index += 1;
                config.relay_bind_addr = arguments
                    .get(index)
                    .ok_or_else(|| "missing value for --relay-bind".to_owned())?
                    .parse()
                    .map_err(|error| format!("invalid --relay-bind socket address: {error}"))?;
            }
            "--shutdown-after" => {
                index += 1;
                let secs = arguments
                    .get(index)
                    .ok_or_else(|| "missing value for --shutdown-after".to_owned())?
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --shutdown-after value: {error}"))?;
                config.shutdown_after = Some(Duration::from_secs(secs));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
        index += 1;
    }

    match command {
        "plan" => Ok(CliCommand::Plan(config)),
        "run" => Ok(CliCommand::Run(config)),
        _ => Err(usage().to_owned()),
    }
}

fn usage() -> &'static str {
    "usage: qls <plan|run> [--signal-bind addr] [--relay-bind addr] [--shutdown-after secs]"
}

#[cfg(test)]
mod tests {
    use super::{parse_cli, CliCommand, QuantumLinkServer, ServerRuntimeConfig};

    #[test]
    fn parses_run_command() {
        let command = parse_cli(vec![
            "qls".to_owned(),
            "run".to_owned(),
            "--signal-bind".to_owned(),
            "127.0.0.1:9443".to_owned(),
            "--relay-bind".to_owned(),
            "127.0.0.1:55182".to_owned(),
        ])
        .unwrap();

        assert!(matches!(command, CliCommand::Run(_)));
    }

    #[tokio::test]
    async fn starts_and_stops_signal_and_relay() {
        let server = QuantumLinkServer::start(ServerRuntimeConfig {
            signal_bind_addr: "127.0.0.1:0".parse().unwrap(),
            relay_bind_addr: "127.0.0.1:0".parse().unwrap(),
            shutdown_after: Some(std::time::Duration::from_millis(1)),
        })
        .await
        .unwrap();

        let status = server.status().await;
        assert_ne!(status.signal_addr.port(), 0);
        assert_ne!(status.relay_addr.port(), 0);
        assert_eq!(status.active_sessions, 0);

        server.stop().await.unwrap();
    }
}
