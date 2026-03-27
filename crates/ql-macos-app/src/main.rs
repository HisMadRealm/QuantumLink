//! Minimal macOS app-shell bootstrap for QuantumLink.

#![forbid(unsafe_code)]

use std::env;
use std::process;

use ql_macos_app::MacOsAppShell;
use ql_macos_runtime::{MacOsAdapterMode, MacOsRuntimeAdapterConfig};

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
	let mut shell = MacOsAppShell::new(adapter_config);

	match command.as_str() {
		"status" => {
			shell.request_status_refresh();
			println!("adapter_mode={:?}", shell.adapter().mode());
			println!("pending_command={:?}", shell.take_pending_command());
			println!("gui_state={:#?}", shell.gui());
			Ok(())
		}
		"connect" => {
			let server = args.next().map(|raw| raw.parse()).transpose().map_err(|error| {
				format!("invalid server socket address: {error}")
			})?;
			shell.request_connect(server);
			println!("adapter_mode={:?}", shell.adapter().mode());
			println!("pending_command={:?}", shell.take_pending_command());
			Ok(())
		}
		"disconnect" => {
			shell.request_disconnect();
			println!("adapter_mode={:?}", shell.adapter().mode());
			println!("pending_command={:?}", shell.take_pending_command());
			Ok(())
		}
		_ => {
			print_usage();
			Err(format!("unknown command: {command}"))
		}
	}
}

fn adapter_config_from_env() -> Result<MacOsRuntimeAdapterConfig, String> {
	let mode = match env::var("QL_MACOS_APP_MODE") {
		Ok(raw) => match raw.as_str() {
			"stub" => MacOsAdapterMode::Stub,
			"external" => MacOsAdapterMode::ExternalProcess,
			other => return Err(format!("unsupported QL_MACOS_APP_MODE: {other}")),
		},
		Err(_) => MacOsAdapterMode::Stub,
	};

	Ok(MacOsRuntimeAdapterConfig {
		mode,
		tunnel_helper_path: env::var_os("QL_MACOS_TUNNEL_HELPER").map(Into::into),
		firewall_helper_path: env::var_os("QL_MACOS_FIREWALL_HELPER").map(Into::into),
	})
}

fn print_usage() {
	eprintln!("usage: ql-macos-app <status|connect [host:port]|disconnect>");
	eprintln!("env: QL_MACOS_APP_MODE=stub|external");
	eprintln!("env: QL_MACOS_TUNNEL_HELPER=/path/to/helper");
	eprintln!("env: QL_MACOS_FIREWALL_HELPER=/path/to/helper");
}

#[cfg(test)]
mod tests {
	use super::adapter_config_from_env;
	use ql_macos_runtime::MacOsAdapterMode;

	#[test]
	fn default_env_uses_stub_mode() {
		std::env::remove_var("QL_MACOS_APP_MODE");
		std::env::remove_var("QL_MACOS_TUNNEL_HELPER");
		std::env::remove_var("QL_MACOS_FIREWALL_HELPER");

		let config = adapter_config_from_env().unwrap();
		assert_eq!(config.mode, MacOsAdapterMode::Stub);
		assert!(config.tunnel_helper_path.is_none());
		assert!(config.firewall_helper_path.is_none());
	}
}