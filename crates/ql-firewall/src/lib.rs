//! Firewall and leak-protection controls for QuantumLink.

use std::net::IpAddr;

use ql_core::{QuantumLinkError, QuantumLinkResult};

#[cfg(target_os = "linux")]
const TABLE_NAME: &str = "quantumlink";

/// Manages QuantumLink nftables rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallManager {
	interface: String,
}

impl FirewallManager {
	/// Creates a firewall manager for the given WireGuard interface.
	#[must_use]
	pub fn new(wireguard_interface: &str) -> Self {
		Self {
			interface: wireguard_interface.to_owned(),
		}
	}
}

#[cfg(target_os = "linux")]
impl FirewallManager {
	/// Enables the full kill switch ruleset.
	///
	/// # Errors
	///
	/// Returns an error if nftables cannot be updated.
	#[must_use]
	pub fn enable_kill_switch(&self, dns_server: IpAddr) -> QuantumLinkResult<()> {
		self.apply_ruleset(build_kill_switch_ruleset(&self.interface, dns_server))
	}

	/// Enables DNS leak protection without a full kill switch.
	///
	/// # Errors
	///
	/// Returns an error if nftables cannot be updated.
	#[must_use]
	pub fn enable_dns_protection(&self, dns_server: IpAddr) -> QuantumLinkResult<()> {
		self.apply_ruleset(build_dns_only_ruleset(&self.interface, dns_server))
	}

	/// Removes all QuantumLink-managed nftables rules.
	///
	/// # Errors
	///
	/// Returns an error only if nftables reports a hard failure other than a missing table.
	#[must_use]
	pub fn disable_all(&self) -> QuantumLinkResult<()> {
		if !self.is_active()? {
			return Ok(());
		}

		match std::process::Command::new("nft")
			.args(["delete", "table", "inet", TABLE_NAME])
			.status()
		{
			Ok(status) if status.success() => Ok(()),
			Ok(status) => Err(QuantumLinkError::WireGuard(format!(
				"failed to delete nftables table with status {status}"
			))),
			Err(error) => Err(QuantumLinkError::Io(error)),
		}
	}

	/// Returns whether the QuantumLink nftables table is active.
	///
	/// # Errors
	///
	/// Returns an error if the nftables query itself fails unexpectedly.
	#[must_use]
	pub fn is_active(&self) -> QuantumLinkResult<bool> {
		match std::process::Command::new("nft")
			.args(["list", "table", "inet", TABLE_NAME])
			.status()
		{
			Ok(status) => Ok(status.success()),
			Err(error) => Err(QuantumLinkError::Io(error)),
		}
	}

	fn apply_ruleset(&self, ruleset: String) -> QuantumLinkResult<()> {
		let temp_path = std::env::temp_dir().join(format!(
			"quantumlink-{}-{}.nft",
			self.interface,
			std::process::id()
		));
		std::fs::write(&temp_path, ruleset).map_err(QuantumLinkError::Io)?;

		let result = std::process::Command::new("nft")
			.args(["-f", temp_path.to_string_lossy().as_ref()])
			.status();
		let _ = std::fs::remove_file(&temp_path);

		match result {
			Ok(status) if status.success() => Ok(()),
			Ok(status) => Err(QuantumLinkError::WireGuard(format!(
				"failed to apply nftables ruleset with status {status}"
			))),
			Err(error) => Err(QuantumLinkError::Io(error)),
		}
	}
}

#[cfg(not(target_os = "linux"))]
impl FirewallManager {
	/// Enables the full kill switch ruleset.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` on non-Linux targets.
	#[must_use]
	pub fn enable_kill_switch(&self, dns_server: IpAddr) -> QuantumLinkResult<()> {
		let _ = (&self.interface, dns_server);
		Err(not_implemented())
	}

	/// Enables DNS leak protection without a full kill switch.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` on non-Linux targets.
	#[must_use]
	pub fn enable_dns_protection(&self, dns_server: IpAddr) -> QuantumLinkResult<()> {
		let _ = (&self.interface, dns_server);
		Err(not_implemented())
	}

	/// Removes all QuantumLink-managed firewall rules.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` on non-Linux targets.
	#[must_use]
	pub fn disable_all(&self) -> QuantumLinkResult<()> {
		let _ = &self.interface;
		Err(not_implemented())
	}

	/// Returns whether the firewall rules are active.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` on non-Linux targets.
	#[must_use]
	pub fn is_active(&self) -> QuantumLinkResult<bool> {
		let _ = &self.interface;
		Err(not_implemented())
	}
}

#[cfg(not(target_os = "linux"))]
fn not_implemented() -> QuantumLinkError {
	QuantumLinkError::NotImplemented("Firewall management is implemented for Linux only in v0.1".to_owned())
}

#[cfg(target_os = "linux")]
fn build_kill_switch_ruleset(interface: &str, dns_server: IpAddr) -> String {
	let dns_rule = dns_match(dns_server);
	format!(
		"flush table inet {table}\n\
		 table inet {table} {{\n\
		   chain output {{\n\
			 type filter hook output priority 0; policy drop;\n\
			 oifname \"lo\" accept\n\
			 oifname \"{interface}\" accept\n\
			 ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }} accept\n\
			 ip6 daddr {{ fe80::/10, fc00::/7 }} accept\n\
			 udp sport 67 udp dport 68 accept\n\
			 {dns_rule} accept\n\
		   }}\n\
		 }}\n",
		table = TABLE_NAME,
		interface = interface,
		dns_rule = dns_rule,
	)
}

#[cfg(target_os = "linux")]
fn build_dns_only_ruleset(interface: &str, dns_server: IpAddr) -> String {
	let dns_rule = dns_match(dns_server);
	format!(
		"flush table inet {table}\n\
		 table inet {table} {{\n\
		   chain output {{\n\
			 type filter hook output priority 0; policy accept;\n\
			 oifname \"{interface}\" accept\n\
			 udp dport 53 {dns_rule} accept\n\
			 tcp dport 53 {dns_rule} accept\n\
			 udp dport 53 reject\n\
			 tcp dport 53 reject\n\
		   }}\n\
		 }}\n",
		table = TABLE_NAME,
		interface = interface,
		dns_rule = dns_rule,
	)
}

#[cfg(target_os = "linux")]
fn dns_match(dns_server: IpAddr) -> String {
	match dns_server {
		IpAddr::V4(address) => format!("ip daddr {address}"),
		IpAddr::V6(address) => format!("ip6 daddr {address}"),
	}
}

#[cfg(test)]
mod tests {
	use super::FirewallManager;

	#[cfg(target_os = "linux")]
	use std::net::{IpAddr, Ipv4Addr};

	#[test]
	fn constructor_preserves_interface_name() {
		let firewall = FirewallManager::new("ql0");

		assert_eq!(firewall, FirewallManager::new("ql0"));
	}

	#[cfg(target_os = "linux")]
	#[test]
	fn kill_switch_ruleset_uses_quantumlink_table() {
		let ruleset = super::build_kill_switch_ruleset(
			"ql0",
			IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
		);

		assert!(ruleset.contains("table inet quantumlink"));
		assert!(ruleset.contains("oifname \"ql0\" accept"));
	}
}
