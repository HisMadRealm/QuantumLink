//! Firewall and leak-protection controls for QuantumLink.

use std::net::{IpAddr, SocketAddr};

use ql_core::{QuantumLinkError, QuantumLinkResult};
#[cfg(target_os = "macos")]
use serde::Serialize;

#[cfg(target_os = "linux")]
const TABLE_NAME: &str = "quantumlink";

/// Manages QuantumLink nftables rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallManager {
    interface: String,
}

/// Describes the runtime firewall backend selected for the current target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallBackendDescriptor {
    /// Stable backend identifier.
    pub name: &'static str,
    /// Whether this backend is meant to become a native product path.
    pub product_target: bool,
    /// Whether this backend currently performs native execution.
    pub native_execution: bool,
    /// Short note describing the backend state.
    pub note: &'static str,
}

/// macOS firewall operation modes exposed to a native integration layer.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum MacOsFirewallOperationMode {
    KillSwitch,
    DnsOnly,
    DisableAll,
    QueryActive,
}

/// Native bridge request handed to a future macOS firewall integration layer.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MacOsFirewallBridgeRequest {
    /// Anchor name expected by the native firewall layer.
    pub anchor_name: String,
    /// Interface associated with this policy request.
    pub interface_name: String,
    /// Runtime driver name.
    pub driver: &'static str,
    /// Requested operation.
    pub operation: MacOsFirewallOperationMode,
    /// DNS server relevant to the requested operation, when applicable.
    pub dns_server: Option<IpAddr>,
    /// VPN peer endpoint allowed outside the tunnel for kill-switch bring-up.
    pub peer_endpoint: Option<SocketAddr>,
}

/// Native executor interface for macOS firewall bridge requests.
#[cfg(target_os = "macos")]
pub trait MacOsFirewallBridgeExecutor {
    /// Applies the supplied firewall bridge request.
    fn execute_firewall_request(
        &self,
        request: &MacOsFirewallBridgeRequest,
    ) -> QuantumLinkResult<Option<bool>>;
}

/// Platform-selected firewall facade used by higher layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformFirewall {
    backend: FirewallManager,
}

impl PlatformFirewall {
    /// Creates the platform-selected firewall backend.
    #[must_use]
    pub fn new(wireguard_interface: &str) -> Self {
        Self {
            backend: FirewallManager::new(wireguard_interface),
        }
    }

    /// Returns the logical backend name selected for the current target.
    #[must_use]
    pub fn backend_name() -> &'static str {
        platform_backend_name()
    }

    /// Returns the backend descriptor selected for the current target.
    #[must_use]
    pub fn backend_descriptor() -> FirewallBackendDescriptor {
        firewall_backend_descriptor()
    }

    /// Enables the full kill switch ruleset.
    ///
    /// # Errors
    ///
    /// Returns an error if the active backend cannot be updated.
    #[must_use]
    pub fn enable_kill_switch(&self, dns_server: IpAddr) -> QuantumLinkResult<()> {
        self.backend.enable_kill_switch(dns_server)
    }

    /// Enables DNS leak protection without a full kill switch.
    ///
    /// # Errors
    ///
    /// Returns an error if the active backend cannot be updated.
    #[must_use]
    pub fn enable_dns_protection(&self, dns_server: IpAddr) -> QuantumLinkResult<()> {
        self.backend.enable_dns_protection(dns_server)
    }

    /// Removes all QuantumLink-managed firewall rules.
    ///
    /// # Errors
    ///
    /// Returns an error if the active backend cannot be cleaned up.
    #[must_use]
    pub fn disable_all(&self) -> QuantumLinkResult<()> {
        self.backend.disable_all()
    }

    /// Returns whether the platform firewall backend is active.
    ///
    /// # Errors
    ///
    /// Returns an error if the active backend cannot report state.
    #[must_use]
    pub fn is_active(&self) -> QuantumLinkResult<bool> {
        self.backend.is_active()
    }

    /// Builds the macOS native bridge request for a kill-switch operation.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn macos_kill_switch_request(
        &self,
        dns_server: IpAddr,
        peer_endpoint: Option<SocketAddr>,
    ) -> MacOsFirewallBridgeRequest {
        MacOsFirewallBackend::new(&self.backend.interface).bridge_request(
            MacOsFirewallOperationMode::KillSwitch,
            Some(dns_server),
            peer_endpoint,
        )
    }

    /// Builds the macOS native bridge request for a DNS-only protection operation.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn macos_dns_request(&self, dns_server: IpAddr) -> MacOsFirewallBridgeRequest {
        MacOsFirewallBackend::new(&self.backend.interface).bridge_request(
            MacOsFirewallOperationMode::DnsOnly,
            Some(dns_server),
            None,
        )
    }

    /// Builds the macOS native bridge request for disabling all rules.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn macos_disable_request(&self) -> MacOsFirewallBridgeRequest {
        MacOsFirewallBackend::new(&self.backend.interface).bridge_request(
            MacOsFirewallOperationMode::DisableAll,
            None,
            None,
        )
    }

    /// Builds the macOS native bridge request for querying runtime state.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn macos_query_request(&self) -> MacOsFirewallBridgeRequest {
        MacOsFirewallBackend::new(&self.backend.interface).bridge_request(
            MacOsFirewallOperationMode::QueryActive,
            None,
            None,
        )
    }

    /// Executes a kill-switch request through a supplied macOS executor.
    #[cfg(target_os = "macos")]
    pub fn enable_kill_switch_with_executor<E: MacOsFirewallBridgeExecutor>(
        &self,
        executor: &E,
        dns_server: IpAddr,
        peer_endpoint: Option<SocketAddr>,
    ) -> QuantumLinkResult<()> {
        executor
            .execute_firewall_request(&self.macos_kill_switch_request(dns_server, peer_endpoint))?;
        Ok(())
    }

    /// Executes a DNS-only request through a supplied macOS executor.
    #[cfg(target_os = "macos")]
    pub fn enable_dns_protection_with_executor<E: MacOsFirewallBridgeExecutor>(
        &self,
        executor: &E,
        dns_server: IpAddr,
    ) -> QuantumLinkResult<()> {
        executor.execute_firewall_request(&self.macos_dns_request(dns_server))?;
        Ok(())
    }

    /// Executes a disable request through a supplied macOS executor.
    #[cfg(target_os = "macos")]
    pub fn disable_all_with_executor<E: MacOsFirewallBridgeExecutor>(
        &self,
        executor: &E,
    ) -> QuantumLinkResult<()> {
        executor.execute_firewall_request(&self.macos_disable_request())?;
        Ok(())
    }

    /// Executes a query request through a supplied macOS executor.
    #[cfg(target_os = "macos")]
    pub fn is_active_with_executor<E: MacOsFirewallBridgeExecutor>(
        &self,
        executor: &E,
    ) -> QuantumLinkResult<bool> {
        Ok(executor
            .execute_firewall_request(&self.macos_query_request())?
            .unwrap_or(false))
    }
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

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum MacOsFirewallDriver {
    PacketFilter,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum MacOsLeakProtectionMode {
    KillSwitch,
    DnsOnly,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum MacOsFirewallState {
    Prepared,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct MacOsFirewallBackend {
    interface: String,
    driver: MacOsFirewallDriver,
    state: MacOsFirewallState,
    anchor_name: String,
}

#[cfg(target_os = "macos")]
impl MacOsFirewallBackend {
    fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_owned(),
            driver: MacOsFirewallDriver::PacketFilter,
            state: MacOsFirewallState::Prepared,
            anchor_name: format!("com.apple/250.QuantumLink.{interface}"),
        }
    }

    fn enable(&self, mode: MacOsLeakProtectionMode, dns_server: IpAddr) -> QuantumLinkResult<()> {
        let _ = (
            &self.interface,
            &self.driver,
            &self.state,
            &self.anchor_name,
            mode,
            dns_server,
        );
        Err(QuantumLinkError::NotImplemented(
			"macOS firewall backend shape is defined but native packet-filter integration is not implemented yet"
				.to_owned(),
		))
    }

    fn disable_all(&self) -> QuantumLinkResult<()> {
        let _ = (&self.interface, &self.state, &self.anchor_name);
        Err(QuantumLinkError::NotImplemented(
            "macOS firewall backend shape is defined but native cleanup is not implemented yet"
                .to_owned(),
        ))
    }

    fn is_active(&self) -> QuantumLinkResult<bool> {
        let _ = (&self.interface, &self.driver, &self.state);
        Err(QuantumLinkError::NotImplemented(
			"macOS firewall backend shape is defined but native state reporting is not implemented yet"
				.to_owned(),
		))
    }

    fn bridge_request(
        &self,
        operation: MacOsFirewallOperationMode,
        dns_server: Option<IpAddr>,
        peer_endpoint: Option<SocketAddr>,
    ) -> MacOsFirewallBridgeRequest {
        MacOsFirewallBridgeRequest {
            anchor_name: self.anchor_name.clone(),
            interface_name: self.interface.clone(),
            driver: "packet-filter",
            operation,
            dns_server,
            peer_endpoint,
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

#[cfg(target_os = "macos")]
impl FirewallManager {
    /// Enables the full kill switch ruleset.
    ///
    /// # Errors
    ///
    /// Always returns `NotImplemented` until the native macOS backend lands.
    #[must_use]
    pub fn enable_kill_switch(&self, dns_server: IpAddr) -> QuantumLinkResult<()> {
        MacOsFirewallBackend::new(&self.interface)
            .enable(MacOsLeakProtectionMode::KillSwitch, dns_server)
    }

    /// Enables DNS leak protection without a full kill switch.
    ///
    /// # Errors
    ///
    /// Always returns `NotImplemented` until the native macOS backend lands.
    #[must_use]
    pub fn enable_dns_protection(&self, dns_server: IpAddr) -> QuantumLinkResult<()> {
        MacOsFirewallBackend::new(&self.interface)
            .enable(MacOsLeakProtectionMode::DnsOnly, dns_server)
    }

    /// Removes all QuantumLink-managed firewall rules.
    ///
    /// # Errors
    ///
    /// Always returns `NotImplemented` until the native macOS backend lands.
    #[must_use]
    pub fn disable_all(&self) -> QuantumLinkResult<()> {
        MacOsFirewallBackend::new(&self.interface).disable_all()
    }

    /// Returns whether the firewall rules are active.
    ///
    /// # Errors
    ///
    /// Always returns `NotImplemented` until the native macOS backend lands.
    #[must_use]
    pub fn is_active(&self) -> QuantumLinkResult<bool> {
        MacOsFirewallBackend::new(&self.interface).is_active()
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
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

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn not_implemented() -> QuantumLinkError {
    QuantumLinkError::NotImplemented(
        "Firewall management is implemented for Linux only in v0.1".to_owned(),
    )
}

#[cfg(target_os = "linux")]
fn platform_backend_name() -> &'static str {
    "linux-reference"
}

#[cfg(target_os = "macos")]
fn platform_backend_name() -> &'static str {
    "macos-scaffold"
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_backend_name() -> &'static str {
    "stub"
}

#[cfg(target_os = "linux")]
fn firewall_backend_descriptor() -> FirewallBackendDescriptor {
    FirewallBackendDescriptor {
        name: "linux-reference",
        product_target: false,
        native_execution: true,
        note: "reference nftables backend used while the macOS product path is built",
    }
}

#[cfg(target_os = "macos")]
fn firewall_backend_descriptor() -> FirewallBackendDescriptor {
    FirewallBackendDescriptor {
        name: "macos-scaffold",
        product_target: true,
        native_execution: false,
        note: "typed macOS packet-filter backend shape without native execution yet",
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn firewall_backend_descriptor() -> FirewallBackendDescriptor {
    FirewallBackendDescriptor {
        name: "stub",
        product_target: false,
        native_execution: false,
        note: "unsupported-target placeholder backend",
    }
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
    use super::{FirewallBackendDescriptor, FirewallManager, PlatformFirewall};
    #[cfg(target_os = "macos")]
    use super::{
        MacOsFirewallBackend, MacOsFirewallBridgeExecutor, MacOsFirewallBridgeRequest,
        MacOsFirewallDriver, MacOsFirewallOperationMode, MacOsFirewallState,
    };

    #[cfg(target_os = "macos")]
    use ql_core::QuantumLinkResult;
    #[cfg(target_os = "macos")]
    use std::cell::RefCell;
    #[cfg(target_os = "linux")]
    use std::net::{IpAddr, Ipv4Addr};
    #[cfg(target_os = "macos")]
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn constructor_preserves_interface_name() {
        let firewall = FirewallManager::new("ql0");

        assert_eq!(firewall, FirewallManager::new("ql0"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_backend_name_reports_scaffold() {
        assert_eq!(PlatformFirewall::backend_name(), "macos-scaffold");
    }

    #[test]
    fn backend_descriptor_exposes_target_state() {
        let descriptor: FirewallBackendDescriptor = PlatformFirewall::backend_descriptor();
        assert_eq!(descriptor.name, PlatformFirewall::backend_name());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_backend_initializes_native_shape() {
        let backend = MacOsFirewallBackend::new("ql0");

        assert_eq!(backend.driver, MacOsFirewallDriver::PacketFilter);
        assert_eq!(backend.state, MacOsFirewallState::Prepared);
        assert_eq!(backend.anchor_name, "com.apple/250.QuantumLink.ql0");
        assert!(backend
            .enable(
                super::MacOsLeakProtectionMode::DnsOnly,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
            )
            .is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_bridge_request_carries_firewall_configuration() {
        let firewall = PlatformFirewall::new("ql0");
        let peer_endpoint = Some("198.51.100.8:51820".parse::<SocketAddr>().unwrap());
        let request = firewall
            .macos_kill_switch_request(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), peer_endpoint);

        assert_eq!(request.driver, "packet-filter");
        assert_eq!(request.anchor_name, "com.apple/250.QuantumLink.ql0");
        assert_eq!(request.interface_name, "ql0");
        assert_eq!(request.operation, MacOsFirewallOperationMode::KillSwitch);
        assert_eq!(
            request.dns_server,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(request.peer_endpoint, peer_endpoint);
    }

    #[cfg(target_os = "macos")]
    #[derive(Default)]
    struct RecordingFirewallExecutor {
        operations: RefCell<Vec<String>>,
    }

    #[cfg(target_os = "macos")]
    impl MacOsFirewallBridgeExecutor for RecordingFirewallExecutor {
        fn execute_firewall_request(
            &self,
            request: &MacOsFirewallBridgeRequest,
        ) -> QuantumLinkResult<Option<bool>> {
            self.operations.borrow_mut().push(format!(
                "{}:{}",
                request.interface_name,
                match request.operation {
                    MacOsFirewallOperationMode::KillSwitch => "kill",
                    MacOsFirewallOperationMode::DnsOnly => "dns",
                    MacOsFirewallOperationMode::DisableAll => "disable",
                    MacOsFirewallOperationMode::QueryActive => "query",
                }
            ));

            if matches!(request.operation, MacOsFirewallOperationMode::QueryActive) {
                Ok(Some(true))
            } else {
                Ok(None)
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_executor_methods_consume_bridge_requests() {
        let firewall = PlatformFirewall::new("ql0");
        let executor = RecordingFirewallExecutor::default();
        let dns = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer_endpoint = Some("198.51.100.8:51820".parse::<SocketAddr>().unwrap());

        firewall
            .enable_kill_switch_with_executor(&executor, dns, peer_endpoint)
            .unwrap();
        firewall
            .enable_dns_protection_with_executor(&executor, dns)
            .unwrap();
        firewall.disable_all_with_executor(&executor).unwrap();
        let active = firewall.is_active_with_executor(&executor).unwrap();

        assert!(active);
        assert_eq!(
            executor.operations.borrow().as_slice(),
            ["ql0:kill", "ql0:dns", "ql0:disable", "ql0:query"]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kill_switch_ruleset_uses_quantumlink_table() {
        let ruleset =
            super::build_kill_switch_ruleset("ql0", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        assert!(ruleset.contains("table inet quantumlink"));
        assert!(ruleset.contains("oifname \"ql0\" accept"));
    }
}
