//! STUN and NAT traversal support for QuantumLink.

#![forbid(unsafe_code)]

use std::net::SocketAddr;

use ql_core::{QuantumLinkError, QuantumLinkResult};

/// Configuration for STUN probing and optional router port mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunConfig {
	/// Public STUN servers used to classify the current NAT.
	pub stun_servers: Vec<SocketAddr>,
	/// The WireGuard UDP port that must be probed.
	pub wireguard_port: u16,
	/// Whether NAT-PMP probing should be attempted.
	pub nat_pmp_enabled: bool,
	/// Whether UPnP probing should be attempted.
	pub upnp_enabled: bool,
}

/// Observed NAT classification after probing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatType {
	/// The interface has a public IP address directly.
	DirectAccess,
	/// Full-cone NAT.
	FullCone,
	/// Restricted-cone NAT.
	RestrictedCone,
	/// Port-restricted-cone NAT.
	PortRestrictedCone,
	/// Symmetric NAT.
	Symmetric,
	/// CGNAT or an otherwise opaque provider network.
	CGNAT,
	/// NAT type could not be determined.
	Unknown,
}

/// STUN probe result returned to the mesh manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunResult {
	/// External endpoint observed by the STUN server.
	pub external_endpoint: SocketAddr,
	/// Classified NAT type.
	pub nat_type: NatType,
	/// Optional external endpoint from UPnP or NAT-PMP mapping.
	pub upnp_mapped: Option<SocketAddr>,
}

/// STUN client API surface reserved for the v0.2 mesh implementation.
#[derive(Debug, Default)]
pub struct StunClient;

impl StunClient {
	/// Probes STUN servers to discover the external endpoint and NAT type.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` in v0.1.
	#[must_use]
	pub async fn probe(config: &StunConfig) -> QuantumLinkResult<StunResult> {
		let _ = config;
		Err(QuantumLinkError::NotImplemented(
			"STUN: planned for v0.2".to_owned(),
		))
	}

	/// Requests a router port mapping via UPnP or NAT-PMP.
	///
	/// # Errors
	///
	/// Always returns `NotImplemented` in v0.1.
	#[must_use]
	pub async fn request_port_mapping(
		internal_port: u16,
		duration_secs: u32,
	) -> QuantumLinkResult<Option<SocketAddr>> {
		let _ = (internal_port, duration_secs);
		Err(QuantumLinkError::NotImplemented(
			"STUN: planned for v0.2".to_owned(),
		))
	}
}

#[cfg(test)]
mod tests {
	use super::{NatType, StunResult};

	#[test]
	fn stun_result_holds_expected_state() {
		let result = StunResult {
			external_endpoint: "198.51.100.20:51820".parse().unwrap(),
			nat_type: NatType::Unknown,
			upnp_mapped: None,
		};

		assert_eq!(result.external_endpoint.port(), 51_820);
		assert!(matches!(result.nat_type, NatType::Unknown));
	}
}
