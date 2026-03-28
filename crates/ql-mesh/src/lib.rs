//! Peer lifecycle and mesh session management for QuantumLink.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;

use ql_core::{
    ConnectionPath, DeviceCertificate, QuantumLinkError, QuantumLinkResult, RelayPolicy,
};

/// Mesh manager configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshConfig {
    /// Whether direct paths should automatically replace relayed paths when they appear.
    pub auto_upgrade_paths: bool,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            auto_upgrade_paths: true,
        }
    }
}

/// Static identity and policy for a mesh peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshPeer {
    /// WireGuard public key of the peer.
    pub peer_key: [u8; 32],
    /// Issued certificate serial associated with the peer.
    pub certificate_serial: String,
    /// CA fingerprint that issued the peer certificate.
    pub issuer_fingerprint: String,
    /// User-facing peer display name.
    pub display_name: String,
    /// Mesh overlay IP bound into the peer certificate.
    pub overlay_ip: IpAddr,
    /// Certificate groups carried for policy checks.
    pub groups: Vec<String>,
    /// Current relay policy for this peer.
    pub relay_policy: RelayPolicy,
    /// Optional self-hosted relay endpoint.
    pub self_hosted_relay: Option<SocketAddr>,
    /// Optional approved community relay endpoint.
    pub community_relay: Option<SocketAddr>,
}

impl MeshPeer {
    /// Builds a mesh peer projection from an issued device certificate.
    #[must_use]
    pub fn from_certificate(
        certificate: &DeviceCertificate,
        relay_policy: RelayPolicy,
        self_hosted_relay: Option<SocketAddr>,
        community_relay: Option<SocketAddr>,
    ) -> Self {
        Self {
            peer_key: certificate.wg_public_key,
            certificate_serial: certificate.serial.clone(),
            issuer_fingerprint: certificate.issuer_fingerprint.clone(),
            display_name: certificate.device_name.clone(),
            overlay_ip: certificate.overlay_ip,
            groups: certificate.groups.clone(),
            relay_policy,
            self_hosted_relay,
            community_relay,
        }
    }
}

/// Live mesh dashboard snapshot for a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshPeerStatus {
    /// WireGuard public key of the peer.
    pub peer_key: [u8; 32],
    /// User-facing peer display name.
    pub display_name: String,
    /// Current relay policy for this peer.
    pub relay_policy: RelayPolicy,
    /// Currently selected path.
    pub path: ConnectionPath,
    /// Packet loss in basis points.
    pub packet_loss_bps: u16,
    /// Age of the latest Rosenpass PSK in seconds.
    pub psk_age_seconds: u64,
    /// Best currently-known direct endpoint.
    pub direct_candidate: Option<SocketAddr>,
    /// Best currently-known relay endpoint.
    pub relay_candidate: Option<SocketAddr>,
}

/// Mesh manager responsible for peer state and path selection.
#[derive(Debug, Default)]
pub struct MeshManager {
    config: MeshConfig,
    peers: HashMap<[u8; 32], PeerState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerState {
    peer: MeshPeer,
    direct_candidate: Option<PathCandidate>,
    relay_candidate: Option<PathCandidate>,
    active_path: ConnectionPath,
    packet_loss_bps: u16,
    psk_age_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathCandidate {
    endpoint: SocketAddr,
    latency_ms: u32,
}

impl MeshManager {
    /// Creates a mesh manager.
    #[must_use]
    pub fn new(config: MeshConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
        }
    }

    /// Adds or replaces a mesh peer.
    pub fn upsert_peer(&mut self, peer: MeshPeer) {
        let peer_key = peer.peer_key;
        let existing = self.peers.remove(&peer_key);
        let mut state = existing.unwrap_or_else(|| PeerState {
            peer: peer.clone(),
            direct_candidate: None,
            relay_candidate: None,
            active_path: ConnectionPath::Unavailable,
            packet_loss_bps: 0,
            psk_age_seconds: 0,
        });
        state.peer = peer;
        state.refresh_relay_candidate();
        state.recompute_active_path(self.config.auto_upgrade_paths);
        self.peers.insert(peer_key, state);
    }

    /// Removes a peer from mesh management.
    #[must_use]
    pub fn remove_peer(&mut self, peer_key: [u8; 32]) -> bool {
        self.peers.remove(&peer_key).is_some()
    }

    /// Updates the measured direct path for a peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer is unknown.
    pub fn set_direct_candidate(
        &mut self,
        peer_key: [u8; 32],
        endpoint: SocketAddr,
        latency_ms: u32,
    ) -> QuantumLinkResult<()> {
        let auto_upgrade_paths = self.config.auto_upgrade_paths;
        let state = self.peer_state_mut(peer_key)?;
        state.direct_candidate = Some(PathCandidate {
            endpoint,
            latency_ms,
        });
        state.recompute_active_path(auto_upgrade_paths);
        Ok(())
    }

    /// Clears the direct path candidate for a peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer is unknown.
    pub fn clear_direct_candidate(&mut self, peer_key: [u8; 32]) -> QuantumLinkResult<()> {
        let auto_upgrade_paths = self.config.auto_upgrade_paths;
        let state = self.peer_state_mut(peer_key)?;
        state.direct_candidate = None;
        state.recompute_active_path(auto_upgrade_paths);
        Ok(())
    }

    /// Updates the relay endpoint currently available for a peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer is unknown.
    pub fn set_relay_latency(
        &mut self,
        peer_key: [u8; 32],
        latency_ms: u32,
    ) -> QuantumLinkResult<()> {
        let auto_upgrade_paths = self.config.auto_upgrade_paths;
        let state = self.peer_state_mut(peer_key)?;
        let relay_endpoint = state.preferred_relay_endpoint().ok_or_else(|| {
            QuantumLinkError::Config("no relay endpoint configured for peer".to_owned())
        })?;
        state.relay_candidate = Some(PathCandidate {
            endpoint: relay_endpoint,
            latency_ms,
        });
        state.recompute_active_path(auto_upgrade_paths);
        Ok(())
    }

    /// Clears the relay candidate for a peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer is unknown.
    pub fn clear_relay_candidate(&mut self, peer_key: [u8; 32]) -> QuantumLinkResult<()> {
        let auto_upgrade_paths = self.config.auto_upgrade_paths;
        let state = self.peer_state_mut(peer_key)?;
        state.relay_candidate = None;
        state.recompute_active_path(auto_upgrade_paths);
        Ok(())
    }

    /// Updates the relay policy for a peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer is unknown.
    pub fn set_relay_policy(
        &mut self,
        peer_key: [u8; 32],
        policy: RelayPolicy,
    ) -> QuantumLinkResult<()> {
        let auto_upgrade_paths = self.config.auto_upgrade_paths;
        let state = self.peer_state_mut(peer_key)?;
        state.peer.relay_policy = policy;
        state.refresh_relay_candidate();
        state.recompute_active_path(auto_upgrade_paths);
        Ok(())
    }

    /// Updates packet-loss telemetry for a peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer is unknown.
    pub fn update_packet_loss(
        &mut self,
        peer_key: [u8; 32],
        packet_loss_bps: u16,
    ) -> QuantumLinkResult<()> {
        let state = self.peer_state_mut(peer_key)?;
        state.packet_loss_bps = packet_loss_bps;
        Ok(())
    }

    /// Updates Rosenpass PSK age telemetry for a peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer is unknown.
    pub fn update_psk_age(
        &mut self,
        peer_key: [u8; 32],
        psk_age_seconds: u64,
    ) -> QuantumLinkResult<()> {
        let state = self.peer_state_mut(peer_key)?;
        state.psk_age_seconds = psk_age_seconds;
        Ok(())
    }

    /// Returns the current path for a peer.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer is unknown.
    pub fn path_for(&self, peer_key: [u8; 32]) -> QuantumLinkResult<ConnectionPath> {
        self.peers
            .get(&peer_key)
            .map(|state| state.active_path.clone())
            .ok_or_else(|| QuantumLinkError::Config("unknown mesh peer".to_owned()))
    }

    /// Returns dashboard snapshots for all peers.
    #[must_use]
    pub fn dashboard(&self) -> Vec<MeshPeerStatus> {
        let mut peers = self
            .peers
            .values()
            .map(|state| MeshPeerStatus {
                peer_key: state.peer.peer_key,
                display_name: state.peer.display_name.clone(),
                relay_policy: state.peer.relay_policy.clone(),
                path: state.active_path.clone(),
                packet_loss_bps: state.packet_loss_bps,
                psk_age_seconds: state.psk_age_seconds,
                direct_candidate: state.direct_candidate.map(|candidate| candidate.endpoint),
                relay_candidate: state.relay_candidate.map(|candidate| candidate.endpoint),
            })
            .collect::<Vec<_>>();
        peers.sort_by(|left, right| left.display_name.cmp(&right.display_name));
        peers
    }

    fn peer_state_mut(&mut self, peer_key: [u8; 32]) -> QuantumLinkResult<&mut PeerState> {
        self.peers
            .get_mut(&peer_key)
            .ok_or_else(|| QuantumLinkError::Config("unknown mesh peer".to_owned()))
    }
}

impl PeerState {
    fn refresh_relay_candidate(&mut self) {
        self.relay_candidate = self
            .preferred_relay_endpoint()
            .map(|endpoint| PathCandidate {
                endpoint,
                latency_ms: self
                    .relay_candidate
                    .map(|candidate| candidate.latency_ms)
                    .unwrap_or_default(),
            });
    }

    fn preferred_relay_endpoint(&self) -> Option<SocketAddr> {
        match self.peer.relay_policy {
            RelayPolicy::SelfHosted => self.peer.self_hosted_relay,
            RelayPolicy::Community => self.peer.community_relay,
            RelayPolicy::Ask | RelayPolicy::None => None,
        }
    }

    fn recompute_active_path(&mut self, auto_upgrade_paths: bool) {
        let preferred_path = if let Some(direct_candidate) = self.direct_candidate {
            ConnectionPath::DirectP2P {
                latency_ms: direct_candidate.latency_ms,
            }
        } else if let Some(relay_candidate) = self.relay_candidate {
            ConnectionPath::Relayed {
                relay_endpoint: relay_candidate.endpoint,
                latency_ms: relay_candidate.latency_ms,
            }
        } else {
            ConnectionPath::Unavailable
        };

        self.active_path = match (&self.active_path, preferred_path) {
            (ConnectionPath::Relayed { .. }, direct @ ConnectionPath::DirectP2P { .. })
                if auto_upgrade_paths =>
            {
                direct
            }
            (ConnectionPath::Relayed { .. }, ConnectionPath::DirectP2P { .. }) => {
                self.active_path.clone()
            }
            (_, next_path) => next_path,
        };
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use ql_core::{ConnectionPath, DeviceCertificate, RelayPolicy};

    use super::{MeshConfig, MeshManager, MeshPeer};

    fn sample_peer(relay_policy: RelayPolicy) -> MeshPeer {
        MeshPeer::from_certificate(
            &DeviceCertificate {
                serial: "cert-9".to_owned(),
                device_name: "Rick Laptop".to_owned(),
                overlay_ip: "10.42.0.9".parse().unwrap(),
                groups: vec!["personal".to_owned()],
                wg_public_key: [9_u8; 32],
                rosenpass_fingerprint: "rp-fingerprint".to_owned(),
                issuer_fingerprint: "ca-fingerprint".to_owned(),
                valid_from: 1_700_000_000,
                valid_until: 1_700_086_400,
            },
            relay_policy,
            Some("198.51.100.20:51821".parse::<SocketAddr>().unwrap()),
            Some("203.0.113.42:51821".parse::<SocketAddr>().unwrap()),
        )
    }

    #[test]
    fn builds_mesh_peer_from_certificate() {
        let peer = MeshPeer::from_certificate(
            &DeviceCertificate {
                serial: "cert-42".to_owned(),
                device_name: "Studio Mac".to_owned(),
                overlay_ip: "10.42.0.42".parse().unwrap(),
                groups: vec!["prod".to_owned()],
                wg_public_key: [4_u8; 32],
                rosenpass_fingerprint: "rp-42".to_owned(),
                issuer_fingerprint: "ca-fingerprint".to_owned(),
                valid_from: 1_700_000_000,
                valid_until: 1_700_086_400,
            },
            RelayPolicy::Ask,
            None,
            None,
        );

        assert_eq!(peer.peer_key, [4_u8; 32]);
        assert_eq!(peer.certificate_serial, "cert-42");
        assert_eq!(peer.display_name, "Studio Mac");
        assert_eq!(
            peer.overlay_ip,
            "10.42.0.42".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn prefers_direct_path_over_relay() {
        let mut manager = MeshManager::new(MeshConfig::default());
        manager.upsert_peer(sample_peer(RelayPolicy::SelfHosted));
        manager.set_relay_latency([9_u8; 32], 80).unwrap();
        manager
            .set_direct_candidate([9_u8; 32], "10.0.0.2:51820".parse().unwrap(), 25)
            .unwrap();

        assert_eq!(
            manager.path_for([9_u8; 32]).unwrap(),
            ConnectionPath::DirectP2P { latency_ms: 25 }
        );
    }

    #[test]
    fn relay_policy_none_blocks_relay_fallback() {
        let mut manager = MeshManager::new(MeshConfig::default());
        manager.upsert_peer(sample_peer(RelayPolicy::None));
        assert!(manager.set_relay_latency([9_u8; 32], 90).is_err());
        assert_eq!(
            manager.path_for([9_u8; 32]).unwrap(),
            ConnectionPath::Unavailable
        );
    }

    #[test]
    fn self_hosted_relay_is_used_when_direct_is_unavailable() {
        let mut manager = MeshManager::new(MeshConfig::default());
        manager.upsert_peer(sample_peer(RelayPolicy::SelfHosted));
        manager.set_relay_latency([9_u8; 32], 90).unwrap();

        assert_eq!(
            manager.path_for([9_u8; 32]).unwrap(),
            ConnectionPath::Relayed {
                relay_endpoint: "198.51.100.20:51821".parse().unwrap(),
                latency_ms: 90,
            }
        );
    }

    #[test]
    fn auto_upgrade_promotes_direct_path_after_relay() {
        let mut manager = MeshManager::new(MeshConfig {
            auto_upgrade_paths: true,
        });
        manager.upsert_peer(sample_peer(RelayPolicy::Community));
        manager.set_relay_latency([9_u8; 32], 110).unwrap();
        manager
            .set_direct_candidate([9_u8; 32], "10.0.0.3:51820".parse().unwrap(), 18)
            .unwrap();

        assert_eq!(
            manager.path_for([9_u8; 32]).unwrap(),
            ConnectionPath::DirectP2P { latency_ms: 18 }
        );
    }

    #[test]
    fn dashboard_includes_packet_loss_and_psk_age() {
        let mut manager = MeshManager::new(MeshConfig::default());
        manager.upsert_peer(sample_peer(RelayPolicy::SelfHosted));
        manager.set_relay_latency([9_u8; 32], 70).unwrap();
        manager.update_packet_loss([9_u8; 32], 125).unwrap();
        manager.update_psk_age([9_u8; 32], 33).unwrap();

        let dashboard = manager.dashboard();
        assert_eq!(dashboard.len(), 1);
        assert_eq!(dashboard[0].packet_loss_bps, 125);
        assert_eq!(dashboard[0].psk_age_seconds, 33);
        assert_eq!(
            dashboard[0].relay_candidate,
            Some("198.51.100.20:51821".parse().unwrap())
        );
    }
}
