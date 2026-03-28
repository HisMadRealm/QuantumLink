import Foundation
@preconcurrency import NetworkExtension
import QuantumLinkTunnelShared

#if canImport(Network)
import Network
#endif

#if canImport(WireGuardKit)
import WireGuardKit
#endif

final class QuantumLinkPacketTunnelProvider: NEPacketTunnelProvider {
	private var state = TunnelControllerState()

	#if canImport(WireGuardKit)
	private lazy var adapter: WireGuardAdapter = {
		WireGuardAdapter(with: self) { _, _ in }
	}()
	private var activeRequest: TunnelRequest?
	private var activePresharedKey: [UInt8]?
	#endif

	override func startTunnel(
		options: [String: NSObject]?,
		completionHandler: @escaping (Error?) -> Void
	) {
		do {
			let request = try loadRequest()
			state.lastOperation = "activate"
			state.lastPayload = nil
			state.endpoint = request.peerEndpoint

			#if canImport(WireGuardKit)
			startWireGuardTunnel(with: request, completionHandler: completionHandler)
			#else
			activateScaffoldTunnel(with: request, completionHandler: completionHandler)
			#endif
		} catch {
			completionHandler(error)
		}
	}

	override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
		#if canImport(WireGuardKit)
		adapter.stop { [weak self] _ in
			guard let self else {
				completionHandler()
				return
			}
			self.state.tunnelActive = false
			self.state.lastOperation = "deactivate"
			completionHandler()
		}
		#else
		state.tunnelActive = false
		state.lastOperation = "deactivate"
		completionHandler()
		#endif
	}

	override func handleAppMessage(
		_ messageData: Data,
		completionHandler: ((Data?) -> Void)? = nil
	) {
		guard let completionHandler else {
			return
		}
		guard let envelope = try? JSONDecoder().decode(TunnelEnvelope.self, from: messageData) else {
			completionHandler(
				encodeAck(
					for: "tunnel",
					operation: "unknown",
					accepted: false,
					message: "invalid provider message payload",
					includeStats: false
				)
			)
			return
		}

		let payload = String(decoding: messageData, as: UTF8.self)
		let operation = envelope.operation ?? (envelope.psk == nil ? "unknown" : "inject-psk")
		state.lastOperation = operation
		state.lastPayload = redactedTunnelPayload(payload)
		if let endpoint = envelope.request.peerEndpoint {
			state.endpoint = endpoint
		}

		#if canImport(WireGuardKit)
		handleWireGuardMessage(
			operation: operation,
			envelope: envelope,
			completionHandler: completionHandler
		)
		#else
		completionHandler(handleScaffoldMessage(operation: operation, envelope: envelope))
		#endif
	}

	private func loadRequest() throws -> TunnelRequest {
		guard let protocolConfiguration = protocolConfiguration as? NETunnelProviderProtocol else {
			throw ProviderError.missingConfiguration("missing tunnel protocol configuration")
		}
		guard let providerBundleIdentifier = protocolConfiguration.providerBundleIdentifier else {
			throw ProviderError.missingConfiguration("missing provider bundle identifier")
		}
		guard let providerConfiguration = protocolConfiguration.providerConfiguration else {
			throw ProviderError.missingConfiguration("missing provider configuration")
		}
		return try TunnelRequest.fromProviderConfiguration(
			providerBundleIdentifier: providerBundleIdentifier,
			config: providerConfiguration
		)
	}

	#if canImport(WireGuardKit)
	private func startWireGuardTunnel(
		with request: TunnelRequest,
		completionHandler: @escaping (Error?) -> Void
	) {
		do {
			let tunnelConfiguration = try makeTunnelConfiguration(from: request, psk: activePresharedKey)
			adapter.start(tunnelConfiguration: tunnelConfiguration) { [weak self] adapterError in
				guard let self else {
					completionHandler(adapterError)
					return
				}
				if let adapterError {
					completionHandler(adapterError)
					return
				}
				self.activeRequest = request
				self.state.tunnelActive = true
				self.state.endpoint = request.peerEndpoint
				self.refreshRuntimeStats {
					completionHandler(nil)
				}
			}
		} catch {
			completionHandler(error)
		}
	}

	private func handleWireGuardMessage(
		operation: String,
		envelope: TunnelEnvelope,
		completionHandler: @escaping (Data?) -> Void
	) {
		switch operation {
		case "activate":
			startWireGuardTunnel(with: envelope.request) { [weak self] error in
				guard let self else {
					completionHandler(nil)
					return
				}
				completionHandler(
					self.encodeAck(
						for: "tunnel",
						operation: operation,
						accepted: error == nil,
						message: error?.localizedDescription ?? "started WireGuard tunnel",
						includeStats: false
					)
				)
			}
		case "deactivate":
			adapter.stop { [weak self] error in
				guard let self else {
					completionHandler(nil)
					return
				}
				if error == nil {
					self.state.tunnelActive = false
				}
				completionHandler(
					self.encodeAck(
						for: "tunnel",
						operation: operation,
						accepted: error == nil,
						message: error?.localizedDescription ?? "stopped WireGuard tunnel",
						includeStats: false
					)
				)
			}
		case "update-endpoint":
			guard envelope.request.peerEndpoint != nil else {
				completionHandler(
					encodeAck(
						for: "tunnel",
						operation: operation,
						accepted: false,
						message: "update-endpoint requires peer_endpoint",
						includeStats: false
					)
				)
				return
			}
			applyRuntimeUpdate(request: envelope.request, psk: activePresharedKey, operation: operation, completionHandler: completionHandler)
		case "inject-psk":
			guard let psk = envelope.psk else {
				completionHandler(
					encodeAck(
						for: "tunnel",
						operation: operation,
						accepted: false,
						message: "inject-psk requires psk",
						includeStats: false
					)
				)
				return
			}
			activePresharedKey = psk
			applyRuntimeUpdate(request: activeRequest ?? envelope.request, psk: psk, operation: operation, completionHandler: completionHandler)
		case "read-stats":
			refreshRuntimeStats { [weak self] in
				guard let self else {
					completionHandler(nil)
					return
				}
				completionHandler(
					self.encodeAck(
						for: "tunnel",
						operation: operation,
						accepted: true,
						message: "reported WireGuard tunnel stats",
						includeStats: true
					)
				)
			}
		default:
			completionHandler(
				encodeAck(
					for: "tunnel",
					operation: operation,
					accepted: false,
					message: "unsupported provider operation: \(operation)",
					includeStats: false
				)
			)
		}
	}

	private func applyRuntimeUpdate(
		request: TunnelRequest,
		psk: [UInt8]?,
		operation: String,
		completionHandler: @escaping (Data?) -> Void
	) {
		do {
			let tunnelConfiguration = try makeTunnelConfiguration(from: request, psk: psk)
			adapter.update(tunnelConfiguration: tunnelConfiguration) { [weak self] adapterError in
				guard let self else {
					completionHandler(nil)
					return
				}
				if adapterError == nil {
					self.activeRequest = request
					self.state.endpoint = request.peerEndpoint
					self.refreshRuntimeStats {
						completionHandler(
							self.encodeAck(
								for: "tunnel",
								operation: operation,
								accepted: true,
								message: "updated WireGuard tunnel runtime",
								includeStats: operation == "read-stats"
							)
						)
					}
				} else {
					completionHandler(
						self.encodeAck(
							for: "tunnel",
							operation: operation,
							accepted: false,
							message: adapterError?.localizedDescription ?? "failed to update WireGuard tunnel",
							includeStats: false
						)
					)
				}
			}
		} catch {
			completionHandler(
				encodeAck(
					for: "tunnel",
					operation: operation,
					accepted: false,
					message: error.localizedDescription,
					includeStats: false
				)
			)
		}
	}

	private func refreshRuntimeStats(completionHandler: @escaping () -> Void) {
		adapter.getRuntimeConfiguration { [weak self] runtimeConfiguration in
			guard let self else {
				completionHandler()
				return
			}
			if let runtimeConfiguration {
				self.state.tunnelStats = Self.parseTunnelStats(from: runtimeConfiguration)
			}
			completionHandler()
		}
	}

	private func makeTunnelConfiguration(from request: TunnelRequest, psk: [UInt8]?) throws -> TunnelConfiguration {
		guard let privateKey = PrivateKey(base64Key: Data(request.privateKey).base64EncodedString()) else {
			throw ProviderError.invalidConfiguration("invalid private key")
		}
		var interface = InterfaceConfiguration(privateKey: privateKey)
		interface.addresses = try request.interfaceAddresses.map { address in
			guard let parsed = IPAddressRange(from: address) else {
				throw ProviderError.invalidConfiguration("invalid interface address: \(address)")
			}
			return parsed
		}
		interface.listenPort = request.listenPort
		interface.mtu = request.mtu
		interface.dns = try request.dnsServers.compactMap { server in
			guard let parsed = DNSServer(from: server) else {
				throw ProviderError.invalidConfiguration("invalid dns server: \(server)")
			}
			return parsed
		}

		guard let publicKey = PublicKey(base64Key: Data(request.peerPublicKey).base64EncodedString()) else {
			throw ProviderError.invalidConfiguration("invalid peer public key")
		}
		var peer = PeerConfiguration(publicKey: publicKey)
		peer.allowedIPs = try request.allowedIps.map { allowedIp in
			guard let parsed = IPAddressRange(from: allowedIp) else {
				throw ProviderError.invalidConfiguration("invalid allowed IP: \(allowedIp)")
			}
			return parsed
		}
		if let peerEndpoint = request.peerEndpoint {
			guard let endpoint = Endpoint(from: peerEndpoint) else {
				throw ProviderError.invalidConfiguration("invalid peer endpoint: \(peerEndpoint)")
			}
			peer.endpoint = endpoint
		}
		peer.persistentKeepAlive = request.persistentKeepalive
		if let psk,
		   let presharedKey = PreSharedKey(base64Key: Data(psk).base64EncodedString()) {
			peer.preSharedKey = presharedKey
		}

		return TunnelConfiguration(name: request.interfaceName, interface: interface, peers: [peer])
	}

	private static func parseTunnelStats(from runtimeConfiguration: String) -> TunnelStatsPayload {
		var bytesSent: UInt64 = 0
		var bytesReceived: UInt64 = 0
		var lastHandshakeSecs: UInt64?

		for line in runtimeConfiguration.split(separator: "\n") {
			guard let separatorIndex = line.firstIndex(of: "=") else {
				continue
			}
			let key = line[..<separatorIndex]
			let value = line[line.index(after: separatorIndex)...]
			switch key {
			case "tx_bytes":
				bytesSent = UInt64(value) ?? bytesSent
			case "rx_bytes":
				bytesReceived = UInt64(value) ?? bytesReceived
			case "last_handshake_time_sec":
				let handshake = UInt64(value) ?? 0
				lastHandshakeSecs = handshake == 0 ? nil : handshake
			default:
				continue
			}
		}

		return TunnelStatsPayload(
			bytesSent: bytesSent,
			bytesReceived: bytesReceived,
			lastHandshakeSecs: lastHandshakeSecs
		)
	}
	#endif

	private func activateScaffoldTunnel(
		with request: TunnelRequest,
		completionHandler: @escaping (Error?) -> Void
	) {
		state.tunnelActive = true
		state.endpoint = request.peerEndpoint
		state.tunnelStats.lastHandshakeSecs = 0
		applyScaffoldNetworkSettings(for: request, completionHandler: completionHandler)
	}

	private func applyScaffoldNetworkSettings(
		for request: TunnelRequest,
		completionHandler: @escaping (Error?) -> Void
	) {
		let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: request.serverAddress)
		let ipv4Addresses = request.interfaceAddresses.compactMap(Self.parseIPv4Address)
		let ipv4Subnets = request.interfaceAddresses.compactMap(Self.parseIPv4SubnetMask)
		if !ipv4Addresses.isEmpty, ipv4Addresses.count == ipv4Subnets.count {
			let ipv4Settings = NEIPv4Settings(addresses: ipv4Addresses, subnetMasks: ipv4Subnets)
			ipv4Settings.includedRoutes = request.allowedIps.compactMap(Self.parseIPv4Route)
			settings.ipv4Settings = ipv4Settings
		}
		if !request.dnsServers.isEmpty {
			settings.dnsSettings = NEDNSSettings(servers: request.dnsServers)
		}
		settings.mtu = NSNumber(value: request.mtu)

		setTunnelNetworkSettings(settings, completionHandler: completionHandler)
	}

	private func handleScaffoldMessage(operation: String, envelope: TunnelEnvelope) -> Data? {
		switch operation {
		case "activate":
			state.tunnelActive = true
			state.tunnelStats.lastHandshakeSecs = 0
		case "deactivate":
			state.tunnelActive = false
		case "update-endpoint":
			guard envelope.request.peerEndpoint != nil else {
				return encodeAck(
					for: "tunnel",
					operation: operation,
					accepted: false,
					message: "update-endpoint requires peer_endpoint",
					includeStats: false
				)
			}
		case "inject-psk":
			guard envelope.psk != nil else {
				return encodeAck(
					for: "tunnel",
					operation: operation,
					accepted: false,
					message: "inject-psk requires psk",
					includeStats: false
				)
			}
			state.tunnelStats.bytesSent += 16
		case "read-stats":
			break
		default:
			return encodeAck(
				for: "tunnel",
				operation: operation,
				accepted: false,
				message: "unsupported provider operation: \(operation)",
				includeStats: false
			)
		}

		let includeStats = operation == "read-stats"
		return encodeAck(
			for: "tunnel",
			operation: operation,
			accepted: true,
			message: "applied provider operation \(operation)",
			includeStats: includeStats
		)
	}

	private func encodeAck(
		for target: String,
		operation: String,
		accepted: Bool,
		message: String,
		includeStats: Bool
	) -> Data? {
		let ack = TunnelControllerAck(
			target: target,
			operation: operation,
			accepted: accepted,
			message: message,
			state: state,
			tunnelStats: includeStats ? state.tunnelStats : nil
		)
		let encoder = JSONEncoder()
		encoder.outputFormatting = [.sortedKeys]
		return try? encoder.encode(ack)
	}

	private static func parseIPv4Address(_ cidr: String) -> String? {
		String(cidr.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: true).first ?? "")
			.nilIfEmpty
	}

	private static func parseIPv4SubnetMask(_ cidr: String) -> String? {
		guard let prefixText = cidr.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: true).last,
			  let prefix = Int(prefixText),
			  (0...32).contains(prefix)
		else {
			return nil
		}
		let mask = prefix == 0 ? UInt32(0) : UInt32.max << (32 - prefix)
		return [24, 16, 8, 0].map { String((mask >> $0) & 0xff) }.joined(separator: ".")
	}

	private static func parseIPv4Route(_ cidr: String) -> NEIPv4Route? {
		guard let address = parseIPv4Address(cidr),
			  let subnetMask = parseIPv4SubnetMask(cidr)
		else {
			return nil
		}
		return NEIPv4Route(destinationAddress: address, subnetMask: subnetMask)
	}
}

private enum ProviderError: Error, LocalizedError {
	case missingConfiguration(String)
	case invalidConfiguration(String)

	var errorDescription: String? {
		switch self {
		case .missingConfiguration(let message):
			return "packet tunnel provider error: \(message)"
		case .invalidConfiguration(let message):
			return "packet tunnel provider configuration error: \(message)"
		}
	}
}

private extension String {
	var nilIfEmpty: String? {
		isEmpty ? nil : self
	}
}
