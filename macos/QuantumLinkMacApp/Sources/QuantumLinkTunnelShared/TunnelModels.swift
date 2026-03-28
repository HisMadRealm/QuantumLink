import Foundation

public struct TunnelControllerAck: Codable {
	public let target: String
	public let operation: String
	public let accepted: Bool
	public let message: String
	public let state: TunnelControllerState
	public let tunnelStats: TunnelStatsPayload?

	public init(
		target: String,
		operation: String,
		accepted: Bool,
		message: String,
		state: TunnelControllerState,
		tunnelStats: TunnelStatsPayload?
	) {
		self.target = target
		self.operation = operation
		self.accepted = accepted
		self.message = message
		self.state = state
		self.tunnelStats = tunnelStats
	}

	enum CodingKeys: String, CodingKey {
		case target
		case operation
		case accepted
		case message
		case state
		case tunnelStats = "tunnel_stats"
	}
}

public struct TunnelControllerState: Codable, Equatable {
	public var tunnelActive: Bool
	public var lastOperation: String?
	public var lastPayload: String?
	public var endpoint: String?
	public var tunnelStats: TunnelStatsPayload

	public init(
		tunnelActive: Bool = false,
		lastOperation: String? = nil,
		lastPayload: String? = nil,
		endpoint: String? = nil,
		tunnelStats: TunnelStatsPayload = TunnelStatsPayload()
	) {
		self.tunnelActive = tunnelActive
		self.lastOperation = lastOperation
		self.lastPayload = lastPayload
		self.endpoint = endpoint
		self.tunnelStats = tunnelStats
	}

	enum CodingKeys: String, CodingKey {
		case tunnelActive = "tunnel_active"
		case lastOperation = "last_operation"
		case lastPayload = "last_payload"
		case endpoint
		case tunnelStats = "tunnel_stats"
	}
}

public struct TunnelStatsPayload: Codable, Equatable {
	public var bytesSent: UInt64
	public var bytesReceived: UInt64
	public var lastHandshakeSecs: UInt64?

	public init(
		bytesSent: UInt64 = 0,
		bytesReceived: UInt64 = 0,
		lastHandshakeSecs: UInt64? = nil
	) {
		self.bytesSent = bytesSent
		self.bytesReceived = bytesReceived
		self.lastHandshakeSecs = lastHandshakeSecs
	}

	enum CodingKeys: String, CodingKey {
		case bytesSent = "bytes_sent"
		case bytesReceived = "bytes_received"
		case lastHandshakeSecs = "last_handshake_secs"
	}
}

public struct TunnelEnvelope: Decodable {
	public let operation: String?
	public let request: TunnelRequest
	public let psk: [UInt8]?
}

public struct TunnelRequest: Codable {
	public let providerBundleIdentifier: String
	public let driver: String
	public let interfaceName: String
	public let interfaceAddresses: [String]
	public let privateKey: [UInt8]
	public let listenPort: UInt16
	public let peerPublicKey: [UInt8]
	public let peerEndpoint: String?
	public let allowedIps: [String]
	public let persistentKeepalive: UInt16?
	public let dnsServers: [String]
	public let mtu: UInt16

	public init(
		providerBundleIdentifier: String,
		driver: String,
		interfaceName: String,
		interfaceAddresses: [String],
		privateKey: [UInt8],
		listenPort: UInt16,
		peerPublicKey: [UInt8],
		peerEndpoint: String?,
		allowedIps: [String],
		persistentKeepalive: UInt16?,
		dnsServers: [String],
		mtu: UInt16
	) {
		self.providerBundleIdentifier = providerBundleIdentifier
		self.driver = driver
		self.interfaceName = interfaceName
		self.interfaceAddresses = interfaceAddresses
		self.privateKey = privateKey
		self.listenPort = listenPort
		self.peerPublicKey = peerPublicKey
		self.peerEndpoint = peerEndpoint
		self.allowedIps = allowedIps
		self.persistentKeepalive = persistentKeepalive
		self.dnsServers = dnsServers
		self.mtu = mtu
	}

	enum CodingKeys: String, CodingKey {
		case providerBundleIdentifier = "provider_bundle_identifier"
		case driver
		case interfaceName = "interface_name"
		case interfaceAddresses = "interface_addresses"
		case privateKey = "private_key"
		case listenPort = "listen_port"
		case peerPublicKey = "peer_public_key"
		case peerEndpoint = "peer_endpoint"
		case allowedIps = "allowed_ips"
		case persistentKeepalive = "persistent_keepalive"
		case dnsServers = "dns_servers"
		case mtu
	}

	public var serverAddress: String {
		peerEndpoint ?? interfaceName
	}

	public var providerConfiguration: [String: Any] {
		var configuration: [String: Any] = [
			"driver": driver,
			"interface_name": interfaceName,
			"interface_addresses": interfaceAddresses,
			"private_key": privateKey.map(Int.init),
			"listen_port": Int(listenPort),
			"peer_public_key": peerPublicKey.map(Int.init),
			"allowed_ips": allowedIps,
			"dns_servers": dnsServers,
			"mtu": Int(mtu),
		]
		if let peerEndpoint {
			configuration["peer_endpoint"] = peerEndpoint
		}
		if let persistentKeepalive {
			configuration["persistent_keepalive"] = Int(persistentKeepalive)
		}
		return configuration
	}

	public static func fromProviderConfiguration(
		providerBundleIdentifier: String,
		config: [String: Any]
	) throws -> TunnelRequest {
		let data = try JSONSerialization.data(withJSONObject: config, options: [])
		let decoded = try JSONDecoder().decode(TunnelProviderConfiguration.self, from: data)
		return TunnelRequest(
			providerBundleIdentifier: providerBundleIdentifier,
			driver: decoded.driver,
			interfaceName: decoded.interfaceName,
			interfaceAddresses: decoded.interfaceAddresses,
			privateKey: decoded.privateKey,
			listenPort: decoded.listenPort,
			peerPublicKey: decoded.peerPublicKey,
			peerEndpoint: decoded.peerEndpoint,
			allowedIps: decoded.allowedIps,
			persistentKeepalive: decoded.persistentKeepalive,
			dnsServers: decoded.dnsServers,
			mtu: decoded.mtu
		)
	}
}

private struct TunnelProviderConfiguration: Decodable {
	let driver: String
	let interfaceName: String
	let interfaceAddresses: [String]
	let privateKey: [UInt8]
	let listenPort: UInt16
	let peerPublicKey: [UInt8]
	let peerEndpoint: String?
	let allowedIps: [String]
	let persistentKeepalive: UInt16?
	let dnsServers: [String]
	let mtu: UInt16

	enum CodingKeys: String, CodingKey {
		case driver
		case interfaceName = "interface_name"
		case interfaceAddresses = "interface_addresses"
		case privateKey = "private_key"
		case listenPort = "listen_port"
		case peerPublicKey = "peer_public_key"
		case peerEndpoint = "peer_endpoint"
		case allowedIps = "allowed_ips"
		case persistentKeepalive = "persistent_keepalive"
		case dnsServers = "dns_servers"
		case mtu
	}
}

public func redactedTunnelPayload(_ payload: String) -> String {
	guard let data = payload.data(using: .utf8),
		  var json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
	else {
		return payload
	}

	if var request = json["request"] as? [String: Any],
	   let privateKey = request["private_key"] as? [Any] {
		request["private_key"] = Array(repeating: 0, count: privateKey.count)
		json["request"] = request
	}
	if let psk = json["psk"] as? [Any] {
		json["psk"] = Array(repeating: 0, count: psk.count)
	}

	guard let redactedData = try? JSONSerialization.data(withJSONObject: json),
		  let redacted = String(data: redactedData, encoding: .utf8)
	else {
		return payload
	}
	return redacted
}
