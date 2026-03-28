import Foundation
@preconcurrency import NetworkExtension
import QuantumLinkTunnelShared

@main
struct QuantumLinkTunnelController {
	static func main() async {
		do {
			try await run()
		} catch {
			FileHandle.standardError.write(Data("\(error)\n".utf8))
			exit(1)
		}
	}

	private static func run() async throws {
		let arguments = Array(CommandLine.arguments.dropFirst())
		guard arguments.count == 3 else {
			throw ControllerError.usage
		}

		let target = arguments[0]
		let operation = arguments[1]
		let payload = arguments[2]
		guard target == "tunnel" else {
			throw ControllerError.unsupportedTarget(target)
		}

		let envelope = try decodeEnvelope(from: payload)
		guard envelope.request.driver == "network-extension" else {
			throw ControllerError.invalidPayload("expected network-extension driver")
		}

		let controller = TunnelController(backend: TunnelControllerBackend.fromEnvironment())
		let ack = try await controller.execute(
			target: target,
			operation: operation,
			payload: payload,
			envelope: envelope,
		)

		let encoder = JSONEncoder()
		encoder.outputFormatting = [.sortedKeys]
		let output = try encoder.encode(ack)
		FileHandle.standardOutput.write(output)
		FileHandle.standardOutput.write(Data("\n".utf8))
	}

	private static func decodeEnvelope(from payload: String) throws -> TunnelEnvelope {
		guard let data = payload.data(using: .utf8) else {
			throw ControllerError.invalidPayload("payload is not valid UTF-8")
		}
		return try JSONDecoder().decode(TunnelEnvelope.self, from: data)
	}

	static func stateURL() -> URL {
		if let raw = ProcessInfo.processInfo.environment["QL_MACOS_TUNNEL_CONTROLLER_STATE"], !raw.isEmpty {
			return URL(fileURLWithPath: raw)
		}
		return URL(fileURLWithPath: NSTemporaryDirectory())
			.appendingPathComponent("quantumlink-native-tunnel-controller-state.json")
	}
}

private struct TunnelController {
	let backend: TunnelControllerBackend

	func execute(
		target: String,
		operation: String,
		payload: String,
		envelope: TunnelEnvelope,
	) async throws -> TunnelControllerAck {
		switch backend {
		case .networkExtension:
			return try await NetworkExtensionTunnelController().execute(
				target: target,
				operation: operation,
				payload: payload,
				envelope: envelope,
			)
		case .statefile:
			return try await StatefileTunnelController(stateURL: QuantumLinkTunnelController.stateURL())
				.execute(target: target, operation: operation, payload: payload, envelope: envelope)
		}
	}
}

private enum TunnelControllerBackend {
	case networkExtension
	case statefile

	static func fromEnvironment() -> Self {
		switch ProcessInfo.processInfo.environment["QL_MACOS_TUNNEL_CONTROLLER_BACKEND"] {
		case "statefile":
			return .statefile
		default:
			return .networkExtension
		}
	}
}

private struct StatefileTunnelController {
	let stateURL: URL

	func execute(
		target: String,
		operation: String,
		payload: String,
		envelope: TunnelEnvelope,
	) async throws -> TunnelControllerAck {
		var state = try loadState()
		state.lastOperation = operation
		state.lastPayload = redactedTunnelPayload(payload)
		if let endpoint = envelope.request.peerEndpoint {
			state.endpoint = endpoint
		}

		let ack: TunnelControllerAck
		switch operation {
		case "activate":
			state.tunnelActive = true
			state.tunnelStats.bytesSent += 512
			state.tunnelStats.bytesReceived += 1_024
			state.tunnelStats.lastHandshakeSecs = 0
			ack = TunnelControllerAck(
				target: target,
				operation: operation,
				accepted: true,
				message: "queued statefile tunnel activation for \(envelope.request.providerBundleIdentifier)",
				state: state,
				tunnelStats: nil
			)
		case "deactivate":
			state.tunnelActive = false
			ack = TunnelControllerAck(
				target: target,
				operation: operation,
				accepted: true,
				message: "queued statefile tunnel deactivation for \(envelope.request.providerBundleIdentifier)",
				state: state,
				tunnelStats: nil
			)
		case "update-endpoint":
			guard envelope.request.peerEndpoint != nil else {
				throw ControllerError.invalidPayload("update-endpoint requires peer_endpoint")
			}
			state.tunnelStats.bytesSent += 64
			ack = TunnelControllerAck(
				target: target,
				operation: operation,
				accepted: true,
				message: "updated statefile tunnel endpoint",
				state: state,
				tunnelStats: nil
			)
		case "inject-psk":
			guard payload.contains("\"psk\"") else {
				throw ControllerError.invalidPayload("inject-psk requires psk")
			}
			state.tunnelStats.bytesSent += 32
			ack = TunnelControllerAck(
				target: target,
				operation: operation,
				accepted: true,
				message: "accepted statefile tunnel psk rotation",
				state: state,
				tunnelStats: nil
			)
		case "read-stats":
			ack = TunnelControllerAck(
				target: target,
				operation: operation,
				accepted: true,
				message: "reported statefile tunnel stats",
				state: state,
				tunnelStats: state.tunnelStats
			)
		default:
			throw ControllerError.unsupportedOperation(operation)
		}

		try saveState(state)
		return ack
	}

	private func loadState() throws -> TunnelControllerState {
		guard FileManager.default.fileExists(atPath: stateURL.path) else {
			return TunnelControllerState()
		}
		let data = try Data(contentsOf: stateURL)
		return try JSONDecoder().decode(TunnelControllerState.self, from: data)
	}

	private func saveState(_ state: TunnelControllerState) throws {
		try FileManager.default.createDirectory(at: stateURL.deletingLastPathComponent(), withIntermediateDirectories: true)
		let encoder = JSONEncoder()
		encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
		try encoder.encode(state).write(to: stateURL)
	}
}

private struct NetworkExtensionTunnelController {
	func execute(
		target: String,
		operation: String,
		payload: String,
		envelope: TunnelEnvelope,
	) async throws -> TunnelControllerAck {
		let manager = try await loadOrCreateManager(for: envelope.request)
		var state = tunnelState(
			from: manager,
			request: envelope.request,
			operation: operation,
			payload: redactedTunnelPayload(payload)
		)

		switch operation {
		case "activate":
			configure(manager: manager, request: envelope.request)
			try await save(manager: manager)
			let refreshed = try await reload(manager: manager)
			do {
				try refreshed.connection.startVPNTunnel(options: activationOptions(from: envelope.request))
			} catch {
				throw ControllerError.networkExtension("failed to start tunnel: \(error.localizedDescription)")
			}
			state = tunnelState(
				from: refreshed,
				request: envelope.request,
				operation: operation,
				payload: redactedTunnelPayload(payload)
			)
			state.tunnelActive = true
			return TunnelControllerAck(
				target: target,
				operation: operation,
				accepted: true,
				message: "requested Network Extension activation for \(envelope.request.providerBundleIdentifier)",
				state: state,
				tunnelStats: nil
			)
		case "deactivate":
			manager.connection.stopVPNTunnel()
			state.tunnelActive = false
			return TunnelControllerAck(
				target: target,
				operation: operation,
				accepted: true,
				message: "requested Network Extension deactivation for \(envelope.request.providerBundleIdentifier)",
				state: state,
				tunnelStats: nil
			)
		case "update-endpoint":
			guard envelope.request.peerEndpoint != nil else {
				throw ControllerError.invalidPayload("update-endpoint requires peer_endpoint")
			}
			configure(manager: manager, request: envelope.request)
			try await save(manager: manager)
			state.endpoint = envelope.request.peerEndpoint
			return TunnelControllerAck(
				target: target,
				operation: operation,
				accepted: true,
				message: "updated Network Extension endpoint configuration",
				state: state,
				tunnelStats: nil
			)
		case "inject-psk":
			guard payload.contains("\"psk\"") else {
				throw ControllerError.invalidPayload("inject-psk requires psk")
			}
			let session = try providerSession(for: manager)
			return try await sendProviderMessage(
				session,
				target: target,
				operation: operation,
				payload: payload
			)
		case "read-stats":
			let session = try providerSession(for: manager)
			return try await sendProviderMessage(
				session,
				target: target,
				operation: operation,
				payload: payload
			)
		default:
			throw ControllerError.unsupportedOperation(operation)
		}
	}

	private func loadOrCreateManager(for request: TunnelRequest) async throws -> NETunnelProviderManager {
		let managers = try await loadAllManagers()
		if let existing = managers.first(where: { manager in
			(manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == request.providerBundleIdentifier
		}) {
			return existing
		}

		let manager = NETunnelProviderManager()
		configure(manager: manager, request: request)
		manager.isEnabled = true
		try await save(manager: manager)
		return try await reload(manager: manager)
	}

	private func configure(manager: NETunnelProviderManager, request: TunnelRequest) {
		let protocolConfiguration = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
		protocolConfiguration.providerBundleIdentifier = request.providerBundleIdentifier
		protocolConfiguration.serverAddress = request.serverAddress
		protocolConfiguration.providerConfiguration = request.providerConfiguration
		manager.protocolConfiguration = protocolConfiguration
		manager.localizedDescription = "QuantumLink \(request.interfaceName)"
		manager.isEnabled = true
	}

	private func loadAllManagers() async throws -> [NETunnelProviderManager] {
		try await withCheckedThrowingContinuation { continuation in
			NETunnelProviderManager.loadAllFromPreferences { managers, error in
				if let error {
					continuation.resume(throwing: ControllerError.networkExtension(
						"failed to load managers: \(error.localizedDescription)"
					))
					return
				}
				continuation.resume(returning: managers ?? [])
			}
		}
	}

	private func save(manager: NETunnelProviderManager) async throws {
		try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
			manager.saveToPreferences { error in
				if let error {
					continuation.resume(throwing: ControllerError.networkExtension(
						"failed to save tunnel preferences: \(error.localizedDescription)"
					))
					return
				}
				continuation.resume(returning: ())
			}
		}
	}

	private func reload(manager: NETunnelProviderManager) async throws -> NETunnelProviderManager {
		try await withCheckedThrowingContinuation { continuation in
			manager.loadFromPreferences { error in
				if let error {
					continuation.resume(throwing: ControllerError.networkExtension(
						"failed to reload tunnel preferences: \(error.localizedDescription)"
					))
					return
				}
				continuation.resume(returning: manager)
			}
		}
	}

	private func providerSession(for manager: NETunnelProviderManager) throws -> NETunnelProviderSession {
		guard let session = manager.connection as? NETunnelProviderSession else {
			throw ControllerError.networkExtension("tunnel connection is not a NETunnelProviderSession")
		}
		return session
	}

	private func sendProviderMessage(
		_ session: NETunnelProviderSession,
		target: String,
		operation: String,
		payload: String
	) async throws -> TunnelControllerAck {
		guard let data = payload.data(using: .utf8) else {
			throw ControllerError.invalidPayload("payload is not valid UTF-8")
		}

		let responseData: Data = try await withCheckedThrowingContinuation {
			(continuation: CheckedContinuation<Data, Error>) in
			do {
				try session.sendProviderMessage(data) { response in
					guard let response else {
						continuation.resume(throwing: ControllerError.networkExtension(
							"provider did not respond to \(operation)"
						))
						return
					}
					continuation.resume(returning: response)
				}
			} catch {
				continuation.resume(throwing: error)
			}
		}

		do {
			return try JSONDecoder().decode(TunnelControllerAck.self, from: responseData)
		} catch {
			throw ControllerError.networkExtension(
				"failed to decode provider response for \(target) \(operation): \(error)"
			)
		}
	}

	private func activationOptions(from request: TunnelRequest) -> [String: NSObject] {
		var options: [String: NSObject] = [
			"interface_name": request.interfaceName as NSString,
		]
		if let endpoint = request.peerEndpoint {
			options["peer_endpoint"] = endpoint as NSString
		}
		return options
	}

	private func tunnelState(
		from manager: NETunnelProviderManager,
		request: TunnelRequest,
		operation: String,
		payload: String,
	) -> TunnelControllerState {
		TunnelControllerState(
			tunnelActive: isActive(manager.connection.status),
			lastOperation: operation,
			lastPayload: payload,
			endpoint: request.peerEndpoint,
			tunnelStats: TunnelStatsPayload(
				bytesSent: 0,
				bytesReceived: 0,
				lastHandshakeSecs: isActive(manager.connection.status) ? 0 : nil
			)
		)
	}

	private func isActive(_ status: NEVPNStatus) -> Bool {
		switch status {
		case .connected, .connecting, .reasserting:
			return true
		default:
			return false
		}
	}

}

private enum ControllerError: Error, CustomStringConvertible {
	case usage
	case unsupportedTarget(String)
	case unsupportedOperation(String)
	case invalidPayload(String)
	case networkExtension(String)

	var description: String {
		switch self {
		case .usage:
			return "usage: QuantumLinkTunnelController tunnel <activate|deactivate|update-endpoint|inject-psk|read-stats> <payload-json>"
		case .unsupportedTarget(let target):
			return "unsupported target: \(target)"
		case .unsupportedOperation(let operation):
			return "unsupported tunnel operation: \(operation)"
		case .invalidPayload(let message):
			return "invalid tunnel payload: \(message)"
		case .networkExtension(let message):
			return "network extension controller error: \(message)"
		}
	}
}
