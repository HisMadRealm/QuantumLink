import Foundation

struct RuntimeStatusResponse: Decodable {
	let adapterMode: String
	let pendingCommand: String?
	let connectionState: String
	let connectionHeadline: String
	let connectionDetail: String
	let trayStatus: String
	let session: RuntimeSessionResponse?

	enum CodingKeys: String, CodingKey {
		case adapterMode = "adapter_mode"
		case pendingCommand = "pending_command"
		case connectionState = "connection_state"
		case connectionHeadline = "connection_headline"
		case connectionDetail = "connection_detail"
		case trayStatus = "tray_status"
		case session
	}
}

struct RuntimeSessionResponse: Decodable {
	let tunnelActive: Bool
	let firewallActive: Bool
	let tunnelStats: RuntimeTunnelStatsResponse

	enum CodingKeys: String, CodingKey {
		case tunnelActive = "tunnel_active"
		case firewallActive = "firewall_active"
		case tunnelStats = "tunnel_stats"
	}
}

struct RuntimeTunnelStatsResponse: Decodable {
	let bytesSent: UInt64
	let bytesReceived: UInt64
	let lastHandshakeSecs: UInt64?

	enum CodingKeys: String, CodingKey {
		case bytesSent = "bytes_sent"
		case bytesReceived = "bytes_received"
		case lastHandshakeSecs = "last_handshake_secs"
	}
}

struct RuntimeOperationResponse: Decodable, Identifiable {
	let target: String
	let operation: String
	let payload: String
	let helperResponse: String?

	var id: String {
		"\(target)-\(operation)-\(payload.hashValue)"
	}

	enum CodingKeys: String, CodingKey {
		case target
		case operation
		case payload
		case helperResponse = "helper_response"
	}
}

struct RuntimeOperationsEnvelope: Decodable {
	let adapterMode: String
	let operations: [RuntimeOperationResponse]

	enum CodingKeys: String, CodingKey {
		case adapterMode = "adapter_mode"
		case operations
	}
}

@MainActor
final class RuntimeShellModel: ObservableObject {
	@Published private(set) var status: RuntimeStatusResponse?
	@Published private(set) var operations: [RuntimeOperationResponse] = []
	@Published private(set) var outputLog: String = ""
	@Published private(set) var lastError: String?
	@Published private(set) var isBusy = false
	@Published private(set) var autoRefreshEnabled = false
	@Published var selectedServer = "198.51.100.8:51820"
	private var refreshTask: Task<Void, Never>?
	private let service = RuntimeShellService()

	deinit {
		refreshTask?.cancel()
		service.stop()
	}

	func start() {
		guard refreshTask == nil else { return }
		autoRefreshEnabled = true
		refreshTask = Task {
			do {
				try await service.start()
			} catch {
				lastError = String(describing: error)
				return
			}

			while !Task.isCancelled {
				await runStatus()
				try? await Task.sleep(for: .seconds(3))
			}
		}
	}

	func stop() {
		autoRefreshEnabled = false
		refreshTask?.cancel()
		refreshTask = nil
		service.stop()
	}

	func refreshStatus() {
		Task { await runStatus() }
	}

	func connect() {
		Task {
			let server = selectedServer.trimmingCharacters(in: .whitespacesAndNewlines)
			await runOperations(command: "mode-a-connect-json", arguments: server.isEmpty ? [] : [server])
			await runStatus()
		}
	}

	func disconnect() {
		Task {
			await runOperations(command: "mode-a-disconnect-json")
			await runStatus()
		}
	}

	private func runStatus() async {
		await runRequest(
			request: { service in
				try await service.status()
			},
			decode: { data in
				self.status = try JSONDecoder().decode(RuntimeStatusResponse.self, from: data)
				self.operations = []
				self.lastError = nil
			}
		)
	}

	private func runOperations(command: String, arguments: [String] = []) async {
		await runRequest(
			request: { service in
				switch command {
				case "mode-a-connect-json":
					return try await service.connect(server: arguments.first)
				case "mode-a-disconnect-json":
					return try await service.disconnect()
				default:
					throw NSError(
						domain: "QuantumLinkMacApp",
						code: 400,
						userInfo: [NSLocalizedDescriptionKey: "unsupported command: \(command)"]
					)
				}
			},
			decode: { data in
				let decoded = try JSONDecoder().decode(RuntimeOperationsEnvelope.self, from: data)
				self.operations = decoded.operations
				self.lastError = nil
			}
		)
	}

	private func runRequest(
		request: @escaping (RuntimeShellService) async throws -> Data,
		decode: @escaping (Data) throws -> Void
	) async {
		isBusy = true
		defer { isBusy = false }

		do {
			try await service.start()
			let data = try await request(service)
			try decode(data)
			outputLog = String(decoding: data, as: UTF8.self)
		} catch {
			lastError = String(describing: error)
			outputLog = String(describing: error)
		}
	}
}

final class RuntimeShellService {
	private let port = Int(ProcessInfo.processInfo.environment["QL_MACOS_APP_SERVICE_PORT"] ?? "58421") ?? 58421
	private var process: Process?
	private var startingTask: Task<Void, Error>?

	func start() async throws {
		if process?.isRunning == true {
			return
		}
		if let startingTask {
			return try await startingTask.value
		}

		let task = Task<Void, Error> {
			let process = Process()
			process.executableURL = Self.resolveBinaryURL()
			process.arguments = ["serve", String(port)]
			process.environment = Self.mergedEnvironment(port: port)
			process.standardOutput = Pipe()
			process.standardError = Pipe()

			try process.run()
			self.process = process
			try await self.waitForHealth()
		}
		startingTask = task
		defer { startingTask = nil }
		try await task.value
	}

	func stop() {
		startingTask?.cancel()
		startingTask = nil
		if let process, process.isRunning {
			process.terminate()
		}
		process = nil
	}

	func status() async throws -> Data {
		try await request(path: "/status")
	}

	func connect(server: String?) async throws -> Data {
		var queryItems: [URLQueryItem] = []
		if let server, !server.isEmpty {
			queryItems.append(URLQueryItem(name: "server", value: server))
		}
		return try await request(path: "/mode-a/connect", method: "POST", queryItems: queryItems)
	}

	func disconnect() async throws -> Data {
		try await request(path: "/mode-a/disconnect", method: "POST")
	}

	private func waitForHealth() async throws {
		for _ in 0..<40 {
			do {
				_ = try await request(path: "/health")
				return
			} catch {
				try await Task.sleep(for: .milliseconds(150))
			}
		}
		throw NSError(
			domain: "QuantumLinkMacApp",
			code: 504,
			userInfo: [NSLocalizedDescriptionKey: "timed out waiting for ql-macos-app service"]
		)
	}

	private func request(
		path: String,
		method: String = "GET",
		queryItems: [URLQueryItem] = []
	) async throws -> Data {
		var components = URLComponents()
		components.scheme = "http"
		components.host = "127.0.0.1"
		components.port = port
		components.path = path
		components.queryItems = queryItems.isEmpty ? nil : queryItems
		guard let url = components.url else {
			throw NSError(
				domain: "QuantumLinkMacApp",
				code: 400,
				userInfo: [NSLocalizedDescriptionKey: "invalid service URL"]
			)
		}

		var request = URLRequest(url: url)
		request.httpMethod = method
		let (data, response) = try await URLSession.shared.data(for: request)
		guard let httpResponse = response as? HTTPURLResponse else {
			throw NSError(
				domain: "QuantumLinkMacApp",
				code: 500,
				userInfo: [NSLocalizedDescriptionKey: "invalid service response"]
			)
		}
		guard (200...299).contains(httpResponse.statusCode) else {
			throw NSError(
				domain: "QuantumLinkMacApp",
				code: httpResponse.statusCode,
				userInfo: [NSLocalizedDescriptionKey: String(decoding: data, as: UTF8.self)]
			)
		}
		return data
	}

	private static func resolveBinaryURL() -> URL {
		let environment = ProcessInfo.processInfo.environment
		if let explicit = environment["QL_MACOS_APP_BINARY"], !explicit.isEmpty {
			return URL(fileURLWithPath: explicit)
		}

		let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
		return cwd
			.appendingPathComponent("../../target/debug/ql-macos-app")
			.standardizedFileURL
	}

	private static func mergedEnvironment(port: Int) -> [String: String] {
		var environment = ProcessInfo.processInfo.environment
		if environment["QL_MACOS_APP_MODE"] == nil {
			environment["QL_MACOS_APP_MODE"] = environment["QL_MACOS_TUNNEL_CONTROLLER"] == nil
				? "stub"
				: "network-extension"
		}
		environment["QL_MACOS_APP_SERVICE_PORT"] = String(port)
		return environment
	}
}
