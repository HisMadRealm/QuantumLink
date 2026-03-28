import SwiftUI

struct ContentView: View {
	@ObservedObject var model: RuntimeShellModel

	var body: some View {
		VStack(alignment: .leading, spacing: 18) {
			header
			controls
			statusCard
			operationsCard
			outputCard
		}
		.padding(24)
		.background(
			LinearGradient(
				colors: [Color(red: 0.93, green: 0.95, blue: 0.98), Color.white],
				startPoint: .topLeading,
				endPoint: .bottomTrailing
			)
		)
		.task {
			model.start()
		}
		.onDisappear {
			model.stop()
		}
	}

	private var header: some View {
		VStack(alignment: .leading, spacing: 6) {
			Text("QuantumLink macOS Host")
				.font(.system(size: 30, weight: .bold, design: .rounded))
			Text("SwiftUI shell over the Rust host service and native tunnel runtime contract.")
				.font(.system(size: 14, weight: .medium, design: .rounded))
				.foregroundStyle(.secondary)
		}
	}

	private var controls: some View {
		VStack(alignment: .leading, spacing: 12) {
			HStack(spacing: 12) {
				TextField("198.51.100.8:51820", text: $model.selectedServer)
					.textFieldStyle(.roundedBorder)
					.frame(maxWidth: 260)
				Button("Connect") {
					model.connect()
				}
				Button("Disconnect") {
					model.disconnect()
				}
				Button("Refresh Status") {
					model.refreshStatus()
				}
			}

			if let error = model.lastError {
				Text(error)
					.font(.system(.caption, design: .monospaced))
					.foregroundStyle(Color(red: 0.68, green: 0.17, blue: 0.11))
			}
		}
		.buttonStyle(.borderedProminent)
		.disabled(model.isBusy)
	}

	private var statusCard: some View {
		GroupBox("Status") {
			if let status = model.status {
				VStack(alignment: .leading, spacing: 10) {
					LabeledContent("Adapter", value: status.adapterMode)
					LabeledContent("Tunnel", value: status.connectionState)
					LabeledContent("Headline", value: status.connectionHeadline)
					LabeledContent("Detail", value: status.connectionDetail)
					LabeledContent("Tray", value: status.trayStatus)
					LabeledContent("Pending", value: status.pendingCommand ?? "none")
					if let session = status.session {
						Divider()
						LabeledContent("Session Tunnel", value: session.tunnelActive ? "active" : "idle")
						LabeledContent("Session Firewall", value: session.firewallActive ? "active" : "idle")
						LabeledContent("Bytes Sent", value: String(session.tunnelStats.bytesSent))
						LabeledContent("Bytes Received", value: String(session.tunnelStats.bytesReceived))
						LabeledContent(
							"Last Handshake",
							value: session.tunnelStats.lastHandshakeSecs.map { "\($0)s" } ?? "none"
						)
					}
				}
			} else {
				Text("No runtime status loaded yet.")
					.foregroundStyle(.secondary)
			}
		}
	}

	private var operationsCard: some View {
		GroupBox("Planned Operations") {
			if model.operations.isEmpty {
				Text("No planned operations loaded.")
					.foregroundStyle(.secondary)
			} else {
				List(model.operations) { operation in
					VStack(alignment: .leading, spacing: 6) {
						Text("\(operation.target) :: \(operation.operation)")
							.font(.system(.body, design: .monospaced))
						Text(operation.payload)
							.font(.system(.caption, design: .monospaced))
							.foregroundStyle(.secondary)
						if let helperResponse = operation.helperResponse {
							Text(helperResponse)
								.font(.system(.caption, design: .monospaced))
								.foregroundStyle(Color(red: 0.12, green: 0.35, blue: 0.64))
						}
					}
					.padding(.vertical, 4)
				}
				.frame(minHeight: 180)
			}
		}
	}

	private var outputCard: some View {
		GroupBox("Raw JSON") {
			ScrollView {
				Text(model.outputLog.isEmpty ? "No command output yet." : model.outputLog)
					.font(.system(.caption, design: .monospaced))
					.frame(maxWidth: .infinity, alignment: .leading)
			}
			.frame(minHeight: 120)
		}
	}
}