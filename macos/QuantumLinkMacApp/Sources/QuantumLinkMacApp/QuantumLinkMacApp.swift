import SwiftUI

@main
struct QuantumLinkMacApp: App {
	@StateObject private var model = RuntimeShellModel()

	var body: some Scene {
		WindowGroup {
			ContentView(model: model)
				.frame(minWidth: 820, minHeight: 560)
		}
	}
}