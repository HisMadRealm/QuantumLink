// swift-tools-version: 5.9

import PackageDescription

let package = Package(
	name: "QuantumLinkMacApp",
	platforms: [
		.macOS(.v13),
	],
	products: [
		.executable(name: "QuantumLinkMacApp", targets: ["QuantumLinkMacApp"]),
		.executable(name: "QuantumLinkTunnelController", targets: ["QuantumLinkTunnelController"]),
		.library(name: "QuantumLinkTunnelShared", targets: ["QuantumLinkTunnelShared"]),
		.library(name: "QuantumLinkPacketTunnelProvider", targets: ["QuantumLinkPacketTunnelProvider"]),
	],
	targets: [
		.target(
			name: "QuantumLinkTunnelShared",
			path: "Sources/QuantumLinkTunnelShared"
		),
		.executableTarget(
			name: "QuantumLinkMacApp",
			path: "Sources/QuantumLinkMacApp"
		),
		.executableTarget(
			name: "QuantumLinkTunnelController",
			dependencies: ["QuantumLinkTunnelShared"],
			path: "Sources/QuantumLinkTunnelController"
		),
		.target(
			name: "QuantumLinkPacketTunnelProvider",
			dependencies: ["QuantumLinkTunnelShared"],
			path: "Sources/QuantumLinkPacketTunnelProvider"
		),
	]
)
