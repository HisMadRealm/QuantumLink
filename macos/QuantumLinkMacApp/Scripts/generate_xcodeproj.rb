#!/usr/bin/env ruby
# frozen_string_literal: true

require 'fileutils'

begin
  require 'xcodeproj'
rescue LoadError
  warn 'missing xcodeproj gem; install with: gem install --user-install xcodeproj --no-document'
  exit 1
end

ROOT = File.expand_path('..', __dir__)
PROJECT_PATH = File.join(ROOT, 'QuantumLinkMacApp.xcodeproj')
WIREGUARD_PACKAGE_URL = 'https://git.zx2c4.com/wireguard-apple'
WIREGUARD_PACKAGE_CHECKOUT = '$(BUILD_DIR%Build/*)SourcePackages/checkouts/wireguard-apple/Sources/WireGuardKitGo'

APP_SOURCES = %w[
  Sources/QuantumLinkMacApp/ContentView.swift
  Sources/QuantumLinkMacApp/QuantumLinkMacApp.swift
  Sources/QuantumLinkMacApp/RuntimeShellModel.swift
].freeze

PROVIDER_SOURCES = %w[
  Sources/QuantumLinkPacketTunnelProvider/QuantumLinkPacketTunnelProvider.swift
  Sources/QuantumLinkTunnelShared/TunnelModels.swift
].freeze

CONTROLLER_SOURCES = %w[
  Sources/QuantumLinkTunnelController/main.swift
  Sources/QuantumLinkTunnelShared/TunnelModels.swift
].freeze

CONFIG_FILES = %w[
  Config/Bundles.xcconfig
  Config/QuantumLinkMacApp-Info.plist
  Config/QuantumLinkMacApp.entitlements
  Config/QuantumLinkMacApp.xcconfig
  Config/QuantumLinkPacketTunnelProvider-Info.plist
  Config/QuantumLinkPacketTunnelProvider.entitlements
  Config/QuantumLinkPacketTunnelProvider.xcconfig
  Config/Signing.xcconfig
  Config/QuantumLinkTunnelController.xcconfig
].freeze

FileUtils.rm_rf(PROJECT_PATH)
project = Xcodeproj::Project.new(PROJECT_PATH)
project.root_object.attributes['LastUpgradeCheck'] = '1600'
project.root_object.attributes['ORGANIZATIONNAME'] = 'QuantumLink'

main_group = project.main_group
sources_group = main_group.find_subpath('Sources', true)
sources_group.set_source_tree('<group>')
config_group = main_group.find_subpath('Config', true)
config_group.set_source_tree('<group>')
scripts_group = main_group.find_subpath('Scripts', true)
scripts_group.set_source_tree('<group>')

(APP_SOURCES + PROVIDER_SOURCES + CONTROLLER_SOURCES).uniq.each do |path|
  main_group.find_file_by_path(path) || main_group.new_file(path)
end
CONFIG_FILES.each do |path|
  main_group.find_file_by_path(path) || main_group.new_file(path)
end
%w[
  Scripts/archive_release.sh
  Scripts/generate_xcodeproj.rb
  Scripts/mode_a_validate.sh
].each do |path|
  main_group.find_file_by_path(path) || scripts_group.new_file(path)
end

app_target = project.new_target(:application, 'QuantumLinkMacApp', :osx, '14.0')
provider_target = project.new_target(:app_extension, 'QuantumLinkPacketTunnelProvider', :osx, '14.0')
controller_target = project.new_target(:command_line_tool, 'QuantumLinkTunnelController', :osx, '14.0')
legacy_target = Xcodeproj::Project::ProjectHelper.new_legacy_target(
  project,
  'WireGuardGoBridgemacOS',
  '/usr/bin/make',
  '$(ACTION)',
  WIREGUARD_PACKAGE_CHECKOUT,
  '1'
)
legacy_target.product_name = 'WireGuardGoBridge'
legacy_target.build_configurations.each do |configuration|
  configuration.build_settings['SDKROOT'] = 'macosx'
end

app_target.add_system_framework('NetworkExtension')
provider_target.add_system_framework('NetworkExtension')
provider_target.add_system_framework('Network')
controller_target.add_system_framework('NetworkExtension')

app_target.add_file_references(APP_SOURCES.map { |path| main_group.find_file_by_path(path) }.compact)
provider_target.add_file_references(PROVIDER_SOURCES.map { |path| main_group.find_file_by_path(path) }.compact)
controller_target.add_file_references(CONTROLLER_SOURCES.map { |path| main_group.find_file_by_path(path) }.compact)

app_config = main_group.find_file_by_path('Config/QuantumLinkMacApp.xcconfig')
provider_config = main_group.find_file_by_path('Config/QuantumLinkPacketTunnelProvider.xcconfig')
controller_config = main_group.find_file_by_path('Config/QuantumLinkTunnelController.xcconfig')

app_target.build_configurations.each do |configuration|
  configuration.base_configuration_reference = app_config
end
provider_target.build_configurations.each do |configuration|
  configuration.base_configuration_reference = provider_config
end
controller_target.build_configurations.each do |configuration|
  configuration.base_configuration_reference = controller_config
end

wireguard_package = project.new(Xcodeproj::Project::Object::XCRemoteSwiftPackageReference)
wireguard_package.repositoryURL = WIREGUARD_PACKAGE_URL
wireguard_package.requirement = { 'kind' => 'branch', 'branch' => 'master' }
project.root_object.package_references << wireguard_package

[app_target, provider_target].each do |target|
  package_product = project.new(Xcodeproj::Project::Object::XCSwiftPackageProductDependency)
  package_product.package = wireguard_package
  package_product.product_name = 'WireGuardKit'
  target.package_product_dependencies << package_product

  build_file = project.new(Xcodeproj::Project::Object::PBXBuildFile)
  build_file.product_ref = package_product
  target.frameworks_build_phase.files << build_file
end

provider_target.add_dependency(legacy_target)
app_target.add_dependency(provider_target)

embed_extensions = project.new(Xcodeproj::Project::Object::PBXCopyFilesBuildPhase)
embed_extensions.name = 'Embed App Extensions'
embed_extensions.dst_subfolder_spec = '13'
app_target.build_phases << embed_extensions

embedded_provider = project.new(Xcodeproj::Project::Object::PBXBuildFile)
embedded_provider.file_ref = provider_target.product_reference
embedded_provider.settings = { 'ATTRIBUTES' => ['RemoveHeadersOnCopy'] }
embed_extensions.files << embedded_provider

project.targets.each do |target|
  next unless target.respond_to?(:build_configurations)

  target.build_configurations.each do |configuration|
    settings = configuration.build_settings
    case target.name
    when 'QuantumLinkMacApp', 'QuantumLinkPacketTunnelProvider'
      settings['CODE_SIGNING_ALLOWED'] = 'YES'
      settings['CODE_SIGNING_REQUIRED'] = 'YES'
      settings['DEVELOPMENT_TEAM'] = '$(QUANTUMLINK_DEVELOPMENT_TEAM)'
    when 'QuantumLinkTunnelController'
      settings['CODE_SIGNING_ALLOWED'] = 'NO'
      settings['CODE_SIGNING_REQUIRED'] = 'NO'
    else
      settings['CODE_SIGNING_ALLOWED'] = 'NO'
      settings['CODE_SIGNING_REQUIRED'] = 'NO'
    end
  end
end

app_scheme = Xcodeproj::XCScheme.new
app_scheme.configure_with_targets(app_target, nil, launch_target: true)
app_scheme.launch_action.build_configuration = 'Debug'
app_scheme.analyze_action.build_configuration = 'Debug'
app_scheme.profile_action.build_configuration = 'Release'
app_scheme.archive_action.build_configuration = 'Release'
app_scheme.archive_action.reveal_archive_in_organizer = true
app_scheme.save_as(PROJECT_PATH, 'QuantumLinkMacApp', true)

controller_scheme = Xcodeproj::XCScheme.new
controller_scheme.configure_with_targets(controller_target, nil, launch_target: true)
controller_scheme.launch_action.build_configuration = 'Debug'
controller_scheme.analyze_action.build_configuration = 'Debug'
controller_scheme.profile_action.build_configuration = 'Release'
controller_scheme.archive_action.build_configuration = 'Release'
controller_scheme.save_as(PROJECT_PATH, 'QuantumLinkTunnelController', true)

project.save
puts "Generated #{PROJECT_PATH}"
