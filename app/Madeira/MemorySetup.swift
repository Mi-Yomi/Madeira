import Foundation
import SwiftUI

// MARK: - Memory setup presentation

/// The signed process and a fresh advisory memory sample, never the requested
/// entitlements file or a guessed per-device RAM allowance.
struct MemorySetupSnapshot {
    enum Installation { case standalone, hosted, simulator }
    let increasedMemory: Bool
    let extendedVA: Bool
    let availableBytes: UInt64
    let physicalBytes: UInt64
    let bundleIdentifier: String?
    let installation: Installation

    var status: String {
        if installation == .simulator { return "Check on your iPhone" }
        return increasedMemory ? "Memory+ entitlement detected" : "Memory+ entitlement not detected"
    }
    var signingTarget: String? {
        guard installation == .standalone,
              let identifier = bundleIdentifier, !identifier.isEmpty else { return nil }
        return identifier
    }
    var availableText: String {
        guard installation != .simulator else { return "Not available in the simulator" }
        guard availableBytes > 0 else { return "Unavailable or exhausted" }
        guard availableBytes >= 1 << 20 else { return "<1 MiB" }
        return "\(availableBytes >> 20) MiB"
    }
    var physicalText: String {
        guard physicalBytes > 0, installation != .simulator else { return "Unknown" }
        return "\(physicalBytes >> 20) MiB"
    }
    static let headroomExplanation = "An advisory snapshot of additional memory this process may allocate. It changes while the app runs and is not total RAM or a guaranteed allocation budget. A zero result can mean the limit is exhausted or the reading is unavailable."
    static let signingExplanation = "Madeira already requests Increased Memory Limit in its build. The installed copy must also be signed with a provisioning profile that grants it. JIT does not add this entitlement."
    var activationSteps: [String] {
        if installation == .hosted {
            return [
                "1. Identify the installed host app and its signing account in your sideloader. Enable Increased Memory Limit for the host's App ID; the host build must request this entitlement too.",
                "2. Back up the host's apps, games and saves. Have the sideloader generate a fresh host provisioning profile, then re-sign and reinstall the host using the same account and host bundle identifier. Do not delete the host app or re-sign only the Madeira guest.",
                "3. Reopen the host and launch Madeira, then check this page again. Changing the guest App ID or only changing the host's server-side capability does not update the installed host signature."
            ]
        }
        return [
            "1. In your signing tool or Apple Developer account, enable Increased Memory Limit for the matching App ID, using the Apple account that signs this installation.",
            "2. Have your sideloader generate a fresh provisioning profile, then re-sign and reinstall this copy with the same account and bundle identifier. Back up games and saves first; do not delete the installed app.",
            "3. Reopen Madeira and check this page. Enabling the capability on the App ID alone does not change a running installation."
        ]
    }
}

// MARK: - Device sampling and interface

extension MemorySetupSnapshot {
    static func current() -> MemorySetupSnapshot {
        let entitlements = EntitlementStatus.check()
        let installation: Installation
        #if targetEnvironment(simulator)
        installation = .simulator
        #else
        installation = getenv("LC_HOME_PATH") == nil ? .standalone : .hosted
        #endif
        return MemorySetupSnapshot(
            increasedMemory: entitlements.increasedMemory,
            extendedVA: entitlements.extendedVA,
            availableBytes: jit_available_memory(),
            physicalBytes: ProcessInfo.processInfo.physicalMemory,
            bundleIdentifier: Bundle.main.bundleIdentifier,
            installation: installation
        )
    }
}

@MainActor
struct MemorySettingsSection: View {
    var body: some View {
        Section("Memory+") {
            NavigationLink {
                MemorySetupView()
            } label: {
                Label("Memory+ setup", systemImage: "memorychip")
            }
        }
    }
}

@MainActor
struct MemorySetupSheet: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            MemorySetupView()
                .toolbar {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Done") { dismiss() }
                    }
                }
        }
    }
}

@MainActor
struct MemorySetupView: View {
    @Environment(\.scenePhase) private var scenePhase
    @State private var snapshot = MemorySetupSnapshot.current()
    @State private var visible = false
    private let ticks = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    var body: some View {
        Form {
            Section {
                Label(snapshot.status, systemImage: snapshot.increasedMemory && snapshot.installation != .simulator
                      ? "checkmark.circle.fill" : "info.circle")
                    .foregroundStyle(snapshot.increasedMemory && snapshot.installation != .simulator
                                     ? Color.green : Color.secondary)
                if snapshot.installation != .simulator {
                    LabeledContent("Extended virtual addressing", value: snapshot.extendedVA ? "Detected" : "Not detected")
                }
            } header: {
                Text("This running process")
            } footer: {
                Text("These checks read the installed process's signed entitlements. An entitlement does not guarantee extra memory on every device. Extended virtual addressing provides address space, not extra physical RAM.")
            }
            Section {
                LabeledContent("Available now", value: snapshot.availableText)
                LabeledContent("Device physical RAM", value: snapshot.physicalText)
                Button("Check again") { refresh() }
            } header: {
                Text("Memory headroom")
            } footer: {
                Text(MemorySetupSnapshot.headroomExplanation)
            }
            if snapshot.installation == .simulator {
                Section {
                    Text("Open this page in the signed app on your iPhone to check its entitlements and available memory.")
                }
            } else if snapshot.installation == .hosted {
                Section("LiveContainer") {
                    Text("These readings belong to the host process. Configure the signed host app's App ID with your sideloader; changing the guest Madeira App ID will not grant memory to the host. The guest bundle identifier is not shown as a signing target.")
                }
            } else {
                Section {
                    if let target = snapshot.signingTarget {
                        Text(target).font(.footnote.monospaced()).textSelection(.enabled)
                    } else {
                        Text("Bundle identifier unavailable. Check Madeira's entry in your sideloader.")
                    }
                } header: {
                    Text("Installed bundle identifier")
                } footer: {
                    Text("Use this installed identifier to find the matching App ID. Sideloaders may change Madeira's original identifier.")
                }
            }
            if snapshot.installation != .simulator {
                Section(snapshot.increasedMemory ? "How Memory+ is enabled" : "Enable Memory+ when missing") {
                    if snapshot.installation == .standalone {
                        Text(MemorySetupSnapshot.signingExplanation)
                    }
                    ForEach(snapshot.activationSteps, id: \.self) { Text($0) }
                    Link("Official GetMoreRAM instructions", destination: URL(string: "https://github.com/hugeBlack/GetMoreRam#how-to-use")!)
                }
                Section {
                    Text("GetMoreRAM performs the App ID capability step. It still requires re-signing and reinstalling. This page checks your setup and guides you; it does not sign in to Apple or modify your account.")
                    Link("Apple: Increased Memory Limit", destination: URL(string: "https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.kernel.increased-memory-limit")!)
                    Link("Apple: Available memory", destination: URL(string: "https://developer.apple.com/documentation/os/os_proc_available_memory")!)
                }
            }
        }
        .navigationTitle("Memory+ setup")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { visible = true; refresh() }
        .onDisappear { visible = false }
        .onChange(of: scenePhase) { _, phase in if visible && phase == .active { refresh() } }
        .onReceive(ticks) { _ in if visible && scenePhase == .active { refresh() } }
    }

    private func refresh() { snapshot = .current() }
}
