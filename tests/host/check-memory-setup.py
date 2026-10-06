#!/usr/bin/env python3
"""Check Memory+ wiring and compile its exact presentation/sampling logic.

No account, device security setting, signing profile or memory limit is changed.
Use --source-only explicitly on hosts without Swift; that is not a compiled pass.
"""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
mode = parser.add_mutually_exclusive_group()
mode.add_argument("--source-only", action="store_true")
mode.add_argument("--ios-typecheck", action="store_true")
args = parser.parse_args()
source = (ROOT / "app/Madeira/MemorySetup.swift").read_text()
library = (ROOT / "app/Madeira/Library.swift").read_text()
content = (ROOT / "app/Madeira/ContentView.swift").read_text()
project = (ROOT / "app/Madeira.xcodeproj/project.pbxproj").read_text()
workflow = (ROOT / ".github/workflows/desktop-compatibility.yml").read_text()
entitlements = (ROOT / "app/Madeira/EntitlementChecker.swift").read_text()


def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + message)


pure = source.split("// MARK: - Memory setup presentation", 1)[1].split("// MARK: - Device sampling and interface", 1)[0]
sample = source.split("// MARK: - Device sampling and interface", 1)[1].split("@MainActor", 1)[0]
require("let entitlements = EntitlementStatus.check()" in sample, "sample signed process entitlements")
require("increasedMemory: entitlements.increasedMemory" in sample, "do not infer entitlement from RAM")
require("availableBytes: jit_available_memory()" in sample, "fresh advisory memory sample")
require("physicalBytes: ProcessInfo.processInfo.physicalMemory" in sample, "separate device RAM")
require("getenv(\"LC_HOME_PATH\")" in sample and "#if targetEnvironment(simulator)" in sample, "host/simulator detection")
require(".onAppear { visible = true; refresh() }" in source, "refresh on entry")
require(".onDisappear { visible = false }" in source, "stop sampling hidden page")
require(".onChange(of: scenePhase)" in source and "if visible && phase == .active { refresh() }" in source, "refresh on foreground")
require(".onReceive(ticks)" in source and "if visible && scenePhase == .active { refresh() }" in source, "visible active-only periodic sample")
require('Button("Check again") { refresh() }' in source, "explicit repeated check")
require("MemorySettingsSection()" in library and '"GetMoreRAM", "entitlement", "signing"' in library, "searchable settings entry")
require('Button("Memory+ setup") { devSheet = .memorySetup }' in content, "reachable developer action")
require("case .memorySetup: MemorySetupSheet()" in content, "developer sheet presenter")
require("case .memorySetup: MemorySetupSheet()" in library, "exhaustive shared sheet switch")
require('Button("Done") { dismiss() }' in source, "sheet dismissal")
require("Must be injected via GetMoreRam" not in content and "Expands virtual address space to ~64GB" not in content,
        "remove unsupported GetMoreRAM and address-space claims")
require(project.count("B1000060 /* MemorySetup.swift in Sources */") == 2, "one build source entry")
require(project.count("B2000060 /* MemorySetup.swift */") == 3, "one file reference in group")
require("python3 tests/host/check-memory-setup.py --source-only" in workflow, "portable source check")
require("python3 tests/host/check-memory-setup.py\n" in workflow, "compiled CI check")
require("python3 tests/host/check-memory-setup.py --ios-typecheck\n" in workflow, "full UI iPhoneOS type-check")
require(entitlements.count("-> Unmanaged<CFTypeRef>?") == 2, "explicit Create/Copy ownership")
checker = entitlements.split("func checkAppEntitlement", 1)[1].split("struct EntitlementStatus", 1)[0]
checker = "func checkAppEntitlement" + checker
require(checker.count(".takeRetainedValue()") == 2, "balance task and value ownership")
for forbidden in ("URLSession", "AppleAPI", "StosSign", "SecItemAdd", "UIPasteboard", "UserDefaults", "malloc("):
    require(forbidden not in source, "setup page must remain read-only: " + forbidden)
print("PASS: Memory+ runtime sources, navigation, active refresh, read-only design and CI wiring", flush=True)
if args.source_only:
    print("SKIP: compiled Swift checks (--source-only)")
    raise SystemExit(0)
if args.ios_typecheck:
    xcrun = shutil.which("xcrun")
    if not xcrun:
        raise SystemExit("FAIL: --ios-typecheck requires Xcode and the iPhoneOS SDK")
    sdk = subprocess.check_output([xcrun, "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
    compiler = subprocess.check_output([xcrun, "--sdk", "iphoneos", "--find", "swiftc"], text=True).strip()
    # Preserve the production CF declarations and ownership code. Only the
    # unrelated runtime bridge is stubbed; the full SwiftUI source is checked.
    dependencies = entitlements.split("struct EntitlementStatus", 1)[0] + r'''
struct EntitlementStatus {
    let increasedMemory: Bool, extendedVA: Bool
    static func check() -> EntitlementStatus {
        Self(increasedMemory: checkAppEntitlement("com.apple.developer.kernel.increased-memory-limit"),
             extendedVA: checkAppEntitlement("com.apple.developer.kernel.extended-virtual-addressing"))
    }
}
func jit_available_memory() -> UInt64 { 0 }
'''
    with tempfile.TemporaryDirectory(prefix="madeira-memory-ios-") as temp:
        dependency = Path(temp) / "Dependencies.swift"
        dependency.write_text(dependencies)
        subprocess.run([compiler, "-typecheck", "-swift-version", "5", "-sdk", sdk,
                        "-target", "arm64-apple-ios17.0", str(dependency),
                        str(ROOT / "app/Madeira/MemorySetup.swift")], check=True)
    print("PASS: full Memory+ SwiftUI and production CF entitlement bridge type-check with iPhoneOS SDK")
    raise SystemExit(0)
swift = shutil.which(os.environ.get("SWIFTC", "swiftc"))
if not swift:
    raise SystemExit("FAIL: swiftc missing; set SWIFTC or explicitly use --source-only")

stubs = r'''
var liveCFObjects = 0
final class TrackedCFObject: NSObject {
    override init() { super.init(); liveCFObjects += 1 }
    deinit { liveCFObjects -= 1 }
}
var createTaskSucceeds = true
var entitlementKind = 0 // absent, true, false, wrong type
func _SecTaskCreateFromSelf(_ allocator: CFAllocator?) -> Unmanaged<CFTypeRef>? {
    createTaskSucceeds ? .passRetained(TrackedCFObject()) : nil
}
func _SecTaskCopyValueForEntitlement(_ task: CFTypeRef, _ entitlement: NSString,
                                    _ error: UnsafeMutableRawPointer?) -> Unmanaged<CFTypeRef>? {
    switch entitlementKind {
    case 1: return .passRetained(NSNumber(value: true))
    case 2: return .passRetained(NSNumber(value: false))
    case 3: return .passRetained(TrackedCFObject())
    default: return nil
    }
}
struct EntitlementStatus {
    static var memory = false, va = false
    let increasedMemory: Bool, extendedVA: Bool
    static func check() -> EntitlementStatus { Self(increasedMemory: memory, extendedVA: va) }
}
var available: UInt64 = 0
var sampleCount = 0
func jit_available_memory() -> UInt64 { sampleCount += 1; return available }
'''
tests = r'''
func make(_ granted: Bool, _ bytes: UInt64,
          _ installation: MemorySetupSnapshot.Installation = .standalone,
          _ id: String? = "com.example.Madeira.TEAM") -> MemorySetupSnapshot {
    MemorySetupSnapshot(increasedMemory: granted, extendedVA: false,
                        availableBytes: bytes, physicalBytes: 8 << 30,
                        bundleIdentifier: id, installation: installation)
}
for granted in [false, true] {
    for bytes: UInt64 in [0, 1, (1 << 20) - 1, 1 << 20, 6 << 30, UInt64.max] {
        let state = make(granted, bytes)
        precondition(state.increasedMemory == granted)
        precondition(state.status == (granted ? "Memory+ entitlement detected" : "Memory+ entitlement not detected"))
        precondition(state.physicalText == "8192 MiB")
        precondition(state.signingTarget == "com.example.Madeira.TEAM")
        if bytes == 0 { precondition(state.availableText == "Unavailable or exhausted") }
        else if bytes < 1 << 20 { precondition(state.availableText == "<1 MiB") }
        else { precondition(state.availableText == "\(bytes >> 20) MiB") }
    }
}
precondition(make(false, 6 << 30).status == "Memory+ entitlement not detected")
precondition(make(true, 0).status == "Memory+ entitlement detected")
precondition(make(true, 6 << 30, .hosted).signingTarget == nil)
precondition(make(true, 6 << 30, .simulator).signingTarget == nil)
precondition(make(true, 6 << 30, .simulator).status == "Check on your iPhone")
precondition(make(true, 6 << 30, .simulator).availableText == "Not available in the simulator")
precondition(make(true, 6 << 30, .simulator).physicalText == "Unknown")
precondition(make(false, 0, .standalone, nil).signingTarget == nil)
precondition(make(false, 0, .standalone, "").signingTarget == nil)
precondition(make(false, 0, .hosted).activationSteps[0].contains("host build must request"))
precondition(make(false, 0, .hosted).activationSteps[1].contains("reinstall the host"))
precondition(make(false, 0, .hosted).activationSteps[1].contains("Do not delete the host"))
precondition(make(false, 0).activationSteps[1].contains("same account and bundle identifier"))
precondition(MemorySetupSnapshot(increasedMemory: false, extendedVA: true,
    availableBytes: 0, physicalBytes: 0, bundleIdentifier: nil,
    installation: .standalone).physicalText == "Unknown")

func testSampling() {
    let previous = getenv("LC_HOME_PATH").map { String(cString: $0) }
    defer {
        if let previous { setenv("LC_HOME_PATH", previous, 1) }
        else { unsetenv("LC_HOME_PATH") }
    }
    unsetenv("LC_HOME_PATH")
    EntitlementStatus.memory = false; EntitlementStatus.va = true; available = 4 << 30
    let first = MemorySetupSnapshot.current()
    precondition(!first.increasedMemory && first.extendedVA)
    precondition(first.availableBytes == 4 << 30 && first.installation == .standalone)
    EntitlementStatus.memory = true; EntitlementStatus.va = false; available = 0
    let second = MemorySetupSnapshot.current()
    precondition(second.increasedMemory && !second.extendedVA && second.availableBytes == 0)
    setenv("LC_HOME_PATH", "/test/host", 1)
    let hosted = MemorySetupSnapshot.current()
    precondition(hosted.installation == .hosted && hosted.signingTarget == nil)
    precondition(sampleCount == 3) // every check samples again, no cached budget
}
testSampling()
for kind in 0...3 {
    entitlementKind = kind
    for _ in 0..<1000 {
        precondition(checkAppEntitlement("test.memory") == (kind == 1))
        precondition(liveCFObjects == 0) // task, including absent/invalid value paths
    }
}
createTaskSucceeds = false
precondition(!checkAppEntitlement("test.memory") && liveCFObjects == 0)
print("PASS: compiled Memory+ signed status, fresh samples, boundary values, simulator/host and bundle targets")
print("PASS: compiled entitlement Create/Copy ownership on success, absent, wrong-type and failed-task paths")
'''
with tempfile.TemporaryDirectory(prefix="madeira-memory-setup-") as temp:
    temp = Path(temp)
    code = temp / "main.swift"
    code.write_text("import Foundation\nimport CoreFoundation\n" + pure + stubs + checker + sample + tests)
    binary = temp / "memory-setup"
    subprocess.run([swift, "-O", str(code), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
