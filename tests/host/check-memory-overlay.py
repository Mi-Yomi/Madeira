#!/usr/bin/env python3
"""Compile the FPS overlay's production memory policy and timer lifecycle.

The Swift harness extracts the real policy, refresh, start and stop functions.
Inert timers and OS readers check repeat-appear/disappear without an iOS SDK or
live memory pressure. --source-only explicitly skips the compiled checks on
hosts without swiftc. SWIFTC overrides the compiler used by the full test.
"""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-only", action="store_true")
args = parser.parse_args()
source = (ROOT / "app/Madeira/FPSOverlay.swift").read_text()


def block(signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


policy = block("struct FPSOverlayMemorySnapshot: Equatable")
read = block("private func readFootprintBytes()")
refresh = block("private func refreshMemory()")
start = block("private func startTimers()")
stop = block("private func stopTimers()")
toggle = block("private func toggleVisibility()")
fps = block("private func computeAdaptiveFPS()")
color = block("private var memColor: Color")

assert "jetsamLimitMB" not in source and "EXACTLY 4096" not in source
assert "guard kr == KERN_SUCCESS else { return nil }" in read
assert "return info.phys_footprint" in read
assert "availableBytes: jit_available_memory()" in refresh
assert "guard !compact else { return }" in refresh
assert source.count("jit_available_memory()") == 1
assert source.count("Timer.scheduledTimer(") == 2
assert start.index("stopTimers()") < start.index("guard visible else { return }") < start.index("Timer.scheduledTimer(")
assert "fps = 0" in start
assert "withTimeInterval: 0.1" in start and "withTimeInterval: 0.25" in start
assert "refreshMemory()" not in start.split("// 100ms sampling", 1)[1].split("// 250ms display", 1)[0]
assert start.count("refreshMemory()") == 2
assert "timer?.invalidate()" in stop and "displayTimer?.invalidate()" in stop
assert "timer = nil" in stop and "displayTimer = nil" in stop
assert ".onAppear { startTimers() }" in source and ".onDisappear { stopTimers() }" in source
assert ".onTapGesture { toggleVisibility() }" in source
assert "if visible { startTimers() } else { stopTimers() }" in toggle
assert "ProMotionIntent" not in stop and "ProMotionIntent" not in toggle
assert "case .unknown: return .secondary" in color
assert "case .unavailableOrExhausted, .veryLow: return .red" in color
assert "Text(memory.footprintText)" in source and "Text(memory.availableText)" in source
assert "memory.footprintBytes == nil ? .secondary : memColor" in source
assert ".accessibilityValue(memory.accessibilityValue)" in source
assert "does not guarantee an allocation or prevent termination" in source
for feature in ("pacingPill", "capturePill", "ecoPill", "fencePill"):
    assert source.count("                    " + feature) == 2, feature
assert "UIKit" not in policy and "task_info" not in policy
print("PASS: advisory bridge, unknown footprint, unchanged cadence, lifecycle and overlay wiring", flush=True)
if args.source_only:
    print("SKIP: compiled Swift memory policy and lifecycle (--source-only)")
    raise SystemExit(0)
compiler = shutil.which(os.environ.get("SWIFTC", "swiftc"))
if not compiler:
    raise SystemExit("FAIL: swiftc missing; set SWIFTC or explicitly request --source-only")

harness = r'''
POLICY
let mb: UInt64 = 1024 * 1024
let empty = FPSOverlayMemorySnapshot()
assert(empty.footprintText == "?MB" && empty.availableText == "avail ?")
assert(empty.headroomBand == .unknown)
assert(empty.accessibilityValue == "Footprint unavailable. Available memory unknown")
let zero = FPSOverlayMemorySnapshot(footprintBytes: 0, availableBytes: 0)
assert(zero.footprintText == "0MB") // A valid zero footprint is not a failed read.
assert(zero.availableText == "avail ?" && zero.headroomBand == .unavailableOrExhausted)
assert(zero.accessibilityValue.contains("exhausted or unavailable"))
let subMB = FPSOverlayMemorySnapshot(footprintBytes: mb - 1, availableBytes: mb - 1)
assert(subMB.footprintText == "0MB" && subMB.availableText == "avail <1MB")
assert(subMB.accessibilityValue.contains("less than one megabyte"))
assert(subMB.headroomBand == .veryLow)
let oneMB = FPSOverlayMemorySnapshot(footprintBytes: mb, availableBytes: mb)
assert(oneMB.footprintText == "1MB" && oneMB.availableText == "avail ~1MB")
let truncated = FPSOverlayMemorySnapshot(footprintBytes: 3 * mb - 1, availableBytes: 3 * mb - 1)
assert(truncated.footprintText == "2MB" && truncated.availableText == "avail ~2MB")
let maximum = FPSOverlayMemorySnapshot(footprintBytes: UInt64.max, availableBytes: UInt64.max)
assert(maximum.footprintText == "17592186044415MB")
assert(maximum.availableText == "avail ~17592186044415MB" && maximum.headroomBand == .higher)

let bands: [(UInt64, FPSOverlayMemorySnapshot.HeadroomBand)] = [
    (1, .veryLow), (128 * mb - 1, .veryLow), (128 * mb, .veryLow),
    (128 * mb + 1, .low), (384 * mb - 1, .low), (384 * mb, .low),
    (384 * mb + 1, .moderate), (768 * mb - 1, .moderate),
    (768 * mb, .moderate), (768 * mb + 1, .higher)
]
for (bytes, band) in bands {
    // Identical headroom must give the same hint on either side of the old
    // 4096 MB assumption, and even if the independent footprint query fails.
    for footprint: UInt64? in [nil, 0, mb, 4096 * mb, 8192 * mb, UInt64.max] {
        let snapshot = FPSOverlayMemorySnapshot(footprintBytes: footprint, availableBytes: bytes)
        assert(snapshot.headroomBand == band)
    }
}
let failedFootprint = FPSOverlayMemorySnapshot(footprintBytes: nil, availableBytes: 800 * mb)
assert(failedFootprint.footprintText == "?MB" && failedFootprint.headroomBand == .higher)
assert(failedFootprint.accessibilityValue.contains("Footprint unavailable"))
assert(FPSOverlayMemorySnapshot(footprintBytes: 800 * mb).headroomBand == .unknown)
print("PASS: zero/unknown/failed reads, byte boundaries, large values and footprint independence")

// Mimic SwiftUI's reference-backed State. All production timer function
// bodies below are compiled unchanged, including callbacks capturing the view.
@propertyWrapper final class State<Value> {
    var wrappedValue: Value
    init(wrappedValue: Value) { self.wrappedValue = wrappedValue }
}
final class Timer {
    static var created: [Timer] = []
    let interval: Double
    private(set) var valid = true
    private var callback: ((Timer) -> Void)?
    init(interval: Double, callback: @escaping (Timer) -> Void) {
        self.interval = interval; self.callback = callback
    }
    static func scheduledTimer(withTimeInterval interval: Double, repeats: Bool,
                               block: @escaping (Timer) -> Void) -> Timer {
        assert(repeats)
        let timer = Timer(interval: interval, callback: block)
        created.append(timer)
        return timer
    }
    func fire() { if valid { callback?(self) } }
    func invalidate() { valid = false; callback = nil }
}
typealias CFAbsoluteTime = Double
var clock: Double = 1
var count: UInt64 = 10
var presentReads = 0, pacingReads = 0
func CFAbsoluteTimeGetCurrent() -> Double { clock }
func madeira_get_present_count() -> UInt64 { presentReads += 1; return count }
func madeira_get_vsync_locked() -> Int32 { pacingReads += 1; return 1 }
enum ProMotionIntent {
    static var applications = 0
    static func apply(mode: Int32) { assert(mode == 1); applications += 1 }
}
var footprintReads = 0, availableReads = 0
var currentFootprint: UInt64? = 1024 * mb
var currentAvailable: UInt64 = 800 * mb
func jit_available_memory() -> UInt64 { availableReads += 1; return currentAvailable }
struct OverlayHarness {
    var compact = false
    @State var visible = true
    @State var timer: Timer? = nil
    @State var displayTimer: Timer? = nil
    @State var memory = FPSOverlayMemorySnapshot()
    @State var samples: [(t: CFAbsoluteTime, c: UInt64)] = []
    @State var presentCount: UInt64 = 0
    @State var fps: Double = 0
    @State var vsyncMode: Int32 = 1
    let bufferCapacity = 50
    private func readFootprintBytes() -> UInt64? { footprintReads += 1; return currentFootprint }
    REFRESH
    START
    STOP
    TOGGLE
    FPS
    func tapVisibility() { toggleVisibility() }
    func appear() { startTimers() }
    func disappear() { stopTimers() }
}
let overlay = OverlayHarness()
overlay.appear()
assert(Timer.created.count == 2 && Timer.created.filter { $0.valid }.count == 2)
assert(footprintReads == 1 && availableReads == 1)
assert(overlay.memory.footprintText == "1024MB" && overlay.memory.headroomBand == .higher)
let firstTimers = Timer.created
assert(firstTimers.map { $0.interval } == [0.1, 0.25])
for _ in 0..<100 { clock += 0.1; count += 1; firstTimers[0].fire() }
assert(footprintReads == 1 && availableReads == 1 && overlay.samples.count == 50)
firstTimers[1].fire()
assert(footprintReads == 2 && availableReads == 2)
assert(overlay.fps > 0)
// Repeated appearance replaces both timers. Retired callbacks cannot query or
// publish anything, and display ticks always get a new system headroom value.
overlay.appear()
assert(firstTimers.allSatisfy { !$0.valid })
assert(Timer.created.count == 4 && Timer.created.filter { $0.valid }.count == 2)
assert(overlay.samples.count == 1 && overlay.fps == 0 && footprintReads == 3 && availableReads == 3)
firstTimers.forEach { $0.fire() }
assert(footprintReads == 3 && availableReads == 3)
currentAvailable = 1
Timer.created.last!.fire()
assert(overlay.memory.headroomBand == .veryLow && availableReads == 4)
currentFootprint = nil; currentAvailable = 0
Timer.created.last!.fire()
assert(overlay.memory.footprintBytes == nil && overlay.memory.footprintText == "?MB")
assert(overlay.memory.headroomBand == .unavailableOrExhausted && availableReads == 5)
overlay.disappear(); overlay.disappear()
assert(overlay.timer == nil && overlay.displayTimer == nil)
assert(Timer.created.allSatisfy { !$0.valid })
Timer.created.forEach { $0.fire() }
assert(footprintReads == 5 && availableReads == 5)
// A later appear takes a new sample instead of reviving the earlier reading.
currentFootprint = 5000 * mb; currentAvailable = 900 * mb
overlay.appear()
assert(overlay.memory.footprintText == "5000MB" && overlay.memory.headroomBand == .higher)
assert(footprintReads == 6 && availableReads == 6)
assert(Timer.created.filter { $0.valid }.count == 2)
overlay.disappear()
assert(Timer.created.allSatisfy { !$0.valid })
print("PASS: production repeat-appear/disappear, fresh display samples, no sampler reads or duplicate timers")

// Hide affects only the overlay: neither the FPS sampler nor any memory
// reader/pacing hook runs while the dot is hidden, including a later appear.
let hooksBeforeHidden = (presentReads, pacingReads, ProMotionIntent.applications,
                         footprintReads, availableReads)
let timersBeforeHidden = Timer.created.count
overlay.tapVisibility()
assert(!overlay.visible && Timer.created.allSatisfy { !$0.valid })
for _ in 0..<20 { overlay.appear() }
Timer.created.forEach { $0.fire() }
assert(Timer.created.count == timersBeforeHidden)
assert((presentReads, pacingReads, ProMotionIntent.applications,
        footprintReads, availableReads) == hooksBeforeHidden)
count = 999; clock += 50
currentFootprint = 700 * mb; currentAvailable = 128 * mb
overlay.tapVisibility()
assert(overlay.visible && overlay.presentCount == 999 && overlay.fps == 0)
assert(overlay.samples.count == 1 && overlay.samples[0].t == clock)
assert(overlay.memory.footprintText == "700MB" && overlay.memory.headroomBand == .veryLow)
assert(footprintReads == 7 && availableReads == 7)
assert(Timer.created.filter { $0.valid }.count == 2)
let firstShown = Array(Timer.created.suffix(2))
for _ in 0..<20 {
    let beforeHide = (presentReads, pacingReads, ProMotionIntent.applications,
                      footprintReads, availableReads)
    overlay.tapVisibility()
    overlay.appear()  // A hidden view reappearing must stay idle.
    Timer.created.forEach { $0.fire() }
    assert((presentReads, pacingReads, ProMotionIntent.applications,
            footprintReads, availableReads) == beforeHide)
    assert(Timer.created.allSatisfy { !$0.valid })
    overlay.tapVisibility()
    assert(Timer.created.filter { $0.valid }.count == 2)
    assert(overlay.samples.count == 1 && overlay.fps == 0)
}
assert(firstShown.allSatisfy { !$0.valid })
assert(footprintReads == 27 && availableReads == 27)
overlay.disappear()
assert(Timer.created.allSatisfy { !$0.valid })
print("PASS: 20 hidden appearances and 20 hide/show cycles; zero hidden hooks, exactly two live timers on show")

// Compact layout keeps its displayed FPS/pacing controls live, but performs
// zero memory calls throughout appearance, display ticks and hide/show cycles.
let compact = OverlayHarness(compact: true)
let memoryBeforeCompact = (footprintReads, availableReads)
let presentsBeforeCompact = presentReads
let pacingBeforeCompact = pacingReads
let promotionsBeforeCompact = ProMotionIntent.applications
let timerCountBeforeCompact = Timer.created.count
compact.appear()
for _ in 0..<100 {
    clock += 0.1; count += 1
    compact.timer!.fire()
    compact.displayTimer!.fire()
}
assert(compact.presentCount == count && compact.fps > 0)
for _ in 0..<20 { compact.appear() }
for _ in 0..<20 {
    compact.tapVisibility()
    compact.appear()
    Timer.created.forEach { $0.fire() }
    compact.tapVisibility()
}
assert((footprintReads, availableReads) == memoryBeforeCompact)
assert(presentReads - presentsBeforeCompact == 141) // 41 starts + 100 FPS ticks.
assert(pacingReads - pacingBeforeCompact == 41)
assert(ProMotionIntent.applications - promotionsBeforeCompact == 41)
assert(Timer.created.count - timerCountBeforeCompact == 82)
assert(Timer.created.filter { $0.valid }.count == 2)
compact.disappear(); compact.disappear()
assert(Timer.created.allSatisfy { !$0.valid })
print("PASS: compact 41 starts + 100 display ticks: zero memory reads, 141 present reads, 82 created/0 surviving timers")
'''
for marker, replacement in (("POLICY", policy), ("REFRESH", refresh), ("START", start),
                            ("STOP", stop), ("TOGGLE", toggle), ("FPS", fps)):
    # Only replace standalone marker lines, not FPSOverlay type names.
    harness = harness.replace("\n" + marker + "\n", "\n" + replacement + "\n")
    harness = harness.replace("\n    " + marker + "\n", "\n    " + replacement + "\n")
with tempfile.TemporaryDirectory(prefix="madeira-memory-overlay-") as directory:
    path = Path(directory)
    (path / "main.swift").write_text(harness)
    subprocess.run([compiler, "-swift-version", "5", str(path / "main.swift"),
                    "-o", str(path / "check")], check=True)
    subprocess.run([str(path / "check")], check=True)
