#!/usr/bin/env python3
"""Check production Wine launch readiness/admission without an iOS SDK.

Compiles the real Swift launch gate and bridge-call wrappers with an injected
clock and inert native hooks. No app build, JIT, Wine process or device is used.
--source-only explicitly skips compiled behavior on hosts without swiftc.
"""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source-only', action='store_true')
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
source = (root / 'app/Madeira/ContentView.swift').read_text()


def function(text, signature):
    start = text.index(signature)
    brace = text.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


gate = source.split('// MARK: - Checked Wine launch readiness', 1)[1].split(
    '// MARK: - Window-hosted Metal layer', 1)[0]
sequence = function(source, 'private func runWineFullSequence(')
server = function(source, 'private func startWineserver() -> Bool')
wine = function(source, 'private func startWineProcess() -> Bool')
admission = function(source, 'private func canStartWineLaunch() -> Bool')
assert 'WineServerLaunchGate.canStart(inFlight: wineLaunchInFlight || dockLaunchInFlight' in admission
assert sequence.index('guard canStartWineLaunch()') < sequence.index('wineLaunchInFlight = true')
assert sequence.index('wineLaunchInFlight = true') < sequence.index('DispatchQueue.global(')
assert 'defer {' in sequence and sequence.count('wineLaunchInFlight = false') == 1
cleanup = sequence.split('defer {', 1)[1].split('func failLaunch(', 1)[0]
assert 'DispatchQueue.main.async {' in cleanup
for requirement in ['heartbeat.invalidate()', 'ws_log_quiet = 0', 'logStore.uiPaused = false']:
    assert requirement in cleanup
failure = function(sequence, 'func failLaunch(')
assert 'DispatchQueue.main.async {' in failure
for requirement in ['heartbeat.invalidate()', 'ws_log_quiet = 0', 'logStore.uiPaused = false',
                    'LibraryModel.shared.launchFailed(reason, offerJIT: offerJIT)']:
    assert requirement in failure
assert 'failLaunch(reason, offerJIT: offerJIT)' in sequence, 'pool failure uses common cleanup too'
assert 'now: { ProcessInfo.processInfo.systemUptime }' in sequence, 'deadline must use monotonic time'
assert 'static let readinessTimeout: TimeInterval = 10.0' in gate
assert 'static let legacyStartDelay: TimeInterval = 2.0' in gate
assert 'observed >= legacyStartDelay' in gate
assert gate.index('guard elapsed <= timeout else { return .timedOut }') < gate.index('let ready = isReady()'), (
    'an oversleep must check the deadline before accepting readiness')
assert gate.index('let ready = isReady()') < gate.index('let observed = now() - began') < gate.index(
    'guard observed <= timeout else { return .timedOut }') < gate.index('if ready &&'), (
    'readiness observation must be timed after reading the ready bit')
assert 'Int(WineServerLaunchGate.readinessTimeout)' in sequence, 'timeout message must track the bound'
assert sequence.count('wineserver ready after') == 1
assert 'serverReady: { elapsed in' in sequence
assert 'guard self.startWineserver() else { return false }' in sequence
assert sequence.count('self.startWineProcess()') == 1
assert 'return self.startWineProcess()' in sequence
abort = sequence.split('if result != .started {', 1)[1].split('// Step 4:', 1)[0]
assert abort.index('failLaunch(') < abort.index('wineserver_stop()') < abort.index('return')
assert 'if result != .serverStartFailed { wineserver_stop() }' in abort
assert 'Close Madeira and reopen it before trying again.' in abort
assert 'CFAbsoluteTimeGetCurrent() - waitStart < 2.0' not in sequence
assert 'return result == 0' in server and 'return result == 0' in wine
assert wine.index('wineserver_is_running() != 0, wineserver_is_ready() != 0') < wine.index('wine_process_start(')

# Readiness's publication site is already correct: do not move it earlier or
# substitute an app-side sleep for observing registry/HID initialization.
server_main = (root / 'build/wineserver/main_ios.c').read_text()
assert server_main.index('init_registry();') < server_main.index('madeira_hidpad_init();') < server_main.index(
    '__atomic_store_n( &wineserver_ready, 1, __ATOMIC_RELEASE );')

# Every old developer launch which sets process-wide environment first checks
# admission. A rejected repeat must not retarget the original pending launch.
for title in ['Steam Testing', 'Wine Virtual Desktop', 'Stray (UE4, -dx11)',
              'Valley of the Ancient (UE5)', 'Thumper (standalone)', 'x64 DX11 cube',
              'D3D12 cube', 'D3D12 M2 ABI', 'x64 clock test', 'x64 call cost']:
    button = function(source, f'Button("{title}")')
    assert button.index('guard canStartWineLaunch()') < button.index('setenv('), title
library = function(source, 'private func startLibraryEntry(')
assert library.index('guard canStartWineLaunch(), library.current == nil') < library.index('entry.configureLaunch()')
dock = function(source, 'private func startDock(')
assert dock.count('guard !wineLaunchInFlight,') == 2, 'Dock rechecks after awaiting account handoff'
assert 'guard !wineLaunchInFlight, !dockLaunchInFlight,' in dock
assert dock.index('guard !wineLaunchInFlight, !dockLaunchInFlight,') < dock.index('jitReadyForLaunch(')
assert dock.index('dockLaunchInFlight = true') < dock.index('Task { @MainActor in')
assert 'defer { dockLaunchInFlight = false }' in dock
handoff = dock[dock.rindex('dockLaunchInFlight = false'):]
assert 'await ' not in handoff and 'runWineFullSequence(profile: profile)' in handoff
assert dock.index('guard !wineLaunchInFlight, StikJITHelper.ready') > dock.index('await SteamOwnedLibrary.shared.prepareDock()')
print('PASS: readiness, checked starts, duplicate admission and main-thread failure cleanup wiring', flush=True)
if args.source_only:
    print('SKIP: compiled Swift launch-readiness behavior (--source-only)')
    raise SystemExit(0)

compiler = shutil.which(os.environ.get('SWIFTC', 'swiftc'))
if not compiler:
    raise SystemExit('FAIL: swiftc not found; set SWIFTC or use --source-only explicitly')

harness = r'''
import Foundation
GATE

// Compile the actual production wrappers too, with native starts reduced to
// counters/status codes. They never create a thread, socket or Wine prefix.
enum LogLevel { case info, success, error }
struct TestLog {
    func log(_ message: String, level: LogLevel = .info) {}
}
var nativeRunning: Int32 = 0
var nativeReady: Int32 = 0
var serverResult: Int32 = 0
var wineResult: Int32 = 0
var serverCalls = 0
var wineCalls = 0
func wineserver_start(_ prefix: String) -> Int32 { serverCalls += 1; return serverResult }
func wineserver_is_running() -> Int32 { nativeRunning }
func wineserver_is_ready() -> Int32 { nativeReady }
func wine_process_start(_ prefix: String) -> Int32 { wineCalls += 1; return wineResult }
struct BridgeCalls {
    let logStore = TestLog()
    SERVER_WRAPPER
    WINE_WRAPPER
}
let bridge = BridgeCalls()
precondition(bridge.startWineserver())
serverResult = -1
precondition(!bridge.startWineserver() && serverCalls == 2)
for running in [Int32(0), 1] {
    for ready in [Int32(0), 1] {
        nativeRunning = running; nativeReady = ready; wineCalls = 0
        let expected = running != 0 && ready != 0
        precondition(bridge.startWineProcess() == expected)
        precondition(wineCalls == (expected ? 1 : 0))
    }
}
nativeRunning = 1; nativeReady = 1; wineResult = -1; wineCalls = 0
precondition(!bridge.startWineProcess() && wineCalls == 1)
print("PASS: compiled native start wrappers propagate errors and reject stopped/not-ready servers")

for inFlight in [false, true] {
    for serverRunning in [false, true] {
        for wineRunning in [false, true] {
            let admitted = WineServerLaunchGate.canStart(inFlight: inFlight,
                serverRunning: serverRunning, wineRunning: wineRunning)
            precondition(admitted == (!inFlight && !serverRunning && !wineRunning))
        }
    }
}
// A rejected repeat during setup does not invoke setup/start again; once the
// original worker ends, a still-running native session continues to exclude it.
var pending = false
var accepted = 0
for _ in 0..<100 {
    if WineServerLaunchGate.canStart(inFlight: pending, serverRunning: false, wineRunning: false) {
        pending = true; accepted += 1
    }
}
precondition(accepted == 1)
precondition(!WineServerLaunchGate.canStart(inFlight: false, serverRunning: true, wineRunning: true))
precondition(WineServerLaunchGate.canStart(inFlight: false, serverRunning: false, wineRunning: false))
print("PASS: compiled admission truth table and 100 repeated requests during setup")

@discardableResult
func check(_ name: String, fast: Bool = true, readyAt: Double? = nil,
           stopAt: Double? = nil, startOK: Bool = true, wineOK: Bool = true,
           oversleep: Double = 0, expected: WineServerLaunchGate.Result,
           expectedReady: Bool = false, minimum: Double = 0, maximum: Double = 10) -> Double {
    var clock = 0.0
    var events: [String] = []
    var reads = 0
    var announced: [Double] = []
    let result = WineServerLaunchGate.run(fastStart: fast,
        startServer: { events.append("server"); return startOK },
        isRunning: { reads += 1; return stopAt.map { clock < $0 } ?? true },
        isReady: { reads += 1; return readyAt.map { clock >= $0 } ?? false },
        now: { clock },
        sleep: { interval in
            precondition(interval > 0 && interval <= 0.01)
            precondition(events.count == 1, "sleep after Wine started")
            clock += interval + oversleep
            precondition(clock < 15, "unbounded readiness wait")
        },
        serverReady: { elapsed in events.append("ready"); announced.append(elapsed) },
        startWine: { events.append("wine"); return wineOK })
    precondition(result == expected, "\(name): got \(result), expected \(expected)")
    precondition(clock >= minimum && clock <= maximum + 0.000001, "\(name): elapsed \(clock)")
    precondition(events == (expectedReady ? ["server", "ready", "wine"] : ["server"]),
                 "\(name): wrong starts/logging \(events)")
    precondition(announced.count == (expectedReady ? 1 : 0))
    if !startOK { precondition(reads == 0 && clock == 0, "failed start must never poll") }
    print("PASS: \(name)")
    return clock
}
check("start error ignores even a stale ready bit", readyAt: 0, startOK: false, expected: .serverStartFailed)
check("immediate readiness starts once", readyAt: 0, expected: .started, expectedReady: true, maximum: 0)
check("delayed readiness starts once", readyAt: 0.1, expected: .started, expectedReady: true, minimum: 0.1, maximum: 0.12)
check("fast timeout never logs ready or starts Wine", expected: .timedOut, minimum: 10)
check("slow cold startup after old cutoff succeeds", readyAt: 2.5, expected: .started, expectedReady: true, minimum: 2.5, maximum: 2.52)
check("legacy slow cold startup after minimum succeeds", fast: false, readyAt: 2.5, expected: .started, expectedReady: true, minimum: 2.5, maximum: 2.52)
check("readiness later than timeout never starts Wine", readyAt: 10.1, expected: .timedOut, minimum: 10)
check("stopped immediately never starts", stopAt: 0, expected: .serverStopped, maximum: 0)
check("stopped with stale readiness never starts", readyAt: 0, stopAt: 0, expected: .serverStopped, maximum: 0)
check("stopped during readiness wait never starts", stopAt: 0.1, expected: .serverStopped, minimum: 0.1, maximum: 0.12)
check("simultaneous stop and readiness favors stopped", readyAt: 0.1, stopAt: 0.1, expected: .serverStopped, minimum: 0.1, maximum: 0.12)
check("readiness observed at deadline is safe", readyAt: 10, expected: .started, expectedReady: true, minimum: 10)
check("legacy readiness observed at deadline is safe", fast: false, readyAt: 10, expected: .started, expectedReady: true, minimum: 10)
check("wine start error propagates without retry", readyAt: 0, wineOK: false, expected: .wineStartFailed, expectedReady: true, maximum: 0)
check("legacy mode preserves fixed minimum", fast: false, readyAt: 0, expected: .started, expectedReady: true, minimum: 2, maximum: 2.01)
check("legacy mode verifies readiness at delay end", fast: false, readyAt: 1, expected: .started, expectedReady: true, minimum: 2, maximum: 2.01)
check("legacy delay is not evidence of readiness", fast: false, expected: .timedOut, minimum: 10)
check("legacy wait detects stopped server", fast: false, readyAt: 0, stopAt: 0.1, expected: .serverStopped, minimum: 0.1, maximum: 0.12)
check("oversleep remains fail-closed", oversleep: 0.1, expected: .timedOut, minimum: 10, maximum: 10.11)
let fastLate = check("fast oversleep rejects readiness after deadline", readyAt: 10.005,
    oversleep: 0.1, expected: .timedOut, minimum: 10, maximum: 10.02)
let legacyLate = check("legacy oversleep rejects readiness after deadline", fast: false, readyAt: 10.005,
    oversleep: 0.1, expected: .timedOut, minimum: 10, maximum: 10.02)
precondition(abs(fastLate - 10.01) < 0.000001 && abs(legacyLate - 10.01) < 0.000001)
// Calls do not retain a previous success/readiness result in the gate.
check("second invocation cannot reuse first readiness", expected: .timedOut, minimum: 10)

// A suspension between the pre-read clock sample and the actual ready load
// must not accept readiness using the earlier timestamp. Run the production
// gate in both modes; no wall-clock timing or scheduler assumptions are used.
for fast in [true, false] {
    for ready in [true, false] {
        var clock = 0.0
        var reads = 0, announcements = 0, starts = 0
        let result = WineServerLaunchGate.run(fastStart: fast,
            startServer: { true },
            isRunning: { clock = 9.999; return true },
            isReady: { reads += 1; clock = 10.001; return ready },
            now: { clock },
            sleep: { _ in preconditionFailure("late observation must not sleep") },
            serverReady: { _ in announcements += 1 },
            startWine: { starts += 1; return true })
        precondition(result == .timedOut && reads == 1 && announcements == 0 && starts == 0,
                     "late readiness observation must time out without a ready log or Wine start")
    }
    // The post-read sample is authoritative for the allowed deadline and log.
    for observed in [9.999, 10.0] {
        var clock = 0.0
        var announced: [Double] = []
        var starts = 0
        let result = WineServerLaunchGate.run(fastStart: fast,
            startServer: { true },
            isRunning: { clock = 9.99; return true },
            isReady: { clock = observed; return true },
            now: { clock },
            sleep: { _ in preconditionFailure("ready observation must not sleep") },
            serverReady: { announced.append($0) },
            startWine: { starts += 1; return true })
        precondition(result == .started && starts == 1 && announced == [observed])
    }
}
print("PASS: fast/legacy ready-read delays fail closed past deadline, accept at deadline and log observation time")
print("PASS: all compiled production launch-readiness regressions")
'''.replace('GATE', gate).replace('SERVER_WRAPPER', server.replace('private func', 'func', 1)).replace(
    'WINE_WRAPPER', wine.replace('private func', 'func', 1))

with tempfile.TemporaryDirectory(prefix='madeira-launch-readiness-') as tmp:
    main, executable = Path(tmp) / 'main.swift', Path(tmp) / 'check'
    main.write_text(harness)
    subprocess.run([compiler, str(main), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
