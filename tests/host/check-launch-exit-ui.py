#!/usr/bin/env python3
"""Compile production Swift exit reporting, polling, failure and finish methods.

The four LibraryModel methods and LibraryLaunchFailure are compiled verbatim;
native status, rendering, Dock and UIKit-independent teardown collaborators are
inert test doubles. This is no iOS UI/device/Wine runtime test. Default mode
requires swiftc (macOS CI); --source-only explicitly skips all Swift execution.
A baseline mutation removes the reported-exit guard and must fail the zero-exit
callback-first regression, rather than merely failing to compile.
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
lib = (root / 'app/Madeira/Library.swift').read_text()
front = (root / 'app/Madeira/ContentView.swift').read_text()
workflow = (root / '.github/workflows/desktop-compatibility.yml').read_text()


def block(text, signature):
    start = text.index(signature)
    brace = text.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


methods = '\n'.join(block(lib, signature) for signature in [
    'private func exitReport()', 'private func poll()', 'func launchFailed(', 'private func finish()'])
failure = block(lib, 'func launchFailed(')
assert 'else if error == nil, wine_process_exit_status(nil) == 0' in failure
assert failure.index('finish()') < failure.index('if offerJIT, let reason') < failure.index('else if let reason')
assert 'if sawProcess || wine_process_exit_status(&status) != 0 { finish() }' in methods
assert 'guard wine_process_exit_status(&status) != 0, status != 0 else { return nil }' in methods
assert 'if let report = exitReport() { error = report }' in methods
assert 'if wine_process_is_running() == 0 { LibraryModel.shared.launchFailed() }' in front
assert '          python3 tests/host/check-launch-exit-ui.py\n' in workflow
print('PASS: production observed-exit fallback guard, poll/status/finish ordering and macOS CI wiring', flush=True)
if args.source_only:
    print('SKIP: compiled Swift lifecycle and baseline mutation (--source-only)')
    raise SystemExit(0)
compiler = shutil.which(os.environ.get('SWIFTC', 'swiftc'))
if not compiler:
    raise SystemExit('FAIL: swiftc not found; set SWIFTC or explicitly use --source-only')

harness = r'''
import Foundation
var nativeStatus: UInt32? = nil
var nativeWine: Int32 = 0
var nativeServer: Int32 = 0
var reportsEnabled = true
var flushes = 0
func wine_process_exit_status(_ status: UnsafeMutablePointer<UInt32>?) -> Int32 {
    guard let value = nativeStatus else { return 0 }
    status?.pointee = value
    return 1
}
func wine_process_is_running() -> Int32 { nativeWine }
func wineserver_is_running() -> Int32 { nativeServer }
@discardableResult func madeira_startup_flush() -> Int32 { flushes += 1; return 0 }
func madeira_get_present_count() -> UInt64 { 0 }
func winios_surface_present_count() -> UInt64 { 0 }
enum MadeiraConfig { static func flag(_ key: String) -> Bool { reportsEnabled } }
final class LogStore {
    static let shared = LogStore()
    func log(_ message: String) {}
    func setDisplayActive(_ active: Bool) {}
}
final class DockStartScreen {
    static let shared = DockStartScreen()
    var active = false, holding = false
    func poll(_ model: LibraryModel, rendered: Bool) {}
    func finish() {}
}
enum MetalBackedView {
    static var presentCountAtLaunch: UInt64 = 0
    static func refreshDisplayMode(reason: String) {}
}
final class TouchControlsModel {
    static let shared = TouchControlsModel()
    var editing = false, visible = true
    var selected: Int? = nil
    var controls: [Int] = []
    var sizeScale = 1.0
    var layoutID: String? = nil
}
enum ControlPresetsModel { static let enabled = false }
enum LibraryKeyboard { static func hide() {} }
final class LibraryController {
    static let shared = LibraryController()
    func configure(enabled: Bool, ownsInput: Bool) {}
}
final class MetalHostView { static let shared = MetalHostView(); var isHidden = false }
final class ProMotionIntent { static let shared = ProMotionIntent(); func setActive(_ active: Bool) {} }
enum DisplayMode { case fit }
FAILURE_ENUM
final class LibraryModel {
    var current: Int? = 1, activeEntry: Int? = 1
    var sawProcess = false, quitRequested = false, error: String? = nil, jitNotice: String? = nil
    var launching = true, launchSlow = false, launchLogs = false
    var launchStarted = Date(), launchPresent: UInt64 = 0, launchSurface: UInt64 = 0
    var sessionMessage = "Starting…", laidOutAfterFirstPresent = false
    var timer: Timer? = nil, controllerMode: String? = nil, controllerBinds: [String: String] = [:]
    var padMouseVertical = 1, savedControls: [Int] = [], savedVisible = true, savedSize = 1.0
    var savedLayout: String? = nil, menu = false, displayMode = DisplayMode.fit, enabled = true
    func saveCurrentProfile() {}
    func showGameView(reason: String) { launching = false }
    func tick() { poll() }
    func reportedMessage() -> String? { exitReport() }
METHODS
}
func require(_ condition: @autoclosure () -> Bool, _ message: String) {
    if !condition() { print("FAIL: \(message)"); fflush(stdout); exit(1) }
}
func model(status: UInt32?, saw: Bool = false, reporting: Bool = true, quit: Bool = false,
           wine: Int32 = 0, server: Int32 = 0) -> LibraryModel {
    nativeStatus = status; nativeWine = wine; nativeServer = server; reportsEnabled = reporting
    let result = LibraryModel(); result.sawProcess = saw; result.quitRequested = quit
    return result
}
// Regression first: runWineFullSequence's callback wins the race with UI poll.
let shortSuccess = model(status: 0)
shortSuccess.launchFailed()
require(shortSuccess.current == nil && shortSuccess.error == nil,
        "reported zero exit must not become generic launch failure")

for status in [UInt32(0), 1, 0xC0000135] {
    for pollFirst in [false, true] {
        let m = model(status: status)
        if pollFirst { m.tick() }
        m.launchFailed()
        require(m.current == nil, "short-lived process must finish in either callback ordering")
        if status == 0 { require(m.error == nil, "zero exit is not an invented failure") }
        else if status == 1 { require(m.error?.contains("exited with code 1") == true, "ordinary nonzero guidance retained") }
        else { require(m.error?.contains("C0000135") == true, "NTSTATUS guidance retained") }
        let existing = m.error
        m.launchFailed()
        require(m.error == existing, "repeat completion callback is inert")
    }
}
let unknown = model(status: nil)
unknown.tick()
require(unknown.current != nil, "no process observation or exit is not completion")
unknown.launchFailed()
require(unknown.error?.contains("session could not start") == true, "unknown failure keeps generic guidance")
for status in [UInt32(0), 1, 0xC0000135] {
    let explicit = model(status: status)
    explicit.launchFailed("known setup failure")
    require(explicit.error == "known setup failure", "explicit reason retains priority over observed exit")
    let jit = model(status: status)
    jit.launchFailed("attach debugger", offerJIT: true)
    require(jit.jitNotice == "attach debugger", "explicit JIT notice retained")
    let disabled = model(status: status, reporting: false)
    disabled.launchFailed()
    require(disabled.error == nil, "disabled exit reports do not reappear as generic failures")
    let quit = model(status: status, quit: true)
    quit.launchFailed()
    require(quit.error == nil, "requested quit does not fabricate a launch failure")
    let running = model(status: status, wine: 1)
    running.tick()
    require(running.sawProcess && running.current != nil && running.sessionMessage.isEmpty,
            "running process remains active even with an initial exit and live children")
    running.launchFailed()
    require(running.current != nil && running.error == nil, "seen running process ignores startup-only completion")
    nativeWine = 0; nativeServer = 1
    running.tick()
    require(running.current != nil, "poll waits for wineserver teardown")
    nativeServer = 0
    running.tick()
    require(running.current == nil, "poll finishes seen process after native teardown")
}
let explicitUnknown = model(status: nil)
explicitUnknown.launchFailed("JIT pool allocation failed")
require(explicitUnknown.error == "JIT pool allocation failed", "explicit pre-process failure retained")
let jitUnknown = model(status: nil)
jitUnknown.launchFailed("JIT unavailable", offerJIT: true)
require(jitUnknown.jitNotice == "JIT unavailable", "pre-process JIT setup notice retained")
let prior = model(status: nil)
prior.error = "existing diagnostic"
prior.launchFailed()
require(prior.error == "existing diagnostic", "fallback does not overwrite an existing diagnostic")
require(flushes > 0, "actual production safe-drain calls were exercised")
print("PASS: compiled production Swift status, poll, failure and finish methods; callback races, zero/nonzero/NTSTATUS, explicit/JIT and reporting preferences")
'''.replace('FAILURE_ENUM', block(lib, 'enum LibraryLaunchFailure {')).replace('METHODS', methods)

with tempfile.TemporaryDirectory(prefix='madeira-launch-exit-ui-') as temp:
    temp = Path(temp)
    src = temp / 'main.swift'; exe = temp / 'check'
    src.write_text(harness)
    subprocess.run([compiler, str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
    guarded = 'else if error == nil, wine_process_exit_status(nil) == 0'
    assert harness.count(guarded) == 1
    baseline = temp / 'baseline.swift'; mutated = temp / 'baseline'
    baseline.write_text(harness.replace(guarded, 'else if error == nil'))
    subprocess.run([compiler, str(baseline), '-o', str(mutated)], check=True)
    result = subprocess.run([str(mutated)], capture_output=True, text=True)
    assert result.returncode != 0 and 'reported zero exit must not become generic launch failure' in result.stdout, result
    print('PASS: compiled baseline mutation reproduces the zero-exit callback-first false failure')
