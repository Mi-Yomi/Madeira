#!/usr/bin/env python3
"""Compile the production Dock report watcher with an inert, controlled clock.

Real Swift tasks/cancellation and MainActor execute the production function.
Only its two-second sleep call is substituted with a controllable suspension;
Dock files, report readers, native flags and account-release hooks are inert.
No credentials, Wine process, app build, network or device is involved.
--source-only explicitly skips compilation on hosts without Swift.
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
source = (ROOT / "app/Madeira/MadeiraDockView.swift").read_text()


def block(signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


watcher = block("func watchReport()")
stop = block("func stopWatchingReport()")
assert "@MainActor\nfinal class MadeiraDockModel: ObservableObject" in source
assert "private var watchID: UUID?" in source
assert watcher.index("stopWatchingReport()") < watcher.index("watchID = id")
assert stop.index("watchID = nil") < stop.index("watch?.cancel()") < stop.index("watch = nil")
assert "cleanup()" not in stop and "dockEnded()" not in stop
launch = (ROOT / "app/Madeira/ContentView.swift").read_text().split("private func startDock(", 1)[1].split(
    "private func prepareSteamLaunch()", 1)[0]
assert launch.index("dockLaunchInFlight = true") < launch.index(
    "MadeiraDockModel.shared.stopWatchingReport()") < launch.index("Task { @MainActor in") < launch.index(
    "await SteamOwnedLibrary.shared.prepareDock()")
guard = "guard !Task.isCancelled, watchID == id else { return }"
assert watcher.count(guard) == 2
sleep = "try? await Task.sleep(nanoseconds: 2_000_000_000)"
assert watcher.count(sleep) == 1
assert watcher.index(sleep) < watcher.index(guard) < watcher.index("MadeiraDock.pollReport()")
assert watcher.rindex(guard) < watcher.index("MadeiraDock.cleanup()") < watcher.index(
    "SteamOwnedLibrary.shared.dockEnded()") < watcher.index("watchID = nil")
assert "watch = nil" in watcher
assert "idle >= 150" in watcher and "idle >= 5" in watcher
print("PASS: report ownership, post-suspension cancellation gate and unchanged timeout wiring", flush=True)
if args.source_only:
    print("SKIP: compiled Swift watcher lifecycle (--source-only)")
    raise SystemExit(0)
compiler = shutil.which(os.environ.get("SWIFTC", "swiftc"))
if not compiler:
    raise SystemExit("FAIL: swiftc missing; set SWIFTC or explicitly request --source-only")

harness = r'''
import Foundation

@MainActor enum Clock {
    static var waiters: [UUID: CheckedContinuation<Void, Error>] = [:]
    static var registrations = 0
    static func sleep(nanoseconds: UInt64) async throws {
        precondition(nanoseconds == 2_000_000_000)
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                if Task.isCancelled { continuation.resume(throwing: CancellationError()) }
                else { waiters[id] = continuation; registrations += 1 }
            }
        } onCancel: {
            Task { @MainActor in
                waiters.removeValue(forKey: id)?.resume(throwing: CancellationError())
            }
        }
    }
    static func tick() {
        precondition(waiters.count == 1, "test must own exactly one suspended watcher")
        let pending = Array(waiters.values)
        waiters.removeAll()
        pending.forEach { $0.resume() }
    }
}
@MainActor enum MadeiraDock {
    struct Report {
        var fields: [String: String] = [:]
        var result: Int? = nil
        var failure: String? = nil
    }
    static var report = Report()
    static let drive = "inert-drive"
    static var handoff = 0
    static var polls: [Int] = []
    static var cleanups: [Int] = []
    static func pollReport() -> Report { polls.append(handoff); return report }
    static func cleanup() { cleanups.append(handoff); handoff = 0 }
}
@MainActor enum DockInstallers {
    static var note: String? = nil
    static var script: String? = nil
    static var progress: String? = nil
    static var polls = 0
    static func poll(drive: String) -> String? {
        precondition(drive == MadeiraDock.drive); polls += 1; return progress
    }
}
@MainActor final class LogStore {
    static let shared = LogStore()
    enum Level { case error }
    var lines: [String] = []
    func log(_ message: String, level: Level? = nil) { lines.append(message) }
}
@MainActor final class SteamOwnedLibrary {
    static let shared = SteamOwnedLibrary()
    var ended = 0
    func dockEnded() { ended += 1 }
}
@MainActor var wineRunning: Int32 = 0
@MainActor var serverRunning: Int32 = 0
@MainActor func wine_process_is_running() -> Int32 { wineRunning }
@MainActor func wineserver_is_running() -> Int32 { serverRunning }
@MainActor final class Watcher {
    var watch: Task<Void, Never>?
    var watchID: UUID?
    var status: String?
    WATCHER
    STOP
}
@MainActor func until(_ condition: () -> Bool) async {
    // Scheduling only, never a wall-clock delay. Bound a broken test instead
    // of letting an accidentally infinite watcher stall the host test job.
    for _ in 0..<100_000 {
        if condition() { return }
        await Task.yield()
    }
    preconditionFailure("controlled watcher did not settle")
}
@MainActor func tickAndWait() async {
    let registered = Clock.registrations
    Clock.tick()
    await until { Clock.registrations > registered && Clock.waiters.count == 1 }
}
@MainActor func reset(_ handoff: Int) {
    precondition(Clock.waiters.isEmpty)
    MadeiraDock.report = .init(); MadeiraDock.handoff = handoff
    MadeiraDock.polls = []; MadeiraDock.cleanups = []
    DockInstallers.note = nil; DockInstallers.script = nil; DockInstallers.progress = nil
    DockInstallers.polls = 0
    SteamOwnedLibrary.shared.ended = 0; LogStore.shared.lines = []
    wineRunning = 0; serverRunning = 0
}
@main struct Regression {
    @MainActor static func main() async {
        // The exact regression: watcher 1 is asleep, watcher 2 is installed
        // after its handoff exists, and cancellation resumes watcher 1.
        reset(1)
        let model = Watcher()
        model.watchReport()
        await until { Clock.waiters.count == 1 }
        for generation in 2...101 {
            let previous = model.watch!
            let oldID = model.watchID
            let registered = Clock.registrations
            MadeiraDock.handoff = generation
            MadeiraDock.report = .init(result: 35, failure: "new report must remain unread")
            model.watchReport()
            let currentID = model.watchID
            precondition(currentID != nil && currentID != oldID)
            let currentStatus = model.status
            await previous.value
            await until { Clock.registrations > registered && Clock.waiters.count == 1 }
            precondition(MadeiraDock.handoff == generation && MadeiraDock.cleanups.isEmpty,
                         "retired watcher cleaned a newer handoff")
            precondition(MadeiraDock.polls.isEmpty && SteamOwnedLibrary.shared.ended == 0)
            precondition(model.watchID == currentID && model.status == currentStatus && model.watch != nil)
        }
        MadeiraDock.report = .init(result: 0)
        let final = model.watch!
        Clock.tick(); await final.value
        precondition(MadeiraDock.cleanups == [101] && MadeiraDock.polls == [101])
        precondition(SteamOwnedLibrary.shared.ended == 1 && model.watchID == nil && model.watch == nil)
        precondition(model.status == "Madeira Dock finished normally.")
        precondition(Clock.waiters.isEmpty)
        print("PASS: 100 canceled-watcher replacements leave newer handoffs, reports, status and account holds untouched")

        // Replacement before the old task gets any executor time must also
        // skip the old tail cleanup, which sits outside its while loop.
        reset(202)
        model.watchReport(); let neverScheduled = model.watch!
        model.watchReport(); let latest = model.watch!
        await neverScheduled.value
        await until { Clock.waiters.count == 1 }
        precondition(MadeiraDock.cleanups.isEmpty && MadeiraDock.handoff == 202)
        MadeiraDock.report = .init(result: 1, failure: "host failure")
        Clock.tick(); await latest.value
        precondition(MadeiraDock.cleanups == [202] && SteamOwnedLibrary.shared.ended == 1)
        precondition(model.status == "host failure" && model.watchID == nil && model.watch == nil)
        print("PASS: never-scheduled replacement cannot clean up; current failure still reports and cleans once")

        // Identity is an independent ownership check, even if cancellation is
        // delayed or unavailable. A stale uncanceled callback cannot act.
        reset(303)
        model.watchReport(); let stale = model.watch!
        await until { Clock.waiters.count == 1 }
        let replacementID = UUID(); model.watchID = replacementID
        let unchangedStatus = model.status
        Clock.tick(); await stale.value
        precondition(MadeiraDock.cleanups.isEmpty && MadeiraDock.polls.isEmpty)
        precondition(MadeiraDock.handoff == 303 && SteamOwnedLibrary.shared.ended == 0)
        precondition(model.watchID == replacementID && model.status == unchangedStatus)
        model.watch = nil; model.watchID = nil
        print("PASS: stale identity without cancellation skips report reads and all cleanup")

        // The next launch invalidates ownership before prepareDock suspends,
        // while no replacement report watcher exists yet. The retiring task
        // must leave cleanup to that launch's success/failure path.
        reset(350)
        model.watchReport(); let previousAttempt = model.watch!
        await until { Clock.waiters.count == 1 }
        model.stopWatchingReport()
        MadeiraDock.handoff = 351
        await previousAttempt.value
        precondition(MadeiraDock.cleanups.isEmpty && MadeiraDock.polls.isEmpty)
        precondition(MadeiraDock.handoff == 351 && SteamOwnedLibrary.shared.ended == 0)
        precondition(model.watchID == nil && model.watch == nil && Clock.waiters.isEmpty)
        model.stopWatchingReport()  // idempotent; does not consume launch-owned cleanup
        precondition(MadeiraDock.handoff == 351 && SteamOwnedLibrary.shared.ended == 0)
        // Model the existing preparation-failure owner, not the stale watcher.
        MadeiraDock.cleanup(); SteamOwnedLibrary.shared.dockEnded()
        precondition(MadeiraDock.cleanups == [351] && SteamOwnedLibrary.shared.ended == 1)
        print("PASS: early retirement leaves pre-watcher preparation and failure cleanup with the new launch")

        // Existing installer and account-wait status behavior remains live.
        reset(404)
        DockInstallers.note = "installer plan"; DockInstallers.script = "inert-script"
        DockInstallers.progress = "installing"
        model.watchReport(); let progress = model.watch!
        precondition(model.status?.hasPrefix("installer plan\n") == true)
        await until { Clock.waiters.count == 1 }
        await tickAndWait()
        precondition(model.status == "installing" && DockInstallers.polls == 1)
        MadeiraDock.report = .init(fields: ["launch-session-wait": "1", "launch-client-error": "35"])
        await tickAndWait()
        precondition(model.status?.contains("Waiting for Steam to end it") == true)
        MadeiraDock.report = .init(result: 0)
        Clock.tick(); await progress.value
        precondition(MadeiraDock.cleanups == [404] && SteamOwnedLibrary.shared.ended == 1)
        print("PASS: installer progress and account-in-use status retain existing behavior")

        // Original 150 idle ticks before first start; no shortened deadline.
        reset(505)
        model.watchReport(); let notStarted = model.watch!
        await until { Clock.waiters.count == 1 }
        for _ in 0..<149 { await tickAndWait() }
        precondition(MadeiraDock.cleanups.isEmpty && MadeiraDock.polls.count == 149)
        Clock.tick(); await notStarted.value
        precondition(MadeiraDock.polls.count == 150 && MadeiraDock.cleanups == [505])
        precondition(model.status == "The Dock session did not start. See the log.")
        precondition(SteamOwnedLibrary.shared.ended == 1 && model.watch == nil && model.watchID == nil)

        // Original five idle ticks after either native running bit was seen.
        for serverOnly in [true, false] {
            reset(serverOnly ? 606 : 707)
            serverRunning = serverOnly ? 1 : 0; wineRunning = serverOnly ? 0 : 1
            model.watchReport(); let stopped = model.watch!
            await until { Clock.waiters.count == 1 }
            await tickAndWait()
            wineRunning = 0; serverRunning = 0
            for _ in 0..<4 { await tickAndWait() }
            precondition(MadeiraDock.cleanups.isEmpty)
            Clock.tick(); await stopped.value
            precondition(MadeiraDock.cleanups == [serverOnly ? 606 : 707])
            precondition(model.status == "Madeira Dock stopped before reporting a result. Export the log.")
            precondition(SteamOwnedLibrary.shared.ended == 1 && model.watch == nil && model.watchID == nil)
        }
        precondition(Clock.waiters.isEmpty)
        print("PASS: unchanged 150-tick startup and five-tick ended-session cleanup, exactly once")
    }
}
'''
harness = harness.replace("    WATCHER\n", "    " + watcher.replace(
    sleep, "try? await Clock.sleep(nanoseconds: 2_000_000_000)") + "\n")
harness = harness.replace("    STOP\n", "    " + stop + "\n")
with tempfile.TemporaryDirectory(prefix="madeira-dock-watch-") as directory:
    path = Path(directory)
    (path / "main.swift").write_text(harness)
    subprocess.run([compiler, "-swift-version", "5", "-parse-as-library", str(path / "main.swift"),
                    "-o", str(path / "check")], check=True)
    subprocess.run([str(path / "check")], check=True, timeout=30)
