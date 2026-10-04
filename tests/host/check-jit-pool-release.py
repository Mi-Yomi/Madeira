#!/usr/bin/env python3
"""Compile the production one-shot pool gate/readiness logic with inert VM hooks.

No JIT, Mach deallocation, Apple account or iOS device is exercised. --source-only
is an explicit limited check for hosts lacking swiftc; CI runs compiled behavior.
"""
from pathlib import Path
import argparse
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-only", action="store_true")
args = parser.parse_args()
source = (ROOT / "app/Madeira/StikJITHelper.swift").read_text()


def function(text, signature):
    start = text.index(signature)
    brace = text.index("{", start)
    depth, end = 1, brace + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


gate = source.split("// MARK: - One-shot early pool ownership", 1)[1].split("// MARK: - StikDebug integration", 1)[0]
ready = function(source, "static var ready: Bool")
flagged = function(source, "static var flaggedWithoutDebugger: Bool")
release_start = source.index("        switch earlyPoolReleaseGate.release(")
release_end = source.index("        do {\n            var holes:", release_start)
release = source[release_start:release_end]
assert "SigningStatus.current.debugged" in ready and "jit_check_debugged()" not in ready
assert "SigningStatus.current.debugged" in flagged and "jit_check_debugged()" not in flagged
assert "!attachCheck || poolTaken || isDebuggerAttached()" in ready
assert source.count("private static let earlyPoolReleaseGate = JITEarlyPoolReleaseGate()") == 1
assert "lock.lock()" in gate and "defer { lock.unlock() }" in gate
assert gate.index("attempted = true") < gate.index("deallocate(base, size)")
assert release.count("vm_deallocate(") == 1
assert "case .alreadyAttempted:" in release and "case .absent:" in release
assert "if result == KERN_SUCCESS" in release
assert "level: .error" in release
print("PASS: one-shot pool ownership, failure reporting and quiet readiness integration", flush=True)
if args.source_only:
    print("SKIP: compiled Swift checks (--source-only)")
    raise SystemExit(0)
swift = shutil.which(os.environ.get("SWIFTC", "swiftc"))
if not swift:
    raise SystemExit("FAIL: swiftc missing; set SWIFTC or use --source-only explicitly")

harness = r'''
import Foundation
import Dispatch
GATE

let base: UInt = 0x150000000
let size: UInt = 600 << 20
let absent = JITEarlyPoolReleaseGate()
var calls = 0
if case .absent = absent.release(base: 0, size: size, deallocate: { _, _ in fatalError("zero base") }) {} else { fatalError() }
if case .absent = absent.release(base: base, size: 0, deallocate: { _, _ in fatalError("zero size") }) {} else { fatalError() }
if case .attempted(0) = absent.release(base: base, size: size, deallocate: { b, s in
    assert(b == base && s == size); calls += 1; return 0
}) {} else { fatalError() }
for _ in 0..<100 {
    if case .alreadyAttempted = absent.release(base: base, size: size, deallocate: { _, _ in fatalError("double free") }) {} else { fatalError() }
}
assert(calls == 1)

let failed = JITEarlyPoolReleaseGate()
if case .attempted(3) = failed.release(base: base, size: size, deallocate: { _, _ in calls += 1; return 3 }) {} else { fatalError() }
if case .alreadyAttempted = failed.release(base: base, size: size, deallocate: { _, _ in fatalError("error retried") }) {} else { fatalError() }
assert(calls == 2)

final class Counter: @unchecked Sendable {
    let lock = NSLock()
    private(set) var count = 0
    func increment() { lock.lock(); count += 1; lock.unlock() }
}
let concurrentGate = JITEarlyPoolReleaseGate()
let concurrentCalls = Counter()
DispatchQueue.concurrentPerform(iterations: 128) { _ in
    _ = concurrentGate.release(base: base, size: size, deallocate: { _, _ in
        concurrentCalls.increment(); Thread.sleep(forTimeInterval: 0.001); return 0
    })
}
assert(concurrentCalls.count == 1)

struct SigningStatus {
    static var debuggedValue = false
    var debugged: Bool { Self.debuggedValue }
    static var current: SigningStatus { SigningStatus() }
}
var noisyChecks = 0, attachQueries = 0, attached = false
func jit_check_debugged() -> Bool { noisyChecks += 1; return SigningStatus.debuggedValue }
func isDebuggerAttached() -> Bool { attachQueries += 1; return attached }
enum Readiness {
    static var attachCheck = true
    static var poolTaken = false
    READY
    FLAGGED
}
for _ in 0..<300 { assert(!Readiness.ready) }
assert(noisyChecks == 0 && attachQueries == 0)
SigningStatus.debuggedValue = true
assert(!Readiness.ready && Readiness.flaggedWithoutDebugger)
attached = true
assert(Readiness.ready && !Readiness.flaggedWithoutDebugger)
attached = false; Readiness.poolTaken = true
let before = attachQueries
assert(Readiness.ready && !Readiness.flaggedWithoutDebugger)
assert(attachQueries == before)
Readiness.poolTaken = false; Readiness.attachCheck = false
assert(Readiness.ready)
assert(noisyChecks == 0)

typealias vm_address_t = UInt
typealias vm_size_t = UInt
let mach_task_self_: UInt32 = 1
let KERN_SUCCESS: Int32 = 0
var vmCalls = 0
func vm_deallocate(_ task: UInt32, _ address: UInt, _ bytes: UInt) -> Int32 {
    assert(task == 1 && address == base && bytes == size)
    vmCalls += 1
    return 0
}
let madeira_early_intruder_base: UInt = 0
let madeira_early_intruder_size: UInt = 0
let madeira_early_intruder_tag: UInt32 = 0
let madeira_early_intruder_prot: UInt32 = 0
final class LogStore {
    enum Level { case error }
    static let shared = LogStore()
    var logs: [String] = []
    func log(_ message: String, level: Level? = nil) { logs.append(message) }
}
enum Integration {
    static let earlyPoolReleaseGate = JITEarlyPoolReleaseGate()
    static func request() {
        let earlyPoolBase = base, earlyPoolSize = size
        RELEASE
    }
}
// Reproduce the old unguarded fragment, without performing any real VM action.
func legacyRequest() { _ = vm_deallocate(mach_task_self_, base, size) }
legacyRequest(); legacyRequest()
assert(vmCalls == 2)
vmCalls = 0
Integration.request()
Integration.request() // a retry after the caller's later debugger request failed
assert(vmCalls == 1)
assert(LogStore.shared.logs.count == 2)
assert(LogStore.shared.logs[0].contains("released the early pool placeholder"))
assert(LogStore.shared.logs[1].contains("not unmapped again"))
print("PASS: 128 concurrent claims, repeated/failed retries, quiet readiness and production VM-call integration")
'''
harness = harness.replace("GATE", gate).replace("READY", ready).replace("FLAGGED", flagged).replace("RELEASE", release)
with tempfile.TemporaryDirectory(prefix="madeira-jit-pool-") as directory:
    path = Path(directory)
    (path / "main.swift").write_text(harness)
    subprocess.run([swift, "-swift-version", "5", str(path / "main.swift"), "-o", str(path / "check")], check=True)
    subprocess.run([str(path / "check")], check=True)
