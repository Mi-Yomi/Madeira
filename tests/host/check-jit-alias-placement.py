#!/usr/bin/env python3
"""Exercise the production Swift RW-alias ladder with inert Mach hooks.

No real VM mapping, JIT, device, Apple account or SDK is used. The default run
requires swiftc and compiles the exact production fragments. --source-only is
an explicitly limited integration check for hosts without Swift; it is not a
substitute for the compiled macOS test.
"""
from pathlib import Path
import argparse
import importlib.util
import os
import re
import shlex
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


allocate = function(source, "static func allocatePool(")
overlap = function(allocate, "func overlapsExeWindow(")
ladder_start = allocate.index("        let (abovePoolHint, hintOverflow)")
ladder_end = allocate.index("\n        guard kr1 == KERN_SUCCESS else {", ladder_start)
ladder = allocate[ladder_start:ladder_end]
alias_start = allocate.index("        // Create RW mapping via vm_remap")
alias_end = allocate.index("        return (rx: rxPtr, rw: rwPtr, size: poolSize)", alias_start)
alias = allocate[alias_start:alias_end] + "        return (rx: rxPtr, rw: rwPtr, size: poolSize)\n"
rx_start = allocate.index("        var rxPtrOpt: UnsafeMutableRawPointer? = nil")
rx_end = allocate.index("        // ml1040: the plugs existed only to steer first-fit", rx_start)
rx_selection = allocate[rx_start:rx_end]

assert ladder.count("vm_remap(") == 1
assert "rxAddrV.addingReportingOverflow(vm_address_t(poolSize))" in ladder
assert re.search(r"hintOverflow\s*\? \[0x7000000000, 0\]\s*: \[0x7000000000, abovePoolHint, 0\]", ladder)
assert 'MadeiraConfig.flag("MADEIRA_RW_ALIAS_RETRY")' in ladder
assert "if kr1 != KERN_NO_SPACE || !aliasRetry { break }" in ladder
assert ladder.index("rwAddr = hint") < ladder.index("kr1 = vm_remap(")
assert "VM_FLAGS_ANYWHERE" in ladder and "VM_INHERIT_NONE" in ladder
assert "FIXED" not in ladder and "OVERWRITE" not in ladder
assert "&curProt" in ladder and "&maxProt" in ladder
assert "a >= goodLow && !inGuestWindow && !hitsExeWindow" in rx_selection
assert "a + poolSize > guestLo && a < guestHi" in rx_selection
assert "overlapsExeWindow(vm_address_t(a), vm_address_t(poolSize))" in rx_selection
assert "let rwOverlaps = overlapsExeWindow(rwAddr, vm_address_t(poolSize))" in alias
assert "level: rwOverlaps ? .error : .success" in alias
assert alias.count("let kr2 = vm_protect(") == 1 and alias.count("vm_deallocate(") == 1
assert "vm_protect(mach_task_self_, rwAddr, vm_size_t(poolSize), 0, VM_PROT_READ | VM_PROT_WRITE)" in alias
assert alias.index("guard kr1 == KERN_SUCCESS") < alias.index("vm_protect(")
assert alias.index("guard kr2 == KERN_SUCCESS") < alias.index("jit_make_region_no_footprint(")
assert alias.index("jit_make_region_no_footprint(") < alias.index("poolTaken = true")

# Check only this generated row, without regenerating away options whose source
# submodules may be absent from a source-only checkout.
spec = importlib.util.spec_from_file_location("catalog", ROOT / "build/tools/gen-config-catalog.py")
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)
lines = source.splitlines()
read_line = next(i for i, line in enumerate(lines) if 'MadeiraConfig.flag("MADEIRA_RW_ALIAS_RETRY")' in line)
note = catalog.comment_near(lines, read_line)
row = next(line for line in (ROOT / "app/Madeira/ConfigCatalog.generated.swift").read_text().splitlines()
           if 'key: "env.MADEIRA_RW_ALIAS_RETRY"' in line)
assert f'note: "{note}"' in row
assert 'kind: .bool, defaultValue: "1"' in row
print("PASS: ordered retry/kill-switch wiring, preserved RX/overlap/protection/cleanup checks and catalog note", flush=True)
if args.source_only:
    print("SKIP: compiled Swift behavior (--source-only)")
    raise SystemExit(0)

swift_command = shlex.split(os.environ.get("SWIFTC", "swiftc"))
if not swift_command or not shutil.which(swift_command[0]):
    raise SystemExit("FAIL: swiftc missing; set SWIFTC or explicitly use --source-only")

harness = r'''
import Foundation

typealias vm_address_t = UInt
typealias vm_size_t = UInt
typealias vm_prot_t = Int32
typealias kern_return_t = Int32
let KERN_SUCCESS: Int32 = 0
let KERN_INVALID_ADDRESS: Int32 = 1
let KERN_PROTECTION_FAILURE: Int32 = 2
let KERN_NO_SPACE: Int32 = 3
let KERN_INVALID_ARGUMENT: Int32 = 4
let KERN_FAILURE: Int32 = 5
let VM_FLAGS_ANYWHERE: Int32 = 1
let VM_INHERIT_NONE: Int32 = 2
let VM_PROT_READ: Int32 = 1
let VM_PROT_WRITE: Int32 = 2
let mach_task_self_: UInt32 = 7

let high: UInt = 0x7000000000
let rx: UInt = 0x300000000
let bytes: Int = 640 << 20
let above: UInt = rx + UInt(bytes)
let lowHole: UInt = 0x11e800000
let exeWinBase: UInt = 0x140000000
let exeWinSize: UInt = 0x8000000
let goodLow: Int = 0x119000000
let guestLo: Int = 0x7000000000
let guestHi: Int = 0x8000000000
__PRODUCTION_OVERLAP__

struct Attempt {
    let code: Int32
    let address: UInt
    init(_ code: Int32, _ address: UInt = 0) { self.code = code; self.address = address }
}
var attempts: [Attempt] = []
var hints: [UInt] = []
var expectedRX = rx
var expectedSize = bytes
var protectCalls: [UInt] = []
var deallocations: [(UInt, UInt)] = []
var protectResult = KERN_SUCCESS
var exemptionCalls = 0
var prepareResults: [UInt] = []
var prepareCalls = 0
var scenarioCount = 0

enum MadeiraConfig {
    static var retry = true
    static var reads = 0
    static func flag(_ name: String) -> Bool {
        precondition(name == "MADEIRA_RW_ALIAS_RETRY")
        reads += 1
        return retry
    }
}
final class LogStore {
    enum Level: Equatable { case info, error, success }
    static let shared = LogStore()
    var logs: [(String, Level)] = []
    func log(_ message: String, level: Level = .info) { logs.append((message, level)) }
}

enum Production {
    static var poolFailure: String? = nil
    static var poolTaken = false
    static func vm_remap(_ task: UInt32, _ address: inout UInt, _ size: UInt, _ mask: UInt,
                  _ flags: Int32, _ sourceTask: UInt32, _ source: UInt, _ copy: Int32,
                  _ current: inout Int32, _ maximum: inout Int32, _ inherit: Int32) -> Int32 {
        precondition(task == mach_task_self_ && sourceTask == mach_task_self_)
        precondition(source == expectedRX && size == UInt(expectedSize))
        precondition(mask == 0 && flags == VM_FLAGS_ANYWHERE && copy == 0 && inherit == VM_INHERIT_NONE)
        precondition(hints.count < attempts.count, "unexpected remap attempt")
        let attempt = attempts[hints.count]
        hints.append(address)
        // Write even on failure: failed calls do not confer ownership of this value.
        address = attempt.address
        current = 5; maximum = 7
        return attempt.code
    }
    static func vm_protect(_ task: UInt32, _ address: UInt, _ size: UInt,
                    _ changeMaximum: Int32, _ protection: Int32) -> Int32 {
        precondition(task == mach_task_self_ && size == UInt(expectedSize))
        precondition(changeMaximum == 0 && protection == (VM_PROT_READ | VM_PROT_WRITE))
        protectCalls.append(address)
        return protectResult
    }
    @discardableResult
    static func vm_deallocate(_ task: UInt32, _ address: UInt, _ size: UInt) -> Int32 {
        precondition(task == mach_task_self_ && size == UInt(expectedSize))
        deallocations.append((address, size))
        return KERN_SUCCESS
    }
    static func jit_make_region_no_footprint(_ pointer: UnsafeMutableRawPointer, _ size: Int, _ label: String) -> Bool {
        precondition(size == expectedSize && label == "pool-RW-alias")
        precondition(protectCalls == [UInt(bitPattern: pointer)])
        exemptionCalls += 1
        return false // The exemption remains non-fatal.
    }
    static func jit26_prepare_region(_ pointer: UnsafeMutableRawPointer?, _ size: Int) -> UnsafeMutableRawPointer? {
        precondition(pointer == nil && size == expectedSize && prepareCalls < prepareResults.count)
        let result = prepareResults[prepareCalls]
        prepareCalls += 1
        return UnsafeMutableRawPointer(bitPattern: result)
    }

    static func alias(rxPointer: UInt = rx, poolSize: Int = bytes, windowHeld: Bool = true)
        -> (rx: UnsafeMutableRawPointer, rw: UnsafeMutableRawPointer, size: Int)? {
        let rxPtr = UnsafeMutableRawPointer(bitPattern: rxPointer)!
        let rxAddr = Int(bitPattern: rxPtr)
        __PRODUCTION_ALIAS__
    }
    // The exact ladder is tested separately at unrepresentable address edges;
    // the full caller only supplies RX placements accepted by its earlier checks.
    static func ladderOnly(rxPointer: UInt, poolSize: Int = bytes) -> (Int32, UInt) {
        let rxPtr = UnsafeMutableRawPointer(bitPattern: rxPointer)!
        let rxAddrV = vm_address_t(bitPattern: rxPtr)
        var rwAddr: vm_address_t = 0
        var curProt: vm_prot_t = 0
        var maxProt: vm_prot_t = 0
        __PRODUCTION_LADDER__
        return (kr1, rwAddr)
    }
    static func selectRX(poolSize: Int = bytes) -> (UInt?, Bool) {
        __PRODUCTION_RX_SELECTION__
        return (rxPtrOpt.map { UInt(bitPattern: $0) }, requestUnanswered)
    }
}

func reset(_ scripted: [Attempt] = [], retry: Bool = true, source: UInt = rx, size: Int = bytes) {
    attempts = scripted; hints = []; expectedRX = source; expectedSize = size
    protectCalls = []; deallocations = []; protectResult = KERN_SUCCESS; exemptionCalls = 0
    prepareResults = []; prepareCalls = 0
    MadeiraConfig.retry = retry; MadeiraConfig.reads = 0
    LogStore.shared.logs = []
    Production.poolFailure = nil; Production.poolTaken = false
    scenarioCount += 1
}
func checkSuccess(_ expectedHints: [UInt], at address: UInt) {
    let result = Production.alias(rxPointer: expectedRX, poolSize: expectedSize)
    precondition(result != nil && UInt(bitPattern: result!.rw) == address)
    precondition(UInt(bitPattern: result!.rx) == expectedRX && result!.size == expectedSize)
    precondition(hints == expectedHints && MadeiraConfig.reads == 1)
    precondition(protectCalls == [address] && deallocations.isEmpty)
    precondition(exemptionCalls == 1 && Production.poolTaken && Production.poolFailure == nil)
}
func checkFailure(_ expectedHints: [UInt]) {
    precondition(Production.alias(rxPointer: expectedRX, poolSize: expectedSize) == nil)
    precondition(hints == expectedHints && MadeiraConfig.reads == 1)
    precondition(protectCalls.isEmpty && deallocations.isEmpty && exemptionCalls == 0)
    precondition(!Production.poolTaken && Production.poolFailure != nil)
}

reset([Attempt(KERN_SUCCESS, high)])
checkSuccess([high], at: high)
precondition(!LogStore.shared.logs.contains { $0.0.contains("[rw-alias]") })
reset([Attempt(KERN_NO_SPACE, UInt.max), Attempt(KERN_SUCCESS, above)])
checkSuccess([high, above], at: above)
precondition(LogStore.shared.logs.contains { $0.0.contains("above the RX pool (hint 0x328000000)") })
reset([Attempt(KERN_NO_SPACE, 1), Attempt(KERN_NO_SPACE, 2), Attempt(KERN_SUCCESS, lowHole)])
checkSuccess([high, above, 0], at: lowHole)
precondition(LogStore.shared.logs.contains { $0.0.contains("kernel placement") })
// ANYWHERE can choose a different valid address. Never assume the hint won.
reset([Attempt(KERN_NO_SPACE), Attempt(KERN_SUCCESS, above + 0x4000)])
checkSuccess([high, above], at: above + 0x4000)
reset([Attempt(KERN_SUCCESS, high)], retry: false)
checkSuccess([high], at: high)
reset([Attempt(KERN_NO_SPACE, UInt.max)], retry: false)
checkFailure([high])
reset([Attempt(KERN_NO_SPACE), Attempt(KERN_NO_SPACE), Attempt(KERN_NO_SPACE)])
checkFailure([high, above, 0])

// Only NO_SPACE is retried. Invalid-address, protection, argument and other
// failures stop at whichever attempt returns them, without deallocating a hint.
for code in [KERN_INVALID_ADDRESS, KERN_PROTECTION_FAILURE, KERN_INVALID_ARGUMENT, KERN_FAILURE, Int32(-1)] {
    for precedingFailures in 0...2 {
        reset(Array(repeating: Attempt(KERN_NO_SPACE, UInt.max), count: precedingFailures)
              + [Attempt(code, UInt.max)])
        checkFailure(Array([high, above, 0].prefix(precedingFailures + 1)))
    }
}

// A successful remap is cleaned up once if setting RW fails. The already
// accepted RX pool is not deallocated here; this preserves the existing path.
for succeedingAttempt in 0...2 {
    let address = succeedingAttempt == 0 ? high : above
    reset(Array(repeating: Attempt(KERN_NO_SPACE), count: succeedingAttempt) + [Attempt(KERN_SUCCESS, address)])
    protectResult = KERN_PROTECTION_FAILURE
    precondition(Production.alias() == nil)
    precondition(hints == Array([high, above, 0].prefix(succeedingAttempt + 1)))
    precondition(protectCalls == [address] && deallocations.count == 1)
    precondition(deallocations[0].0 == address && deallocations[0].1 == UInt(bytes))
    precondition(exemptionCalls == 0 && !Production.poolTaken)
    precondition(Production.poolFailure!.contains("vm_protect error 2"))
}

// The intermediate hint must not wrap into a low address. These synthetic RX
// values cannot pass the app's accepted-placement checks, so test the isolated
// production ladder rather than pretending to allocate such a real pool.
for overflowRX in [UInt.max, UInt.max - UInt(bytes) + 1] {
    reset([Attempt(KERN_NO_SPACE), Attempt(KERN_SUCCESS, above)], source: overflowRX)
    let result = Production.ladderOnly(rxPointer: overflowRX)
    precondition(result.0 == KERN_SUCCESS && result.1 == above && hints == [high, 0])
    precondition(protectCalls.isEmpty && deallocations.isEmpty)
}
let boundaryRX = UInt.max - UInt(bytes)
reset([Attempt(KERN_NO_SPACE), Attempt(KERN_NO_SPACE, UInt.max), Attempt(KERN_SUCCESS, above)], source: boundaryRX)
let boundary = Production.ladderOnly(rxPointer: boundaryRX)
precondition(boundary.0 == KERN_SUCCESS && hints == [high, UInt.max, 0])
reset([Attempt(KERN_NO_SPACE)], retry: false, source: UInt.max)
precondition(Production.ladderOnly(rxPointer: UInt.max).0 == KERN_NO_SPACE && hints == [high])

// Preserve diagnostic-only RW overlap handling: this port must not quietly
// change the existing policy to reject a mapping when reservation was absent.
reset([Attempt(KERN_SUCCESS, exeWinBase)])
checkSuccess([high], at: exeWinBase)
precondition(LogStore.shared.logs.contains { $0.0.contains("rwOverlap=true") && $0.1 == .error })

// Exercise the exact production RX-selection loop independently of alias
// placement. Rejected ranges are released, accepted boundaries are untouched.
for bad in [UInt(goodLow - 0x4000), exeWinBase, exeWinBase - UInt(bytes) + 0x4000,
            UInt(guestLo), UInt(guestLo) - UInt(bytes) + 0x4000] {
    reset(); prepareResults = [bad, rx]
    let selected = Production.selectRX()
    precondition(selected.0 == rx && !selected.1 && prepareCalls == 2)
    precondition(deallocations.count == 1 && deallocations[0].0 == bad)
    precondition(hints.isEmpty && protectCalls.isEmpty)
}
for good in [rx, exeWinBase + exeWinSize, UInt(guestLo) - UInt(bytes), UInt(guestHi)] {
    reset(); prepareResults = [good]
    let selected = Production.selectRX()
    precondition(selected.0 == good && !selected.1 && prepareCalls == 1 && deallocations.isEmpty)
}
reset([], size: 64 << 20); prepareResults = [UInt(goodLow)]
precondition(Production.selectRX(poolSize: expectedSize).0 == UInt(goodLow) && deallocations.isEmpty)
reset(); prepareResults = [0]
let unanswered = Production.selectRX()
precondition(unanswered.0 == nil && unanswered.1 && prepareCalls == 1 && deallocations.isEmpty)
reset(); prepareResults = Array(repeating: exeWinBase, count: 3)
let rejected = Production.selectRX()
precondition(rejected.0 == nil && !rejected.1 && prepareCalls == 3 && deallocations.count == 3)

print("PASS: \(scenarioCount) inert Swift scenarios; ordered hints, exact Mach arguments, kill switch, errors, overflow, RX bounds, overlap diagnostics and cleanup")
print("PASS: remap calls: high success=1; above-RX success=2; kernel fallback=3; retry disabled=1; no real VM operations")
'''
harness = (harness.replace("__PRODUCTION_OVERLAP__", overlap).replace("__PRODUCTION_ALIAS__", alias)
           .replace("__PRODUCTION_LADDER__", ladder).replace("__PRODUCTION_RX_SELECTION__", rx_selection))
with tempfile.TemporaryDirectory(prefix="madeira-jit-alias-") as directory:
    path = Path(directory)
    (path / "main.swift").write_text(harness)
    subprocess.run(swift_command + ["-swift-version", "5", str(path / "main.swift"), "-o", str(path / "check")], check=True)
    # Foundation on macOS can expose Darwin APIs with these names. Verify the
    # executable links only our inert hooks before allowing it to run.
    symbols = subprocess.run(["nm", "-u", str(path / "check")], capture_output=True, text=True, check=True).stdout
    assert not re.search(r"(?m)\b_?(?:mach_)?vm_(?:allocate|map|remap|protect|deallocate)(?:\$\w+)?$", symbols), symbols
    subprocess.run([str(path / "check")], check=True, timeout=30)
