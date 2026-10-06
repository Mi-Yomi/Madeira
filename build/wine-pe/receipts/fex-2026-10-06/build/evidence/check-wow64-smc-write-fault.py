#!/usr/bin/env python3
"""Compile the production SMC gate and call, then test fault routing.

Usage: check-wow64-smc-write-fault.py BASE_MODULE PATCHED_MODULE
This focused host regression is not a FEX build or an iOS integration test.
The baseline must fail and the patched implementation must pass.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def extract(path):
    text = Path(path).read_text()
    start = text.index("bool BTCpuResetToConsistentStateImpl(")
    end = text.index("NTSTATUS BTCpuResetToConsistentState(", start)
    body = text[start:end]
    match = re.search(
        r"if \((?P<gate>Thread[^\n]*)\) \{\s*"
        r"std::scoped_lock Lock\(ThreadCreationMutex\);\s*"
        r"FEXCORE_PROFILE_INSTANT_INCREMENT\(Thread, AccumulatedSMCCount, 1\);\s*"
        r"if \((?P<call>InvalidationTracker->HandleRWXAccessViolation\([^\n]+\))\) \{",
        body,
    )
    if not match:
        raise AssertionError(f"Production SMC gate/call not found: {path}")
    return match.group("gate"), match.group("call")


HARNESS = r'''
#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <mutex>

constexpr uint64_t EXCEPTION_WRITE_FAULT = 1;
struct Record { uint64_t ExceptionInformation[2]; };
struct CPUContext { uint64_t Pc; };
struct Tracker {
  unsigned calls = 0;
  uint64_t address = 0, pc = 0;
  bool HandleRWXAccessViolation(void *, uint64_t host_pc, uint64_t host_address) {
    ++calls;
    pc = host_pc;
    address = host_address;
    return true; // A stale RWX interval claims the address, as in the regression.
  }
};
static std::mutex ThreadCreationMutex;

static bool production_gate(void *Thread, Record *Exception, CPUContext *Context,
                            Tracker *InvalidationTracker, uint64_t FaultAddress) {
  (void)Exception; // Baseline does not inspect the access-violation kind.
  if (__GATE__) {
    std::scoped_lock Lock(ThreadCreationMutex);
    if (__CALL__) {
      return true;
    }
  }
  return false;
}

int main() {
  unsigned failures = 0;
  for (uint64_t fault_kind : {uint64_t(0), uint64_t(1), uint64_t(8)}) {
    for (bool has_thread : {false, true}) {
      // Both identity-mapped and high host-window addresses must pass unchanged.
      for (uint64_t host_address : {uint64_t(0x10203040), uint64_t(0x7123456780)}) {
        Record exception{{fault_kind, host_address}};
        CPUContext context{0x118abc000};
        Tracker tracker;
        int thread_storage = 0;
        void *thread = has_thread ? &thread_storage : nullptr;
        bool handled = production_gate(thread, &exception, &context, &tracker, host_address);
        bool expected = has_thread && fault_kind == EXCEPTION_WRITE_FAULT;
        bool good = handled == expected && tracker.calls == unsigned(expected);
        if (expected) good = good && tracker.address == host_address && tracker.pc == context.Pc;
        if (!good) {
          ++failures;
          std::fprintf(stderr, "wrong SMC routing: kind=%llu thread=%d host=%llx handled=%d calls=%u\n",
                       (unsigned long long)fault_kind, has_thread,
                       (unsigned long long)host_address, handled, tracker.calls);
        }
      }
    }
  }
  std::printf("12 extracted-production cases; failures=%u\n", failures);
  return failures ? 1 : 0;
}
'''


def run(path, work, label):
    gate, call = extract(path)
    print(f"{label} gate: {gate}", flush=True)
    print(f"{label} call: {call}", flush=True)
    source = work / (label + ".cpp")
    binary = work / label
    source.write_text(HARNESS.replace("__GATE__", gate).replace("__CALL__", call))
    subprocess.run([
        "g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic",
        str(source), "-o", str(binary),
    ], check=True)
    return subprocess.run([str(binary)], check=False).returncode


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    with tempfile.TemporaryDirectory(prefix="smc-regression-", dir=Path(__file__).parent) as temp:
        work = Path(temp)
        baseline = run(sys.argv[1], work, "baseline")
        patched = run(sys.argv[2], work, "patched")
    if baseline != 1 or patched != 0:
        raise SystemExit(f"Unexpected results: baseline={baseline}, patched={patched}")
    print("PASS: baseline reproduced read/execute misrouting; patched gate passed all 12 cases")


if __name__ == "__main__":
    main()
