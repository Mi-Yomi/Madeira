#!/usr/bin/env python3
"""Compile the production WoW64 SMC branch from pinned, hash-checked sources.

No network, initialized FEX submodule, PE toolchain or Apple SDK is needed.
The host stubs exercise the SMC branch boundary; this is not a whole-handler
or device test. The preceding production thread-initialization checks are not
included, so the branch's own null-thread guard is tested independently.
"""
from pathlib import Path
import re
import tempfile

from fex_guard_test_support import repaired_sources, replace_once, require, run_harness


def extract(text):
    start = text.index("bool BTCpuResetToConsistentStateImpl(")
    end = text.index("NTSTATUS BTCpuResetToConsistentState(", start)
    body = text[start:end]
    declaration = re.search(r"    const auto FaultAddress = [^\n]+;", body)
    require(declaration is not None, "Production host-address declaration not found")
    gate = re.search(r"    if \([^\n]+\) \{\n      std::scoped_lock Lock\(ThreadCreationMutex\);", body)
    require(gate is not None, "Production SMC branch not found")
    # Preserve the entire real branch, including profiling, the tracker call,
    # guest-address conversion for current-block lookup, and the handled return.
    finish = body.index("\n  }\n\n  if (!Thread || !IsAddressInJit(", gate.start())
    return declaration.group() + "\n" + body[gate.start():finish]


HARNESS = r'''
#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <mutex>

#ifndef TRACKER_CLAIMS
#define TRACKER_CLAIMS true
#endif
constexpr uint64_t EXCEPTION_WRITE_FAULT = 1;
[[maybe_unused]] constexpr uint64_t EXCEPTION_READ_FAULT = 0;
struct Record { uint64_t ExceptionInformation[2]; };
struct CPUContext { uint64_t Pc, X1 = 0; };
struct Frame { struct { uint64_t rip = 0; } State; };
struct ThreadState { Frame *CurrentFrame; };
struct Tracker {
  unsigned calls = 0;
  uint64_t address = 0, pc = 0;
  ThreadState *thread = nullptr;
  bool HandleRWXAccessViolation(ThreadState *source, uint64_t host_pc, uint64_t host_address) {
    ++calls;
    thread = source;
    pc = host_pc;
    address = host_address;
    return TRACKER_CLAIMS;
  }
};
namespace GuestWindow {
  static uint64_t ToGuestIfInWindow(uint64_t address) {
    return address >= 0x7000000000 ? address - 0x7000000000 : address;
  }
}
namespace FEXCore { namespace Utils {
  constexpr uint64_t FEX_PAGE_MASK = ~uint64_t(4095), FEX_PAGE_SIZE = 4096;
} }
namespace LogMan { namespace Msg {
  template<typename... Args> void DFmt(const char *, Args...) {}
} }
namespace Context { static void ReconstructThreadState(int, CPUContext *) {} }
struct CoreContext {
  // Inline-SMC reconstruction is outside this fault-routing regression.
  bool IsAddressInCodeBuffer(ThreadState *, uint64_t) { return false; }
  bool IsCurrentBlockSingleInst(ThreadState *) { return false; }
  bool IsAddressInCurrentBlock(ThreadState *, uint64_t, uint64_t) { return false; }
};
struct Delegator {
  struct Config { uint64_t AbsoluteLoopTopAddressFillSRA = 0; } config;
  const Config &GetConfig() { return config; }
};
static unsigned profiles = 0;
// Keep a null-thread gate mutation observable without dereferencing null in the
// profiling stub before the tracker call can be checked.
#define FEXCORE_PROFILE_INSTANT_INCREMENT(thread, field, value) (profiles += (value))
static std::mutex ThreadCreationMutex;

static bool production_smc(ThreadState *Thread, Record *Exception, CPUContext *Context,
                           Tracker *InvalidationTracker) {
  CoreContext core;
  CoreContext *CTX = &core;
  Delegator delegator;
  Delegator *SignalDelegator = &delegator;
  int TLS = 0;
__BLOCK__
  return false;
}

int main() {
  unsigned failures = 0;
  for (uint64_t fault_kind : {uint64_t(0), uint64_t(1), uint64_t(8)}) {
    for (bool has_thread : {false, true}) {
      for (uint64_t host_address : {uint64_t(0x10203040), uint64_t(0x7123456780)}) {
        Record exception{{fault_kind, host_address}};
        CPUContext context{0x118abc000};
        Tracker tracker;
        Frame frame;
        ThreadState thread_storage{&frame};
        auto *thread = has_thread ? &thread_storage : nullptr;
        profiles = 0;
        bool handled = production_smc(thread, &exception, &context, &tracker);
        bool offered = has_thread && fault_kind == EXCEPTION_WRITE_FAULT;
        bool good = handled == (offered && TRACKER_CLAIMS) && tracker.calls == unsigned(offered);
        good = good && profiles == unsigned(offered);
        if (offered)
          good = good && tracker.address == host_address && tracker.pc == context.Pc && tracker.thread == thread;
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


def main():
    baseline, patched = map(extract, repaired_sources("WOW64"))
    mutations = (
        ("wrong-fault-kind", replace_once(patched, "== EXCEPTION_WRITE_FAULT", "== EXCEPTION_READ_FAULT"), 4),
        ("missing-thread-gate", replace_once(patched, "Thread && Exception->", "Exception->"), 2),
        ("translated-tracker-address", replace_once(
            patched, "HandleRWXAccessViolation(Thread, Context->Pc, FaultAddress)",
            "HandleRWXAccessViolation(Thread, Context->Pc, GuestWindow::ToGuestIfInWindow(FaultAddress))"), 1),
        ("translated-record-address", replace_once(
            patched, "static_cast<uint64_t>(Exception->ExceptionInformation[1])",
            "GuestWindow::ToGuestIfInWindow(static_cast<uint64_t>(Exception->ExceptionInformation[1]))"), 1),
        ("missing-handled-return", replace_once(patched, "        return true;", "        return false;"), 2),
    )
    with tempfile.TemporaryDirectory(prefix="FEX WoW64 SMC ") as temporary:
        work = Path(temporary)
        for ios in (False, True):
            mode = "ios" if ios else "non-ios"
            for label, block, failures in (("baseline", baseline, 4), ("patched", patched, 0), *mutations):
                run_harness(HARNESS.replace("__BLOCK__", block), work, f"{label}-{mode}", failures, 12, ios)
            declined = "#define TRACKER_CLAIMS false\n" + HARNESS.replace("__BLOCK__", patched)
            run_harness(declined, work, f"patched-tracker-declines-{mode}", 0, 12, ios)
    print("PASS: original misroutes 4/12 faults; repaired production branch passes both platforms and rejects all mutations")


if __name__ == "__main__":
    main()
