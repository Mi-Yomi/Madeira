#!/usr/bin/env python3
"""Compile the real ARM64EC alias-init block and following InitCore sentinel.

Inputs are complete pinned source snapshots. The actual checked-in repair is
applied and hash-verified before extraction; no network/submodule is required.
Host stubs observe status, write-offset installation, InitCore ordering and
bounded diagnostics. This is not a FEX/PE build or on-device validation.
"""
from pathlib import Path
import tempfile

from fex_guard_test_support import repaired_sources, replace_once, require, run_harness


def extract(text):
    process = text.index("NTSTATUS ProcessInit() {")
    anchor = text.index("  CTX->SetSyscallHandler(SyscallHandler.get());", process)
    start = text.index("#ifdef FEX_IOS_HOST", anchor)
    finish = text.index("  CTX->InitCore();", start) + len("  CTX->InitCore();")
    block = text[start:finish]
    require(block.count("#ifdef") == 1 and block.count("#endif") == 1,
            "Unexpected alias-init preprocessor structure")
    require('getenv("WINE_IOS_JIT_SIZE")' not in block, "Repair introduced a JIT pool-size requirement")
    require("int64_t off = (rw && rx) ? (int64_t)(rw - rx) : 0;" in block,
            "Production alias-offset parsing changed")
    require("if (off != 0) {" in block, "Production valid-alias branch changed")
    return block


HARNESS = r'''
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <string>

using HANDLE = void *;
using ULONG = uint32_t;
using NTSTATUS = int32_t;
[[maybe_unused]] constexpr NTSTATUS STATUS_UNSUCCESSFUL = static_cast<NTSTATUS>(0xc0000001u);
constexpr NTSTATUS STATUS_SUCCESS = 0;
namespace FEXCore { namespace DualMap { int64_t WriteOffset = 0; } }
struct RTL_USER_PROCESS_PARAMETERS64 { HANDLE hStdError = nullptr; };
struct PEB { RTL_USER_PROCESS_PARAMETERS64 *ProcessParameters = nullptr; };
struct TEB { PEB *ProcessEnvironmentBlock = nullptr; };
static RTL_USER_PROCESS_PARAMETERS64 params;
static PEB peb;
static TEB teb;
[[maybe_unused]] static TEB *NtCurrentTeb() { return &teb; }
static unsigned writes = 0, unsafe_writes = 0;
static std::string log_text;
template<size_t N>
static bool WriteFile(HANDLE, const char (&data)[N], ULONG count, ULONG *written, void *) {
  ++writes;
  if (count > N) { // Track the real production array extent; never overread it.
    ++unsafe_writes;
    *written = 0;
    return false; // Do not perform the baseline's out-of-bounds read.
  }
  log_text.assign(data, count);
  *written = count;
  return true;
}
struct TestContext {
  unsigned calls = 0;
  int64_t seen_offset = 0;
  void InitCore() { ++calls; seen_offset = FEXCore::DualMap::WriteOffset; }
};
static TestContext context;
static TestContext *CTX = &context;

static NTSTATUS production_init() {
__BLOCK__
  return STATUS_SUCCESS;
}

struct Case { const char *name, *rw, *rx; bool valid; int64_t offset; };
static void env(const char *key, const char *value) {
  if (value) setenv(key, value, 1);
  else unsetenv(key);
}

int main() {
  const std::string long_invalid(2048, 'z');
  const Case cases[] = {
    {"both missing", nullptr, nullptr, false, 0},
    {"RW missing", nullptr, "10000", false, 0},
    {"RX missing", "20000", nullptr, false, 0},
    {"RW empty", "", "10000", false, 0},
    {"RX empty", "20000", "", false, 0},
    {"RW zero", "0", "10000", false, 0},
    {"RX zero", "20000", "0", false, 0},
    {"both zero", "0", "0", false, 0},
    {"equal", "10000", "10000", false, 0},
    {"invalid", "garbage", "10000", false, 0},
    {"long invalid", long_invalid.c_str(), nullptr, false, 0},
    {"positive offset", "20000", "10000", true, 65536},
    {"negative offset", "10000", "20000", true, -65536},
    {"high host address", "7000000000", "110000000", true, 0x6ef0000000ll},
    {"hex prefix", "0X20000", "0x10000", true, 65536},
    // Document existing permissive parsing rather than claiming full validation.
    {"trailing junk accepted", "20000tail", "10000tail", true, 65536},
  };
  unsigned failures = 0, total = 0;
  for (const auto &test : cases) {
    for (int stderr_mode = 0; stderr_mode != 3; ++stderr_mode) {
      // 0: no process parameters; 1: no stderr; 2: working stderr.
      for (const char *size : {static_cast<const char *>(nullptr), "0", "40000000"}) {
        ++total;
        env("WINE_IOS_JIT_RW", test.rw);
        env("WINE_IOS_JIT_RX", test.rx);
        env("WINE_IOS_JIT_SIZE", size);
        params.hStdError = stderr_mode == 2 ? reinterpret_cast<HANDLE>(1) : nullptr;
        peb.ProcessParameters = stderr_mode == 0 ? nullptr : &params;
        teb.ProcessEnvironmentBlock = &peb;
        FEXCore::DualMap::WriteOffset = 0;
        context = {};
        writes = unsafe_writes = 0;
        log_text.clear();
        NTSTATUS result = production_init();
#ifdef FEX_IOS_HOST
        bool ok = result == (test.valid ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL);
        ok = ok && context.calls == unsigned(test.valid);
        ok = ok && FEXCore::DualMap::WriteOffset == test.offset;
        if (test.valid) ok = ok && context.seen_offset == test.offset;
        ok = ok && writes == unsigned(stderr_mode == 2) && unsafe_writes == 0;
        ok = ok && log_text.find('\0') == std::string::npos;
        if (test.valid && stderr_mode == 2)
          ok = ok && log_text.find("fast-write ENABLED") != std::string::npos;
        if (!test.valid && stderr_mode == 2) {
          ok = ok && log_text.find("refusing to start") != std::string::npos;
          ok = ok && log_text.find(long_invalid) == std::string::npos;
        }
#else
        bool ok = result == STATUS_SUCCESS && context.calls == 1;
        ok = ok && FEXCore::DualMap::WriteOffset == 0 && context.seen_offset == 0;
        ok = ok && writes == 0 && unsafe_writes == 0;
#endif
        if (!ok) {
          ++failures;
          if (failures <= 5)
            std::fprintf(stderr, "failed: %s stderr=%d size=%s result=%x init=%u writes=%u unsafe=%u\n",
                         test.name, stderr_mode, size ? size : "unset", unsigned(result),
                         context.calls, writes, unsafe_writes);
        }
      }
    }
  }
  std::printf("%u extracted-production cases; failures=%u\n", total, failures);
  return failures ? 1 : 0;
}
'''


def main():
    baseline, patched = map(extract, repaired_sources("ARM64EC"))
    # All changes occur only in generated temporary harnesses after full-source
    # integrity verification. Each mutation must fail at run time, not compile.
    mutations = (
        ("missing-failure-return", replace_once(patched, "      return STATUS_UNSUCCESSFUL;", ""), 99),
        ("late-failure-return", replace_once(
            patched, "      return STATUS_UNSUCCESSFUL;",
            "      CTX->InitCore();\n      return STATUS_UNSUCCESSFUL;"), 99),
        ("wrong-failure-status", replace_once(
            patched, "return STATUS_UNSUCCESSFUL;", "return STATUS_SUCCESS;"), 99),
        ("missing-alias-install", replace_once(
            patched, "      FEXCore::DualMap::WriteOffset = off;", ""), 45),
        ("late-alias-install", replace_once(
            patched, "      FEXCore::DualMap::WriteOffset = off;",
            "      CTX->InitCore();\n      FEXCore::DualMap::WriteOffset = off;"), 45),
        ("reversed-alias-offset", replace_once(
            patched, "FEXCore::DualMap::WriteOffset = off;", "FEXCore::DualMap::WriteOffset = -off;"), 45),
        ("oversized-error-log", replace_once(patched, "sizeof(message) - 1", "sizeof(message) + 160"), 33),
        ("error-log-includes-nul", replace_once(patched, "sizeof(message) - 1", "sizeof(message)"), 33),
    )
    with tempfile.TemporaryDirectory(prefix="FEX ARM64EC alias ") as temporary:
        work = Path(temporary)
        for ios in (False, True):
            mode = "ios" if ios else "non-ios"
            scenarios = (("baseline", baseline, 99 if ios else 0), ("patched", patched, 0),
                         *((label, block, failures if ios else 0) for label, block, failures in mutations))
            for label, block, failures in scenarios:
                run_harness(HARNESS.replace("__BLOCK__", block), work, f"{label}-{mode}", failures, 144, ios)
    print("PASS: original fails 99/144 iOS cases; repaired block passes, mutations fail, non-iOS stays unchanged")


if __name__ == "__main__":
    main()
