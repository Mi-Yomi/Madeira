#!/usr/bin/env python3
"""Compile the actual alias-init source block and InitCore sentinel with host stubs.

Usage: check-arm64ec-jit-rw-alias.py BASE_MODULE PATCHED_MODULE
No FEX, PE or iOS runtime is built. Temporary host binaries are removed.
"""
from pathlib import Path
import subprocess
import sys
import tempfile


def extract(path):
    text = Path(path).read_text()
    process = text.index("NTSTATUS ProcessInit() {")
    anchor = text.index("  CTX->SetSyscallHandler(SyscallHandler.get());", process)
    start = text.index("#ifdef FEX_IOS_HOST", anchor)
    finish = text.index("  CTX->InitCore();", start) + len("  CTX->InitCore();")
    block = text[start:finish]
    assert block.count("#ifdef") == 1 and block.count("#endif") == 1
    assert "getenv(\"WINE_IOS_JIT_SIZE\")" not in block
    assert "int64_t off = (rw && rx) ? (int64_t)(rw - rx) : 0;" in block
    assert "if (off != 0) {" in block
    return block


HARNESS = r'''
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

using HANDLE = void *;
using ULONG = uint32_t;
using NTSTATUS = int32_t;
constexpr NTSTATUS STATUS_UNSUCCESSFUL = static_cast<NTSTATUS>(0xc0000001u);
constexpr NTSTATUS STATUS_SUCCESS = 0;
namespace FEXCore { namespace DualMap { int64_t WriteOffset = 0; } }
struct RTL_USER_PROCESS_PARAMETERS64 { HANDLE hStdError = nullptr; };
struct PEB { RTL_USER_PROCESS_PARAMETERS64 *ProcessParameters = nullptr; };
struct TEB { PEB *ProcessEnvironmentBlock = nullptr; };
static RTL_USER_PROCESS_PARAMETERS64 params;
static PEB peb;
static TEB teb;
static TEB *NtCurrentTeb() { return &teb; }
static unsigned writes = 0, unsafe_writes = 0;
static std::string log_text;
static bool WriteFile(HANDLE, const void *data, ULONG count, ULONG *written, void *) {
  ++writes;
  if (count > 160) { // The production snprintf buffer is 160 bytes.
    ++unsafe_writes;
    *written = 0;
    return false; // Do not perform the baseline's out-of-bounds read.
  }
  log_text.assign(static_cast<const char *>(data), count);
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


def run(path, directory, label, ios):
    block = extract(path)
    source = directory / (label + ".cpp")
    binary = directory / label
    source.write_text(HARNESS.replace("__BLOCK__", block))
    command = ["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic"]
    if ios:
        command.append("-DFEX_IOS_HOST")
    else:
        command.append("-Wno-unused-function")
    command.extend([str(source), "-o", str(binary)])
    print(f"{label}: compile extracted block, ios={ios}", flush=True)
    subprocess.run(command, check=True)
    return subprocess.run([str(binary)], check=False).returncode


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    baseline, patched = map(Path, sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix="alias-regression-", dir=Path(__file__).parent) as temp:
        work = Path(temp)
        results = [
            run(baseline, work, "baseline-ios", True),
            run(patched, work, "patched-ios", True),
            run(baseline, work, "baseline-non-ios", False),
            run(patched, work, "patched-non-ios", False),
        ]
    if results != [1, 0, 0, 0]:
        raise SystemExit(f"Unexpected regression results: {results}")
    print("PASS: baseline reproduced the missing fail-closed guard; patched iOS and both non-iOS blocks passed")


if __name__ == "__main__":
    main()
