// SPDX-License-Identifier: MIT
// The upstream notice is retained from Arm64.cpp; it is not a blanket grant.
// Fork additions retain their terms under the pinned FEX LICENSE-MADEIRA.md:
// https://github.com/willfaust/FEX/blob/1adb337a2f2270434ba731346438c072337a5d5f/LICENSE-MADEIRA.md
// New harness: GPL-3.0-or-later with the Madeira Converter Exception, version 1
// (see this repository's LICENSE and LICENSE-EXCEPTION.md).
// Exact IosLogUnimplementedCASPAL and HandleCASPAL source from pinned Arm64.cpp
// 1adb337a2f2270434ba731346438c072337a5d5f, blob b2eca70f89ca0f7a8b0eb4fa7db1984eb3f3fb33.
// Only the surrounding diagnostic-capture harness is synthetic. No Windows
// types or functions are supplied: native compilation must need none.
#include <cstdint>
#include <string_view>
namespace LogMan::Msg {
inline unsigned diagnostic_count;
inline uint32_t last_size, last_register;
inline uint64_t last_address, last_misalignment;
inline std::string_view last_format, last_crosses;
inline void EFmt(const char* format, uint32_t size, uint32_t reg,
                 uint64_t address, uint64_t misalignment, const char* crosses) {
  ++diagnostic_count;
  last_format = format;
  last_size = size;
  last_register = reg;
  last_address = address;
  last_misalignment = misalignment;
  last_crosses = crosses;
}
}
// A declaration only: the unchanged caller is checked with -fsyntax-only.
// Runtime tests omit the caller and exercise the exact diagnostic function only.
static bool RunCASPAL(uint64_t*, uint32_t, uint32_t, uint32_t, uint32_t,
                      uint32_t, uint32_t, uint32_t*);

/* iOS-Madeira ml220 PROBE. RunCASPAL implements ONLY Size==0 (32-bit pairs); Size==1
 * (64-bit pairs, i.e. a 128-bit CAS from x86 LOCK CMPXCHG16B) falls straight through to
 * `return false`, which callers report as "Unhandled JIT SIGBUS CASPAL" and escalate to a
 * fatal STATUS_DATATYPE_MISALIGNMENT. Steam/CEF hits this
 *   Unhandled JIT SIGBUS CASPAL: PC: 0x120e53c00 Instruction: 0x4866fd64
 *     = CASPAL x6,x7, x4,x5, [x11]   (sz=1)
 *
 * Implementing a 128-bit unaligned CAS is real work, so establish WHY the address is
 * unaligned first: a correct x86 program cannot issue an unaligned LOCK CMPXCHG16B (it
 * #GPs on hardware), so either the guest really does it -- and we must emulate -- or the
 * address we computed is wrong, which is a different bug entirely and would make the
 * emulation pointless. Print the address and its misalignment so the next run decides. */
static void IosLogUnimplementedCASPAL(uint32_t Size, uint64_t* GPRs, uint32_t AddressReg) {
  static int reports;

  /* ml258: Size==1 is IMPLEMENTED now (see RunCASPAL). The only case still handed
   * back to the caller is a misaligned CASP, which a correct guest cannot emit, so
   * report exactly that and stay quiet otherwise. */
  if (Size == 0 || (GPRs[AddressReg] & 15) == 0 || reports >= 8) {
    return;
  }
  reports++;

  /* ml223: the address came back 16-byte ALIGNED (misalign=0), so this is not the
   * unaligned-CAS case the Size==0 path exists for -- implementing a 128-bit unaligned
   * CAS would not have fixed it. An aligned LSE atomic that still faults points at the
   * MEMORY rather than the instruction, and the address sits inside the JIT pool's range,
   * which we DUAL-MAP (RW alias + RX alias). Aliased mappings are exactly where atomics
   * can fault despite correct alignment. Report what the region actually is, so "guest
   * data in a dual-mapped pool page" is distinguishable from ordinary private memory. */
  MEMORY_BASIC_INFORMATION mbi {};
  const char* type = "?";
  if (VirtualQuery(reinterpret_cast<LPCVOID>(GPRs[AddressReg]), &mbi, sizeof(mbi))) {
    type = mbi.Type == MEM_IMAGE ? "MEM_IMAGE" : mbi.Type == MEM_MAPPED ? "MEM_MAPPED" : "MEM_PRIVATE";
  }
  LogMan::Msg::EFmt("[caspal128] MISALIGNED-UNSUPPORTED Size={} addrReg=x{} addr={:#x} misalign={} "
                    "crosses16B={} | region base={} size={:#x} prot={:#x} type={} state={:#x}",
                    Size, AddressReg, GPRs[AddressReg], GPRs[AddressReg] & 15,
                    (GPRs[AddressReg] & 15) ? "yes" : "no", mbi.BaseAddress, mbi.RegionSize,
                    mbi.Protect, type, mbi.State);
}

static bool HandleCASPAL(uint32_t Instr, uint64_t* GPRs, uint32_t* StrictSplitLockMutex) {
  uint32_t Size = (Instr >> 30) & 1;

  uint32_t DesiredReg1 = Instr & 0b11111;
  uint32_t DesiredReg2 = DesiredReg1 + 1;
  uint32_t ExpectedReg1 = (Instr >> 16) & 0b11111;
  uint32_t ExpectedReg2 = ExpectedReg1 + 1;
  uint32_t AddressReg = (Instr >> 5) & 0b11111;

  IosLogUnimplementedCASPAL(Size, GPRs, AddressReg);
  return RunCASPAL(GPRs, Size, DesiredReg1, DesiredReg2, ExpectedReg1, ExpectedReg2, AddressReg, StrictSplitLockMutex);
}

