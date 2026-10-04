// SPDX-License-Identifier: MIT
// The line above retains the upstream notice from Core.cpp; it is not a
// blanket grant for the fork additions or the new regression harness.
// Fork additions retain their terms under the pinned FEX LICENSE-MADEIRA.md:
// https://github.com/willfaust/FEX/blob/1adb337a2f2270434ba731346438c072337a5d5f/LICENSE-MADEIRA.md
// New harness: GPL-3.0-or-later with the Madeira Converter Exception, version 1
// (see this repository's LICENSE and LICENSE-EXCEPTION.md).
// Extracted regression fixture from willfaust/FEX Core.cpp at
// 1adb337a2f2270434ba731346438c072337a5d5f (blob be5431125a7ae54cb0caba0a3ed7f68e2edd46a1).
// Only the surrounding C++ harness is synthetic. Declarations, reporter bodies,
// and low-RIP rejection below retain the pinned source text for patch testing.
#include <cstdint>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>

/* iOS-Madeira ml622: mirror of rpmalloc's POD snapshot (rpmalloc.c). Declared here
 * rather than in a shared header because rpmalloc is C and vendored; keep the two
 * definitions in sync — the drain below is the only consumer. */
extern "C" {
struct rpm_cas_snapshot {
  unsigned long long page_addr, block_addr, heap_addr, owner_teb;
  unsigned long long prev_token, cur_token, ret_addr, atomic_addr;
  unsigned int size_class, page_type, block_index, list_size;
  unsigned int fail_changed, fail_unchanged, fail_invalid, quarantined;
  unsigned int block_count, block_used, is_full, which_loop;
};
int rpm_cas_snapshot_take(struct rpm_cas_snapshot* out);
}
#include <condition_variable>
#include <fcntl.h>
#include <functional>
#include <string_view>
static int ffs_reports, callback_reports, invalid_reports;
namespace LogMan::Msg {
template<class... Args> void EFmt(const char* message, Args...) {
  if (std::string_view(message).starts_with("[ffs-bypass]")) ++ffs_reports;
  if (std::string_view(message).starts_with("[cb-entry]")) ++callback_reports;
}
template<class... Args> void IFmt(const char*, Args...) { ++invalid_reports; }
}
namespace FEXCore::Context {
#ifdef FEX_IOS_HOST
#ifdef ARCHITECTURE_arm64ec
/* iOS-Madeira ml306 (task #51): CallbackPtr entry-state capture buffer, defined in Dispatcher.cpp
 * and written by emitted code at CallbackPtr entry. Read by the [cb-entry] reporter below. */
extern "C" uint64_t IosCbEntryLog[8];
/* iOS-Madeira ml315 (#52): alias-table walk from IosJitAlias.cpp (same DLL link). Maps a
 * module-pool-copy address back to its PE VA; returns the input unchanged on no match. */
extern "C" uint64_t IosJitReverseTranslate(uint64_t Addr);
/* iOS-Madeira ml316: ExitToX64's FFS-bypass counters, defined in Module.cpp and written by
 * the bypass asm in Module.S. Reported below the same way as [cb-entry]. */
extern "C" uint64_t IosFfsBypassLog[4];
#else
/* The WOW64 module (libwow64fex.dll) is a plain aarch64 PE with no Module.S, no EC entry thunks
 * and no FFS bypass, so the last two symbols above do not exist in its link. Zeroed storage and an
 * identity translation: the FFS reporter below compares against counters nothing increments, and
 * the module has no PE-image-to-pool alias table (its guest images are mapped normally). */
extern "C" uint64_t IosCbEntryLog[8];
static uint64_t IosFfsBypassLog[4] {};
static inline uint64_t IosJitReverseTranslate(uint64_t Addr) {
  return Addr;
}
#endif
#endif

uint64_t Report(uint64_t GuestRIP) {
#ifdef FEX_IOS_HOST
  if (false) {
  }
#endif

  /* iOS-Madeira ml304 (task #51): REPORT CallbackPtr ENTRY ON ITS OWN, not via the bogus-RIP path.
   *
   * ml302 proved the JITCallback prologue writes the bad State.rip, and ml303 added an LR witness --
   * but gated the report on a later bogus-RIP hit, which only occurs in roughly half of runs. That
   * repeats the mistake of gating a probe on the rare downstream event instead of the thing being
   * measured. Entry into CallbackPtr is itself the anomaly: on ARM64EC that block should be
   * unreachable (ExecuteJITCallback is only called from ContextImpl::HandleCallback, whose sole
   * caller is LinuxEmulation/Thunks.cpp which is not built for this target, and the emitted code
   * before it ends in hlt(0) so fall-through is impossible).
   *
   * So report the first few entries directly. CompileBlock runs often enough to notice promptly and
   * is not hot enough for a load+branch to matter. If nothing prints, CallbackPtr genuinely is not
   * being entered in that run -- which is equally informative, and is a real negative rather than
   * silence from an unexercised probe. */
  /* ml306 GATE FIX: the ml304 version keyed on Frame->IosLastCallbackLR != 0, and ml306's hit
   * showed the real entries arrive with LR == 0 -- so the gate was blind to exactly the case it
   * existed for ([cb-entry] printed 0 in the same run whose [bogus-writer] proved a CallbackPtr
   * entry happened). Key on the entry COUNTER in the static capture buffer instead, and print the
   * full captured entry state; x16/x17 are the interesting ones since a `br` through an IP register
   * is the most plausible way to arrive with LR=0. */
  /* iOS-Madeira ml316: report ExitToX64 FFS bypasses (native short-circuit of an EC target
   * reached via its x64 fast-forward sequence -- preserves the x4/x5 varargs contract that
   * the emulation round trip destroys; see Module.S). Same change-detection pattern as
   * [cb-entry] below: CompileBlock runs often enough to notice promptly. */
  {
    static uint64_t FfsLastCount = 0;
    static uint32_t FfsReports = 0;
    const uint64_t FfsCount = IosFfsBypassLog[0] + IosFfsBypassLog[2];
    if (FfsCount != FfsLastCount && FfsReports < 12) {
      FfsLastCount = FfsCount;
      FfsReports++;
      LogMan::Msg::EFmt("[ffs-bypass] taken={} (last EC target {:#x} called natively, x4/x5 preserved) "
                        "rejected={} (last non-EC target {:#x} emulated normally)",
                        IosFfsBypassLog[0], IosFfsBypassLog[1], IosFfsBypassLog[2], IosFfsBypassLog[3]);
    }
  }

  {
    static uint64_t CBLastCount = 0;
    static uint32_t CBReports = 0;
    const uint64_t CBCount = IosCbEntryLog[6];
    if (CBCount != CBLastCount && CBReports < 8) {
      CBLastCount = CBCount;
      CBReports++;
      LogMan::Msg::EFmt("[cb-entry] CallbackPtr entered (count={}) -- unreachable by design on ARM64EC: "
                        "x0(Frame)={:#x} x1(RIP)={:#x} x16={:#x} x17={:#x} x30={:#x} nsp={:#x} guestRSP(x23)={:#x}",
                        CBCount, IosCbEntryLog[0], IosCbEntryLog[1], IosCbEntryLog[2], IosCbEntryLog[3],
                        IosCbEntryLog[4], IosCbEntryLog[5], IosCbEntryLog[7]);
    }
  }

  /* iOS-Madeira: refuse to compile obviously-invalid guest RIPs. After a
   * NULL-vtable virtual call (`call [rax+8]` with rax=0), control flow
   * lands at RIP=0x8, which then loops compiling thousands of garbage
   * blocks before SEH unwinds. Returning 0 here raises C0000005 to the
   * guest immediately so the first AV is the only AV. */
  if (GuestRIP < 0x10000) {
    LogMan::Msg::IFmt("[iOS] CompileBlock: REFUSING low/invalid RIP={:#x}", GuestRIP);
    return 0;
  }

  return GuestRIP;
}

// Minimal surroundings for the unchanged production summary body below.
static volatile uint64_t g_cb_total, g_cb_real_compiles;
struct SnapshotCache { uint64_t GetL1Pointer() { return 0; } };
struct SnapshotThread { SnapshotCache* LookupCache; };
struct SnapshotFrame {
  SnapshotThread* Thread;
  struct { uint64_t L1Pointer, L1Mask; } State;
};
void SnapshotReport() {
  uint64_t GuestRIP = 0x123456;
  SnapshotFrame* Frame = nullptr;
  /* iOS-Madeira 2026-05-18 low-noise summary. Replaces per-call log (which
   * was producing ~180K lines/run for hot RIP 0x140028d46 alone, each
   * amplified ~6× by Wine's file trace). Counters: g_cb_total bumped
   * every CompileBlock call; g_cb_real_compiles bumped after cache miss
   * proves we actually compile (see below at LookupCache fallthrough).
   * Boyer-Moore-style 1-slot hot-RIP estimator. Summary every 16K calls. */
  {
    static volatile uint64_t g_cb_last_summary_total = 0;
    static volatile uint64_t g_cb_hot_rip = 0;
    static volatile uint64_t g_cb_hot_rip_count = 0;
    if (GuestRIP == g_cb_hot_rip) {
      __sync_add_and_fetch(&g_cb_hot_rip_count, 1);
    } else if (g_cb_hot_rip_count == 0) {
      g_cb_hot_rip = GuestRIP;
      __sync_add_and_fetch(&g_cb_hot_rip_count, 1);
    } else {
      __sync_sub_and_fetch(&g_cb_hot_rip_count, 1);
    }
    uint64_t total = __sync_add_and_fetch(&g_cb_total, 1);
    if ((total - g_cb_last_summary_total) >= 16384) {
      g_cb_last_summary_total = total;
      uint64_t reals = g_cb_real_compiles;
      /* iOS-Madeira 2026-07-03 perf hunt: also print the JIT-visible L1
       * lookup fields. The emitted dispatcher L1 probe reads
       * State.L1Pointer/L1Mask; the measured ~15K CompileBlock calls per
       * frame (~60us each = the whole frame time) with 99% cache hits mean
       * that probe is missing for blocks the C++ path finds instantly. If
       * State.L1Pointer here is 0 (or differs from the LookupCache's own
       * pointer), the emitted probe reads the iOS-emulated zero page and
       * silently misses every time — no crash, pure 60us tax per lookup. */
      auto* T = Frame ? Frame->Thread : nullptr;
      LogMan::Msg::EFmt("[CB_SUMMARY] total={} real_compiles={} cache_hits={} "
                        "hit_rate={}%  hottest_rip≈0x{:x} repeats~{} "
                        "L1ptr=0x{:x} L1mask=0x{:x} cacheL1=0x{:x}",
                        total, reals,
                        total - reals,
                        (total > 0) ? (100 * (total - reals) / total) : 0,
                        g_cb_hot_rip, g_cb_hot_rip_count,
                        Frame ? Frame->State.L1Pointer : 0,
                        Frame ? Frame->State.L1Mask : 0,
                        (T && T->LookupCache) ? T->LookupCache->GetL1Pointer() : 0);

      /* iOS-Madeira ml622: drain the rpmalloc remote-free CAS snapshot HERE —
       * outside rpmalloc, where formatting is safe. The allocator side only ever
       * copies scalars into a POD and sets a flag; it must never format, because
       * LogMan/fmt can allocate and re-enter the very allocator that is stuck
       * (that is how ml620 killed itself).
       *
       * Read the counters, not the total: fail_changed vs fail_unchanged is the
       * discriminator, and fail_invalid outranks both. ⚠️ A changed token is NOT
       * automatically healthy contention — it can equally be page reuse or a
       * foreign writer, so check block_index/list_size against block_count before
       * concluding anything. */
      {
        rpm_cas_snapshot Snap;
        if (rpm_cas_snapshot_take(&Snap)) {
          LogMan::Msg::EFmt("[rpm-cas] ml622 loop={} {} page=0x{:x} block=0x{:x} heap=0x{:x} atomic=0x{:x} "
                            "teb=0x{:x} ret=0x{:x} class={} ptype={} idx={}/{} list_size={} used={} is_full={} "
                            "prev_token=0x{:x} cur_token=0x{:x} | fail changed={} unchanged={} invalid={}",
                            Snap.which_loop, Snap.quarantined ? "QUARANTINED (block leaked, spin abandoned)" : "spinning",
                            Snap.page_addr, Snap.block_addr, Snap.heap_addr, Snap.atomic_addr, Snap.owner_teb,
                            Snap.ret_addr, Snap.size_class, Snap.page_type, Snap.block_index, Snap.block_count,
                            Snap.list_size, Snap.block_used, Snap.is_full, Snap.prev_token, Snap.cur_token,
                            Snap.fail_changed, Snap.fail_unchanged, Snap.fail_invalid);
        }
      }
    }
  }

}
}
