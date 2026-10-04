/* Extracted unchanged from willfaust/rpmalloc at
 * 812c2b9cf4310ffacf14e6b64066e78ab0c394b5/rpmalloc/rpmalloc.c.
 * Upstream license: 0BSD (see LICENSES/rpmalloc-0BSD.txt).
 * Fork modifications: see the pinned repository's LICENSE-MADEIRA.md.
 * This fixture exercises the real allocation-free snapshot drain, without
 * compiling the rest of rpmalloc or pretending to emulate CAS contention. */
#include <stdatomic.h>
struct rpm_cas_snapshot {
	unsigned long long page_addr, block_addr, heap_addr, owner_teb;
	unsigned long long prev_token, cur_token, ret_addr, atomic_addr;
	unsigned int size_class, page_type, block_index, list_size;
	unsigned int fail_changed, fail_unchanged, fail_invalid, quarantined;
	unsigned int block_count, block_used, is_full, which_loop;
};
static struct rpm_cas_snapshot rpm_cas_snap;
static _Atomic(int) rpm_cas_snap_ready;
static _Atomic(int) rpm_cas_snap_taken;

/* Drained by the periodic sampler OUTSIDE rpmalloc. Returns 1 if a snapshot was
 * copied out. Caller formats; this function must stay allocation-free. */
int
rpm_cas_snapshot_take(struct rpm_cas_snapshot* out) {
	if (!atomic_load_explicit(&rpm_cas_snap_ready, memory_order_acquire))
		return 0;
	*out = rpm_cas_snap;
	atomic_store_explicit(&rpm_cas_snap_ready, 0, memory_order_release);
	return 1;
}

