/*
 * Bounded, opt-in sparse JIT-pool diagnostics.
 *
 * Based on the opt-in/sparse fix by spitefulowl in Madeira commit
 * bc46c48ca364d60b5f21e41344abd9daea70baa4 (ml1242).
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * This header is shared with the portable fault-injection tests. Configure it
 * during normal initialization, then publish the immutable policy with a
 * release store of READY. The fault path never parses environment variables,
 * allocates memory, takes a lock or reads the pool in userspace. mincore is a
 * Darwin syscall, but is not specified async-signal-safe by POSIX. This remains
 * opt-in crash-time I/O, not a promise of async-signal-safety or bounded latency.
 */
#ifndef MADEIRA_IOS_JIT_DUMP_H
#define MADEIRA_IOS_JIT_DUMP_H

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#define IOS_JIT_DUMP_DEFAULT_MB 16u
#define IOS_JIT_DUMP_MAX_MB 1024u
#define IOS_JIT_DUMP_CHUNK (1024u * 1024u)
#define IOS_JIT_DUMP_RETRY_BUDGET 8u
#define IOS_JIT_DUMP_READY 1u
#define IOS_JIT_DUMP_ATTEMPTED 2u

/* The Mach handler and SIGILL handler share a guard; a reentrant signal must
 * never wait for a suspended writer. Require an inline, lock-free atomic. */
_Static_assert( __atomic_always_lock_free( sizeof(unsigned int), 0 ),
                "JIT dump guard must be lock-free" );

struct ios_jit_dump_policy
{
    size_t limit, page_size;
    char path[512];
};

struct ios_jit_dump_result
{
    const char *status;
    size_t pool_bytes, logical_bytes, written_bytes;
    unsigned int query_calls, write_calls;
    int attempted, error;
};

/* Normal initialization only. Invalid options fail closed, including a path
 * that does not fit: never silently write to a truncated or unrelated path. */
static void ios_jit_dump_prepare( struct ios_jit_dump_policy *policy,
                                 const char *enabled, const char *max_mb,
                                 const char *docs, size_t page_size )
{
    static const char suffix[] = "/fex-jit-dump.bin";
    size_t len = 0, i;
    unsigned int mb = IOS_JIT_DUMP_DEFAULT_MB;

    policy->limit = 0;
    policy->page_size = page_size;
    policy->path[0] = 0;
    if (!enabled || enabled[0] != '1' || enabled[1]) return;
    if (page_size < 4096 || page_size > 65536 || (page_size & (page_size - 1))) return;
    if (max_mb && *max_mb)
    {
        mb = 0;
        for (; *max_mb; ++max_mb)
        {
            unsigned int digit = (unsigned char)*max_mb - '0';
            if (digit > 9 || mb > (IOS_JIT_DUMP_MAX_MB - digit) / 10) return;
            mb = mb * 10 + digit;
        }
        if (!mb) return;
    }
    if (!docs || !*docs) docs = "/tmp";
    while (docs[len])
    {
        if (len >= sizeof(policy->path) - sizeof(suffix)) return;
        ++len;
    }
    for (i = 0; i < len; ++i) policy->path[i] = docs[i];
    for (i = 0; i < sizeof(suffix); ++i) policy->path[len + i] = suffix[i];
    policy->limit = (size_t)mb * 1024 * 1024;
}

/* One attempt for the entire host process, including failed opens. O_EXCL
 * preserves the previous capture across launches and rejects symlinks/FIFOs.
 * Users explicitly remove or rename an old capture before requesting a new one.
 * Only the kernel's pwrite copies pool contents: an invalidated mapping becomes
 * an I/O error rather than a recursive userspace memory read in this helper.
 * Resident/paged-out pages retain their pool-relative file offsets; untouched
 * pages remain holes. Failed residency queries never fall back to dense reads.
 */
static struct ios_jit_dump_result ios_jit_dump_capture(
        const struct ios_jit_dump_policy *policy, unsigned int *state,
        const void *pool, size_t total )
{
    struct ios_jit_dump_result result = {0};
    unsigned int expected = IOS_JIT_DUMP_READY, write_budget;
    int fd, saved_errno = errno;
    size_t limit, off, ps;
    unsigned char vec[256];

    result.status = "disabled";
    if (__atomic_load_n( state, __ATOMIC_ACQUIRE ) != IOS_JIT_DUMP_READY || !policy->limit)
        return result;
    if (!__atomic_compare_exchange_n( state, &expected, IOS_JIT_DUMP_ATTEMPTED,
                                     0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE ))
        return result;

    result.attempted = 1;
    result.pool_bytes = total;
    ps = policy->page_size;
    if (!pool || !total || (uintptr_t)pool % ps || total > UINTPTR_MAX - (uintptr_t)pool)
    {
        result.status = "invalid-pool";
        goto restore_errno;
    }
    limit = total < policy->limit ? total : policy->limit;
    write_budget = (unsigned int)(limit / ps + !!(limit % ps)) + IOS_JIT_DUMP_RETRY_BUDGET;
    fd = open( policy->path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600 );
    if (fd < 0)
    {
        result.status = "open-failed";
        result.error = errno;
        goto restore_errno;
    }
    result.status = limit < total ? "capped" : "complete";
    for (off = 0; off < limit; )
    {
        size_t len = limit - off < IOS_JIT_DUMP_CHUNK ? limit - off : IOS_JIT_DUMP_CHUNK;
        size_t i;
        const unsigned char *base = (const unsigned char *)pool + off;

        ++result.query_calls;
        if (mincore( (void *)base, len, (void *)vec ) < 0)
        {
            result.status = "residency-failed";
            result.error = errno;
            break;
        }
        for (i = 0; i < len; i += ps)
        {
            size_t n = len - i < ps ? len - i : ps, done = 0;
            unsigned char resident = MINCORE_INCORE;
#ifdef MINCORE_PAGED_OUT
            resident |= MINCORE_PAGED_OUT;
#endif
            if (vec[i / ps] & resident)
            {
                while (done < n)
                {
                    ssize_t written;
                    if (result.write_calls == write_budget)
                    {
                        result.status = "write-budget";
                        goto finish;
                    }
                    ++result.write_calls;
                    written = pwrite( fd, base + i + done, n - done, (off_t)(off + i + done) );
                    if (written < 0)
                    {
                        if (errno == EINTR) continue;
                        result.status = "write-failed";
                        result.error = errno;
                        goto finish;
                    }
                    if (!written || (size_t)written > n - done)
                    {
                        result.status = "write-failed";
                        result.error = EIO;
                        goto finish;
                    }
                    done += written;
                    result.written_bytes += written;
                    result.logical_bytes = off + i + done;
                }
            }
            result.logical_bytes = off + i + n;
        }
        off += len;
    }
finish:
    /* Only extend over pages actually examined. A failed query/write must not
     * leave a full-sized file that looks like a complete sparse capture. */
    if (ftruncate( fd, (off_t)result.logical_bytes ) < 0 && !result.error)
    {
        result.status = "truncate-failed";
        result.error = errno;
    }
    /* Never retry close after EINTR: the fd may already have been recycled. */
    if (close( fd ) < 0 && !result.error)
    {
        result.status = "close-failed";
        result.error = errno;
    }
restore_errno:
    errno = saved_errno;
    return result;
}

#endif /* MADEIRA_IOS_JIT_DUMP_H */
