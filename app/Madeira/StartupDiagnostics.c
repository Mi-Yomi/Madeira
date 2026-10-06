/* SPDX-License-Identifier: GPL-3.0-or-later WITH Madeira-Converter-Exception-1 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#define _DARWIN_C_SOURCE 1
#include "StartupDiagnostics.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MDS_MAX_EVENTS 64
#define MDS_REPORT "madeira-startup.json"
static const char *const phase_names[MDS_EVENT_COUNT] = {
    "attempt_begin", "jit_unavailable", "jit_preparing", "jit_pool_failed",
    "detach_begin", "detach_end", "network_restore_begin", "network_restore_end",
    "server_start_requested", "server_ready", "server_start_failed",
    "server_stopped", "server_ready_timeout", "wine_start_requested",
    "socket_failed", "thread_create_failed", "thread_entered",
    "arguments_rejected", "directory_rejected", "loader_entered",
    "process_exit_reported", "loader_returned", "loader_longjmp",
    "live_children_observed", "thread_finished", "first_frame_observed",
    "close_requested", "observation_settled", "observation_limit", "wine_start_failed"
};
struct startup_event { MadeiraStartupEvent event; uint32_t code; uint64_t elapsed_ms; };
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int directory_fd = -1;
static char attempt[33];
static struct timespec began;
static int64_t began_unix;
static struct startup_event events[MDS_MAX_EVENTS];
static unsigned event_count, dropped;
static uint64_t pending_exit, pending_exit_ns;
static int exit_flushed, snapshot_dirty;
_Static_assert(__atomic_always_lock_free(sizeof(uint64_t), 0), "exit capture requires lock-free 64-bit atomics");

static uint64_t elapsed_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    int64_t ns = (int64_t)(now.tv_sec - began.tv_sec) * 1000000000 + now.tv_nsec - began.tv_nsec;
    return ns > 0 ? (uint64_t)ns / 1000000 : 0;
}

/* Atomic replacement keeps a previous valid snapshot if writing is interrupted.
 * This is a bounded lifecycle summary, deliberately separate from raw logs. */
static int persist(void)
{
    char output[16384];
    int used = snprintf(output, sizeof output,
        "{\"schema\":1,\"attempt_id\":\"%s\",\"started_unix\":%" PRId64
        ",\"scope\":\"initial_process\",\"dropped_events\":%u,\"events\":[",
        attempt, began_unix, dropped);
    for (unsigned i = 0; i < event_count; i++) {
        int n = snprintf(output + used, sizeof output - (size_t)used,
            "%s{\"phase\":\"%s\",\"elapsed_ms\":%" PRIu64 ",\"code\":%" PRIu32 "}",
            i ? "," : "", phase_names[events[i].event], events[i].elapsed_ms, events[i].code);
        if (n < 0 || (size_t)n >= sizeof output - (size_t)used) { errno = EOVERFLOW; return -1; }
        used += n;
    }
    if ((size_t)used + 4 > sizeof output) { errno = EOVERFLOW; return -1; }
    memcpy(output + used, "]}\n", 3); used += 3;
    /* Private directory, fixed names, and no following a pre-existing symlink. */
    if (unlinkat(directory_fd, ".startup.tmp", 0) && errno != ENOENT) return -1;
    int fd = openat(directory_fd, ".startup.tmp", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    size_t done = 0;
    while (done < (size_t)used) {
        ssize_t n = write(fd, output + done, (size_t)used - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (!n) errno = EIO; goto failed; }
        done += (size_t)n;
    }
    if (fsync(fd)) goto failed;
    if (close(fd)) { fd = -1; goto failed; }
    fd = -1;
    if (renameat(directory_fd, ".startup.tmp", directory_fd, MDS_REPORT)) goto failed;
    return 0;
failed: {
    int saved = errno;
    if (fd >= 0) close(fd);
    unlinkat(directory_fd, ".startup.tmp", 0);
    errno = saved;
    return -1;
}
}

/* The only function called from asynchronous Wine exit teardown. */
void madeira_startup_note_exit(uint32_t status)
{
    struct timespec now = {0};
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t ns = (uint64_t)now.tv_sec * 1000000000 + (uint64_t)now.tv_nsec;
    __atomic_store_n(&pending_exit_ns, ns, __ATOMIC_RELAXED);
    __atomic_store_n(&pending_exit, (UINT64_C(1) << 32) | status, __ATOMIC_RELEASE);
}

static void append_event(MadeiraStartupEvent event, uint32_t code, uint64_t ms)
{
    /* Keep attempt_begin and the first observed process exit. Before exit,
     * retain the newest 63 other events; after exit, retain the newest 62.
     * Once the first exit reaches index 1, evict index 2 instead. Later exit
     * duplicates, if any, are ordinary events and cannot replace that evidence. */
    if (event_count == MDS_MAX_EVENTS) {
        unsigned victim = events[1].event == MDS_PROCESS_EXIT_REPORTED ? 2 : 1;
        memmove(events + victim, events + victim + 1,
                sizeof events[0] * (event_count - victim - 1));
        event_count--; dropped++;
    }
    events[event_count++] = (struct startup_event){ event, code, ms };
}

static int drain_exit(void)
{
    uint64_t value = __atomic_load_n(&pending_exit, __ATOMIC_ACQUIRE);
    if (!(value >> 32) || exit_flushed) return 0;
    uint64_t ns = __atomic_load_n(&pending_exit_ns, __ATOMIC_RELAXED);
    uint64_t start = (uint64_t)began.tv_sec * 1000000000 + (uint64_t)began.tv_nsec;
    append_event(MDS_PROCESS_EXIT_REPORTED, (uint32_t)value, ns > start ? (ns - start) / 1000000 : 0);
    exit_flushed = 1;
    return 1;
}

int madeira_startup_flush(void)
{
    int incoming_errno = errno;
    pthread_mutex_lock(&lock);
    int result = 0;
    if (directory_fd >= 0) {
        if (drain_exit()) snapshot_dirty = 1;
        if (snapshot_dirty) { result = persist(); if (!result) snapshot_dirty = 0; }
    }
    int saved = errno;
    pthread_mutex_unlock(&lock);
    errno = result ? saved : incoming_errno;
    return result;
}

int madeira_startup_begin(const char *documents_directory)
{
    pthread_mutex_lock(&lock);
    if (directory_fd >= 0) close(directory_fd);
    directory_fd = -1;
    int docs = open(documents_directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (docs < 0) goto failed;
    if (mkdirat(docs, "startup-diagnostics", 0700) && errno != EEXIST) {
        int saved = errno; close(docs); errno = saved; goto failed;
    }
    directory_fd = openat(docs, "startup-diagnostics", O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    { int saved = errno; close(docs); errno = saved; }
    if (directory_fd < 0) goto failed;
    /* Rotate only when a new attempt starts, never simply on app restart. */
    for (int i = 3; i >= 1; i--) {
        char from[64], to[64];
        snprintf(to, sizeof to, "madeira-startup.prev%d.json", i);
        if (i == 1) snprintf(from, sizeof from, "%s", MDS_REPORT);
        else snprintf(from, sizeof from, "madeira-startup.prev%d.json", i - 1);
        if (renameat(directory_fd, from, directory_fd, to) && errno != ENOENT) goto failed;
    }
    unsigned char bytes[16];
    arc4random_buf(bytes, sizeof bytes);
    for (unsigned i = 0; i < sizeof bytes; i++) snprintf(attempt + 2 * i, 3, "%02x", bytes[i]);
    if (clock_gettime(CLOCK_MONOTONIC, &began)) goto failed;
    began_unix = (int64_t)time(NULL);
    event_count = 1; dropped = 0; exit_flushed = 0; snapshot_dirty = 0;
    __atomic_store_n(&pending_exit, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&pending_exit_ns, 0, __ATOMIC_RELAXED);
    events[0] = (struct startup_event){ MDS_ATTEMPT_BEGIN, 0, 0 };
    if (persist()) goto failed;
    pthread_mutex_unlock(&lock);
    return 0;
failed: {
    int saved = errno;
    if (directory_fd >= 0) close(directory_fd);
    directory_fd = -1;
    pthread_mutex_unlock(&lock);
    errno = saved;
    return -1;
}
}

int madeira_startup_record(MadeiraStartupEvent event, uint32_t code)
{
    if (event < 0 || event >= MDS_EVENT_COUNT) { errno = EINVAL; return -1; }
    int incoming_errno = errno;
    pthread_mutex_lock(&lock);
    if (directory_fd < 0) { pthread_mutex_unlock(&lock); errno = ENOENT; return -1; }
    drain_exit();
    append_event(event, code, elapsed_ms());
    int result = persist(), saved = errno;
    snapshot_dirty = result != 0;
    pthread_mutex_unlock(&lock);
    errno = result ? saved : incoming_errno;
    return result;
}
