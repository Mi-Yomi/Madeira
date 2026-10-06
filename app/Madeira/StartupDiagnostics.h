/* SPDX-License-Identifier: GPL-3.0-or-later WITH Madeira-Converter-Exception-1 */
#pragma once
#include <stdint.h>

/* Only fixed phase names and numbers enter the shareable report. Never pass
 * arguments, environment values, executable names, paths or guest log text. */
typedef enum {
    MDS_ATTEMPT_BEGIN, MDS_JIT_UNAVAILABLE, MDS_JIT_PREPARING, MDS_JIT_POOL_FAILED,
    MDS_DETACH_BEGIN, MDS_DETACH_END, MDS_NETWORK_RESTORE_BEGIN, MDS_NETWORK_RESTORE_END,
    MDS_SERVER_START_REQUESTED, MDS_SERVER_READY, MDS_SERVER_START_FAILED,
    MDS_SERVER_STOPPED, MDS_SERVER_READY_TIMEOUT, MDS_WINE_START_REQUESTED,
    MDS_SOCKET_FAILED, MDS_THREAD_CREATE_FAILED, MDS_THREAD_ENTERED,
    MDS_ARGUMENTS_REJECTED, MDS_DIRECTORY_REJECTED, MDS_LOADER_ENTERED,
    MDS_PROCESS_EXIT_REPORTED, MDS_LOADER_RETURNED, MDS_LOADER_LONGJMP,
    MDS_LIVE_CHILDREN_OBSERVED, MDS_THREAD_FINISHED, MDS_FIRST_FRAME_OBSERVED,
    MDS_CLOSE_REQUESTED, MDS_OBSERVATION_SETTLED, MDS_OBSERVATION_LIMIT,
    MDS_WINE_START_FAILED, MDS_EVENT_COUNT
} MadeiraStartupEvent;

/* Creates one attempt, rotating up to three previous reports. Called before
 * asynchronous startup. A failure must not prevent launching the application.
 * Returns 0 on success, -1 on persistence failure (errno is preserved). */
int madeira_startup_begin(const char *documents_directory);
int madeira_startup_record(MadeiraStartupEvent event, uint32_t code);

/* Exit teardown can run from a signal handler. Capture without locks, allocation
 * or I/O; safe observer/thread code flushes it, keeping the original timestamp.
 * The bridge admits only one first-exit report per attempt. */
void madeira_startup_note_exit(uint32_t status);
int madeira_startup_flush(void);
