#!/usr/bin/env python3
"""Compile production child tracking, process-exit wiring and opt-in wait policy.

No Wine/FEX guest or Apple SDK runs. PEB/socket/image teardown are modeled;
registry locking, teardown pins, generation tokens, the common exit wrapper and bridge wait
loop are production C. Tests normal/worker-thread exits, crashes, graceful
close, handoff, age eligibility, helpers, failed boot, saturation and reuse.
Owner-abort tests exercise pthread_exit and the actual Wine exit shim, including
nested teardown. Arbitrary raw longjmp, async cancellation and Mach termination
are outside this lifetime-bookkeeping test; interrupted resource reclamation is
not retried by the finalizer.
LeakSanitizer needs ASAN_OPTIONS=detect_leaks=0 on ptraced hosts.
This does not prove force-stop, an absolute wait timeout, or repeat-session
safety; Madeira's existing one-session-per-app-run rule is unchanged.
"""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
process = (ROOT / 'build/ntdll-unix/process_ios.c').read_text()
server = (ROOT / 'build/ntdll-unix/server_ios.c').read_text()
bridge = (ROOT / 'app/Madeira/WineProcessBridge.m').read_text()
library = (ROOT / 'app/Madeira/Library.swift').read_text()
exit_shim = (ROOT / 'build/ntdll-unix/shims/wine_ios_exit.h').read_text()


def function(source, signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2] + '\n'


entry = function(process, 'static void *ios_child_thread_entry( void *arg )')
assert entry.index('ios_child_current_token = args->lifetime;') < entry.index('wine_ios_child_main(')
assert entry.index('madeira_child_lifetime_release( args->lifetime );') < entry.index('free( args );')
spawn = function(process, 'static NTSTATUS spawn_process(')
assert spawn.index('args->lifetime = ios_child_slot_take(') < spawn.index('ret = pthread_create(')
assert 'madeira_child_lifetime_release( args->lifetime );' in spawn.split('if (ret) {', 1)[1]
register = function(server, 'static void ios_register_proc_socket(')
assert register.index('ios_proc_sockets[idx].peb = peb_id;') < register.index('madeira_child_lifetime_bind( peb_id );')
exit_wrapper = function(server, 'void process_exit_wrapper( int status )')
assert exit_wrapper.index('madeira_child_lifetime_begin_exit( dead_peb )') < exit_wrapper.index('ios_retire_own_fixed_base_image( dead_peb );')
assert exit_wrapper.index('ios_exe_win_mark_ready( dead_peb )') < exit_wrapper.index('pthread_cleanup_pop( 1 )')
assert exit_wrapper.index('pthread_cleanup_pop( 1 )') < exit_wrapper.index('exit( final_status )')
assert exit_wrapper.index('if (!setjmp( scope.jump ))') < exit_wrapper.index('madeira_child_exit_scope_enter( &scope )')
cleanup = function(process, 'void madeira_child_exit_scope_cleanup( void *arg )')
assert cleanup.index('ios_child_exit_scope = scope->previous') < cleanup.index('madeira_child_lifetime_finish_exit( scope->token )')
assert exit_shim.index('madeira_child_lifetime_redirect_exit(status)') < exit_shim.index('longjmp(wine_ios_exit_jmpbuf, 1)')
# Graceful Quit still asks the actual focused app to save/close, without
# force-killing children or disabling a save-confirmation dialog.
quit_body = library.split('    func requestQuit() {', 1)[1].split('\n    func ', 1)[0]
assert 'winios_post_key(0x12, 1); winios_post_key(0x73, 1)' in quit_body
assert 'wineserver_stop' not in quit_body
wait = bridge.split('        /* A launcher stub that starts the game', 1)[1]
wait = wait[wait.index('        {'):wait.index('\n        g_wine_running = 0;')]
assert '!(wc && wc[0] == \'1\')' in wait  # no global enable
assert '60.0' in wait and '-1.0' in wait  # old-child cutoff only at entry

harness = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "child_lifetime_ios.h"
#define WINE_IOS 1
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
typedef uint16_t WCHAR;
typedef struct { uint16_t Length; WCHAR *Buffer; } UNICODE_STRING;
static double test_now = 100;
static int test_clock_gettime(clockid_t clock, struct timespec *ts) {
    assert(clock == CLOCK_MONOTONIC);
    ts->tv_sec = (time_t)test_now;
    ts->tv_nsec = (long)((test_now - ts->tv_sec) * 1e9);
    return 0;
}
#define clock_gettime test_clock_gettime
'''
harness += process[process.index('#define IOS_CHILD_SLOTS'):process.index('/* the machine of the child\'s main image')]
harness += r'''
_Thread_local jmp_buf wine_ios_exit_jmpbuf;
_Thread_local volatile int wine_ios_exit_code;
_Thread_local pthread_t wine_ios_main_thread;
_Thread_local int wine_ios_exit_initialized;
#define os_log_error(...) ((void)0)
'''
harness += function(exit_shim, 'static inline __attribute__((noreturn)) void wine_ios_exit(int status)')
harness += r'''
#undef clock_gettime
static uint64_t peek_lifetime(void *peb) {
    uint64_t token = 0;
    pthread_mutex_lock(&ios_child_lock);
    if (peb) for (unsigned i = 0; i < IOS_CHILD_SLOTS; i++)
        if (ios_child_slots[i].peb == peb) { token = ios_child_slots[i].token; break; }
    pthread_mutex_unlock(&ios_child_lock);
    return token;
}
static _Thread_local uint64_t cleanup_token;
static _Thread_local void *current_peb;
static _Thread_local int cleanup_stage, fault_kind, fault_stage;
static int launch_reports, last_launch_report, server_stops, g_wine_running;
static int fd_socket = 900;
static void *ios_jit_current_peb(void) { return current_peb; }
static void wine_log_write(const char *format, ...) { (void)format; }
static void ios_fdt_reg(int fd, int kind, void *peb) { (void)fd; (void)kind; (void)peb; }
static void ios_fdt_note_close(int fd, const char *why, void *peb) { (void)fd; (void)why; (void)peb; }
static int test_close(int fd) { assert(fd >= 0); return 0; }
static void *interleaved_entry_cleanup(void *opaque) {
    /* The boot thread's fallback cleanup owns the same generation token. */
    madeira_child_lifetime_release(*(uint64_t *)opaque);
    return NULL;
}
static void assert_still_tracked(void *peb) {
    assert(peb == current_peb && cleanup_token && !peek_lifetime(peb));
    /* Force boot-thread cleanup while the worker's process-exit teardown
       is paused at each image/FD/JIT/window cleanup stage. */
    pthread_t boot;
    uint64_t token = cleanup_token;
    assert(!pthread_create(&boot, NULL, interleaved_entry_cleanup, &token));
    assert(!pthread_join(boot, NULL));
    int found = 0;
    pthread_mutex_lock(&ios_child_lock);
    for (unsigned i = 0; i < IOS_CHILD_SLOTS; i++)
        if (ios_child_slots[i].token == cleanup_token) found = 1;
    pthread_mutex_unlock(&ios_child_lock);
    assert(found);
    assert(madeira_live_game_children(NULL, 0, -1) > 0); /* waiter must stay alive */
}
void process_exit_wrapper(int status);
static void cleanup_step(void *peb, int stage) {
    assert_still_tracked(peb);
    assert(cleanup_stage++ == stage);
    if (fault_kind && fault_stage == stage) {
        int kind = fault_kind;
        fault_kind = 0;
        if (kind == 1) pthread_exit(NULL);
        if (kind == 2 || kind == 4) wine_ios_exit(77);
        if (kind == 3) { cleanup_stage = 0; process_exit_wrapper(78); }
        assert(0);
    }
}
void ios_retire_own_fixed_base_image(void *peb) { cleanup_step(peb, 0); }
void ios_fd_cache_release(void *peb) { cleanup_step(peb, 1); }
void ios_jit_reclaim_process(void *peb) { cleanup_step(peb, 2); }
void ios_wow_window_release(void *peb) { cleanup_step(peb, 3); }
void ios_exe_win_mark_ready(void *peb) { cleanup_step(peb, 4); }
/* Clang requires the production weak declaration before our test definition. */
void wine_launched_process_did_exit(int status) __attribute__((weak));
void wine_launched_process_did_exit(int status) { launch_reports++; last_launch_report = status; }
#define FALSE 0
#define FDT_MASTER 1
typedef int BOOL;
'''
harness += server[server.index('#define IOS_MAX_PROC_SOCKETS'):server.index('extern void *ios_jit_current_peb(void);')]
harness += function(server, 'static int ios_proc_socket_index(void)')
harness += register
harness += '#define close test_close\n#define exit wine_ios_exit\n' + exit_wrapper + '\n#undef exit\n#undef close\n'
harness += r'''
static uint64_t reserve(const char *path) {
    WCHAR text[256];
    size_t n = strlen(path);
    assert(n < ARRAY_SIZE(text));
    for (size_t i = 0; i < n; i++) text[i] = (unsigned char)path[i];
    UNICODE_STRING image = { (uint16_t)(n * sizeof(WCHAR)), text };
    return ios_child_slot_take(&image);
}
static uint64_t start_child(const char *path, void *peb) {
    uint64_t token = reserve(path);
    assert(token);
    ios_child_current_token = token;
    ios_register_proc_socket(peb, 20 + ios_proc_socket_count);
    assert(peek_lifetime(peb) == token);
    ios_child_current_token = 0;
    return token;
}
struct finish { void *peb; int status; };
static void *worker_exit(void *opaque) {
    struct finish *f = opaque;
    assert(ios_child_current_token == 0); /* worker has no boot-thread TLS */
    current_peb = f->peb;
    cleanup_stage = 0; cleanup_token = peek_lifetime(f->peb);
    wine_ios_exit_initialized = 1; wine_ios_main_thread = pthread_self();
    if (!setjmp(wine_ios_exit_jmpbuf)) process_exit_wrapper(f->status);
    assert(wine_ios_exit_code == f->status && cleanup_stage == 5);
    assert(!peek_lifetime(f->peb) && !ios_child_exit_scope);
    return NULL;
}
static void finish_child(void *peb, int status) {
    struct finish f = {peb, status};
    pthread_t thread;
    assert(!pthread_create(&thread, NULL, worker_exit, &f));
    assert(!pthread_join(thread, NULL));
}
struct fault { void *peb; int kind, stage; };
static void *faulting_owner(void *opaque) {
    struct fault *f = opaque;
    current_peb = f->peb; cleanup_token = peek_lifetime(f->peb);
    cleanup_stage = 0; fault_kind = f->kind; fault_stage = f->stage;
    wine_ios_exit_initialized = f->kind != 4; wine_ios_main_thread = pthread_self();
    if (!setjmp(wine_ios_exit_jmpbuf)) process_exit_wrapper(0);
    assert(f->kind != 1 && f->kind != 4); /* pthread_exit bypasses outer setjmp */
    assert(wine_ios_exit_code == (f->kind == 2 ? 77 : 78));
    assert(!ios_child_exit_scope && !peek_lifetime(f->peb));
    return (void *)1;
}
static void *no_scope_worker_exit(void *unused) {
    (void)unused;
    assert(!ios_child_exit_scope && !wine_ios_exit_initialized);
    wine_ios_exit(99); /* original fallback: pthread_exit, no synthetic longjmp */
}
static void assert_count(int expected, double age) {
    char names[256];
    assert(madeira_live_game_children(names, sizeof(names), age) == expected);
    assert(madeira_live_game_children(NULL, 0, age) == expected);
}
static void *wait_child;
static int polls, exit_at, wait_status;
static int test_usleep(unsigned usec) {
    assert(usec == 200000 && ++polls < 100); /* catch regressions, not production timeout */
    test_now += .2;
    if (polls == exit_at) finish_child(wait_child, wait_status);
    return 0;
}
static int test_dprintf(int fd, const char *format, ...) { (void)fd; (void)format; return 0; }
static void wineserver_stop(void) { server_stops++; }
#define usleep test_usleep
#define dprintf test_dprintf
static void wait_after_main_exit(void) {
'''
harness += wait
harness += r'''
    g_wine_running = 0;
    wineserver_stop();
}
#undef dprintf
#undef usleep
static void poll_case(void *peb, int status, const char *enabled, int expected_polls) {
    if (enabled) assert(!setenv("MADEIRA_WAIT_CHILDREN", enabled, 1));
    else assert(!unsetenv("MADEIRA_WAIT_CHILDREN"));
    wait_child = peb; polls = 0; exit_at = 3; wait_status = status;
    g_wine_running = 1;
    int stops_before = server_stops;
    wait_after_main_exit();
    assert(polls == expected_polls && !g_wine_running && server_stops == stops_before + 1);
}
static void bind_token(uint64_t token, void *peb) {
    ios_child_current_token = token;
    madeira_child_lifetime_bind(peb);
    ios_child_current_token = 0;
}
static void *stress_registry(void *opaque) {
    uintptr_t base = (uintptr_t)opaque;
    for (unsigned i = 0; i < 1500; i++) {
        uint64_t token = reserve("client.exe");
        assert(token);
        void *peb = (void *)(base + i * 16);
        bind_token(token, peb);
        assert(peek_lifetime(peb) == token);
        madeira_child_lifetime_release(token);
        madeira_child_lifetime_release(token); /* repeated cleanup is idempotent */
    }
    return NULL;
}
int main(void) {
    void *client = (void *)0x1010, *game = (void *)0x2020;
    char names[256];
    assert_count(0, -1);
    madeira_child_lifetime_release(0);
    madeira_child_lifetime_bind(NULL);
    assert(!peek_lifetime(NULL));
    /* A direct game without children still stops immediately, opt-in or not. */
    poll_case(NULL, 0, NULL, 0);
    poll_case(NULL, 0, "1", 0);
    /* Default/off keep legacy termination; do not silently enable wait-all. */
    uint64_t first = start_child("C:\\Ubisoft\\upc.exe", client);
    poll_case(client, 0, NULL, 0);
    poll_case(client, 0, "0", 0);
    assert_count(1, -1);
    /* Launcher main has gone; real child stays until its own graceful close. */
    poll_case(client, 0, "1", 3);
    assert_count(0, -1);
    madeira_child_lifetime_release(first); /* delayed boot-thread cleanup */
    /* NTSTATUS crash on a child worker clears tracking, without misreporting
       the child as the session's initial program. */
    start_child("Blender.exe", game);
    poll_case(game, (int)0xc0000005, "1", 3);
    assert(!launch_reports && !peek_lifetime(game));
    /* A normal game's old helper and crash reporter cannot opt it into wait. */
    uint64_t helper = reserve("C:/tools/CRASHREPORTER64.EXE");
    uint64_t old = start_child("background.exe", client);
    test_now += 60.1;
    assert_count(1, -1); assert_count(0, 60.0);
    poll_case(client, 0, "1", 0);
    finish_child(client, 0); madeira_child_lifetime_release(old);
    madeira_child_lifetime_release(helper);
    /* Child eligibility exactly at the 60-second boundary remains inclusive;
       after entry, a live child is not timed out just because it ages. */
    start_child("app.exe", client); test_now += 60.0;
    assert_count(1, 60.0);
    poll_case(client, 0, "1", 3);
    /* Parent/child/grandchild handoff: retiring a launcher never releases the
       child's own reservation or its descendant. */
    uint64_t launcher = start_child("launcher.exe", client);
    uint64_t descendant = start_child("1cv8.exe", game);
    finish_child(client, 0); assert_count(1, -1);
    assert(peek_lifetime(game) == descendant);
    poll_case(game, 0, "1", 3);
    madeira_child_lifetime_release(launcher);
    /* Teardown detaches ownership but keeps the reservation live until its
       server-dependent cleanup finishes. Reused PEBs identify the new child. */
    uint64_t retiring = reserve("retiring.exe"); bind_token(retiring, client);
    assert(madeira_child_lifetime_begin_exit(client) == retiring);
    assert(!peek_lifetime(client)); assert_count(1, -1);
    uint64_t reused = reserve("reused-peb.exe"); bind_token(reused, client);
    assert(madeira_child_lifetime_begin_exit(client) == reused);
    /* Fallback entry cleanup and a repeated bind cannot undo the pin. */
    madeira_child_lifetime_release(retiring); assert_count(2, -1);
    madeira_child_lifetime_release(reused); assert_count(2, -1);
    bind_token(reused, client); assert(!peek_lifetime(client));
    assert(!madeira_child_lifetime_begin_exit(client));
    madeira_child_lifetime_finish_exit(retiring); assert_count(1, -1);
    madeira_child_lifetime_finish_exit(reused); assert_count(0, -1);
    /* Late cleanup cannot clear a slot/PEB now occupied by another generation. */
    uint64_t stale = reserve("first.exe"); bind_token(stale, client);
    madeira_child_lifetime_release(stale);
    uint64_t replacement = reserve("second.exe"); bind_token(replacement, client);
    assert(replacement != stale);
    madeira_child_lifetime_finish_exit(stale);
    /* Finalize requires begin_exit; it cannot cancel a live reservation. */
    madeira_child_lifetime_finish_exit(replacement);
    madeira_child_lifetime_release(stale);
    assert(peek_lifetime(client) == replacement);
    assert_count(1, -1); madeira_child_lifetime_release(replacement);
    /* Early boot/pthread_create failure has no PEB; token release still works. */
    uint64_t failed = reserve("failed.exe");
    assert_count(1, -1); madeira_child_lifetime_release(failed); assert_count(0, -1);
    /* Session exit reporting and server shutdown remain on their old routes. */
    current_peb = (void *)0x9999;
    wine_ios_exit_initialized = 1; wine_ios_main_thread = pthread_self();
    if (!setjmp(wine_ios_exit_jmpbuf)) process_exit_wrapper((int)0xc000001d);
    assert(launch_reports == 1 && (uint32_t)last_launch_report == 0xc000001d);
    /* Without an owner scope the original Wine exit shim is unchanged. */
    wine_ios_exit_code = 0;
    if (!setjmp(wine_ios_exit_jmpbuf)) wine_ios_exit(66);
    assert(wine_ios_exit_code == 66 && !ios_child_exit_scope);
    pthread_t no_scope_thread; void *no_scope_result = (void *)1;
    assert(!pthread_create(&no_scope_thread, NULL, no_scope_worker_exit, NULL));
    assert(!pthread_join(no_scope_thread, &no_scope_result) && !no_scope_result);
    assert_count(0, -1);
    /* A nested zero-token scope restores the outer owner without unpinning it. */
    uint64_t scoped = reserve("nested-scope.exe"); bind_token(scoped, client);
    assert(madeira_child_lifetime_begin_exit(client) == scoped);
    struct madeira_child_exit_scope outer_scope, inner_scope;
    madeira_child_exit_scope_prepare(&outer_scope, scoped);
    if (setjmp(outer_scope.jump)) assert(0);
    madeira_child_exit_scope_enter(&outer_scope);
    madeira_child_exit_scope_prepare(&inner_scope, 0);
    if (setjmp(inner_scope.jump)) assert(0);
    madeira_child_exit_scope_enter(&inner_scope);
    madeira_child_exit_scope_cleanup(&inner_scope);
    assert(ios_child_exit_scope == &outer_scope); assert_count(1, -1);
    madeira_child_exit_scope_cleanup(&outer_scope);
    assert(!ios_child_exit_scope); assert_count(0, -1);
    /* Owner pthread_exit and actual Wine exit-shim longjmp at every teardown
       stage. Entry fallback attempts still run concurrently before each fault. */
    for (int kind = 1; kind <= 4; kind++) {
        for (int stage = 0; stage < (kind == 3 ? 1 : 5); stage++) {
            void *peb = (void *)(uintptr_t)(0x4000 + kind * 0x100 + stage * 0x10);
            uint64_t token = start_child("aborting-owner.exe", peb);
            struct fault f = {peb, kind, stage};
            pthread_t owner; void *result;
            assert(!pthread_create(&owner, NULL, faulting_owner, &f));
            assert(!pthread_join(owner, &result));
            assert(result == (kind == 1 || kind == 4 ? NULL : (void *)1));
            assert_count(0, -1);
            madeira_child_lifetime_release(token); /* late fallback is harmless */
            assert_count(0, -1);
        }
    }
    /* Repeated normal teardown after abnormal exits does not inherit an owner. */
    start_child("after-abort.exe", (void *)0x7070);
    finish_child((void *)0x7070, 0); assert_count(0, -1);
    /* Bounded registry saturation, name truncation, zero/one-byte output. */
    uint64_t full[IOS_CHILD_SLOTS];
    for (int i = 0; i < IOS_CHILD_SLOTS; i++) assert((full[i] = reserve("C:\\Long\\APP.EXE")));
    assert(!reserve("overflow.exe")); assert_count(IOS_CHILD_SLOTS, -1);
    assert(madeira_live_game_children(names, 1, -1) == IOS_CHILD_SLOTS && !names[0]);
    assert(madeira_live_game_children(names, 2, -1) == IOS_CHILD_SLOTS && !names[1]);
    for (int i = 0; i < IOS_CHILD_SLOTS; i++) madeira_child_lifetime_release(full[i]);
    /* Thousands of interleaved child lifetimes, not whole app sessions. */
    pthread_t stress[4];
    for (uintptr_t i = 0; i < 4; i++) assert(!pthread_create(&stress[i], NULL, stress_registry, (void *)(0x100000 + i * 0x100000)));
    for (unsigned i = 0; i < 4; i++) assert(!pthread_join(stress[i], NULL));
    assert_count(0, -1);
    ios_child_next_token = UINT64_MAX;
    assert(!reserve("never-wrap.exe")); assert_count(0, -1);
    puts("PASS: production child lifetimes, worker exits/crashes, graceful close, opt-in handoff, age cutoff, failed boot, 6000 concurrent reuse cycles, generation guards, teardown/entry-cleanup races and owner pthread_exit/longjmp/nested-exit faults");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='madeira-child-lifetime-') as tmp:
    src, exe = Path(tmp) / 'check.c', Path(tmp) / 'check'
    src.write_text(harness)
    flags = shlex.split(os.environ.get('CFLAGS', '-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer'))
    subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-Wno-address', '-pthread', *flags, '-I', str(ROOT / 'build/ntdll-unix'),
                    str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True, timeout=30)
print('PASS: production spawn/bind/teardown ordering, default-off policy, existing Alt+F4 semantics')
