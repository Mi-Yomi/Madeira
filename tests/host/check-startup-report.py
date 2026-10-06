#!/usr/bin/env python3
"""Compile the production persistent startup journal and exit-status capture.

No iOS SDK, Wine guest, Blender or on-device UI is exercised. Swift integration
and project membership are source-checked, not an iOS build/typecheck.
"""
from pathlib import Path
import json
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / 'app/Madeira'
bridge = (APP / 'WineProcessBridge.m').read_text()
front = (APP / 'ContentView.swift').read_text()
lib = (APP / 'Library.swift').read_text()
project = (ROOT / 'app/Madeira.xcodeproj/project.pbxproj').read_text()
assert project.count('StartupDiagnostics.c in Sources') == 2
assert 'sourcecode.c.c; path = StartupDiagnostics.c;' in project
assert '#include "StartupDiagnostics.h"' in (APP / 'WineProcessBridge.h').read_text()
sequence = front.split('private func runWineFullSequence(', 1)[1]
assert sequence.index('madeira_startup_begin(') < sequence.index('guard jit_check_debugged()') < sequence.index('DispatchQueue.global(')
assert 'static let readinessTimeout: TimeInterval = 10.0' in front
assert 'let maxWait = 1200.0' in front
assert 'Wine observation ended after' in front and 'Wine finished after' not in front
for event in ['MDS_JIT_UNAVAILABLE', 'MDS_JIT_PREPARING', 'MDS_JIT_POOL_FAILED',
              'MDS_DETACH_BEGIN', 'MDS_DETACH_END', 'MDS_NETWORK_RESTORE_BEGIN', 'MDS_NETWORK_RESTORE_END',
              'MDS_SERVER_READY_TIMEOUT', 'MDS_SERVER_START_FAILED', 'MDS_SERVER_STOPPED',
              'MDS_WINE_START_FAILED', 'MDS_OBSERVATION_SETTLED', 'MDS_OBSERVATION_LIMIT']:
    assert event in sequence, event
for event in ['MDS_THREAD_ENTERED', 'MDS_SOCKET_FAILED', 'MDS_THREAD_CREATE_FAILED',
              'MDS_ARGUMENTS_REJECTED', 'MDS_DIRECTORY_REJECTED', 'MDS_LOADER_ENTERED',
              'MDS_LOADER_RETURNED', 'MDS_LOADER_LONGJMP', 'MDS_THREAD_FINISHED']:
    assert event in bridge, event
assert bridge.index('madeira_startup_record(MDS_LOADER_ENTERED') < bridge.index('__wine_main(argc, argv);')
assert 'if sawProcess || wine_process_exit_status(&status) != 0 { finish() }' in lib
assert 'if let report = exitReport() { error = report }' in lib
assert 'ShareLink(item: StartupReport.url)' in lib
assert 'startup-diagnostics/madeira-startup.json' in lib
assert 'madeira_startup_flush()' in front and 'madeira_startup_flush()' in lib
assert 'scope' in (APP / 'StartupDiagnostics.c').read_text()
# API does not accept free-form event text. Persist never consumes raw logs.
header = (APP / 'StartupDiagnostics.h').read_text()
assert 'madeira_startup_record(MadeiraStartupEvent event, uint32_t code)' in header
capture = bridge[bridge.index('static uint64_t g_launch_exit = 0;'):bridge.index('static char *g_prefix_path')]
assert 'madeira_startup_record(' not in capture and 'madeira_startup_note_exit(' in capture
assert capture.index('madeira_startup_note_exit(') < capture.index('__atomic_store_n(&g_launch_exit, (UINT64_C(1) << 32)')

harness = r'''
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
/* Feature selection must precede every system header, as in production. */
#define _DARWIN_C_SOURCE 1
#include <assert.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static _Atomic long fake_seconds = 100;
static int diagnostic_clock(clockid_t clock, struct timespec *ts) {
    assert(clock == CLOCK_MONOTONIC);
    ts->tv_sec = atomic_load(&fake_seconds); ts->tv_nsec = 0; return 0;
}
#define clock_gettime diagnostic_clock
#include "StartupDiagnostics.c"
CAPTURE
static void *writer(void *unused) {
    (void)unused;
    for (int i = 0; i < 20; ++i) assert(!madeira_startup_record(MDS_FIRST_FRAME_OBSERVED, 0));
    return NULL;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    assert(madeira_startup_record(MDS_LOADER_ENTERED, 0) == -1);
    assert(!madeira_startup_begin(argv[1]));
    assert(!madeira_startup_record(MDS_WINE_START_REQUESTED, 0));
    assert(!madeira_startup_record(MDS_THREAD_ENTERED, 0));
    assert(!madeira_startup_record(MDS_LOADER_ENTERED, 0));
    atomic_store(&fake_seconds, 216);
    wine_exit_status_reset();
    uint32_t status = 99;
    assert(!wine_process_exit_status(&status) && status == 99);
    /* Simulate interruption of the persistence lock holder by exit teardown:
     * capture must return without acquiring that lock or writing a file. */
    assert(!pthread_mutex_lock(&lock));
    wine_launched_process_did_exit(1);
    assert(!pthread_mutex_unlock(&lock));
    assert(wine_process_exit_status(&status) && status == 1);
    assert(!wine_crash_exit_status(&status));
    atomic_store(&fake_seconds, 219);
    wine_launched_process_did_exit(0); /* Preserve the first actual report and timestamp. */
    assert(wine_process_exit_status(&status) && status == 1);
    atomic_store(&fake_seconds, 220); /* Persistence four seconds after actual exit. */
    assert(!mkdirat(directory_fd, ".startup.tmp", 0700));
    assert(madeira_startup_flush() == -1); /* Prior snapshot remains intact. */
    assert(snapshot_dirty && exit_flushed);
    assert(!unlinkat(directory_fd, ".startup.tmp", AT_REMOVEDIR));
    assert(!madeira_startup_flush() && !snapshot_dirty);
    assert(!madeira_startup_record(MDS_LOADER_LONGJMP, 1));
    /* Initial launcher exits while a child is still alive. Repeated graceful
     * close requests must not erase the already-flushed initial exit. */
    assert(!madeira_startup_record(MDS_LIVE_CHILDREN_OBSERVED, 1));
    for (int i = 0; i < 140; i++) assert(!madeira_startup_record(MDS_CLOSE_REQUESTED, 0));
    assert(!madeira_startup_record(MDS_THREAD_FINISHED, 0));
    unsigned preserved_exits = 0;
    for (unsigned i = 0; i < event_count; i++) {
        if (events[i].event == MDS_PROCESS_EXIT_REPORTED) {
            preserved_exits++;
            assert(events[i].elapsed_ms == 116000 && events[i].code == 1);
        }
    }
    assert(preserved_exits == 1 && "flushed process exit was evicted by late events");
    assert(event_count == 64 && dropped == 84);
    /* Rotate; first report will remain at prev3 after the next two attempts. */
    assert(!madeira_startup_begin(argv[1]));
    wine_exit_status_reset(); wine_launched_process_did_exit(0);
    assert(wine_process_exit_status(&status) && status == 0);
    assert(!wine_crash_exit_status(&status));
    assert(!madeira_startup_flush());
    assert(!madeira_startup_begin(argv[1]));
    wine_exit_status_reset(); wine_launched_process_did_exit((int)0xC0000135u);
    assert(wine_crash_exit_status(&status) && status == 0xC0000135u);
    assert(!madeira_startup_flush());
    assert(!madeira_startup_begin(argv[1]));
    pthread_t threads[6];
    for (int i = 0; i < 6; i++) assert(!pthread_create(&threads[i], NULL, writer, NULL));
    for (int i = 0; i < 6; i++) assert(!pthread_join(threads[i], NULL));
    assert(madeira_startup_record((MadeiraStartupEvent)-1, 0) == -1 && errno == EINVAL);
    assert(madeira_startup_record(MDS_EVENT_COUNT, 0) == -1 && errno == EINVAL);
    assert(!madeira_startup_record(MDS_SERVER_READY_TIMEOUT, 10000));
    /* Begin failure closes the prior attempt: later events cannot contaminate it. */
    assert(madeira_startup_begin("/definitely-absent/madeira-test") == -1);
    assert(madeira_startup_record(MDS_LOADER_ENTERED, 0) == -1);
    /* In-memory production append logic: cover exit before, at and after the
     * journal fills, and ensure even duplicate exit events cannot replace it.
     * No writes follow, so the four persisted reports above remain unchanged. */
    for (unsigned prefix = 0; prefix <= 70; prefix++) {
        event_count = 1; dropped = 0;
        events[0] = (struct startup_event){ MDS_ATTEMPT_BEGIN, 0, 0 };
        for (unsigned i = 0; i < prefix; i++) append_event(MDS_FIRST_FRAME_OBSERVED, 0, i);
        append_event(MDS_PROCESS_EXIT_REPORTED, 0xC0000135u, 116000);
        append_event(MDS_PROCESS_EXIT_REPORTED, 99, 117000);
        for (unsigned i = 0; i < 140; i++) append_event(MDS_CLOSE_REQUESTED, i, 118000 + i);
        assert(event_count == 64 && dropped == prefix + 79);
        assert(events[0].event == MDS_ATTEMPT_BEGIN);
        assert(events[1].event == MDS_PROCESS_EXIT_REPORTED && events[1].code == 0xC0000135u);
        assert(events[1].elapsed_ms == 116000);
        for (unsigned i = 2; i < 64; i++) {
            assert(events[i].event == MDS_CLOSE_REQUESTED && events[i].code == i + 76);
        }
    }
    puts("PASS: 71 exit positions preserve the first exit, reject duplicate replacement and retain newest events within 64 slots");
    puts("PASS: all exit codes, first-report-wins, 116-second monotonic timing, concurrent bounded persistence");
}
'''.replace('CAPTURE', capture)

with tempfile.TemporaryDirectory(prefix='madeira-startup-report-') as temp:
    temp = Path(temp)
    docs = temp / 'private-user-password=SECRET-project-path'
    docs.mkdir()
    src = temp / 'main.c'; exe = temp / 'check'
    # Compile the production translation unit on its own too: the embedded
    # harness must not conceal a missing declaration in its real header order.
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', '-pthread',
                    *shlex.split(os.environ.get('CFLAGS', '')), '-c', str(APP / 'StartupDiagnostics.c'),
                    '-o', str(temp / 'StartupDiagnostics.o')], check=True)
    src.write_text(harness)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', '-pthread',
                    *shlex.split(os.environ.get('CFLAGS', '')), '-I', str(APP), str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe), str(docs)], check=True)
    folder = docs / 'startup-diagnostics'
    paths = sorted(folder.glob('*.json'))
    assert len(paths) == 4 and len(list(folder.iterdir())) == 4
    reports = [json.loads(p.read_text()) for p in paths]
    assert len({r['attempt_id'] for r in reports}) == 4
    for path, report in zip(paths, reports):
        text = path.read_text()
        assert path.stat().st_size < 16384 and path.stat().st_mode & 0o777 == 0o600
        assert 'SECRET' not in text and str(docs) not in text
        assert report['schema'] == 1 and report['scope'] == 'initial_process'
        assert len(report['attempt_id']) == 32 and all(c in '0123456789abcdef' for c in report['attempt_id'])
        assert len(report['events']) <= 64 and report['events'][0]['phase'] == 'attempt_begin'
        assert all(set(e) == {'phase', 'elapsed_ms', 'code'} for e in report['events'])
    last = json.loads((folder / 'madeira-startup.json').read_text())
    assert last['dropped_events'] == 58
    assert last['events'][-1] == {'phase': 'server_ready_timeout', 'elapsed_ms': 0, 'code': 10000}
    first = json.loads((folder / 'madeira-startup.prev3.json').read_text())
    exited = [e for e in first['events'] if e['phase'] == 'process_exit_reported']
    assert exited == [{'phase': 'process_exit_reported', 'elapsed_ms': 116000, 'code': 1}]
    assert first['events'][-1]['phase'] == 'thread_finished' and first['events'][-1]['elapsed_ms'] == 120000
    assert len(first['events']) == 64 and first['dropped_events'] == 84
    assert first['events'][1] == exited[0]
    assert [e['phase'] for e in first['events'][2:]] == ['close_requested'] * 61 + ['thread_finished']
    normal = json.loads((folder / 'madeira-startup.prev2.json').read_text())
    assert normal['events'][-1]['phase'] == 'process_exit_reported' and normal['events'][-1]['code'] == 0
    crashed = json.loads((folder / 'madeira-startup.prev1.json').read_text())
    assert crashed['events'][-1]['phase'] == 'process_exit_reported' and crashed['events'][-1]['code'] == 0xC0000135
    print('PASS: four retained reports, attempt IDs, valid JSON, private permissions, no input paths/secrets, first exit and newest late events retained')
    # A pre-existing symlink directory must not redirect diagnostic writes.
    attack = temp / 'attack'; attack.mkdir()
    outside = temp / 'outside'; outside.mkdir()
    (attack / 'startup-diagnostics').symlink_to(outside, target_is_directory=True)
    blocked = subprocess.run([str(exe), str(attack)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert blocked.returncode != 0 and not list(outside.iterdir())
    print('PASS: symlink directory cannot redirect persistent startup writes')
    # Failure mutation: reinstate unconditional index-1 eviction. The same
    # production-code harness must fail specifically on post-exit saturation.
    mutation = temp / 'mutation'; mutation.mkdir()
    production = (APP / 'StartupDiagnostics.c').read_text()
    pin = 'unsigned victim = events[1].event == MDS_PROCESS_EXIT_REPORTED ? 2 : 1;'
    assert production.count(pin) == 1
    (mutation / 'StartupDiagnostics.c').write_text(production.replace(pin, 'unsigned victim = 1;'))
    mutant_src = mutation / 'main.c'; mutant_src.write_text(harness)
    mutant_exe = mutation / 'check'
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', '-pthread',
                    *shlex.split(os.environ.get('CFLAGS', '')), '-I', str(APP), str(mutant_src), '-o', str(mutant_exe)], check=True)
    mutant_docs = mutation / 'documents'; mutant_docs.mkdir()
    failed = subprocess.run([str(mutant_exe), str(mutant_docs)], capture_output=True, text=True)
    assert failed.returncode != 0 and 'flushed process exit was evicted by late events' in failed.stderr, failed.stderr
    print('PASS: failure mutation detects eviction of an already-flushed process exit')
print('PASS: startup, native lifecycle, missed UI poll, export and Xcode source wiring (source-only Swift validation)')
