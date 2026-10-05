#!/usr/bin/env python3
"""Opt-in, bounded JIT crash I/O; compile and execute the production helper.

No Wine, iOS SDK, or large real dump required. Tests use real small files, an
unreadable-page sparse-hole guard, injected system-call failures, competing
threads and mock writes for the 1 GiB upper-bound case. Run with JIT_DUMP_TSAN=1
for an additional ThreadSanitizer run on a host with a working TSan runtime.
"""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SIGNAL = (ROOT / "build/ntdll-unix/signal_arm64_ios.c").read_text()
HEADER = (ROOT / "build/ntdll-unix/ios_jit_dump.h").read_text()


def function(name):
    start = SIGNAL.index(name)
    return SIGNAL[start:SIGNAL.index("\n}", start) + 2]


assert SIGNAL.count('ios_dump_jit_pool( "mach UNHANDLED" )') == 1
assert SIGNAL.count('ios_dump_jit_pool( "ILL diag" )') == 1
assert 'static volatile int ill_dumped' not in SIGNAL
assert 'static volatile int dumped = 0;' not in SIGNAL
assert 'O_TRUNC' not in HEADER
for name in ('static void ios_dump_jit_pool(', 'static void ios_jit_dump_append(',
             'static void ios_jit_dump_number('):
    body = function(name)
    for unsafe in ('getenv(', 'getenv (', 'snprintf(', 'snprintf (', 'dprintf(',
                   'malloc(', 'pthread_once(', 'pthread_mutex_'):
        assert unsafe not in body, (name, unsafe)
init = function('void signal_init_process(void)')
assert init.index('pthread_once( &ios_jit_dump_once') < init.index('sigaction(')
mach_init = function('static void ios_setup_mach_exception_handler(')
assert mach_init.index('pthread_once( &ios_jit_dump_once') < mach_init.index('pthread_create(')
assert '__ATOMIC_RELEASE' in function('static void ios_init_jit_dump_policy(void)')
print('PASS: both fault paths share a guard; immutable policy is published before handler installation')

cc = shlex.split(os.environ.get('CC', 'cc'))
with tempfile.TemporaryDirectory(prefix='madeira-jit-dump-') as tmp:
    output = Path(tmp)
    wrapper_start = SIGNAL.index('static struct ios_jit_dump_policy ios_jit_dump_policy;')
    wrapper_end = SIGNAL.index('static void *ios_mach_exception_thread(', wrapper_start)
    (output / 'jit-dump-wrapper.inc').write_text(SIGNAL[wrapper_start:wrapper_end])
    binary = output / 'jit-dump'
    command = cc + ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1', '-g', '-pthread',
                    '-I', str(ROOT / 'build/ntdll-unix'),
                    str(ROOT / 'tests/host/fixtures/jit-dump-io.c'), '-o', str(binary)]
    subprocess.run(command, check=True)
    subprocess.run([str(binary), tmp], check=True, timeout=30)
    sanitized = output / 'jit-dump-sanitized'
    sanitizer_flags = ['-fsanitize=address,undefined', '-fno-sanitize-recover=all']
    subprocess.run(command[:-1] + [str(sanitized)] + sanitizer_flags, check=True)
    # LeakSanitizer cannot operate under the managed executor's ptrace wrapper.
    # Keep address/UB checks; the helper contains no heap allocation.
    environment = os.environ.copy()
    environment['ASAN_OPTIONS'] = environment.get('ASAN_OPTIONS', '') + ':detect_leaks=0'
    subprocess.run([str(sanitized), tmp], check=True, timeout=30, env=environment)
    wrapper = output / 'jit-dump-wrapper'
    wrapper_command = cc + ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1', '-g', '-pthread',
                            '-I', str(ROOT / 'build/ntdll-unix'), '-I', tmp,
                            str(ROOT / 'tests/host/fixtures/jit-dump-wrapper.c'), '-o', str(wrapper)]
    subprocess.run(wrapper_command + sanitizer_flags, check=True)
    subprocess.run([str(wrapper)], check=True, timeout=30, env=environment)
    print('PASS: AddressSanitizer + UndefinedBehaviorSanitizer')
    if os.environ.get('JIT_DUMP_TSAN') == '1':
        tsan = output / 'jit-dump-tsan'
        subprocess.run(command[:-1] + [str(tsan), '-fsanitize=thread'], check=True)
        subprocess.run([str(tsan), tmp], check=True, timeout=30)
        print('PASS: ThreadSanitizer')
