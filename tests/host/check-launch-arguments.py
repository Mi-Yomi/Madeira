#!/usr/bin/env python3
"""Compile and exercise the production Windows argument parser on a C host.

No Wine, Swift or Apple SDK is needed. Uses ASan/UBSan and an independent
Windows command-line encoder (Python's subprocess.list2cmdline) for round trips.
Leak detection can be disabled on ptraced hosts with ASAN_OPTIONS=detect_leaks=0.
"""
from pathlib import Path
import os
import random
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
bridge = (ROOT / 'app/Madeira/WineProcessBridge.m').read_text()
section = bridge.split('// Optional MADEIRA_ARGS', 1)[1].split('/* iOS-Madeira: chdir', 1)[0]
assert 'madeira_parse_launch_arguments(madeira_args, args_buf, extra_argv)' in section
assert 'strtok_r' not in section and 'strncpy' not in section
assert 'char *argv[MADEIRA_LAUNCH_ARGS_COUNT + 3]' in section
assert 'if (extra_argc < 0 || exe_path_length < 0 || exe_path_length >= (int)sizeof(exe_path))' in section
assert 'wineserver_stop();' in section
assert 'close(pending_client_fd);' in section and 'unsetenv("WINESERVERSOCKET");' in section
assert 'wine_launched_process_did_exit(wine_ios_exit_code);' in section
assert 'wine_process_thread, (void *)(intptr_t)pair[1]' in bridge
path_builder = bridge.split('        char exe_path[1024];', 1)[1].split('// Optional MADEIRA_ARGS', 1)[0]
path_builder = 'char exe_path[1024];' + path_builder
directory_helper = bridge[bridge.index('static int madeira_set_launch_directory('):]
directory_helper = directory_helper.split('\nstatic void *wine_process_thread(', 1)[0]
assert 'madeira_prepare_launch_directory(exe_path, g_prefix_path)' in bridge
assert 'launch refused' in bridge
assert 'extra_argv[i]);' not in section  # argument values must not enter default logs

# Known outputs, including quoted desktop paths and arguments previously lost
# beyond the native bridge's undocumented 16-token / 1023-byte cutoffs.
cases = [
    ('', []), (' \t  ', []), ('-dx11 -windowed', ['-dx11', '-windowed']),
    ('"" ""', ['', '']), ('one\ttwo', ['one', 'two']),
    ('/F "C:\\Data Folder\\База" /N "Иван Иванов"',
     ['/F', 'C:\\Data Folder\\База', '/N', 'Иван Иванов']),
    ('/S "server\\base"', ['/S', 'server\\base']),
    ('--background "C:\\My Project\\scene.blend" --factory-startup',
     ['--background', 'C:\\My Project\\scene.blend', '--factory-startup']),
    ('-name="a b" tail', ['-name=a b', 'tail']),
    ('"a""b"', ['a"b']), ('"unfinished argument', ['unfinished argument']),
    ("'a b' ^ & %PATH%", ["'a", "b'", '^', '&', '%PATH%']),
    (r'"C:\Data Folder\\"', ['C:\\Data Folder\\']),
    ('x' * 2048, ['x' * 2048]), ('x' * 4095, ['x' * 4095]),
    ('x' * 4096, None), ('я' * 2048, None),
    (' '.join('arg%d' % i for i in range(64)), ['arg%d' % i for i in range(64)]),
    (' '.join('arg%d' % i for i in range(65)), None),
    (' '.join(['""'] * 64), [''] * 64),
    ('/desktop=madeira,1280x720 C:\\windows\\system32\\cmd.exe /c call C:\\i.cmd & C:\\windows\\system32\\dockhost.exe',
     ['/desktop=madeira,1280x720', 'C:\\windows\\system32\\cmd.exe', '/c', 'call', 'C:\\i.cmd', '&', 'C:\\windows\\system32\\dockhost.exe']),
]

# Deterministic property checks against an encoder maintained independently of
# Madeira. Covers adjacent quotes, backslashes before closing quotes, tabs,
# empty arguments, multibyte text and supplementary-plane Unicode.
rng = random.Random(73792)
alphabet = 'abAZ09 \\t\\\\"/:-_^&я中😀'.replace('\\t', '\t')
for _ in range(2500):
    args = [''.join(rng.choice(alphabet) for _ in range(rng.randrange(30)))
            for _ in range(rng.randrange(20))]
    command = subprocess.list2cmdline(args)
    cases.append((command, args))

harness = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include "WineLaunchArguments.h"

/* Match Darwin's smaller PATH_MAX even on a Linux test host. No real cwd or
 * environment is changed: record the exact native calls around the helpers. */
#undef PATH_MAX
#define PATH_MAX 1024
static int chdir_calls, chdir_result;
static const char *launch_workdir;
static char captured_cwd[8192], captured_pwd[8192], captured_windows_cwd[8192];
static int escape_directory;
static char *test_realpath(const char *path, char *output) {
    if (strlen(path) >= PATH_MAX) { errno = ENAMETOOLONG; return NULL; }
    if (escape_directory && strstr(path, "/drive_c/")) strcpy(output, "/elsewhere");
    else strcpy(output, path);
    size_t n = strlen(output);
    if (n && output[n - 1] == '/') output[n - 1] = 0;
    return output;
}
static int test_chdir(const char *path) {
    chdir_calls++;
    strcpy(captured_cwd, path);
    if (chdir_result) errno = ENOENT;
    return chdir_result;
}
static int test_setenv(const char *key, const char *value, int overwrite) {
    (void)overwrite;
    if (!strcmp(key, "PWD")) strcpy(captured_pwd, value);
    else if (!strcmp(key, "MADEIRA_INITIAL_CWD")) strcpy(captured_windows_cwd, value);
    else assert(0);
    return 0;
}
static int test_unsetenv(const char *key) {
    if (!strcmp(key, "MADEIRA_INITIAL_CWD")) captured_windows_cwd[0] = 0;
    else if (!strcmp(key, "MADEIRA_WORKDIR")) launch_workdir = NULL;
    else assert(0);
    return 0;
}
static char *test_getenv(const char *key) {
    assert(!strcmp(key, "MADEIRA_WORKDIR"));
    return (char *)launch_workdir;
}
static int madeira_resolve_launch_directory(const char *prefix, const char *relative, char *resolved) {
    char root[PATH_MAX], source[PATH_MAX + 1024 + 16], base[PATH_MAX + 16];
    int n = snprintf(base, sizeof(base), "%s/drive_c", prefix);
    if (n < 0 || n >= (int)sizeof(base)) { errno = ENAMETOOLONG; return -1; }
    if (!test_realpath(base, root)) return -1;
    n = snprintf(source, sizeof(source), "%s/drive_c/%s", prefix, relative);
    if (n < 0 || n >= (int)sizeof(source)) { errno = ENAMETOOLONG; return -1; }
    if (!test_realpath(source, resolved)) return -1;
    size_t size = strlen(root);
    if (strncmp(root, resolved, size) || (resolved[size] && resolved[size] != '/')) { errno = EACCES; return -1; }
    return 0;
}
#define realpath test_realpath
#define chdir test_chdir
#define setenv test_setenv
#define unsetenv test_unsetenv
#define getenv test_getenv
DIRECTORY_HELPER
static int select_directory(const char *madeira_exe, const char *g_prefix_path) {
    return madeira_prepare_launch_directory(madeira_exe, g_prefix_path);
}
#undef realpath
#undef chdir
#undef setenv
#undef unsetenv
#undef getenv

static void reset_directory_test(void) {
    chdir_calls = chdir_result = escape_directory = 0;
    launch_workdir = NULL;
    captured_cwd[0] = 0;
    strcpy(captured_pwd, "/old/cwd");
    strcpy(captured_windows_cwd, "C:\\stale\\");
}
static void check_directories(void) {
    reset_directory_test();
    select_directory("C:\\Data Folder\\app.exe", "/prefix");
    assert(chdir_calls == 1 && !strcmp(captured_cwd, "/prefix/drive_c/Data Folder"));
    assert(!strcmp(captured_pwd, captured_cwd) && !strcmp(captured_windows_cwd, "C:\\Data Folder\\"));

    reset_directory_test();
    launch_workdir = "C:\\Working Folder";
    select_directory("C:\\Game\\app.exe", "/prefix");
    assert(chdir_calls == 1 && launch_workdir == NULL);
    assert(!strcmp(captured_pwd, "/prefix/drive_c/Working Folder"));
    assert(!strcmp(captured_windows_cwd, "C:\\Working Folder\\"));

    reset_directory_test();
    chdir_result = -1;
    launch_workdir = "C:\\Missing";
    select_directory("C:\\Game\\app.exe", "/prefix");
    assert(chdir_calls == 1 && errno == ENOENT);
    assert(!strcmp(captured_pwd, "/old/cwd") && !captured_windows_cwd[0]);

    reset_directory_test();
    chdir_result = -1;
    select_directory("C:\\Missing\\app.exe", "/prefix");
    assert(chdir_calls == 1 && errno == ENOENT);
    assert(!strcmp(captured_pwd, "/old/cwd") && !captured_windows_cwd[0]);

    /* Bare names and non-C paths must not reuse a previous launch override or
     * reinterpret a different drive / short relative path as drive_c. */
    const char *other_paths[] = {"app.exe", "D:\\Data\\app.exe", "\\", "C:", NULL};
    for (int i = 0; other_paths[i]; i++) {
        reset_directory_test();
        select_directory(other_paths[i], "/prefix");
        assert(chdir_calls == 0 && !captured_windows_cwd[0]);
    }

    reset_directory_test();
    assert(select_directory("C:\\app.exe", "/prefix") == 0);
    assert(chdir_calls == 1 && !strcmp(captured_pwd, "/prefix/drive_c"));
    assert(!strcmp(captured_windows_cwd, "C:\\"));

    reset_directory_test();
    assert(select_directory("C:/Data Folder/app.exe", "/prefix") == 0);
    assert(!strcmp(captured_pwd, "/prefix/drive_c/Data Folder"));
    assert(!strcmp(captured_windows_cwd, "C:\\Data Folder\\"));

    reset_directory_test();
    launch_workdir = "c:/Working Folder/База/";
    assert(select_directory("C:\\app.exe", "/prefix") == 0);
    assert(!strcmp(captured_windows_cwd, "C:\\Working Folder\\База\\"));

    reset_directory_test();
    launch_workdir = "C:\\";
    assert(select_directory("C:\\Game\\app.exe", "/prefix") == 0);
    assert(!strcmp(captured_pwd, "/prefix/drive_c") && !strcmp(captured_windows_cwd, "C:\\"));

    const char *invalid[] = {"D:\\Folder", "C:relative", "C:\\..\\escape", "C:\\Bad.\\name", "C:\\bad*", NULL};
    for (int i = 0; invalid[i]; i++) {
        reset_directory_test(); launch_workdir = invalid[i];
        assert(select_directory("C:\\Game\\app.exe", "/prefix") == -1);
        assert(errno == EINVAL && !chdir_calls && !captured_windows_cwd[0] && launch_workdir == NULL);
    }
    reset_directory_test(); escape_directory = 1;
    launch_workdir = "C:\\EscapeLink";
    assert(select_directory("C:\\Game\\app.exe", "/prefix") == -1);
    assert(errno == EACCES && !chdir_calls && !captured_windows_cwd[0]);

    char prefix[1024], path[1024];
    memset(prefix, 'p', 1023); prefix[1023] = 0;
    memset(path, 'a', 1023); memcpy(path, "C:\\", 3); path[1019] = '\\'; path[1023] = 0;
    reset_directory_test();
    assert(select_directory(path, prefix) == -1);
    assert(errno == ENAMETOOLONG && !chdir_calls);

    /* Oversized composed paths are refused before chdir or environment writes. */
    char too_long[4096]; memset(too_long, 'x', sizeof(too_long) - 1); too_long[4095] = 0;
    reset_directory_test();
    assert(madeira_set_launch_directory(too_long, "folder", "C:\\folder\\") == -1);
    assert(errno == ENAMETOOLONG && chdir_calls == 0);
    assert(!strcmp(captured_pwd, "/old/cwd") && !strcmp(captured_windows_cwd, "C:\\stale\\"));
}

static int build_path(const char *madeira_exe, int is_i386_target, char *out) {
    PATH_BUILDER
    if (exe_path_length < 0 || exe_path_length >= (int)sizeof(exe_path)) return 0;
    strcpy(out, exe_path);
    return 1;
}
int main(void) {
    check_directories();
    char path[2048], output[1024];
    assert(build_path("test.exe", 0, output) && !strcmp(output, "C:\\windows\\system32\\test.exe"));
    assert(build_path("test.exe", 1, output) && !strcmp(output, "C:\\windows\\syswow64\\test.exe"));
    memset(path, 'x', sizeof path); memcpy(path, "C:\\", 3); path[1023] = 0;
    assert(build_path(path, 0, output) && !strcmp(path, output));
    assert(!build_path(path + 3, 0, output)); /* prefix would overflow: no truncation */
    path[1023] = 'x'; path[1024] = 0;
    assert(!build_path(path, 0, output)); /* full paths cannot overflow either */
    uint32_t length;
    while (fread(&length, sizeof length, 1, stdin) == 1) {
        char input[8193];
        struct { uint32_t before; char data[MADEIRA_LAUNCH_ARGS_BYTES]; uint32_t after; } storage;
        struct { uintptr_t before; char *data[MADEIRA_LAUNCH_ARGS_COUNT + 1]; uintptr_t after; } args;
        storage.before = storage.after = 0x1234abcd;
        args.before = args.after = 0x5678abcd;
        assert(length < sizeof input);
        assert(fread(input, 1, length, stdin) == length);
        input[length] = 0;
        int32_t count = madeira_parse_launch_arguments(input, storage.data, args.data);
        assert(storage.before == 0x1234abcd && storage.after == 0x1234abcd);
        assert(args.before == 0x5678abcd && args.after == 0x5678abcd);
        assert(args.data[count < 0 ? 0 : count] == NULL);
        assert(fwrite(&count, sizeof count, 1, stdout) == 1);
        for (int i = 0; i < count; i++) {
            uint32_t bytes = (uint32_t)strlen(args.data[i]);
            assert(fwrite(&bytes, sizeof bytes, 1, stdout) == 1);
            assert(fwrite(args.data[i], 1, bytes, stdout) == bytes);
        }
    }
    char storage[MADEIRA_LAUNCH_ARGS_BYTES], *argv[MADEIRA_LAUNCH_ARGS_COUNT + 1];
    assert(madeira_parse_launch_arguments(NULL, storage, argv) == 0 && argv[0] == NULL);
    return ferror(stdin) ? 1 : 0;
}
'''.replace('PATH_BUILDER', path_builder).replace('DIRECTORY_HELPER', directory_helper)

with tempfile.TemporaryDirectory(prefix='madeira-launch-arguments-') as tmp:
    tmp = Path(tmp)
    c, exe = tmp / 'check.c', tmp / 'check'
    c.write_text(harness)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-O1', '-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-I' + str(ROOT / 'app/Madeira'), str(c), '-o', str(exe)], check=True)
    inputs = b''.join(struct.pack('=I', len(command.encode())) + command.encode() for command, _ in cases)
    result = subprocess.run([str(exe)], input=inputs, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    data, offset = result.stdout, 0
    for command, expected in cases:
        count, = struct.unpack_from('=i', data, offset)
        offset += 4
        if expected is None:
            assert count == -1, ('must reject over-limit command', len(command.encode()), count)
            continue
        actual = []
        for _ in range(count):
            length, = struct.unpack_from('=I', data, offset)
            offset += 4
            actual.append(data[offset:offset + length].decode())
            offset += length
        assert actual == expected, (command, actual, expected)
    assert offset == len(data), 'unexpected parser output'

print(f'PASS: {len(cases)} production-parser cases, path/cwd bounds and failure handling, ASan/UBSan and bridge wiring')
