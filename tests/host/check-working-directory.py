#!/usr/bin/env python3
"""Compile C and Swift working-folder rules and exercise real prefix/symlink checks.

--c-only runs the native suite on a host without swiftc. No guest software runs.
"""
from pathlib import Path
import argparse
import json
import os
import random
import shlex
import struct
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--c-only', action='store_true')
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
bridge = (root / 'app/Madeira/WineProcessBridge.m').read_text()
lib = (root / 'app/Madeira/Library.swift').read_text()
cf_helper = bridge[bridge.index('static int madeira_working_names_equal('):bridge.index('static int madeira_path_is_within(')]
helper = bridge[bridge.index('static int madeira_path_is_within('):bridge.index('\nstatic void *wine_process_thread(')]


def block(text, key):
    start = text.index(key)
    end = text.index('\n}', start) + 2
    return text[start:end]


cases = [('C:\\', 'C:\\'), ('c:/', 'C:\\'), ('C:/My Project/База/', 'C:\\My Project\\База'),
         ('C:\\\\one//two\\', 'C:\\one\\two'), ('C:\\foo..bar', 'C:\\foo..bar')]
for path in ['', 'C:', 'C:relative', 'D:\\Data', '\\\\server\\share', '/absolute',
             'C:\\..\\escape', 'C:\\.\\folder', 'C:\\foo.\\bar', 'C:\\space \\bar',
             'C:\\star*', 'C:\\nul\0tail', 'C:\\tab\tname', 'C:\\a:b', 'C:\\"quote"',
             'C:\\' + 'x' * 1021, 'C:\\' + 'я' * 511]:
    cases.append((path, None))
cases.extend([('C:\\' + 'x' * 1020, 'C:\\' + 'x' * 1020),
              ('C:\\' + 'я' * 510, 'C:\\' + 'я' * 510)])
cases.extend([('C:\\́folder', 'C:\\́folder'),
              ('C:\\outer\\́folder', 'C:\\outer\\́folder'),
              ('C:/́folder/', 'C:\\́folder')])
rng = random.Random(73792)
for _ in range(1000):
    parts = [''.join(rng.choice('a09 Я中😀') for _ in range(rng.randrange(1, 30))).rstrip(' ') + 'z'
             for _ in range(rng.randrange(8))]
    cases.append(('c:/' + '//'.join(parts) + '/', 'C:\\' + '\\'.join(parts)))

c = r'''
#define _XOPEN_SOURCE 700
#include <assert.h>
#include <dirent.h>
#include <sys/stat.h>
#include <strings.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "WineLaunchArguments.h"
#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
CF_HELPER
#else
/* Linux checks traversal with ASCII case comparison; macOS compiles the
 * production CoreFoundation Unicode comparator below. */
static int madeira_working_names_equal(const char *a, const char *b) { return !strcasecmp(a, b); }
#endif
HELPER
int main(int argc, char **argv) {
#if defined(__APPLE__)
    assert(madeira_working_names_equal("My Project", "my PROJECT"));
    assert(madeira_working_names_equal("База", "бАЗА"));
    assert(madeira_working_names_equal("Δοκιμή", "δοκιμή"));
    assert(!madeira_working_names_equal("База", "Другая база"));
    assert(!madeira_working_names_equal("Project", "Project two"));
#endif
    /* Keep the production argument parser checked by the compiler as well. */
    char storage[4096], *unused[65];
    assert(madeira_parse_launch_arguments(NULL, storage, unused) == 0);
    if (argc == 4) {
        if (strcmp(argv[3], "DEFAULT")) setenv("MADEIRA_WORKDIR", argv[3], 1);
        else unsetenv("MADEIRA_WORKDIR");
        setenv("MADEIRA_INITIAL_CWD", "stale", 1);
        int status = madeira_prepare_launch_directory("C:\\app.exe", argv[2]);
        char cwd[PATH_MAX]; assert(getcwd(cwd, sizeof cwd));
        printf("%d\n%s\n%s\n%s\n", status, cwd,
               getenv("MADEIRA_INITIAL_CWD") ? getenv("MADEIRA_INITIAL_CWD") : "UNSET",
               getenv("MADEIRA_WORKDIR") ? "STALE" : "CLEARED");
        return 0;
    }
    uint32_t size;
    while (fread(&size, 4, 1, stdin) == 1) {
        char input[8192], output[1024];
        assert(size < sizeof(input)); assert(fread(input, 1, size, stdin) == size); input[size] = 0;
        /* Environment strings cannot contain embedded NUL; reject malformed test transport. */
        int32_t status = memchr(input, 0, size) ? -1 : madeira_normalize_working_directory(input, output);
        uint32_t length = status ? 0 : (uint32_t)strlen(output);
        assert(fwrite(&status, 4, 1, stdout) == 1 && fwrite(&length, 4, 1, stdout) == 1);
        assert(fwrite(output, 1, length, stdout) == length);
    }
    return 0;
}
'''.replace('CF_HELPER', cf_helper).replace('HELPER', helper)

with tempfile.TemporaryDirectory(prefix='madeira-working-directory-') as temp:
    temp = Path(temp)
    source, executable = temp / 'check.c', temp / 'check'
    source.write_text(c)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-I' + str(root / 'app/Madeira'), str(source), '-o', str(executable)] +
                   shlex.split(os.environ.get('CFLAGS', '')) +
                   (['-framework', 'CoreFoundation'] if os.uname().sysname == 'Darwin' else []), check=True)
    payload = b''.join(struct.pack('=I', len(path.encode())) + path.encode() for path, _ in cases)
    out = subprocess.run([str(executable)], input=payload, capture_output=True, check=True).stdout
    cursor = 0
    for path, expected in cases:
        status, length = struct.unpack_from('=iI', out, cursor); cursor += 8
        actual = out[cursor:cursor + length].decode() if status == 0 else None; cursor += length
        assert actual == expected, (path, actual, expected)
    assert cursor == len(out)

    prefix = temp / 'prefix'; drive = prefix / 'drive_c'; drive.mkdir(parents=True)
    project = drive / 'My Project' / 'База'; project.mkdir(parents=True)
    (drive / 'plain.txt').write_text('not a directory')
    combined = drive / '́folder'; combined.mkdir()
    outside = prefix / 'drive_c-other'; outside.mkdir()
    (drive / 'outside').symlink_to(outside, target_is_directory=True)
    (drive / 'inside').symlink_to(project, target_is_directory=True)
    (drive / 'root-link').symlink_to(drive, target_is_directory=True)
    filesystem = [('DEFAULT', drive, 'C:\\'), ('C:\\', drive, 'C:\\'),
                  ('c:/My Project/База/', project, 'C:\\My Project\\База\\'),
                  ('C:\\inside', project, 'C:\\inside\\'),
                  ('C:\\root-link', drive, 'C:\\root-link\\'),
                  ('C:\\my project\\База', project, 'C:\\my project\\База\\'),
                  ('C:\\́folder', combined, 'C:\\́folder\\')]
    if os.uname().sysname == 'Darwin':
        filesystem.append(('C:\\MY PROJECT\\бАЗА', project, 'C:\\MY PROJECT\\бАЗА\\'))
    rejected = ['C:\\missing', 'C:\\plain.txt', 'C:\\outside', 'D:\\Data', 'C:\\..\\drive_c-other']
    (drive / 'Alpha').mkdir()
    try:
        (drive / 'ALPHA').mkdir()
        rejected.append('C:\\alpha')
    except FileExistsError:
        pass  # macOS runner volume may itself be case-insensitive
    for path, expected_cwd, expected_windows in filesystem:
        lines = subprocess.run([str(executable), 'cwd', str(prefix), path], capture_output=True, text=True, check=True).stdout.splitlines()
        assert lines == ['0', str(expected_cwd.resolve()), expected_windows, 'CLEARED'], (path, lines)
    for path in rejected:
        lines = subprocess.run([str(executable), 'cwd', str(prefix), path], capture_output=True, text=True, check=True).stdout.splitlines()
        assert lines[0] == '-1' and lines[2:] == ['UNSET', 'CLEARED'], (path, lines)
    print(f'PASS: {len(cases)} compiled C working-folder cases and {len(filesystem) + len(rejected)} real filesystem/default/symlink cases', flush=True)
    if args.c_only:
        print('SKIP: compiled Swift parity (--c-only)')
    else:
        swift_helper = block(lib, 'enum LibraryWorkingDirectory {')
        start = lib.index('    static func validateWorkingDirectory(')
        finish = lib.index('\n    }', start) + len('\n    }')
        swift_filesystem = lib[start:finish]
        assert 'url.path.utf8.starts(with: (root.path + "/").utf8)' in swift_filesystem
        assert 'url.path.hasPrefix' not in swift_filesystem
        swift = '''import Foundation
        enum LibraryError: Error { case message(String) }
        HELPER
        struct LibraryModel {
            static var drive = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
            FILESYSTEM
        }
        struct Fixture: Decodable { let input: String; let expected: String? }
        let fixtures = try JSONDecoder().decode([Fixture].self, from: FileHandle.standardInput.readDataToEndOfFile())
        for fixture in fixtures {
            let actual = try? LibraryWorkingDirectory.canonical(fixture.input)
            precondition(actual == fixture.expected, "canonical mismatch: \\(fixture.input)")
        }
        for value in ["C:\\\\", "C:\\\\inside", "C:\\\\root-link", "c:/My Project/База/", "c:/my project/база/", "C:/́folder/"] {
            do { try LibraryModel.validateWorkingDirectory(value) }
            catch { fatalError("working-folder fixture \\(value.debugDescription) failed: \\(error)") }
        }
        try LibraryModel.validateWorkingDirectory(nil)
        for value in ["C:\\\\outside", "C:\\\\missing", "C:\\\\plain.txt", "C:\\\\..\\\\drive_c-other"] {
            do { try LibraryModel.validateWorkingDirectory(value); fatalError("accepted invalid folder") }
            catch { }
        }
        print("PASS: \\(fixtures.count) compiled Swift working-folder parity cases and filesystem confinement")
        '''.replace('HELPER', swift_helper).replace('FILESYSTEM', swift_filesystem)
        swift_path, swift_exe = temp / 'main.swift', temp / 'swift-check'
        swift_path.write_text(swift)
        subprocess.run([os.environ.get('SWIFTC', 'swiftc'), str(swift_path), '-o', str(swift_exe)], check=True)
        subprocess.run([str(swift_exe), str(drive)], input=json.dumps([{'input': p, 'expected': e} for p, e in cases], ensure_ascii=False).encode(), check=True)
