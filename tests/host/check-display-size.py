#!/usr/bin/env python3
"""Compile production session-size parsing on the host, without Wine or UIKit.

C: the full ios_screen_size and winios_screen_size bodies, shared parser,
and real host pthread lock. Swift: GuestDisplay and LibraryEntry.validate,
with inert publication and unrelated profile-field stubs. The INT_MAX cases
check integer representation only; no surfaces, allocations or guests run.
Needs cc and swiftc (CC/SWIFTC overrides). --c-only is an explicit Swift skip.
--root can verify another source tree, including the pre-fix worktree.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
parser.add_argument('--c-only', action='store_true')
args = parser.parse_args()
root = args.root.resolve()
lib = (root / 'app/Madeira/Library.swift').read_text()
display = (root / 'app/Madeira/GuestDisplay.swift').read_text()
native = (root / 'build/win32u-unix/sysparams_ios.c').read_text()
shim = (root / 'app/Madeira/IOSDisplayShim.m').read_text()
content = (root / 'app/Madeira/ContentView.swift').read_text()


def function(source, marker, indent=''):
    start = source.index(marker)
    end = source.index('\n' + indent + '}', start) + len(indent) + 2
    return source[start:end]


# Reachability: normal library and Dock launches validate before publication.
launch = content.split('private func startLibraryEntry(', 1)[1].split('entry.configureLaunch()', 1)[0]
assert 'try entry.validate()' in launch
launch = content.split('try profile?.validate()', 1)[1].split('winios_display_mode_changed(Int32(width)', 1)[0]
assert 'profile?.resolution' in launch

# Independent oracle: whole positive decimal int, preserving ordinary legacy
# whitespace, leading zeroes and +, but never atoi prefix or overflow behavior.
cases = [None, '', ' ', '0', '-1', '+0', '+', 'garbage', '1280junk', '1280 720',
         '0x500', '1e3', '1.5', '--1', '++1', ' + 1 ', '2560', '\t+02560\r\n',
         '1', '2147483646', '2147483647', '2147483648', '4294967297',
         '-4294964736', '9223372036854775807', '9223372036854775808',
         '-9223372036854775808', '-9223372036854775809', '9' * 10000, '２５６０']
for base in (2**31, 2**32, 2**63):
    for delta in range(-17, 18):
        cases += [str(base + delta), str(-base + delta)]


def expected(value, fallback):
    if value is None or not re.fullmatch(r'[ \t\n\r\v\f]*\+?[0-9]+[ \t\n\r\v\f]*', value):
        return fallback
    # Avoid Python's huge-decimal limit; this fixture is necessarily invalid.
    digits = value.strip().lstrip('+').lstrip('0')
    if len(digits) > 10:
        return fallback
    size = int(value)
    return size if 0 < size <= 2147483647 else fallback


failures = []
with tempfile.TemporaryDirectory(prefix='madeira-display-size-') as work:
    work = Path(work)
    state_start = native.index('static int ios_screen_cur_w, ios_screen_cur_h;')
    state_end = native.index('static void ios_screen_size', state_start)
    header = root / 'build/madeira_display_size.h'
    c = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
_Static_assert(INT_MAX == 2147483647, "iOS uses 32-bit int");
static int g_screen_w, g_screen_h;
static pthread_mutex_t g_screen_lock = PTHREAD_MUTEX_INITIALIZER;
'''
    if header.exists():
        c += '#include "madeira_display_size.h"\n'
    c += native[state_start:state_end]
    c += function(native, 'static void ios_screen_size(')
    c += '\n' + function(shim, 'void winios_screen_size(')
    c += r'''
static void env(const char *name, const char *value)
{
    assert((strcmp(value, "<unset>") ? setenv(name, value, 1) : unsetenv(name)) == 0);
}
int main(int argc, char **argv)
{
    int w, h, sw, sh;
    assert(argc == 3);
    env("MADEIRA_SCREEN_W", argv[1]); env("MADEIRA_SCREEN_H", argv[2]);
    ios_screen_size(&w, &h); winios_screen_size(&sw, &sh);
    assert(w == sw && h == sh);
    printf("%d %d\n", w, h);
    /* Native caches its initialized session; shim fallback is read each time. */
    env("MADEIRA_SCREEN_W", "800"); env("MADEIRA_SCREEN_H", "600");
    ios_screen_size(&sw, &sh); assert(sw == w && sh == h);
    winios_screen_size(&sw, &sh); assert(sw == 800 && sh == 600);
    /* Once published, shim uses that current mode instead of its env seed. */
    g_screen_w = 1920; g_screen_h = 1080;
    winios_screen_size(&sw, &sh); assert(sw == 1920 && sh == 1080);
    winios_screen_size(NULL, NULL);
    return 0;
}
'''
    cfile = work / 'test.c'
    cfile.write_text(c)
    binary = work / 'test-c'
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    *shlex.split(os.environ.get('CFLAGS', '')), '-I', str(root / 'build'),
                    str(cfile), '-pthread', '-o', str(binary)], check=True)
    for value in cases:
        for axis in (0, 1):
            values = ['2560', '1440']
            values[axis] = value
            result = subprocess.run([str(binary), *[v if v is not None else '<unset>' for v in values]],
                                    text=True, capture_output=True)
            want = [expected(values[0], 1024), expected(values[1], 768)]
            for label, raw in zip(('W', 'H'), values):
                diagnostic = 'invalid MADEIRA_SCREEN_' + label
                if (diagnostic in result.stderr) != (raw is not None and expected(raw, 0) == 0):
                    failures.append(f'C diagnostic mismatch for axis {label}, input {raw[:40] if raw else raw!r}')
            if result.returncode or result.stdout.strip() != ' '.join(map(str, want)):
                failures.append(f'C dimension {value[:40] if value else value!r}, axis {axis}: '
                                f'expected {want}, exit={result.returncode}, got {result.stdout.strip()}')
    print(f'C: {len(cases) * 2} production native/shim cases; {len(failures)} failure(s)', flush=True)

    if args.c_only:
        print('SKIP: compiled Swift checks (--c-only)', flush=True)
    else:
        compiler = shutil.which(os.environ.get('SWIFTC', 'swiftc'))
        if not compiler:
            raise SystemExit('FAIL: swiftc unavailable; set SWIFTC or explicitly pass --c-only')
        presets = re.search(r'static let presetResolutions = (\[[^\n]+\])', lib)
        assert presets
        profiles = [(value, True, True) for value in json.loads(presets.group(1))]
        profiles += [(value, True, True) for value in ('1728x720', '320x240', '4096x4096', '+800x+600', '0800x0600')]
        # Tuple: value, accepts saved profile, accepts configure's standalone knob.
        profiles += [(value, False, False) for value in (
            '', 'x800x600', '800x600x', '800xx600', '800xgarbagex600',
            '800x9223372036854775808x600', '800x600x700', '0x720', '-800x600',
            '2147483648x720', '800x2147483648', '9223372036854775807x720',
            '800x9223372036854775807', '9223372036854775808x720',
            '800 x600', '800x 600', '800x600junk', '８００x６００')]
        profiles += [(value, False, True) for value in (
            '2147483647x720', '800x2147483647', '2147483647x2147483647',
            '319x240', '320x239', '4097x720', '800X600', ' 800x600\n')]
        validation = function(lib, '    func validate() throws {', '    ')
        swift = r'''
import Foundation
#if canImport(CoreGraphics)
import CoreGraphics
#endif
enum LibraryError: Error { case message(String) }
enum LibraryWorkingDirectory { static func canonical(_ s: String) throws -> String { s } }
struct Profile {
    var resolution: String
    var fpsMode = 1
    var arguments = "", windowsPath = "C:\\program.exe", launchArguments = "", launchWindowsPath = "C:\\program.exe"
    var launchWorkingWindowsPath: String? = nil
    var config: String? = nil
'''+validation+r'''
}
var published: (Int32, Int32) = (0, 0)
func winios_display_mode_changed(_ w: Int32, _ h: Int32) { published = (w, h) }
'''+display+r'''
let fixture = URL(fileURLWithPath: CommandLine.arguments[1])
let cases = try JSONSerialization.jsonObject(with: Data(contentsOf: fixture)) as! [[Any]]
var failures = 0
func expect(_ condition: Bool, _ message: String) {
    if !condition { fputs("FAIL: \(message)\n", stderr); failures += 1 }
}
for row in cases {
    let raw = row[0] as! String, valid = row[1] as! Bool, knob = row[2] as! Bool
    var accepted = true
    do { try Profile(resolution: raw).validate() } catch { accepted = false }
    expect(accepted == valid, "saved profile \(raw.debugDescription) accepted=\(accepted)")
    let got = GuestDisplay.configureSessionDefault(view: CGSize(width: 1280, height: 720), knob: raw)
    var width = 1280, height = 720
    if knob {
        let parts = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().split(separator: "x")
        width = Int(parts[0])!; height = Int(parts[1])!
    }
    expect(got.w == width && got.h == height && got.source == (knob ? "knob" : "view"),
           "session knob \(raw.debugDescription) selected \(got)")
    expect(published.0 == Int32(width) && published.1 == Int32(height), "publication matches selected size")
    expect(String(cString: getenv("MADEIRA_SCREEN_W")) == String(width), "width env matches selected size")
    expect(String(cString: getenv("MADEIRA_SCREEN_H")) == String(height), "height env matches selected size")
}
for raw in [nil, "", "2147483648x720"] as [String?] {
    let got = GuestDisplay.configureSessionDefault(view: CGSize(width: 768, height: 1024), knob: raw)
    expect(got.w == 1152 && got.h == 864 && got.source == "view", "invalid knob preserves view-derived fallback")
}
print("Swift: \(cases.count) profile/session fixtures and tablet fallback; \(failures) failure(s)")
exit(failures == 0 ? 0 : 1)
'''
        (work / 'test.swift').write_text(swift)
        (work / 'cases.json').write_text(json.dumps(profiles))
        subprocess.run([compiler, str(work / 'test.swift'), '-o', str(work / 'test-swift')], check=True)
        result = subprocess.run([str(work / 'test-swift'), str(work / 'cases.json')])
        if result.returncode:
            failures.append(f'Swift production checks exited {result.returncode}')

if failures:
    raise SystemExit('\n'.join(failures[:15]) + f'\nFAIL: {len(failures)} total failures')
print('PASS: integer-safe session dimensions; current presets and profile bounds preserved')
