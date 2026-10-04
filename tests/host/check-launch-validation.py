#!/usr/bin/env python3
"""Check the production launch-profile validator without an Apple SDK.

Compiles LibraryEntry.validate() with a small Foundation-only profile stub.
Fixtures cover the Windows quoting rules used by WineLaunchArguments.h and the
editor's additional requirement for balanced quotes. Python's independent
Windows encoder supplies 2500 deterministic valid command lines.

Needs python3 and swiftc (SWIFTC to override). --source-only explicitly skips
the compiled behavior on hosts without a Swift toolchain.
"""
from pathlib import Path
import argparse
import json
import os
import random
import re
import shutil
import subprocess
import tempfile


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source-only', action='store_true', help='skip compiled Swift validation')
options = parser.parse_args()
root = Path(__file__).resolve().parents[2]
source = (root / 'app/Madeira/Library.swift').read_text()
start = source.index('    func validate() throws {')
end = source.index('\n    }', start) + len('\n    }')
validation = source[start:end].rstrip()
assert validation.endswith('}'), 'cannot isolate LibraryEntry.validate()'
compact = re.sub(r'\s+', '', re.sub(r'//[^\n]*', '', validation))
for contract in [
    'launchArguments.utf8.count<4096',
    'letbytes=Array(launchArguments.utf8)',
    'byte==0x22&&slashes%2==0',
    'quoted&&index+1<bytes.count&&bytes[index+1]==0x22',
    '!quoted,tokens<=64',
]:
    assert contract in compact, 'launch validator contract missing: ' + contract
assert compact.index('launchArguments.utf8.count<4096') < compact.index('Array(launchArguments.utf8)'), (
    'reject an oversized command before allocating the byte scanner')
print('PASS: production validator uses Windows escaped/doubled-quote rules and native bounds', flush=True)
if options.source_only:
    print('SKIP: compiled Swift launch validation (--source-only)')
    raise SystemExit(0)

compiler = shutil.which(os.environ.get('SWIFTC', 'swiftc'))
if not compiler:
    raise SystemExit('FAIL: swiftc not found; set SWIFTC or use --source-only for source checks only')

# The C decoder accepts an unmatched quote through end-of-input; the editor
# deliberately rejects it, as before, to catch mistyped launch paths.
cases = [
    ('', True), (' \t  ', True), ('-dx11 -windowed', True),
    ('"" ""', True), ('one\ttwo', True),
    ('/F "C:\\Data Folder\\База" /N "Иван Иванов"', True),
    ('/S "server\\base"', True),
    ('--background "C:\\My Project\\scene.blend" --factory-startup', True),
    ('-name="a b" tail', True), ('"a""b"', True),
    ('"unfinished argument', False),
    ("'a b' ^ & %PATH%", True),
    (r'"C:\Data Folder\\"', True),
    ('x' * 2048, True), ('x' * 4095, True), ('x' * 4096, False),
    ('я' * 2047 + 'x', True), ('я' * 2048, False),
    (' '.join('arg%d' % i for i in range(64)), True),
    (' '.join('arg%d' % i for i in range(65)), False),
    (' '.join(['""'] * 64), True), ('\t'.join(['""'] * 65), False),
    ('/desktop=madeira,1280x720 C:\\windows\\system32\\cmd.exe /c call C:\\i.cmd & C:\\windows\\system32\\dockhost.exe', True),
    (r'a\"b', True), (r'"a\"b c"', True), (r'"a""b c"', True),
    (r'"C:\Data Folder\"', False), (r'a\\"b', False),
    (r'"a\\" b', True), (r'"a\\\"b c"', True),
    (' '.join([r'a\"b'] * 64), True),
    (' '.join([r'a\"b'] * 65), False),
    (' '.join([r'a\"b'] * 66), False),
    ('"a\t b"' + '\t""' * 63, True),
    ('"a\t b"' + '\t""' * 64, False),
    ('"' + 'x' * 4093 + '"', True),
    ('"' + 'x' * 4094 + '"', False),
    ('contains\0nul', False),
]

rng = random.Random(73792)
alphabet = 'abAZ09 \t\\"/:-_^&я中😀'
for _ in range(2500):
    arguments = [''.join(rng.choice(alphabet) for _ in range(rng.randrange(30)))
                 for _ in range(rng.randrange(20))]
    command = subprocess.list2cmdline(arguments)
    assert len(command.encode()) < 4096 and len(arguments) <= 64
    cases.append((command, True))

harness = r'''
import Foundation

enum LibraryError: Error { case message(String) }
struct LibraryEntry {
    var resolution = "1280x720"
    var fpsMode = 0
    var arguments = ""
    var windowsPath = "C:\\test.exe"
    var launchArguments: String { arguments }
    var launchWindowsPath: String { windowsPath }
    var steamWorkingWindowsPath: String? = nil
    var config: String? = nil

    VALIDATION
}

struct Fixture: Decodable {
    let command: String
    let accepted: Bool
}
let data = FileHandle.standardInput.readDataToEndOfFile()
let fixtures = try JSONDecoder().decode([Fixture].self, from: data)
for (index, fixture) in fixtures.enumerated() {
    var entry = LibraryEntry()
    entry.arguments = fixture.command
    let accepted: Bool
    do { try entry.validate(); accepted = true }
    catch { accepted = false }
    guard accepted == fixture.accepted else {
        fatalError("case \(index): accepted=\(accepted), expected=\(fixture.accepted), command=\(fixture.command.debugDescription)")
    }
}
print("PASS: \(fixtures.count) compiled production launch-validator cases")
'''.replace('VALIDATION', validation)

with tempfile.TemporaryDirectory(prefix='madeira-launch-validation-') as tmp:
    main, executable = Path(tmp) / 'main.swift', Path(tmp) / 'check'
    main.write_text(harness)
    subprocess.run([compiler, str(main), '-o', str(executable)], check=True)
    payload = json.dumps([{'command': command, 'accepted': accepted}
                          for command, accepted in cases], ensure_ascii=False).encode()
    subprocess.run([str(executable)], input=payload, check=True)
