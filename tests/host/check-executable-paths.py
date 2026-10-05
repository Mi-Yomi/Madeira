#!/usr/bin/env python3
"""Compile production executable selection/inspection against disposable files.

Exercises exact Unicode spelling, PE headers, resolved drive roots, and symlink
confinement. No Windows executable is run. Needs swiftc (SWIFTC to override).
"""
from pathlib import Path
import json
import os
import shutil
import struct
import subprocess
import tempfile


root = Path(__file__).resolve().parents[2]
source = (root / 'app/Madeira/Library.swift').read_text()


def function(name):
    start = source.index('    static func ' + name + '(')
    end = source.index('\n    }', start) + len('\n    }')
    return source[start:end]


drive_start = source.index('    static var drive: URL {')
drive = source[drive_start:source.index('\n', drive_start)]
harness = r'''
import Foundation
enum LibraryError: Error { case message(String) }
struct LibraryEntry {
    let title: String
    let relativePath: String
    let bits: Int
    var graphicsAPI: String? = nil
}
struct LibraryModel {
    static var documents = URL(fileURLWithPath: "/", isDirectory: true)
    DRIVE
    FUNCTIONS
}
struct Fixture: Decodable {
    let name: String
    let documents: String
    let operation: String
    let path: String
}
struct Result: Encodable {
    let name: String
    var path: String? = nil
    var relative: String? = nil
    var title: String? = nil
    var bits: Int? = nil
    var error: String? = nil
}
let fixtures = try JSONDecoder().decode([Fixture].self, from: FileHandle.standardInput.readDataToEndOfFile())
var results: [Result] = []
for fixture in fixtures {
    LibraryModel.documents = URL(fileURLWithPath: fixture.documents, isDirectory: true)
    var result = Result(name: fixture.name)
    do {
        if fixture.operation == "executable" {
            result.path = try LibraryModel.executable(fixture.path).path
        } else {
            let entry = try LibraryModel.inspect(URL(fileURLWithPath: fixture.path))
            result.relative = entry.relativePath
            result.title = entry.title
            result.bits = entry.bits
            // Persisted relative paths must resolve back to the inspected file.
            result.path = try LibraryModel.executable(entry.relativePath).path
        }
    } catch LibraryError.message(let message) { result.error = message }
      catch { result.error = "filesystem error" }
    results.append(result)
}
let encoded = try JSONEncoder().encode(results)
FileHandle.standardOutput.write(encoded)
'''.replace('DRIVE', drive).replace('FUNCTIONS', '\n'.join(
    function(name) for name in ['executable', 'inspect', 'apiNames', 'graphicsImports', 'importNames']))

compiler = shutil.which(os.environ.get('SWIFTC', 'swiftc'))
if not compiler:
    raise SystemExit('FAIL: swiftc not found; set SWIFTC to a Swift compiler')


def pe(machine=0x8664):
    data = bytearray(70)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 64)
    data[64:68] = b'PE\0\0'
    struct.pack_into('<H', data, 68, machine)
    return data


def same_result(got, want):
    if got.keys() != want.keys():
        return False
    if 'path' not in want:
        return got == want
    # Foundation may report /var where Python reports /private/var on macOS.
    # Resolve only real absolute filesystem paths; all other fields stay exact.
    if any(got[key] != value for key, value in want.items() if key != 'path'):
        return False
    actual, expected = Path(got['path']), Path(want['path'])
    if not actual.is_absolute() or not expected.is_absolute():
        return False
    try:
        return actual.resolve(strict=True) == expected.resolve(strict=True)
    except (OSError, RuntimeError):
        return False


with tempfile.TemporaryDirectory(prefix='madeira-executable-paths-') as directory:
    temp = Path(directory).resolve()
    main, executable = temp / 'main.swift', temp / 'check'
    main.write_text(harness)
    subprocess.run([compiler, str(main), '-o', str(executable)], check=True)
    documents = temp / 'Documents'
    drive_root = documents / 'wine' / 'drive_c'
    drive_root.mkdir(parents=True)
    fixtures, expected = [], []

    def fixture(name, operation, path, result, docs=documents):
        fixtures.append(dict(name=name, documents=str(docs), operation=operation, path=str(path)))
        expected.append(dict(name=name, **result))

    def accepted(name, relative, machine=0x8664, docs=documents, actual=None):
        target = docs / 'wine' / 'drive_c' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(pe(machine))
        actual = target.resolve() if actual is None else actual
        fixture(name + ': executable', 'executable', relative, dict(path=str(actual)), docs)
        fixture(name + ': inspect', 'inspect', target,
                dict(path=str(actual), relative=str(actual.relative_to((docs / 'wine' / 'drive_c').resolve())),
                     title=target.stem.replace('_', ' '), bits=32 if machine == 0x14c else 64), docs)

    for name, relative, machine in [
        ('plain x86', 'plain_x86.exe', 0x14c),
        ('Cyrillic', 'Программы/1С_Предприятие.exe', 0x8664),
        ('non-BMP', '😀/🧪_app.EXE', 0x8664),
        ('leading combining file', '\u0301app.exe', 0x8664),
        ('leading combining folder', '\u0301folder/app.exe', 0x14c),
        ('nested combining file', 'nested/\u0301app.exe', 0x8664),
        ('decomposed Unicode', 'Cafe\u0301/Re\u0301sume\u0301.exe', 0x8664),
    ]:
        accepted(name, relative, machine)

    # The production drive property resolves aliases before containment checks.
    alias_documents = temp / 'DocumentsAlias'
    alias_documents.symlink_to(documents, target_is_directory=True)
    accepted('document-root symlink', 'via_documents.exe', docs=alias_documents)
    linked_documents = temp / 'LinkedDriveDocuments'
    (linked_documents / 'wine').mkdir(parents=True)
    (linked_documents / 'wine' / 'drive_c').symlink_to(drive_root, target_is_directory=True)
    accepted('drive-root symlink', 'via_drive.exe', docs=linked_documents)

    target = drive_root / 'Программы' / '1С_Предприятие.exe'
    (drive_root / 'inside.exe').symlink_to(target)
    (drive_root / 'inside-folder').symlink_to(target.parent, target_is_directory=True)
    (drive_root / 'root-link').symlink_to(drive_root, target_is_directory=True)
    for relative, title in [('inside.exe', 'inside'),
                            ('inside-folder/1С_Предприятие.exe', '1С Предприятие'),
                            ('root-link/Программы/1С_Предприятие.exe', '1С Предприятие')]:
        fixture(relative + ': executable', 'executable', relative, dict(path=str(target)))
        fixture(relative + ': inspect', 'inspect', drive_root / relative,
                dict(path=str(target), relative='Программы/1С_Предприятие.exe', title=title, bits=64))

    outside = documents / 'wine' / 'drive_c-other'
    outside.mkdir()
    (outside / 'outside.exe').write_bytes(pe())
    (drive_root / 'outside.exe').symlink_to(outside / 'outside.exe')
    (drive_root / 'outside-folder').symlink_to(outside, target_is_directory=True)
    (drive_root / 'dangling.exe').symlink_to(outside / 'missing.exe')
    select_error = 'Choose an executable inside drive_c.'
    inspect_error = 'The executable must be inside drive_c.'
    for relative in ['outside.exe', 'outside-folder/outside.exe', '../drive_c-other/outside.exe']:
        fixture(relative + ': executable', 'executable', relative, dict(error=select_error))
        fixture(relative + ': inspect', 'inspect', drive_root / relative, dict(error=inspect_error))
    fixture('outside absolute: inspect', 'inspect', outside / 'outside.exe', dict(error=inspect_error))
    (drive_root / 'plain.txt').write_bytes(pe())
    for relative in ['', '.', 'missing.exe', 'dangling.exe', 'plain.txt']:
        fixture(relative + ': rejected selection', 'executable', relative, dict(error=select_error))

    # Canonically equivalent names may identify different directories on a
    # normalization-sensitive host. String equality must not join those roots.
    nfd_documents, nfc_documents = temp / 'Cafe\u0301', temp / 'Caf\u00e9'
    (nfd_documents / 'wine' / 'drive_c').mkdir(parents=True)
    try:
        (nfc_documents / 'wine' / 'drive_c').mkdir(parents=True)
    except FileExistsError:
        pass
    if nfd_documents.samefile(nfc_documents):
        print('SKIP: filesystem aliases canonically equivalent root names', flush=True)
    else:
        print(f'CHECK: distinct canonically equivalent filesystem roots on {os.uname().sysname}', flush=True)
        foreign = nfc_documents / 'wine' / 'drive_c' / 'foreign.exe'
        foreign.write_bytes(pe())
        nfd_drive = nfd_documents / 'wine' / 'drive_c'
        (nfd_drive / 'foreign.exe').symlink_to(foreign)
        fixture('distinct equivalent root: executable', 'executable', 'foreign.exe',
                dict(error=select_error), nfd_documents)
        fixture('distinct equivalent root: inspect', 'inspect', foreign,
                dict(error=inspect_error), nfd_documents)
    accepted('decomposed drive ancestor', 'native.exe', docs=nfd_documents)

    malformed = [
        ('short.exe', b'MZ', 'This is not a Windows executable.'),
        ('not-mz.exe', b'XX' + bytes(68), 'This is not a Windows executable.'),
        ('wrong-machine.exe', pe(0xaa64), 'Only x86 and x64 executables are supported.'),
        ('missing-pe.exe', pe()[:64], 'Missing PE header.'),
    ]
    for name, offset in [('small-offset.exe', 63), ('large-offset.exe', 16 * 1024 * 1024)]:
        data = pe()
        struct.pack_into('<I', data, 60, offset)
        malformed.append((name, data, 'Invalid executable header.'))
    for name, data, error in malformed:
        path = drive_root / name
        path.write_bytes(data)
        fixture(name + ': malformed PE', 'inspect', path, dict(error=error))

    output = subprocess.run([str(executable)], input=json.dumps(fixtures, ensure_ascii=False).encode(),
                            capture_output=True, check=True).stdout
    actual = json.loads(output)
    failures = []
    control = dict(path=str(target), relative='Программы/1С_Предприятие.exe',
                   title='1С Предприятие', bits=64)
    controls = [('same file through alias', dict(control, path=str(drive_root / 'inside.exe')), True),
                ('different file', dict(control, path=str(drive_root / 'plain_x86.exe')), False),
                ('different root', dict(control, path=str(outside / 'outside.exe')), False),
                ('missing file', dict(control, path=str(drive_root / 'missing.exe')), False),
                ('relative path', dict(control, path=target.name), False),
                ('changed relative spelling', dict(control, relative='Программы/1C_Предприятие.exe'), False),
                ('changed title', dict(control, title='different'), False),
                ('changed bitness', dict(control, bits=32), False)]
    for name, got, matches in controls:
        if same_result(got, control) != matches:
            failures.append('path comparison control: ' + name)
    if len(actual) != len(expected):
        failures.append(f'result count: {len(actual)} != {len(expected)}')
    for got, want in zip(actual, expected):
        if not same_result(got, want):
            failures.append(f'{want["name"]}:\n  expected {want!r}\n  received {got!r}')
    if failures:
        raise SystemExit('FAIL: ' + '\n'.join(failures))
    print(f'PASS: {len(fixtures)} compiled production executable-path, Unicode, PE and symlink cases')
    print(f'PASS: {len(controls)} strict filesystem-alias and exact-metadata comparison controls')
