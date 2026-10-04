#!/usr/bin/env python3
"""Check status guidance and that Madeira's default launch logs omit argument/config values.

This does not sanitize guest output or opt-in Wine traces. --source-only skips Swift.
"""
from pathlib import Path
import argparse
import os
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source-only', action='store_true')
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
lib = (root / 'app/Madeira/Library.swift').read_text()
bridge = (root / 'app/Madeira/WineProcessBridge.m').read_text()
front = (root / 'app/Madeira/ContentView.swift').read_text()
launch = bridge.split('// Optional MADEIRA_ARGS', 1)[1].split('// Record this thread', 1)[0]
assert 'launch argument count=%d (values omitted)' in launch
for line in launch.splitlines():
    if 'dprintf(' in line or 'LOG(' in line:
        assert 'extra_argv[' not in line and 'madeira_args' not in line and 'exe_path)' not in line
for line in bridge.splitlines():
    if ('LOG(' in line or 'fprintf(' in line) and ('config env:' in line or 'madeira.cfg env:' in line or '[madeira-env]' in line):
        assert 'v.UTF8String' not in line
        if 'k.UTF8String' in line: assert '<omitted>' in line
assert 'pairs.sorted' not in lib
assert 'pairs.count) setting(s); values omitted' in lib
assert 'cfg.count) setting(s) applied; values omitted' in front
assert 'cfg.map { "\\($0.key)=\\($0.value)" }' not in front
assert 'return LibraryLaunchFailure.message(status)' in lib
print('PASS: default launch/config log privacy wiring and status-message route', flush=True)
if args.source_only:
    print('SKIP: compiled status guidance (--source-only)')
    raise SystemExit(0)
start = lib.index('enum LibraryLaunchFailure {')
end = lib.index('\n}\n', start) + 3
source = 'import Foundation\n' + lib[start:end] + r'''
let fixtures: [(UInt32, String)] = [
 (0xC0000005, "memory access violation"), (0xC0000017, "memory allocation"),
 (0xC000001D, "CPU instruction"), (0xC000003A, "working folder"),
 (0xC000007B, "compatible bitness"), (0xC0000135, "Windows module"),
 (0xC0000139, "Windows function"), (0xC0000142, "initialize"),
 (0xC0150002, "side-by-side"), (0xC1234567, "diagnostic log")]
for (code, text) in fixtures {
 let message = LibraryLaunchFailure.message(code)
 precondition(message.contains(text) && message.contains(String(code, radix: 16, uppercase: true)))
}
print("PASS: \(fixtures.count) compiled production Windows-status diagnostic cases")
'''
with tempfile.TemporaryDirectory(prefix='madeira-launch-diagnostics-') as temp:
    src, exe = Path(temp) / 'main.swift', Path(temp) / 'check'
    src.write_text(source)
    subprocess.run([os.environ.get('SWIFTC', 'swiftc'), str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
