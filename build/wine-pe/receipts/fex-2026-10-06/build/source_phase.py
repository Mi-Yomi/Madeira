"""Verify all approved FEX edits before allowing a recorded build phase."""
import hashlib
import json
from pathlib import Path
import subprocess

def verify_source_phase(phase):
    w = Path(__file__).resolve().parent
    s = w/'FEX'
    existing = json.loads((w/'evidence/existing-source-repairs.json').read_text())
    added = json.loads((w/'evidence/source-repairs.additions.json').read_text())
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=s, text=True).strip()
    assert revision == existing['source_revision'] == added['source_revision']
    expected_files = {}
    for manifest, state in [(existing, 'patched_sha256'), (added, 'patched_sha256' if phase == 'patched' else 'original_sha256')]:
        for repair in manifest['repairs']:
            for entry in repair['files']:
                actual = hashlib.sha256((s/entry['path']).read_bytes()).hexdigest()
                assert actual == entry[state], (phase, entry['path'], actual, entry[state])
                expected_files[entry['path']] = actual
    expected_dirty = {entry['path'] for repair in existing['repairs'] for entry in repair['files']}
    if phase == 'patched':
        expected_dirty |= {entry['path'] for repair in added['repairs'] for entry in repair['files']}
    dirty = set(subprocess.check_output(['git', 'diff', '--name-only'], cwd=s, text=True).splitlines())
    assert dirty == expected_dirty, (dirty, expected_dirty)
    assert not subprocess.check_output(['git', 'diff', '--cached', '--name-only'], cwd=s)
    return expected_files
