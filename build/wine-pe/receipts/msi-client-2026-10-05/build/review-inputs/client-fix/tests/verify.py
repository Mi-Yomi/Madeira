#!/usr/bin/env python3
"""Verify narrow source change and preservation of every sealed provider file.

LGPL-2.1-or-later. Run from anywhere; this writes only local review reports.
"""
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
from run_portable import extract


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    root = Path(__file__).resolve().parent.parent
    provider = root.parent/'madeira-msi-patched-provider-build-20261005'
    before = json.loads((root/'reports/sealed-workspace-before.json').read_text())
    after = {}
    for path in sorted(provider.rglob('*')):
        if path.is_symlink(): after[str(path.relative_to(provider))] = {'link':str(path.readlink())}
        elif path.is_file(): after[str(path.relative_to(provider))] = {'sha256':sha(path), 'size':path.stat().st_size}
    changed = [k for k in before.keys() | after.keys() if before.get(k) != after.get(k)]
    baseline = (root/'baseline/custom.c').read_text()
    patched = (root/'custom.c').read_text()
    baseline_fn, patched_fn = (extract(code, 'custom_client_thread') for code in (baseline, patched))
    narrow = baseline.replace(baseline_fn, '<CLIENT>\n', 1) == patched.replace(patched_fn, '<CLIENT>\n', 1)
    baseline_ok = sha(root/'baseline/custom.c') == '31c63ede3acf225cfe4d9d772a00b752e82410ebcb060f58f0bfbc9f9e2ea0c5'
    sealed_copy_ok = sha(provider/'wine/dlls/msi/custom.c') == sha(root/'baseline/custom.c')
    record = {'sealed_workspace':str(provider), 'before_file_or_link_count':len(before),
              'after_file_or_link_count':len(after), 'changed_paths':changed,
              'all_regular_files_and_links_preserved':not changed,
              'baseline_matches_requested_compiled_source':baseline_ok,
              'sealed_custom_matches_baseline':sealed_copy_ok,
              'only_custom_client_thread_changed':narrow,
              'candidate_sha256':sha(root/'custom.c')}
    (root/'reports/preservation.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))
    return 0 if not changed and narrow and baseline_ok and sealed_copy_ok else 1

if __name__ == '__main__':
    raise SystemExit(main())
