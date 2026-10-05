#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Seal compact deliverables; large source/build evidence stays in its manifests."""
from pathlib import Path
import hashlib, json
HERE=Path(__file__).resolve().parent
EXCLUDED={'wine','build-aarch64','build-arm64ec','build-i386','resolver-overlays','attempts'}
EXCLUDED_FILES={'SHA256SUMS','seal-verification.log','compact-package.tar.gz'}
def main():
    lines=[];total=0
    for p in sorted(HERE.rglob('*')):
        rel=p.relative_to(HERE)
        if rel.parts[0] in EXCLUDED or str(rel) in EXCLUDED_FILES: continue
        if p.is_symlink(): raise ValueError('Unexpected compact-deliverable symlink: '+str(rel))
        if not p.is_file(): continue
        h=hashlib.sha256(p.read_bytes()).hexdigest()
        lines.append(h+'  '+str(rel));total+=p.stat().st_size
    (HERE/'SHA256SUMS').write_text('\n'.join(lines)+'\n')
    print(json.dumps({'sealed_files':len(lines),'sealed_file_bytes':total,
        'seal_sha256':hashlib.sha256((HERE/'SHA256SUMS').read_bytes()).hexdigest()},indent=2))
if __name__=='__main__': main()
