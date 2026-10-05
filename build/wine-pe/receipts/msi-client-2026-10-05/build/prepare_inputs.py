#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Copy retained offline inputs independently; never hardlink or write old trees."""
from pathlib import Path
import hashlib, json, os, shutil, subprocess, time

HERE = Path(__file__).resolve().parent
OLD = HERE.parent/'madeira-msi-patched-provider-build-20261005'
FIX = HERE.parent/'madeira-msi-client-fix-20261005'
MIN_FREE = 8 * 1024**3
MAX_NEW = 2 * 1024**3

def digest(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024), b''): h.update(b)
    return {'sha256':h.hexdigest(), 'size':p.stat().st_size}

def snapshot(root):
    return {str(p.relative_to(root)):({'link':str(p.readlink())} if p.is_symlink() else digest(p))
            for p in sorted(root.rglob('*')) if p.is_symlink() or p.is_file()}

def write(path, data):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')

def main():
    free=shutil.disk_usage(HERE).free
    size=sum(p.stat().st_size for p in OLD.rglob('*') if p.is_file() and not p.is_symlink())
    if free<MIN_FREE+800*1024**2: raise ValueError('Insufficient space for independent source plus fresh builds')
    before=snapshot(OLD)
    historical=json.loads((FIX/'reports/sealed-workspace-before.json').read_text())
    if before != historical: raise ValueError('Old sealed workspace differs from prior independently checked snapshot')
    write(HERE/'evidence/old-workspace-before.json', before)
    write(HERE/'evidence/fix-workspace-before.json', snapshot(FIX))
    for name in ('wine','tools','build','licenses','reference-inputs'):
        shutil.copytree(OLD/name,HERE/name,symlinks=True)
    shutil.copytree(FIX,HERE/'review-inputs/client-fix',symlinks=True)
    (HERE/'patches').mkdir()
    shutil.copy2(OLD/'patches/msi-combined.patch',HERE/'patches/msi-combined.patch')
    shutil.copy2(FIX/'msi-client-failure.patch',HERE/'patches/msi-client-failure.patch')
    for arch in ('aarch64','arm64ec','i386'):
        dest=HERE/'preserved-original'/f'{arch}-windows'
        dest.mkdir(parents=True)
        shutil.copy2(OLD/'candidate'/f'{arch}-windows/msi.dll',dest/'msi.dll')
    shutil.copy2(OLD/'SHA256SUMS',HERE/'preserved-original/old-provider-SHA256SUMS')
    shutil.copy2(OLD/'README.md',HERE/'preserved-original/old-provider-README.md')
    shutil.copy2(OLD/'evidence/provenance.json',HERE/'preserved-original/old-provider-provenance.json')
    shutil.copytree(FIX/'licenses',HERE/'licenses/client-fix')
    custom=HERE/'wine/dlls/msi/custom.c'
    if digest(custom)['sha256']!='31c63ede3acf225cfe4d9d772a00b752e82410ebcb060f58f0bfbc9f9e2ea0c5': raise ValueError('Wrong incremental baseline')
    commands=[]
    for extra in (['--check'],[]):
        argv=['/usr/bin/git','apply',*extra,'--whitespace=error-all','../patches/msi-client-failure.patch']
        result=subprocess.run(argv,cwd=HERE/'wine',capture_output=True,text=True,timeout=30)
        commands.append({'argv':argv,'cwd':str(HERE/'wine'),'exit_code':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        result.check_returncode()
    if digest(custom)['sha256']!='9c6db8469d1db7d1fff83af45e4f4851238e3b09fc06055996cfbb956fd6af50': raise ValueError('Wrong final source')
    # Prove no corresponding source path shares a mutable inode with the old tree.
    same=[]
    for p in (HERE/'wine').rglob('*'):
        q=OLD/p.relative_to(HERE)
        if p.is_file() and not p.is_symlink() and os.path.samestat(p.stat(),q.stat()): same.append(str(p))
    if same: raise ValueError('Hardlinked input copies')
    write(HERE/'evidence/preparation.json',{'free_before_bytes':free,'old_workspace_logical_bytes':size,
        'copy_strategy':'independent shutil.copy2 bytes; no hardlinks or copied build intermediates',
        'old_workspace_matches_prior_snapshot':True,'copied_source_shares_no_inodes':True,
        'patch_commands':commands,'final_source':digest(custom),'free_after_bytes':shutil.disk_usage(HERE).free})
    print('Independent source and original-provider snapshots prepared')

if __name__=='__main__': main()
