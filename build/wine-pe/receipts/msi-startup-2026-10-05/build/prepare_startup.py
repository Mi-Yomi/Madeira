#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Materialize a compact receipt's exact sources and host prerequisites offline."""
from pathlib import Path
import argparse, hashlib, json, shutil, subprocess, tarfile
HERE=Path(__file__).resolve().parent

def identity(path):
    data=path.read_bytes()
    return {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--downloads',required=True,type=Path,help='Directory containing the exact recorded Wine tar.gz and three Debian .deb archives')
    args=parser.parse_args()
    receipt=json.loads((HERE/'evidence/source-inputs.json').read_text())
    pin=receipt['wine_pin'];archive=args.downloads/f'wine-{pin}.tar.gz'
    if identity(archive)!=receipt['archive']:raise ValueError('Wine archive identity mismatch')
    if (HERE/'wine').exists() or (HERE/'prerequisites').exists():raise ValueError('Use a fresh compact receipt copy without working source/build/prerequisite directories')
    (HERE/'wine').mkdir(); seen=set()
    with tarfile.open(archive) as tar:
        prefix='wine-'+pin+'/'
        for member in tar:
            if member.name!=prefix[:-1] and not member.name.startswith(prefix):raise ValueError('Unsafe archive prefix')
            if member.isdir():continue
            name=member.name[len(prefix):]
            if not member.isfile() or name not in receipt['files'] or name in seen:raise ValueError('Unexpected/duplicate archive member')
            entry=receipt['files'][name]
            if member.size>16*1024**2:raise ValueError('Archive member too large')
            data=tar.extractfile(member).read()
            blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            if blob!=entry['pinned_git_blob']:raise ValueError('Pinned Git blob mismatch: '+name)
            if bool(member.mode&0o111)!=(entry['git_mode']=='100755'):raise ValueError('Git mode mismatch: '+name)
            path=HERE/'wine'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(0o755 if entry['git_mode']=='100755' else 0o644);seen.add(name)
    if seen!=set(receipt['files']):raise ValueError('Incomplete source archive')
    patches=dict(receipt['patches'])
    patches['msi-startup-wait.patch']={k:receipt['incremental_patch'][k] for k in ('bytes','sha256')}
    for name in ('msi-combined.patch','msi-client-failure.patch','msi-startup-wait.patch'):
        path=HERE/'patches'/name
        if identity(path)!=patches[name]:raise ValueError('Patch identity mismatch')
        for extra in (['--check'],[]):subprocess.run(['/usr/bin/git','apply',*extra,'--whitespace=error-all',str(path)],cwd=HERE/'wine',check=True)
    for name,entry in receipt['files'].items():
        if identity(HERE/'wine'/name)!={k:entry[k] for k in ('bytes','sha256')}:raise ValueError('Patched source mismatch: '+name)
    downloads=json.loads((HERE/'evidence/prerequisite-downloads.json').read_text())
    prereqs=HERE/'prerequisites';prereqs.mkdir()
    for entry in downloads:
        path=args.downloads/Path(entry['local_path']).name
        if identity(path)!={k:entry[k] for k in ('bytes','sha256')}:raise ValueError('Prerequisite archive mismatch')
        subprocess.run(['/usr/bin/dpkg-deb','--extract',str(path.resolve()),str(prereqs)],check=True)
    expected=json.loads((HERE/'evidence/restored-prerequisites.json').read_text())['files']
    paths={str(p.relative_to(prereqs)) for p in prereqs.rglob('*') if p.is_file() or p.is_symlink()}
    if paths!=set(expected):raise ValueError('Prerequisite file set changed')
    for name,entry in expected.items():
        path=prereqs/name;got={'link':str(path.readlink())} if path.is_symlink() else identity(path)
        if got!=entry:raise ValueError('Prerequisite bytes changed: '+name)
    (HERE/'prerequisite-bin').mkdir(exist_ok=True)
    wrapper=HERE/'prerequisite-bin/bison'
    wrapper.write_text('#!/bin/sh\nexport BISON_PKGDATADIR="'+str(prereqs/'usr/share/bison')+'"\nexec "'+str(prereqs/'usr/bin/bison')+'" "$@"\n');wrapper.chmod(0o755)
    print('Exact patched source and host prerequisites prepared; no provider built or installed')

if __name__=='__main__':main()
