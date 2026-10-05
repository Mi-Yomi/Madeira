#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Bounded, offline source/toolchain receipts and all-or-nothing stage sealing.

No downloads or guest execution. An archive digest is not an extracted-tool
identity: every file/link in the selected installation is compared as well.
Host tools are separately recorded, not claimed to belong to llvm-mingw.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import selectors
import signal
import time
import shutil
import stat
import subprocess
import tarfile

CHUNK = 1024 * 1024
MAX_FILE = 512 * CHUNK
MAX_SOURCE_BYTES = 1024 * CHUNK
MAX_TOOLCHAIN_BYTES = 2048 * CHUNK
MAX_FILES = 30000
RECIPE_INPUTS = (
    'build/madeira_cfg.h', 'build/wine-pe/build_desktop.py',
    'build/wine-pe/build_receipt.py', 'build/wine-pe/symbol_audit.py',
    'build/wine-pe/guest_inventory.py', 'build/wine-pe/desktop-components.json',
    'build/wine-pe/README.md', 'tests/host/check-guest-dll-inventory.py',
    'tests/host/check-desktop-build-receipts.py', 'tests/host/check-desktop-symbol-audit.py',
    'docs/BUILDING.md', 'docs/DESKTOP_OVERLAY_BUILD.md', 'THIRD-PARTY-NOTICES.md',
    'COPYING', 'LICENSE', 'LICENSE-EXCEPTION.md',
)
# Recorded official GitHub release-asset digests; no caller-supplied digest is
# trusted as proof of origin. Support only these reviewed 20260421 host builds.
RELEASES = {
    'llvm-mingw-20260421-ucrt-ubuntu-22.04-x86_64.tar.xz': {
        'bytes': 82139820,
        'sha256': 'f8b8cce779affeab47bcaec6ce6e9e768b166094a366123ef64b2d0b389cc121',
        'asset_id': 401855784,
    },
    'llvm-mingw-20260421-ucrt-macos-universal.tar.xz': {
        'bytes': 121909316,
        'sha256': 'bd85a3975723815cef28dbbd2ca2cb0c926f6b348a12a0453f39f7af273cb3f7',
        'asset_id': 401855787,
    },
}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def hash_stream(stream, size, *, git_blob=False, max_bytes=MAX_FILE):
    if not 0 <= size <= max_bytes:
        raise ValueError('hash input exceeds per-file byte budget')
    digest = hashlib.sha256()
    blob = hashlib.sha1(b'blob ' + str(size).encode() + b'\0') if git_blob else None
    consumed = 0
    while True:
        data = stream.read(min(CHUNK, size - consumed + 1))
        if not data:
            break
        consumed += len(data)
        if consumed > size:
            raise ValueError('hash input grew during read')
        digest.update(data)
        if blob is not None:
            blob.update(data)
    if consumed != size:
        raise ValueError('hash input changed size during read')
    result = {'bytes': consumed, 'sha256': digest.hexdigest()}
    if blob is not None:
        result['git_blob'] = blob.hexdigest()
    return result


def hash_file(path, *, git_blob=False, max_bytes=MAX_FILE):
    path = Path(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f'not a regular hash input: {path}')
    with path.open('rb') as stream:
        result = hash_stream(stream, before.st_size, git_blob=git_blob, max_bytes=max_bytes)
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError(f'hash input changed while reading: {path}')
    return result


def safe_relative(name):
    p = PurePosixPath(name)
    if p.is_absolute() or not p.parts or any(x in ('..', '.') for x in p.parts) or '\\' in name or '\n' in name or '\r' in name:
        raise ValueError(f'unsafe receipt path: {name!r}')
    return p


def verify_toolchain(toolchain, archive):
    """Verify archive bytes and every extracted member without extracting it."""
    if archive is None:
        raise ValueError('--toolchain-archive is required for an actual build')
    archive = Path(archive).absolute()
    expected = RELEASES.get(archive.name)
    if expected is None:
        raise ValueError('toolchain archive is not a reviewed official 20260421 host release')
    digest = hash_file(archive)
    if digest != {k: expected[k] for k in ('bytes', 'sha256')}:
        raise ValueError('toolchain archive differs from the recorded official release digest')
    root = Path(toolchain).resolve().parent
    if Path(toolchain).resolve().name != 'bin':
        raise ValueError('toolchain must name the verified installation bin directory')
    prefix = archive.name.removesuffix('.tar.xz')
    members = {}
    total = 0
    with tarfile.open(archive, 'r|xz') as tar:
        for item in tar:
            parts = safe_relative(item.name).parts
            if parts[0] != prefix:
                raise ValueError('unexpected archive root')
            if len(parts) == 1:
                if not item.isdir():
                    raise ValueError('archive root must be a directory')
                continue
            relative = '/'.join(parts[1:])
            if relative in members or len(members) >= MAX_FILES:
                raise ValueError('duplicate archive member or file-count budget exceeded')
            path = root / relative
            if item.isdir():
                if path.is_symlink() or not path.is_dir():
                    raise ValueError(f'extracted directory differs: {relative}')
                members[relative] = {'type': 'directory'}
            elif item.issym():
                if not path.is_symlink() or os.readlink(path) != item.linkname:
                    raise ValueError(f'extracted symlink differs: {relative}')
                if not path.resolve().is_relative_to(root):
                    raise ValueError(f'toolchain link escapes installation: {relative}')
                members[relative] = {'type': 'symlink', 'target': item.linkname}
            elif item.isfile():
                total += item.size
                if total > MAX_TOOLCHAIN_BYTES or path.is_symlink():
                    raise ValueError('toolchain size budget or regular-file requirement violated')
                archived = hash_stream(tar.extractfile(item), item.size)
                actual = hash_file(path)
                if archived != actual or bool(path.stat().st_mode & 0o111) != bool(item.mode & 0o111):
                    raise ValueError(f'extracted toolchain bytes/mode differ: {relative}')
                members[relative] = {'type': 'file', **actual}
            else:
                raise ValueError(f'unsupported archive member type: {relative}')
    # A substituted extra helper/config/library must not be discovered through
    # the verified toolchain path. Do not follow directory symlinks.
    actual_paths = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            actual_paths.add((Path(directory) / name).relative_to(root).as_posix())
            if len(actual_paths) > MAX_FILES:
                raise ValueError('extracted toolchain file-count budget exceeded')
    if actual_paths != members.keys():
        raise ValueError('extracted toolchain has missing or unrecorded entries')
    return {'archive': str(archive), 'archive_name': archive.name, **digest,
            'official_release': 'https://github.com/mstorsjo/llvm-mingw/releases/tag/20260421',
            'official_asset_api': f'https://api.github.com/repos/mstorsjo/llvm-mingw/releases/assets/{expected["asset_id"]}',
            'download_url': 'https://github.com/mstorsjo/llvm-mingw/releases/download/20260421/' + archive.name,
            'verification': 'pinned official archive digest and all extracted files/links matched',
            'installation': str(root), 'expanded_file_bytes': total, 'members': members}


def bounded_output(argv, *, env=None, cwd=None, timeout=60, max_bytes=8 * CHUNK):
    """Drain both pipes within a shared byte/time budget, before allocation."""
    process = subprocess.Popen([str(a) for a in argv], cwd=cwd, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    output, errors, consumed = bytearray(), bytearray(), 0
    deadline = time.monotonic() + timeout
    completed = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, output)
            selector.register(process.stderr, selectors.EVENT_READ, errors)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("command exceeded time budget")
                for key, _ in selector.select(remaining):
                    data = os.read(key.fd, min(CHUNK, max_bytes - consumed + 1))
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    consumed += len(data)
                    if consumed > max_bytes:
                        raise ValueError("command output exceeds byte budget")
                    key.data.extend(data)
            try:
                status = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                raise ValueError("command exceeded time budget") from exc
            if status:
                raise ValueError(f"command failed ({status}): {argv[0]}: {bytes(errors[-2000:]).decode(errors='replace')}")
        completed = True
        return bytes(output), bytes(errors)
    finally:
        if not completed:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        process.stdout.close()
        process.stderr.close()


def git_output(git, root, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env['GIT_NO_REPLACE_OBJECTS'] = '1'
    return bounded_output([git, '--no-replace-objects', '-C', root, *args], env=env)[0]


def capture_source(root, git, revision):
    """Hash actual source bytes and compare every tracked Wine blob to HEAD."""
    root = Path(root)
    listing = git_output(git, root / 'wine', 'ls-tree', '-rz', '--full-tree', 'HEAD')
    entries = [line for line in listing.split(b'\0') if line]
    if len(entries) > MAX_FILES:
        raise ValueError('Wine source file-count budget exceeded')
    if git_output(git, root / 'wine', 'ls-files', '--others', '-z'):
        raise ValueError('Wine contains untracked/ignored build inputs; use a clean source checkout')
    wine, total = {}, 0
    for line in entries:
        metadata, encoded = line.split(b'\t', 1)
        mode, kind, blob = metadata.decode('ascii').split()
        name = encoded.decode('utf-8')
        safe_relative(name)
        path = root / 'wine' / name
        if kind != 'blob' or mode not in ('100644', '100755') or path.is_symlink():
            raise ValueError(f'unsupported Wine source type: {name}')
        total += path.stat().st_size
        if total > MAX_SOURCE_BYTES:
            raise ValueError('Wine source hashing byte budget exceeded')
        info = hash_file(path, git_blob=True)
        if info['git_blob'] != blob or bool(path.stat().st_mode & 0o111) != (mode == '100755'):
            raise ValueError(f'Wine source differs from pinned Git blob/mode: {name}')
        wine[name] = {'git_mode': mode, **info}
    inputs = {}
    for name in RECIPE_INPUTS:
        path = root / name
        if path.is_symlink():
            raise ValueError(f'rebuild input must not be a symlink: {name}')
        inputs[name] = hash_file(path, max_bytes=16 * CHUNK)
    return {'schema_version': 1,
            'madeira_base_revision': git_output(git, root, 'rev-parse', 'HEAD').decode().strip(),
            'madeira_repository': 'https://github.com/Mi-Yomi/Madeira.git',
            'wine_revision': revision,
            'wine_repository': 'https://github.com/willfaust/wine.git',
            'wine_tree': git_output(git, root / 'wine', 'rev-parse', 'HEAD^{tree}').decode().strip(),
            'wine_tracked_sources_clean': True, 'wine_file_bytes': total,
            'wine_files': wine, 'recipe_inputs': inputs,
            'runtime_tested': False, 'bitwise_reproducibility_established': False}


def capture_inputs(root, stage, source):
    for relative, expected in source['recipe_inputs'].items():
        src, dest = root / relative, stage / 'rebuild-inputs' / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        if hash_file(dest) != expected:
            raise ValueError(f'copied recipe input differs: {relative}')
    write_json(stage / 'source-inputs.json', source)


def write_rebuild(stage, source, toolchain, recipe):
    flags = ' '.join('--arch ' + shlex.quote(x['arch']) for x in recipe['architectures'])
    (stage / 'SOURCE-REBUILD.md').write_text(f'''# Rebuild this uninstalled Wine desktop overlay

Wine commit: `{source['wine_revision']}`; Git tree: `{source['wine_tree']}`.
Madeira base commit: `{source['madeira_base_revision']}`.
`source-inputs.json` contains SHA-256 hashes of every actual Wine source file
and captured build input. Wine blobs/modes were checked against the pinned tree.
`rebuild-inputs/` includes local recipe additions not present at the base commit.
`toolchain-receipt.json` binds all extracted files/links to the official archive.
`provenance.json` separately records host tools; this is not a hermetic host image.

1. Clone {source['madeira_repository']} and check out
   `{source['madeira_base_revision']}`. Initialize only its exact Wine submodule:
   `git submodule update --init wine`. Keep Wine adjacent to `build/`.
2. Verify this package with `sha256sum -c SHA256SUMS` (or a SHA-256 equivalent).
   Copy `rebuild-inputs/.` into the Madeira checkout, preserving relative paths.
   Keep the complete corresponding Wine source at {source['wine_repository']}
   and the exact revision above available when redistributing the binaries.
3. Supply the host compiler, make, bison 3.0+, flex, m4 and shell tools recorded in
   `provenance.json`. Relocated bison needs its matching package data and M4;
   a wrapper's hash alone does not capture those external host dependencies.
4. Obtain `{toolchain['archive_name']}` from {toolchain['download_url']}.
   Its expected SHA-256 is `{toolchain['sha256']}`. Verify before extraction or
   execution. The recipe rechecks both archive and extracted installation.
5. From the fresh Madeira root run, with new output and actual absolute paths:

   python3 build/wine-pe/build_desktop.py --build {flags} --jobs {recipe['jobs']} --toolchain /path/to/llvm-mingw/bin --toolchain-archive /path/to/{toolchain['archive_name']} --output /new/path/desktop-overlay

6. Run `python3 tests/host/check-guest-dll-inventory.py`,
   `python3 tests/host/check-desktop-symbol-audit.py` and
   `python3 tests/host/check-desktop-build-receipts.py`.
   Review provenance, notices, symbol audits and LLVM metadata, including
   unchanged pre-existing full-farm closure gaps. Static audits are not Wine
   loader, implementation, ABI, installer/COM or device tests.

All files other than SHA256SUMS itself are listed in SHA256SUMS. The checksum
index is an integrity record, not a digital signature or an external trust root.
Host/path/time-independent bitwise reproducibility is NOT established; it needs
at least two independently clean matching runs. No app resources, guest runtime,
IPA, installation, signing or publication are part of this recipe.
Keep original license notices, complete corresponding source and rebuild inputs
with any integration; this record does not settle redistribution/relinking duties.
''')


def seal_stage(stage, arches, modules, source, licenses):
    """Missing evidence is fatal even if every compiler command succeeded."""
    required = {'provenance.json', 'source-inputs.json', 'toolchain-receipt.json',
                'SOURCE-REBUILD.md', 'licenses/Madeira-THIRD-PARTY-NOTICES.md'}
    required.update('licenses/' + name for name in licenses.values())
    required.update('rebuild-inputs/' + name for name in source['recipe_inputs'])
    for arch in arches:
        required.update({arch + '-build.log', arch + '-inventory.json', arch + '-symbol-audit.json'})
        required.update(f'{arch}-windows/{m}.dll' for m in modules)
        required.update(f'readobj/{arch}-{m}.txt' for m in modules)
        report = json.loads((stage / (arch + '-symbol-audit.json')).read_text())
        if report.get('architecture') != arch or report.get('passed') is not True or report.get('issues') != [] or set(report.get('modules', {})) != {m + '.dll' for m in modules}:
            raise ValueError(f'incomplete/failed symbol audit for {arch}')
        for name, module in report['modules'].items():
            expected = {key: module.get(key) for key in ('bytes', 'sha256')}
            if module.get('architecture') != arch or hash_file(stage / (arch + '-windows') / name) != expected:
                raise ValueError(f'output differs from audited symbol evidence: {arch}/{name}')
    for relative in required:
        path = stage / relative
        if path.is_symlink() or not path.is_file() or not path.stat().st_size:
            raise ValueError(f'missing/nonregular/empty stage evidence: {relative}')
    for relative, name in licenses.items():
        expected = source['wine_files'][relative]
        if hash_file(stage / 'licenses' / name) != {k: expected[k] for k in ('bytes', 'sha256')}:
            raise ValueError(f'copied Wine license differs: {relative}')
    if hash_file(stage / 'licenses/Madeira-THIRD-PARTY-NOTICES.md') != source['recipe_inputs']['THIRD-PARTY-NOTICES.md']:
        raise ValueError('copied Madeira notice differs')
    for relative, expected in source['recipe_inputs'].items():
        if hash_file(stage / 'rebuild-inputs' / relative) != expected:
            raise ValueError(f'captured build input changed: {relative}')
    lines, total = [], 0
    for path in sorted(stage.rglob('*')):
        if path.is_symlink():
            raise ValueError(f'stage evidence must not contain symlinks: {path}')
        if path.is_dir():
            continue
        relative = path.relative_to(stage).as_posix()
        safe_relative(relative)
        total += path.stat().st_size
        if len(lines) >= MAX_FILES or total > MAX_TOOLCHAIN_BYTES:
            raise ValueError('stage receipt hash budget exceeded')
        lines.append(hash_file(path)['sha256'] + '  ' + relative + '\n')
    (stage / 'SHA256SUMS').write_text(''.join(lines))
