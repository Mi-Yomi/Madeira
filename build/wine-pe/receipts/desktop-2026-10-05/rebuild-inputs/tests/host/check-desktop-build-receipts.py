#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Portable failure injection for build evidence; only local Python/Git, no guest."""
from contextlib import ExitStack
import hashlib
import io
import json
import os
import shutil
import subprocess
from pathlib import Path
import sys
import tarfile
import tempfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'build/wine-pe'))
import build_receipt as receipt
import build_desktop as builder


def rejects(call, message=None):
    try:
        call()
    except (ValueError, OSError) as exc:
        if message is not None:
            assert message in str(exc), (message, str(exc))
        return
    raise AssertionError('invalid input unexpectedly accepted')


class BoundedStream(io.BytesIO):
    def read(self, n=-1):
        assert 0 <= n <= receipt.CHUNK, n
        return super().read(n)


sample = b'x' * (receipt.CHUNK + 71)
assert receipt.hash_stream(BoundedStream(sample), len(sample))['sha256'] == hashlib.sha256(sample).hexdigest()
rejects(lambda: receipt.hash_stream(BoundedStream(b'x'), 1, max_bytes=0), 'budget')
rejects(lambda: receipt.hash_stream(BoundedStream(b'xx'), 1), 'grew')
rejects(lambda: receipt.hash_stream(BoundedStream(b''), 1), 'changed size')
rejects(lambda: receipt.bounded_output([sys.executable, '-c', 'print("x"*200)'], max_bytes=100), 'byte budget')
rejects(lambda: receipt.bounded_output([sys.executable, '-c', 'import sys; sys.stderr.write("x"*200)'], max_bytes=100), 'byte budget')
rejects(lambda: receipt.bounded_output([sys.executable, '-c', 'import time; time.sleep(1)'], timeout=0.02), 'time budget')
print('PASS: streaming hashes and command pipes use byte/time budgets and reject changed/oversized inputs')

with tempfile.TemporaryDirectory(prefix='desktop-receipt-tests-') as temp:
    root = Path(temp)
    tc = root / 'tc'; (tc / 'bin').mkdir(parents=True)
    archive = root / 'fixture.tar.xz'
    (tc / 'bin/clang').write_bytes(b'fixture executable')
    (tc / 'bin/clang').chmod(0o755)
    (tc / 'bin/link').symlink_to('clang')
    with tarfile.open(archive, 'w:xz') as tar:
        tar.add(tc, arcname='fixture')
    expected = {**receipt.hash_file(archive), 'asset_id': 1}
    with mock.patch.dict(receipt.RELEASES, {archive.name: expected}):
        record = receipt.verify_toolchain(tc / 'bin', archive)
        assert record['members']['bin/clang']['sha256'] == receipt.hash_file(tc / 'bin/clang')['sha256']
        (tc / 'bin/extra').write_text('unrecorded tool')
        rejects(lambda: receipt.verify_toolchain(tc / 'bin', archive), 'unrecorded')
        (tc / 'bin/extra').unlink()
        (tc / 'bin/clang').write_text('substituted')
        rejects(lambda: receipt.verify_toolchain(tc / 'bin', archive), 'differ')
        (tc / 'bin/clang').write_bytes(b'fixture executable')
        (tc / 'bin/link').unlink(); (tc / 'bin/link').symlink_to('/usr/bin/true')
        rejects(lambda: receipt.verify_toolchain(tc / 'bin', archive), 'symlink differs')
        (tc / 'bin/link').unlink(); (tc / 'bin/link').symlink_to('clang')
        with mock.patch.object(receipt, 'MAX_TOOLCHAIN_BYTES', 0):
            rejects(lambda: receipt.verify_toolchain(tc / 'bin', archive), 'budget')
        with mock.patch.object(receipt, 'MAX_FILES', 0):
            rejects(lambda: receipt.verify_toolchain(tc / 'bin', archive), 'budget')
        archive.write_bytes(b'wrong archive')
        rejects(lambda: receipt.verify_toolchain(tc / 'bin', archive), 'digest')
    rejects(lambda: receipt.verify_toolchain(tc / 'bin', None), 'required')
    print('PASS: archive receipts reject changed bytes, extracted substitutions/extras, missing archive and exhausted budgets')

    source_root = root / 'source'; (source_root / 'wine').mkdir(parents=True)
    (source_root / 'wine/source.c').write_bytes(b'original source')
    (source_root / 'recipe.py').write_text('recipe')
    blob = receipt.hash_file(source_root / 'wine/source.c', git_blob=True)['git_blob']
    untracked = [b'']
    def fake_git(git, path, *args):
        if args[0] == 'ls-tree':
            return f'100644 blob {blob}\tsource.c\0'.encode()
        if args[0] == 'ls-files':
            return untracked[0]
        return b'0' * 40
    with mock.patch.object(receipt, 'git_output', side_effect=fake_git), mock.patch.object(receipt, 'RECIPE_INPUTS', ('recipe.py',)):
        source = receipt.capture_source(source_root, '/fixture/git', '0' * 40)
        assert source['wine_files']['source.c']['git_blob'] == blob
        (source_root / 'wine/source.c').write_bytes(b'changed source')
        rejects(lambda: receipt.capture_source(source_root, '/fixture/git', '0' * 40), 'pinned Git blob')
        (source_root / 'wine/source.c').write_bytes(b'original source')
        untracked[0] = b'ignored-injected.h\0'
        rejects(lambda: receipt.capture_source(source_root, '/fixture/git', '0' * 40), 'untracked/ignored')
        untracked[0] = b''
        with mock.patch.object(receipt, 'MAX_SOURCE_BYTES', 0):
            rejects(lambda: receipt.capture_source(source_root, '/fixture/git', '0' * 40), 'budget')
        with mock.patch.object(receipt, 'MAX_FILES', 0):
            rejects(lambda: receipt.capture_source(source_root, '/fixture/git', '0' * 40), 'budget')
        (source_root / 'recipe.py').unlink()
        rejects(lambda: receipt.capture_source(source_root, '/fixture/git', '0' * 40))
    print('PASS: source receipts reject missing inputs, changed pinned blobs, ignored injections and exhausted budgets')

    # Replacement objects must not make different source masquerade as the pin.
    git = shutil.which('git')
    if not git:
        raise AssertionError('Git is required for the replacement-ref regression')
    replaced = root / 'git-replacement'; (replaced / 'wine').mkdir(parents=True)
    def git_run(path, *args):
        return subprocess.run([git, '-C', str(path), '-c', 'user.name=Receipt Test',
                               '-c', 'user.email=receipt-test@example.invalid', *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()
    for repository, filename in ((replaced, 'recipe.py'), (replaced / 'wine', 'source.c')):
        git_run(repository, 'init', '-q')
        (repository / filename).write_text('original')
        git_run(repository, 'add', filename)
        git_run(repository, 'commit', '-qm', 'Fixture original')
    original = git_run(replaced / 'wine', 'rev-parse', 'HEAD')
    (replaced / 'wine/source.c').write_text('replacement source')
    git_run(replaced / 'wine', 'commit', '-qam', 'Fixture replacement')
    replacement = git_run(replaced / 'wine', 'rev-parse', 'HEAD')
    git_run(replaced / 'wine', 'replace', original, replacement)
    git_run(replaced / 'wine', 'reset', '--hard', original)
    assert git_run(replaced / 'wine', 'rev-parse', 'HEAD') == original
    assert not git_run(replaced / 'wine', 'status', '--porcelain')
    with mock.patch.object(receipt, 'RECIPE_INPUTS', ('recipe.py',)):
        rejects(lambda: receipt.capture_source(replaced, git, original), 'pinned Git blob')
    with mock.patch.dict(os.environ, {'GIT_DIR': str(replaced / 'wine/.git')}):
        assert receipt.git_output(git, replaced, 'rev-parse', '--show-toplevel').decode().strip() == str(replaced)
    print('PASS: replacement refs and ambient Git overrides cannot bypass exact source identity')

    # Full orchestration with simulated compile/audit, real copy and final seal.
    # The PE/symbol parsers have separate executable-byte tests.
    work = root / 'orchestration'; (work / 'wine').mkdir(parents=True)
    for relative in receipt.RECIPE_INPUTS:
        path = work / relative; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('fixture ' + relative)
    wine_files = {}
    for relative in builder.LICENSE_FILES:
        path = work / 'wine' / relative; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('unchanged upstream notice ' + relative)
        wine_files[relative] = receipt.hash_file(path)
    source = {'wine_revision': '0' * 40, 'wine_tree': '1' * 40, 'madeira_base_revision': '2' * 40,
              'madeira_repository': 'https://example.invalid/Madeira.git', 'wine_repository': 'https://example.invalid/wine.git',
              'wine_files': wine_files, 'recipe_inputs': {n: receipt.hash_file(work / n) for n in receipt.RECIPE_INPUTS}}
    toolchain = {'archive_name': 'fixture.tar.xz', 'sha256': '0' * 64, 'download_url': 'https://example.invalid/fixture'}
    modules = builder.manifest()['profiles']['desktop']
    fault = [None]
    def run(argv, cwd, env, log):
        log.write('fixture compile log\n')
    def outputs(build, dest, arch, modules, strip, env):
        dest.mkdir()
        for module in modules:
            (dest / (module + '.dll')).write_bytes(b'fixture PE; parser tested separately')
    def symbols(root, arch, overlay, readobj, stage, **kwargs):
        if fault[0] == 'audit-error':
            raise ValueError('injected import/export audit error')
        report = {'architecture': arch, 'counts': {}, 'issues': [], 'passed': True, 'input_modules': {}, 'modules': {m + '.dll': {'architecture': arch, **receipt.hash_file(overlay / (m + '.dll'))} for m in modules}}
        if fault[0] == 'audit-issues':
            report['issues'] = ['unresolved symbol']
        receipt.write_json(stage / (arch + '-symbol-audit.json'), report)
        (stage / 'readobj').mkdir(exist_ok=True)
        for module in modules:
            (stage / 'readobj' / (arch + '-' + module + '.txt')).write_text('fixture LLVM evidence')
        return report
    seen_inventories = {}
    def inventory(folder, arch, required, overlay):
        # A fresh temporary overlay identifies this build independently.
        identity = str(overlay)
        seen_inventories[identity] = seen_inventories.get(identity, 0) + 1
        report = {'errors': [], 'missing_required': [], 'missing_dependencies': [], 'modules': {}}
        if fault[0] == 'changed-farm-before-publish' and seen_inventories[identity] > 1:
            report['errors'] = ['farm changed after successful symbol audit']
        return report
    seal = receipt.seal_stage
    def inject(stage, *args):
        if isinstance(fault[0], str) and fault[0].startswith('remove:'):
            (stage / fault[0].split(':', 1)[1]).unlink()
        if fault[0] == 'changed-output':
            (stage / 'aarch64-windows/riched20.dll').write_text('substituted after audit')
        if fault[0] == 'changed-license':
            (stage / 'licenses/Wine-LGPL-2.1.txt').write_text('changed')
        return seal(stage, *args)
    with ExitStack() as stack:
        for target, name, kwargs in (
            (builder, 'build_environment', {'return_value': {'MAKE': '/fixture/make', 'GIT': '/fixture/git'}}),
            (builder, 'validate_source', {'return_value': '0' * 40}),
            (builder, 'validate_tools', {'return_value': {'fixture': True}}),
            (receipt, 'verify_toolchain', {'return_value': toolchain}),
            (receipt, 'capture_source', {'return_value': source}),
            (builder, 'run_logged', {'side_effect': run}),
            (builder, 'stage_outputs', {'side_effect': outputs}),
            (builder, 'audit_farm', {'side_effect': inventory}),
            (builder.symbol_audit, 'audit', {'side_effect': symbols}),
            (receipt, 'seal_stage', {'side_effect': inject}),
        ):
            stack.enter_context(mock.patch.object(target, name, **kwargs))
        dest = root / 'successful-stage'
        result = builder.build(work, ['aarch64', 'arm64ec'], tc / 'bin', 2, dest, archive)
        assert result['staged_only'] and not result['bitwise_reproducibility_established']
        lines = (dest / 'SHA256SUMS').read_text().splitlines()
        expected_files = {p.relative_to(dest).as_posix() for p in dest.rglob('*') if p.is_file()} - {'SHA256SUMS'}
        assert {line.split('  ', 1)[1] for line in lines} == expected_files
        for line in lines:
            digest, relative = line.split('  ', 1)
            assert receipt.hash_file(dest / relative)['sha256'] == digest
        for failure in ('audit-error', 'audit-issues', 'remove:source-inputs.json', 'remove:toolchain-receipt.json',
                        'remove:SOURCE-REBUILD.md', 'remove:aarch64-symbol-audit.json', 'remove:aarch64-inventory.json',
                        'remove:readobj/arm64ec-riched20.txt', 'remove:licenses/Wine-LGPL-2.1.txt',
                        'remove:rebuild-inputs/build/wine-pe/symbol_audit.py', 'changed-license', 'changed-output', 'changed-farm-before-publish'):
            fault[0] = failure
            failed = root / ('failed-' + str(len(list(root.iterdir()))))
            rejects(lambda: builder.build(work, ['aarch64', 'arm64ec'], tc / 'bin', 2, failed, archive))
            assert not failed.exists(), failure
            assert not list(root.glob('.desktop-stage-*')), failure
        fault[0] = None
        rejects(lambda: builder.build(work, ['aarch64'], tc / 'bin', 3, root / 'too-many-jobs', archive), 'bounded')
        rejects(lambda: builder.build(work, ['aarch64'], tc / 'bin', 2, work / 'app/Madeira/new', archive), 'outside app')
        assert not (work / 'app').exists()
    print('PASS: whole-stage publication requires every receipt, audit, LLVM dump, captured input and unchanged license; all checksums verified')

print('PASS: desktop build receipt regressions')
