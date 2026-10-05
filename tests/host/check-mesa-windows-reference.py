#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable negative controls for the source-built Windows reference contract."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'tests/desktop/mesa_wgl'
spec = importlib.util.spec_from_file_location('mesa_reference', SOURCE / 'windows_reference.py')
ref = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ref)
checks = 0


def reject(call, label):
    global checks
    try:
        call()
    except (ValueError, OSError):
        checks += 1
        return
    raise AssertionError('Unsafe input accepted: ' + label)


def transcript(stage):
    rows = [f'CANARY stage={stage} pointer_bits=64']
    rows += [f'PASS stage={s}' for s in ['window', 'gdi-memory', 'gdi-window']]
    if stage != 'gdi':
        rows += [r'MODULE opengl32=C:\sandbox\bundle\opengl32.dll',
                 r'MODULE gallium=C:\sandbox\bundle\libgallium_wgl.dll',
                 'GL renderer=softpipe version=3.3 (Compatibility Profile) Mesa 26.2.4',
                 'LEGACY version=3.3 profile=0x2']
        rows += [f'PASS stage={s}' for s in ['gl-load', 'pixel-format', 'legacy-context']]
        for tag, colors in [('legacy-clear-readback', '64,128,191'),
                            ('legacy-second-readback', '191,64,128')]:
            rows += [f'PIXEL stage={tag} rgba={colors},255 gl_error=0x0', f'PASS stage={tag}']
        for tag, colors in [('legacy-window-readback', '64,128,191'),
                            ('legacy-second-window-readback', '191,64,128')]:
            rows += [f'WINDOW_PIXEL stage={tag} rgb={colors}', f'PASS stage={tag}']
        rows += ['PASS stage=legacy-swap', 'PASS stage=legacy-second-swap']
    if stage == 'core43':
        rows += ['CORE version=4.3 profile=0x1', 'PASS stage=core43-context',
                 'PIXEL stage=core-shader-readback rgba=255,0,0,255 gl_error=0x0',
                 'PASS stage=core-shader-readback', 'PASS stage=core-swap',
                 'WINDOW_PIXEL stage=core-window-readback rgb=255,0,0',
                 'PASS stage=core-window-readback']
    rows += [f'PASS requested-stage={stage}']
    return '\n'.join(rows)


def parse(log, code=0, stage='legacy'):
    return ref.parse_proof(log, code, stage, r'C:\sandbox\bundle')


for stage in ['gdi', 'legacy', 'core43']:
    assert parse(transcript(stage), stage=stage)['status'] == 'passed'
    checks += 1
legacy = transcript('legacy')
for old, new in [
        ('pointer_bits=64', 'pointer_bits=32'),
        ('PASS stage=gdi-window', 'FAIL stage=gdi-window'),
        ('PASS stage=legacy-second-swap', ''),
        (r'C:\sandbox\bundle\opengl32.dll', r'C:\Windows\System32\opengl32.dll'),
        (r'C:\sandbox\bundle\libgallium_wgl.dll', r'C:\other\libgallium_wgl.dll'),
        ('renderer=softpipe', 'renderer=llvmpipe'),
        ('Mesa 26.2.4', 'Mesa 26.2.3'),
        ('LEGACY version=3.3 profile=0x2', ''),
        ('rgba=64,128,191,255', 'rgba=191,128,64,255'),
        ('rgba=64,128,191,255', 'rgba=64,128,191,999'),
        ('rgb=191,64,128', 'rgb=64,128,191'),
        ('gl_error=0x0', 'gl_error=0x502'),
        ('PASS requested-stage=legacy', ''),
        ('PASS stage=window', 'PASS stage=window\nPASS stage=window'),
        ('PIXEL stage=legacy-clear-readback rgba=64,128,191,255 gl_error=0x0', ''),
        ('WINDOW_PIXEL stage=legacy-window-readback rgb=64,128,191', ''),
]:
    reject(lambda old=old, new=new: parse(legacy.replace(old, new)), old)
reject(lambda: parse(legacy, code=1), 'nonzero process exit')
reject(lambda: parse(legacy + '\nUNAVAILABLE core43=missing-create-context-attribs'), 'contradictory legacy result')
core = transcript('core43')
for old, new in [('CORE version=4.3', 'CORE version=4.2'), ('profile=0x1', 'profile=0x2'),
                 ('PASS stage=core-shader-readback', ''), ('rgba=255,0,0,255', 'rgba=0,0,255,255'),
                 ('WINDOW_PIXEL stage=core-window-readback rgb=255,0,0', '')]:
    reject(lambda old=old, new=new: parse(core.replace(old, new), stage='core43'), old)
unsupported = legacy.replace('CANARY stage=legacy', 'CANARY stage=core43').replace(
    'PASS requested-stage=legacy', 'UNAVAILABLE core43=context-rejected win32_error=8341')
assert parse(unsupported, code=77, stage='core43')['status'] == 'unavailable'
checks += 1
for old, new in [('win32_error=8341', 'win32_error=8'), ('win32_error=8341', 'win32_error=0'),
                 ('PASS stage=gdi-memory', ''), ('rgb=191,64,128', 'rgb=64,128,191')]:
    reject(lambda old=old, new=new: parse(unsupported.replace(old, new), code=77, stage='core43'), old)
reject(lambda: parse(unsupported, code=1, stage='core43'), 'wrong unavailable exit')
reject(lambda: parse(unsupported + '\nPASS stage=core43-context', code=77, stage='core43'), 'contradictory core outcome')
for name in ['/absolute/file', '../escape', 'a/../../escape', 'C:/escape', r'a\..\escape']:
    reject(lambda name=name: ref.safe_name(name), name)
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory)
    data = path / 'input'
    data.write_bytes(b'official')
    item = {'size': 8, 'sha256': hashlib.sha256(b'official').hexdigest()}
    ref.verify_file(data, item)
    data.write_bytes(b'tampered')
    reject(lambda: ref.verify_file(data, item), 'same-size checksum corruption')
    archive = path / 'bad.zip'
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('../escape', b'bad')
    reject(lambda: ref.unpack_zip(archive, path / 'output', 100), 'ZIP traversal')
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('large', b'x' * 101)
    reject(lambda: ref.unpack_zip(archive, path / 'output', 100), 'ZIP expansion cap')
    assert not (path / 'escape').exists()

lock = json.loads((SOURCE / 'inputs.lock.json').read_text())
assert lock['host_python'] == '3.12.10'
assert len(lock['inputs']) == 9 and sum(d['size'] for d in lock['inputs']) < 260 * 1024**2
for d in lock['inputs']:
    assert len(d['sha256']) == 64 and all(c in '0123456789abcdef' for c in d['sha256'])
    assert d['url'].startswith(('https://archive.mesa3d.org/', 'https://github.com/mstorsjo/llvm-mingw/',
                                'https://github.com/lexxmark/winflexbison/', 'https://files.pythonhosted.org/'))
expected = ''.join(f'{d["name"]}=={d["version"]} --hash=sha256:{d["sha256"]}\n'
                   for d in lock['inputs'] if d['kind'] == 'wheel')
assert (SOURCE / 'host-requirements.txt').read_text() == expected
workflow = (ROOT / '.github/workflows/mesa-windows-reference.yml').read_text()
for text in ['runs-on: windows-2025', 'timeout-minutes: 25', 'contents: read',
             'persist-credentials: false', "github.repository == 'Mi-Yomi/Madeira'",
             'github.event.repository.private == false', "github.ref == 'refs/heads/compatibility/desktop-apps'",
             'tests/desktop/mesa_wgl/reference-request.json', 'workflow_dispatch:']:
    assert text in workflow, text
assert workflow.count('uses:') == 1
assert 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262' in workflow
assert all(text not in workflow.lower() for text in ['pull_request', 'schedule:', 'secrets.', 'upload-artifact@', 'actions/cache@'])
assert '-Dgallium-drivers=softpipe' in ref.OPTIONS and '--wrap-mode=nodownload' in ref.OPTIONS
assert '-Dllvm=disabled' in ref.OPTIONS and '-Ddraw-use-llvm=false' in ref.OPTIONS
runner_source = (SOURCE / 'windows_reference.py').read_text()
assert 'needs_exe_wrapper = true' in runner_source and 'skip_sanity_check = true' in runner_source
assert "'-j2'" in runner_source and "'--no-cache-dir'" in runner_source
request = json.loads((SOURCE / 'reference-request.json').read_text())
assert request['mesa'] == '26.2.4' and request['renderer'] == 'softpipe'
print(f'PASS: {checks} positive/negative proof and archive controls; pinned-input/workflow boundaries')
print('NOT RUN: Windows build/runtime, Madeira/iOS display and Blender acceptance')
