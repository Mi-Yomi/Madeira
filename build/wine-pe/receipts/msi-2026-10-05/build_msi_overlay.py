#!/usr/bin/env python3
"""Offline patched MSI build: two seven-provider farms plus i386 msi.dll."""
from pathlib import Path
import argparse, hashlib, json, os, selectors, shutil, signal, subprocess, sys, time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'tools'))
import build_receipt as receipt
import build_desktop as desktop
import guest_inventory as inventory
import symbol_audit

PIN = '4f5b19718f4de88ecc5cb0dc08b119497a67ba8f'
MAIN = HERE.parent / 'madeira-graphics-bootstrap'
EXISTING = HERE.parent / 'madeira-desktop-overlay-build'
TOOLCHAIN = EXISTING / 'toolchains/llvm-mingw-20260421-ucrt-ubuntu-22.04-x86_64/bin'
ARCHIVE = EXISTING / 'downloads/llvm-mingw-20260421-ucrt-ubuntu-22.04-x86_64.tar.xz'
COMPONENTS = {'msi.dll':'dlls/msi', 'msiexec.exe':'programs/msiexec',
              'cabinet.dll':'dlls/cabinet', 'sxs.dll':'dlls/sxs',
              'mspatcha.dll':'dlls/mspatcha', 'odbccp32.dll':'dlls/odbccp32',
              'regsvr32.exe':'programs/regsvr32'}
ARCHES = ['aarch64', 'arm64ec', 'i386']
PATCH_SHA = '3efc2fb4733e67f8951284d5f0384a4df4a39f284a5f30fc395840bbbc1ea4a8'
CUSTOM_BEFORE = '201da579180bccd76abbf0feb291686faa29c7940357e55a08838bde5b501c25'
CUSTOM_AFTER = '31c63ede3acf225cfe4d9d772a00b752e82410ebcb060f58f0bfbc9f9e2ea0c5'
ORIGINAL_FARMS = {arch: MAIN/'app/Madeira'/f'{arch}-windows' for arch in ARCHES[:2]}
ORIGINAL_FARMS['i386'] = HERE.parent/'madeira-installer-provider-audit-20261005/extension-modern-i386/experimental-i386-candidate'
MAX_LOG = 64 * 1024**2
MAX_WORK = 2 * 1024**3
MIN_FREE = 8 * 1024**3
ATTEMPT_SECONDS = 2700

def components_for(arch):
    return {'msi.dll': 'dlls/msi'} if arch == 'i386' else COMPONENTS

def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_json(path, data)

def git(*args):
    return receipt.git_output('/usr/bin/git', HERE / 'wine', *args)

def source_identity():
    if git('rev-parse', 'HEAD').decode().strip() != PIN:
        raise ValueError('Wine pin mismatch')
    if git('status', '--porcelain=v1', '--untracked-files=all').decode() != ' M dlls/msi/custom.c\n':
        raise ValueError('Wine modifications differ from the approved single-file patch')
    if receipt.hash_file(HERE/'patches/msi-combined.patch')['sha256'] != PATCH_SHA:
        raise ValueError('Combined patch hash mismatch')
    if hashlib.sha256(git('show', PIN + ':dlls/msi/custom.c')).hexdigest() != CUSTOM_BEFORE:
        raise ValueError('Pinned custom.c baseline hash mismatch')
    if receipt.hash_file(HERE/'wine/dlls/msi/custom.c')['sha256'] != CUSTOM_AFTER:
        raise ValueError('Patched custom.c hash mismatch')
    if git('ls-files', '--others', '-z'):
        raise ValueError('Wine contains ignored/untracked input')
    files, total = {}, 0
    for entry in git('ls-tree', '-rz', '--full-tree', 'HEAD').split(b'\0'):
        if not entry:
            continue
        meta, rawname = entry.split(b'\t', 1)
        mode, kind, blob = meta.decode().split()
        name = rawname.decode()
        receipt.safe_relative(name)
        path = HERE / 'wine' / name
        if kind != 'blob' or mode not in ('100644', '100755') or path.is_symlink():
            raise ValueError('Unexpected source type: ' + name)
        info = receipt.hash_file(path, git_blob=True)
        total += info['bytes']
        if (info['git_blob'] != blob and name != 'dlls/msi/custom.c') or bool(path.stat().st_mode & 0o111) != (mode == '100755'):
            raise ValueError('Wine source blob/mode mismatch: ' + name)
        if total > receipt.MAX_SOURCE_BYTES or len(files) >= receipt.MAX_FILES:
            raise ValueError('Source budget exceeded')
        files[name] = {'git_mode':mode, 'pinned_git_blob':blob, 'patched':name == 'dlls/msi/custom.c', **info}
    inputs = {}
    for path in [HERE / 'build_msi_overlay.py', HERE / 'check_exe_audit.py', HERE / 'build/madeira_cfg.h',
                 *sorted((HERE/'tools').glob('*.py')), HERE/'tools/desktop-components.json',
                 *sorted((HERE/'reference-inputs').rglob('*')), *sorted((HERE/'patches').rglob('*')),
                 *sorted((HERE/'review-inputs').rglob('*'))]:
        if path.is_file():
            inputs[str(path.relative_to(HERE))] = receipt.hash_file(path)
    return {'wine_revision':PIN, 'wine_tree':git('rev-parse','HEAD^{tree}').decode().strip(),
            'wine_repository':'https://github.com/willfaust/wine.git',
            'wine_files':files, 'wine_file_bytes':total, 'wine_tracked_sources_clean':False,
            'only_reviewed_patch_applied':True, 'patch_sha256':PATCH_SHA,
            'patched_file':{'path':'dlls/msi/custom.c','before_sha256':CUSTOM_BEFORE,'after_sha256':CUSTOM_AFTER},
            'recipe_inputs':inputs, 'main_published_revision':'942801fc11ee5a572fbf129c27f3c7618ed1cb2b',
            'main_local_head':'stale; not used as source identity', 'runtime_tested':False}

def host_environment():
    prior = os.environ.get('PATH','')
    os.environ['PATH'] = str(EXISTING/'prerequisite-bin') + os.pathsep + str(EXISTING/'prerequisites/usr/bin') + os.pathsep + prior
    try:
        return desktop.build_environment(TOOLCHAIN, ARCHES)
    finally:
        os.environ['PATH'] = prior

def work_size(work):
    if shutil.disk_usage(HERE).free < MIN_FREE:
        raise ValueError('Free disk fell below the 8 GiB shared-build floor')
    total = 0
    for directory, dirs, files in os.walk(work, followlinks=False):
        for name in files:
            path = Path(directory)/name
            if not path.is_symlink():
                total += path.stat().st_size
                if total > MAX_WORK:
                    raise ValueError('Build tree exceeds 2 GiB budget')
    return total

def run_logged(argv, cwd, env, logpath, deadline, records):
    work_size(cwd)
    record = {'argv':[str(x) for x in argv], 'cwd':str(cwd)}
    records.append(record)
    write(HERE/'evidence/commands.json', records)
    print('RUN ' + ' '.join(record['argv']), flush=True)
    start = time.monotonic()
    p = subprocess.Popen(record['argv'], cwd=cwd, env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, start_new_session=True)
    finished, last_disk = False, 0
    try:
        with logpath.open('ab') as log, selectors.DefaultSelector() as sel:
            sel.register(p.stdout, selectors.EVENT_READ)
            while sel.get_map():
                if time.monotonic() >= deadline:
                    raise ValueError('Architecture attempt exceeds 45 minutes')
                if time.monotonic() - last_disk >= 5:
                    work_size(cwd)
                    last_disk = time.monotonic()
                for key, _ in sel.select(min(1, max(.001, deadline-time.monotonic()))):
                    data = os.read(key.fd, 65536)
                    if not data:
                        sel.unregister(key.fileobj)
                        continue
                    if log.tell() + len(data) > MAX_LOG:
                        raise ValueError('Architecture log exceeds 64 MiB')
                    log.write(data)
            status = p.wait(timeout=max(.001,deadline-time.monotonic()))
        record.update(exit_code=status, elapsed_seconds=round(time.monotonic()-start,3),
                      work_bytes=work_size(cwd))
        write(HERE/'evidence/commands.json', records)
        if status:
            raise ValueError('Build command failed: ' + str(status))
        finished = True
    finally:
        if not finished:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        p.wait()
        p.stdout.close()

def preflight():
    work_size(HERE/'evidence')
    evidence = HERE/'evidence'
    source = source_identity()
    write(evidence/'source-inputs.json',source)
    toolchain = receipt.verify_toolchain(TOOLCHAIN, ARCHIVE)
    write(evidence/'toolchain-receipt.json',toolchain)
    env = host_environment()
    tools = desktop.validate_tools(TOOLCHAIN, ARCHES, env)
    # Relocated host prerequisite data is part of the recorded input set too.
    tools['prerequisite_files'] = {str(p.relative_to(EXISTING)):receipt.hash_file(p)
        for root in ('prerequisites','prerequisite-bin') for p in sorted((EXISTING/root).rglob('*'))
        if p.is_file() and not p.is_symlink()}
    write(evidence/'host-tools.json',tools)
    for arch in ARCHES:
        baseline = inventory.audit_farm(HERE/'baseline/app/Madeira'/f'{arch}-windows',arch,set())
        original = inventory.audit_farm(ORIGINAL_FARMS[arch],arch,set())
        if baseline['modules'] != original['modules']:
            raise ValueError('Snapshot differs from main farm')
        if arch != 'i386' and any(name in baseline['modules'] for name in COMPONENTS):
            raise ValueError('Requested provider unexpectedly present')
        if arch == 'i386' and 'msi.dll' not in baseline['modules']:
            raise ValueError('The i386 resolver peer is missing its baseline msi.dll')
        write(evidence/f'{arch}-baseline-inventory.json',baseline)
    plan = {'architectures':ARCHES, 'components':{a:components_for(a) for a in ARCHES},'jobs':2,'seconds_per_attempt':ATTEMPT_SECONDS,
            'max_log_bytes_per_architecture':MAX_LOG,'max_build_bytes_per_architecture':MAX_WORK,
            'minimum_free_disk_bytes':MIN_FREE, 'patch_sha256':PATCH_SHA,
            'configured_windows_compiler':str(TOOLCHAIN/'clang'),
            'no_downloads':True,'no_primary_farm_writes':True,'runtime_tested':False}
    write(evidence/'plan.json',plan)
    print('PREFLIGHT PASS', flush=True)
    return source, toolchain, tools, env

def build_one(arch, env, commands):
    components = components_for(arch)
    work = HERE/f'build-{arch}'
    work.mkdir(exist_ok=False)
    stage = HERE/'candidate'/f'{arch}-windows'
    stage.mkdir(parents=True,exist_ok=False)
    log = HERE/'evidence'/f'{arch}-build.log'
    deadline = time.monotonic()+ATTEMPT_SECONDS
    run_logged([HERE/'wine/configure', '--enable-archs='+arch, *desktop.CONFIGURE],work,env,log,deadline,commands)
    if arch == 'arm64ec':
        typelib = work/'dlls/stdole2.tlb'
        typelib.mkdir(parents=True,exist_ok=True)
        (typelib/'aarch64-windows').symlink_to('arm64ec-windows',target_is_directory=True)
    targets = [f'{src}/{arch}-windows/{name}' for name,src in components.items()]
    run_logged([env['MAKE'],'-j2',*targets],work,env,log,deadline,commands)
    for name,src in components.items():
        output = stage/name
        shutil.copyfile(work/src/f'{arch}-windows'/name, output)
        argv = [TOOLCHAIN/(desktop.TRIPLES[arch]+'-strip'),'--strip-debug',output]
        run_logged(argv,work,env,log,deadline,commands)
        pe = inventory.PE(inventory.read_pe_bytes(output))
        if pe.architecture() != arch:
            raise ValueError('Wrong output architecture: '+str(output))
        pe.dependencies()
    inv = inventory.audit_farm(HERE/'baseline/app/Madeira'/f'{arch}-windows',arch,set(components),stage)
    write(HERE/'evidence'/f'{arch}-inventory.json',inv)
    audit = symbol_audit.audit(HERE/'baseline',arch,stage,TOOLCHAIN/'llvm-readobj',HERE/'evidence',
                               modules=list(components),env=env)
    expected = {name:{key:value[key] for key in ('bytes','sha256','architecture')}
                for name,value in inv['modules'].items()}
    if expected != audit['input_modules']:
        raise ValueError('Inventory and symbol evidence differ')
    print(arch+' STATIC AUDIT PASS '+json.dumps(audit['counts']),flush=True)

def verify_preserved():
    reports = {}
    for arch in ARCHES:
        baseline = json.loads((HERE/'evidence'/f'{arch}-baseline-inventory.json').read_text())
        original = inventory.audit_farm(ORIGINAL_FARMS[arch],arch,set())
        snapshot = inventory.audit_farm(HERE/'baseline/app/Madeira'/f'{arch}-windows',arch,set())
        if original['modules'] != baseline['modules'] or snapshot != baseline:
            raise ValueError('Original/snapshot farm changed')
        reports[arch] = {'preserved':True,'module_count':len(baseline['modules'])}
    write(HERE/'evidence/original-preservation.json',reports)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--build',action='store_true')
    args=parser.parse_args()
    source,toolchain,tools,env=preflight()
    if not args.build:
        return
    commands=[]
    for arch in ARCHES:
        build_one(arch,env,commands)
    if source_identity()!=source or receipt.verify_toolchain(TOOLCHAIN,ARCHIVE)!=toolchain:
        raise ValueError('Source/toolchain inputs changed')
    current_tools=desktop.validate_tools(TOOLCHAIN,ARCHES,env)
    if any(current_tools[k]!=tools[k] for k in current_tools):
        raise ValueError('Host tools changed')
    verify_preserved()
    write(HERE/'evidence/build-status.json',{'status':'static-audited','runtime_tested':False,
          'candidate_installed':False,'bitwise_reproducibility_established':False})
    print('BUILD AND STATIC AUDIT COMPLETE',flush=True)

if __name__ == '__main__':
    main()
