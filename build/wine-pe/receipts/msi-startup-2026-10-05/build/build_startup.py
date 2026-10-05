#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Fresh bounded reviewed MSI startup fix; no activation or guest execution."""
from pathlib import Path
import hashlib, json, os, selectors, shlex, shutil, signal, subprocess, sys, time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'tools'))
import build_desktop as desktop
import build_receipt as receipt
import guest_inventory as inventory
import symbol_audit
PRIMARY=HERE.parent/'madeira-graphics-bootstrap'
RETAINED=PRIMARY/'build/wine-pe/receipts/msi-client-2026-10-05/build'
TOOLCHAIN=HERE.parent/'madeira-desktop-overlay-build/toolchains/llvm-mingw-20260421-ucrt-ubuntu-22.04-x86_64/bin'
ARCHIVE=TOOLCHAIN.parent.parent/(TOOLCHAIN.parent.name+'.tar.xz')
ARCHES=('aarch64','arm64ec','i386')
EXPECTED_ADDED={'CancelIoEx','CreateEventW','GetOverlappedResult','WaitForMultipleObjects'}
DEADLINE=time.monotonic()+1800
commands=[]

def write(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')

def snapshot(root):
    return {str(p.relative_to(root)):({'link':str(p.readlink())} if p.is_symlink() else receipt.hash_file(p)) for p in sorted(root.rglob('*')) if p.is_file() or p.is_symlink()}

def budget():
    total=sum(p.stat().st_size for p in HERE.rglob('*') if p.is_file() and not p.is_symlink())
    if total>2*1024**3: raise ValueError('Isolated workspace exceeds 2 GiB')
    if shutil.disk_usage(HERE).free<8*1024**3: raise ValueError('Free disk below 8 GiB')
    if time.monotonic()>DEADLINE: raise ValueError('Build exceeds 30-minute limit')
    return total

def run(argv,cwd,env,log):
    argv=list(map(str,argv));print('RUN '+' '.join(argv),flush=True)
    record={'argv':argv,'cwd':str(cwd)};commands.append(record)
    write(HERE/'evidence/rebuild-commands.json',commands)
    start=time.monotonic();proc=subprocess.Popen(argv,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
    try:
        with log.open('ab') as dest,selectors.DefaultSelector() as sel:
            sel.register(proc.stdout,selectors.EVENT_READ);last=0
            while sel.get_map():
                if time.monotonic()-last>5: budget();last=time.monotonic()
                for key,_ in sel.select(1):
                    data=os.read(key.fd,65536)
                    if not data: sel.unregister(key.fileobj);continue
                    if dest.tell()+len(data)>64*1024**2: raise ValueError('Log exceeds 64 MiB')
                    dest.write(data)
        status=proc.wait(timeout=10)
        record.update(exit_code=status,elapsed_seconds=round(time.monotonic()-start,3))
        write(HERE/'evidence/rebuild-commands.json',commands)
        if status: raise ValueError(f'Command failed: {status}; {log}')
    finally:
        if proc.poll() is None: os.killpg(proc.pid,signal.SIGKILL);proc.wait()
        proc.stdout.close()

def contract(path):
    pe=inventory.PE(inventory.read_pe_bytes(path))
    return {'architecture':pe.architecture(),'machine':hex(pe.machine),
      'exports':[{k:v for k,v in e.items() if k!='rva'} for e in symbol_audit.exports(pe)],
      'imports':[{'module':e['module'],'kind':e['kind'],'symbols':[s.get('name',s.get('ordinal')) for s in e['symbols']]} for e in symbol_audit.imports(pe)]}

def verify_source():
    saved=json.loads((HERE/'evidence/source-inputs.json').read_text())
    all_files={str(p.relative_to(HERE/'wine')) for p in (HERE/'wine').rglob('*') if p.is_file()}
    if all_files!=set(saved['files']): raise ValueError('Source file set changed')
    for name,expect in saved['files'].items():
        p=HERE/'wine'/name; got=receipt.hash_file(p)
        if got!={k:expect[k] for k in ('bytes','sha256')}: raise ValueError('Source changed: '+name)
        if bool(p.stat().st_mode & 0o111)!=(expect['git_mode']=='100755'): raise ValueError('Source mode changed: '+name)
    return saved

def main():
    budget();source=verify_source()
    toolchain=receipt.verify_toolchain(TOOLCHAIN,ARCHIVE)
    write(HERE/'evidence/rebuild-toolchain.json',toolchain)
    oldpath=os.environ.get('PATH',os.defpath)
    os.environ['PATH']=str(HERE/'prerequisite-bin')+':'+str(HERE/'prerequisites/usr/bin')+':'+oldpath
    env=desktop.build_environment(TOOLCHAIN,ARCHES)
    os.environ['PATH']=oldpath
    host=desktop.validate_tools(TOOLCHAIN,ARCHES,env)
    write(HERE/'evidence/rebuild-host.json',host)
    write(HERE/'evidence/rebuild-plan.json',{'wine_pin':source['wine_pin'],'source_sha256':source['files']['dlls/msi/custom.c']['sha256'],
       'configure_flags':desktop.CONFIGURE,'jobs':2,'seconds_limit':1800,'workspace_bytes_limit':2*1024**3,
       'guest_execution':False,'primary_writes':False,'remote_writes':False,'i386_activation':False,
       'recipe_helpers':snapshot(HERE/'tools'),'rebuild_script':receipt.hash_file(Path(__file__))})
    peer_root=HERE/'resolver-baseline'
    peers={}
    for arch in ARCHES[:2]:
        dest=peer_root/'app/Madeira'/f'{arch}-windows'
        shutil.copytree(PRIMARY/'app/Madeira'/f'{arch}-windows',dest)
        peers[arch]=snapshot(dest)
    write(HERE/'evidence/current-resolver-snapshot.json',peers)
    results=[]
    for arch in ARCHES:
        work=HERE/f'build-{arch}';work.mkdir();(work/'tmp').mkdir()
        local_env=dict(env,TMPDIR=str(work/'tmp'))
        write(HERE/'evidence'/f'{arch}-environment.json',{k:v for k,v in local_env.items() if k not in ('HOME','USER','LOGNAME')})
        log=HERE/'evidence'/f'{arch}-build.log'
        run([HERE/'wine/configure','--enable-archs='+arch,*desktop.CONFIGURE],work,local_env,log)
        if arch=='arm64ec':
            path=work/'dlls/stdole2.tlb';path.mkdir(parents=True,exist_ok=True)
            (path/'aarch64-windows').symlink_to('arm64ec-windows',target_is_directory=True)
        makefile=work/'Makefile';original=makefile.read_text();start=original.index(f'dlls/msi/{arch}-windows/msi.dll:')
        pos=original.index('\ttools/winegcc/winegcc -o $@ --wine-objdir .',start)
        changed=original[:pos]+original[pos:].replace('\ttools/winegcc/winegcc -o $@ --wine-objdir .','\ttools/winegcc/winegcc -v -save-temps -o $@ --wine-objdir .',1)
        before=receipt.hash_file(makefile);makefile.write_text(changed)
        write(HERE/'evidence'/f'{arch}-makefile-trace.json',{'before':before,'after':receipt.hash_file(makefile),'change':'Add only -v -save-temps to generated MSI link command'})
        target=f'dlls/msi/{arch}-windows/msi.dll'
        run([env['MAKE'],'-j2',target],work,local_env,log)
        output=HERE/'candidate'/f'{arch}-windows/msi.dll';output.parent.mkdir(parents=True)
        shutil.copy2(work/target,output)
        run([TOOLCHAIN/(desktop.TRIPLES[arch]+'-strip'),'--strip-debug',output],work,local_env,log)
        old=HERE/'preserved-original'/f'{arch}-windows/msi.dll'
        comparison=contract(output);old_contract=contract(old)
        for key in ('architecture','machine','exports'):
            if comparison[key]!=old_contract[key]: raise ValueError('Architecture/export contract changed: '+arch)
        def import_set(c):
            return {(d['module'],d['kind'],str(symbol)) for d in c['imports'] for symbol in d['symbols']}
        added=import_set(comparison)-import_set(old_contract)
        removed=import_set(old_contract)-import_set(comparison)
        if added!={('kernel32.dll','import',x) for x in EXPECTED_ADDED} or removed:
            raise ValueError('Unexpected import delta: '+repr((added,removed)))
        identity=receipt.hash_file(output);published=receipt.hash_file(old)
        result={'architecture':arch,'output':str(output),'identity':identity,'published':published,
            'architecture_export_contract_equal':True,'import_delta_verified':True,
            'added_imports':[{'module':m,'kind':k,'symbol':s} for m,k,s in sorted(added)],'removed_imports':[],
            'custom_object':receipt.hash_file(work/f'dlls/msi/{arch}-windows/custom.o'),
            'full_current_farm_import_resolution':False,'runtime_tested':False,'active':False}
        compile_commands=json.loads((work/'compile_commands.json').read_text())
        matches=[c for c in compile_commands if c['file']==str(HERE/'wine/dlls/msi/custom.c')]
        if len(matches)!=1: raise ValueError('Missing unique compiled custom source command')
        obj=work/f'dlls/msi/{arch}-windows/custom.o'
        rawobj=subprocess.run([str(TOOLCHAIN/'llvm-readobj'),'--file-headers',str(obj)],capture_output=True,text=True,check=True,timeout=30)
        expected_machine={'aarch64':'IMAGE_FILE_MACHINE_ARM64','arm64ec':'IMAGE_FILE_MACHINE_ARM64EC','i386':'IMAGE_FILE_MACHINE_I386'}[arch]
        if expected_machine not in rawobj.stdout: raise ValueError('Wrong custom object architecture')
        objdest=HERE/'evidence/compiled-custom';objdest.mkdir(exist_ok=True)
        shutil.copy2(obj,objdest/f'{arch}-custom.o');(objdest/f'{arch}-headers.txt').write_text(rawobj.stdout)
        logical=log.read_text().replace('\\\n',' ').splitlines()
        link_lines=[s.strip() for s in logical if s.startswith('tools/winegcc/winegcc ') and '-o '+target+' ' in s]
        if len(link_lines)!=1: raise ValueError('Expected unique fresh MSI link command')
        traced=link_lines+[s.strip() for s in logical if ('/clang ' in s or '/ld.lld ' in s or '/winebuild ' in s) and (target in s or '/tmp/' in s)]
        inputs={}
        for line in traced:
            for token in shlex.split(line):
                if token.startswith('-'):continue
                p=Path(token)
                if not p.is_absolute():p=work/p
                if p.is_file() and p.resolve()!=(work/target).resolve():inputs[str(p.resolve())]=receipt.hash_file(p)
        if str(obj.resolve()) not in inputs: raise ValueError('Fresh custom.o absent from traced link inputs')
        write(HERE/'evidence'/f'{arch}-link-inputs.json',{'source':receipt.hash_file(HERE/'wine/dlls/msi/custom.c'),
            'compile_command':matches[0],'custom_object':receipt.hash_file(obj),'custom_object_machine_verified':True,
            'link_commands':traced,'explicit_link_inputs':inputs,'unstripped_provider':receipt.hash_file(work/target),
            'implicit_inputs':'rebuild-toolchain.json','full_build_files':f'{arch}-build-files.json',
            'host_external_headers_libraries_hermetic':False})
        write(HERE/'evidence'/f'{arch}-contract.json',comparison)
        raw=subprocess.run([str(TOOLCHAIN/'llvm-readobj'),'--file-headers','--coff-imports','--coff-exports','--coff-load-config',str(output)],capture_output=True,text=True,check=True,timeout=30)
        (HERE/'evidence'/f'{arch}-readobj.txt').write_text(raw.stdout)
        if arch!='i386':
            audit=symbol_audit.audit(peer_root,arch,output.parent,TOOLCHAIN/'llvm-readobj',HERE/'evidence',modules=['msi.dll'],env=local_env)
            if not audit['passed']: raise ValueError('Static symbol resolution failed: '+arch)
            result['full_current_farm_import_resolution']=True;result['static_counts']=audit['counts']
        else:
            result['resolution_limit']='Historical i386 peer farm is absent after reset; exact reviewed four-symbol import delta is verified but fresh full resolution was not run.'
        write(HERE/'evidence'/f'{arch}-build-files.json',snapshot(work))
        results.append(result);write(HERE/'replacement-identity.json',{'wine_pin':source['wine_pin'],
            'status':'inactive-static-audited','final_source_sha256':source['files']['dlls/msi/custom.c']['sha256'],
            'incremental_baseline_sha256':source['incremental_baseline_custom_sha256'],
            'incremental_patch_sha256':source['incremental_patch']['sha256'],'outputs':results,
            'installed':False,'published':False,'runtime_tested':False,'guest_execution':False,'bitwise_reproducibility_established':False})
        print(json.dumps(result),flush=True)
    if verify_source()!=source: raise ValueError('Source identity changed')
    if receipt.verify_toolchain(TOOLCHAIN,ARCHIVE)!=toolchain: raise ValueError('Toolchain changed')
    for arch in ARCHES[:2]:
        if snapshot(peer_root/'app/Madeira'/f'{arch}-windows')!=peers[arch]: raise ValueError('Resolver snapshot changed')
    write(HERE/'evidence/final-verification.json',{'three_providers_rebuilt':True,'source_preserved':True,'toolchain_preserved':True,
        'resolver_snapshots_preserved':True,'only_expected_import_delta':True,'export_contracts_unchanged':True,'workspace_bytes':budget(),
        'guest_execution':False,'primary_writes':False,'remote_writes':False,'i386_activation':False})
    print('THREE FRESH MSI STARTUP PROVIDERS VERIFIED',flush=True)

if __name__=='__main__': main()
