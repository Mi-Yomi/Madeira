#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Fresh offline MSI-only builds with explicit link-input and preservation receipts."""
from pathlib import Path
import hashlib, json, os, re, shlex, shutil, subprocess, sys, time
sys.dont_write_bytecode=True
import prepare_inputs as prep
import build_msi_overlay as base

HERE=Path(__file__).resolve().parent
OLD=prep.OLD
FIX=prep.FIX
ARCHES=('aarch64','arm64ec','i386')
FINAL='9c6db8469d1db7d1fff83af45e4f4851238e3b09fc06055996cfbb956fd6af50'
BASELINE='31c63ede3acf225cfe4d9d772a00b752e82410ebcb060f58f0bfbc9f9e2ea0c5'
PATCH='6dc3802f26e98a0cc03462b989e2d3619b74f9374d325784009c1df5a8623ebe'
DEADLINE=time.monotonic()+2700
commands=[]
budget_samples=[]

def write(name,data): prep.write(HERE/name,data)
def sha(p): return base.receipt.hash_file(p)

def budget(_=None):
    total=sum(p.stat().st_size for p in HERE.rglob('*') if p.is_file() and not p.is_symlink())
    free=shutil.disk_usage(HERE).free
    budget_samples.append({'unix_time':time.time(),'new_logical_bytes':total,'free_bytes':free})
    if total>2*1024**3: raise ValueError('Whole new workspace exceeds 2 GiB logical budget')
    if free<8*1024**3: raise ValueError('Free disk below 8 GiB floor')
    if time.monotonic()>DEADLINE: raise ValueError('Build session exceeds 45 minutes')
    return total

def source_identity():
    base.CUSTOM_AFTER=FINAL
    result=base.source_identity()
    if sha(HERE/'patches/msi-client-failure.patch')['sha256']!=PATCH: raise ValueError('Client patch mismatch')
    result.update(incremental_baseline_sha256=BASELINE,incremental_patch_sha256=PATCH,
        production_functions_changed_by_incremental_patch=['custom_client_thread'])
    for p in (HERE/'prepare_inputs.py',HERE/'build_msi_client.py'):
        result['recipe_inputs'][p.name]=sha(p)
    return result

def command(argv,cwd,env,log):
    base.run_logged(argv,cwd,env,log,DEADLINE,commands)

def contract(path):
    pe=base.inventory.PE(base.inventory.read_pe_bytes(path))
    exports=[{k:v for k,v in e.items() if k!='rva'} for e in base.symbol_audit.exports(pe)]
    imports=[{'module':e['module'],'kind':e['kind'],'symbols':[
        s.get('name',s.get('ordinal')) for s in e['symbols']]} for e in base.symbol_audit.imports(pe)]
    return {'architecture':pe.architecture(),'machine':hex(pe.machine),'exports':exports,'imports':imports}

def record_link_inputs(arch,work,log):
    joined=log.read_text().replace('\\\n',' ')
    logical=[line.strip() for line in joined.splitlines()]
    target=f'dlls/msi/{arch}-windows/msi.dll'
    recipe=[x for x in logical if x.startswith('tools/winegcc/winegcc ') and '-o '+target+' ' in x]
    if len(recipe)!=1: raise ValueError('Expected exactly one fresh MSI link command')
    recipes=recipe+[x for x in logical if ('/clang ' in x or '/ld.lld ' in x or '/winebuild ' in x)
             and (target in x or '/tmp/' in x)]
    inputs={}
    for line in recipes:
        try: words=shlex.split(line)
        except ValueError: continue
        for word in words:
            if word.startswith('-'): continue
            p=Path(word)
            if not p.is_absolute(): p=work/p
            if p.is_file() and p.resolve()!=(work/target).resolve(): inputs[str(p.resolve())]=sha(p)
    obj=work/f'dlls/msi/{arch}-windows/custom.o'
    if str(obj.resolve()) not in inputs: raise ValueError('Fresh custom.o not present in recorded link inputs')
    if sha(obj)==sha(OLD/f'build-{arch}/dlls/msi/{arch}-windows/custom.o'): raise ValueError('Custom object unexpectedly equals old baseline')
    compiled=json.loads((work/'compile_commands.json').read_text())
    match=[c for c in compiled if c['file']==str(HERE/'wine/dlls/msi/custom.c')]
    if len(match)!=1: raise ValueError('Wrong custom compile command')
    headers=subprocess.run([str(base.TOOLCHAIN/'llvm-readobj'),'--file-headers',str(obj)],capture_output=True,text=True,timeout=30,check=True)
    expected={'aarch64':'IMAGE_FILE_MACHINE_ARM64','arm64ec':'IMAGE_FILE_MACHINE_ARM64EC','i386':'IMAGE_FILE_MACHINE_I386'}[arch]
    if expected not in headers.stdout: raise ValueError('Wrong custom object architecture')
    dest=HERE/'evidence/compiled-custom'
    dest.mkdir(exist_ok=True)
    shutil.copy2(obj,dest/f'{arch}-custom.o')
    (dest/f'{arch}-header.txt').write_text(headers.stdout)
    data={'architecture':arch,'source':sha(HERE/'wine/dlls/msi/custom.c'),'custom_object':sha(obj),
        'custom_compile_command':match[0],'object_machine_verified':True,'link_commands':recipes,
        'explicit_link_inputs':inputs,'unstripped_provider':sha(work/target),
        'link_temp_policy':'Winegcc -v -save-temps; TMPDIR inside fresh architecture build',
        'build_input_superset_receipt':f'{arch}-build-files.json',
        'toolchain_implicit_inputs_receipt':'toolchain-receipt.json',
        'host_external_headers_libraries_hermetic':False}
    write(f'evidence/{arch}-link-inputs.json',data)
    write(f'evidence/{arch}-build-files.json',prep.snapshot(work))
    return data

def build_one(arch,env):
    work=HERE/f'build-{arch}'
    work.mkdir(exist_ok=False)
    (work/'tmp').mkdir()
    env=dict(env,TMPDIR=str(work/'tmp'))
    write(f'evidence/{arch}-environment.json',{k:v for k,v in env.items() if k not in ('HOME','USER','LOGNAME')})
    log=HERE/'evidence'/f'{arch}-build.log'
    command([HERE/'wine/configure','--enable-archs='+arch,*base.desktop.CONFIGURE],work,env,log)
    if arch=='arm64ec':
        p=work/'dlls/stdole2.tlb'
        p.mkdir(exist_ok=True,parents=True)
        (p/'aarch64-windows').symlink_to('arm64ec-windows',target_is_directory=True)
    # Change only the generated MSI link recipe to retain/trace its transient inputs.
    makefile=work/'Makefile'
    text=makefile.read_text()
    start=text.index(f'dlls/msi/{arch}-windows/msi.dll:')
    pos=text.index('\ttools/winegcc/winegcc -o $@ --wine-objdir .',start)
    before=sha(makefile)
    changed=text[:pos]+text[pos:].replace('\ttools/winegcc/winegcc -o $@ --wine-objdir .',
        '\ttools/winegcc/winegcc -v -save-temps -o $@ --wine-objdir .',1)
    makefile.write_text(changed)
    line=text.count('\n',0,pos)+1
    (HERE/'evidence'/f'{arch}-generated-Makefile-trace.patch').write_text(
        '--- generated/Makefile\n+++ traced/Makefile\n'+f'@@ -{line},1 +{line},1 @@\n'+
        '-\ttools/winegcc/winegcc -o $@ --wine-objdir . \\\n'+
        '+\ttools/winegcc/winegcc -v -save-temps -o $@ --wine-objdir . \\\n')
    write(f'evidence/{arch}-generated-Makefile-trace.json',{'before':before,'after':sha(makefile),
        'purpose':'Retain and trace actual transient MSI linker inputs; production source/flags unchanged'})
    command([env['MAKE'],'-j2',f'dlls/msi/{arch}-windows/msi.dll'],work,env,log)
    link=record_link_inputs(arch,work,log)
    output=HERE/'candidate'/f'{arch}-windows/msi.dll'
    output.parent.mkdir(parents=True)
    shutil.copy2(work/f'dlls/msi/{arch}-windows/msi.dll',output)
    command([base.TOOLCHAIN/(base.desktop.TRIPLES[arch]+'-strip'),'--strip-debug',output],work,env,log)
    old=HERE/'preserved-original'/f'{arch}-windows/msi.dll'
    before,after=contract(old),contract(output)
    if before!=after: raise ValueError('MSI architecture/import/export contract changed')
    comparison={'architecture':arch,'old':sha(old),'new':sha(output),
        'same_architecture':True,'same_export_name_ordinal_forwarder_contract':True,
        'same_normal_delay_import_contract':True,'contract':after}
    write(f'evidence/{arch}-contract-comparison.json',comparison)
    resolver=HERE/'resolver-overlays'/f'{arch}-windows'
    shutil.copytree(OLD/'candidate'/f'{arch}-windows',resolver)
    shutil.copy2(output,resolver/'msi.dll')
    audit=base.symbol_audit.audit(OLD/'baseline',arch,resolver,base.TOOLCHAIN/'llvm-readobj',HERE/'evidence',modules=['msi.dll'],env=env)
    if not audit['passed']: raise ValueError('MSI static symbol resolution failed')
    write(f'evidence/{arch}-inventory.json',base.inventory.audit_farm(OLD/'baseline/app/Madeira'/f'{arch}-windows',arch,['msi.dll'],resolver))
    print(f'{arch}: fresh MSI compiled, linked, contract unchanged; {audit["counts"]}',flush=True)
    return {'path':str(output.relative_to(HERE)),**sha(output),'architecture':arch,
        'replaces':{'path':str(old.relative_to(HERE)),**sha(old)},'source_sha256':FINAL,
        'custom_object_sha256':link['custom_object']['sha256'],'static_audit':audit['counts'],
        'contract_unchanged':True,'active':False,'runtime_tested':False}

def main():
    base.work_size=budget
    budget()
    source=source_identity()
    write('evidence/source-inputs.json',source)
    toolchain=base.receipt.verify_toolchain(base.TOOLCHAIN,base.ARCHIVE)
    write('evidence/toolchain-receipt.json',toolchain)
    env=base.host_environment()
    host=base.desktop.validate_tools(base.TOOLCHAIN,list(ARCHES),env)
    host['prerequisite_files']={str(p.relative_to(base.EXISTING)):sha(p)
       for root in ('prerequisites','prerequisite-bin') for p in sorted((base.EXISTING/root).rglob('*'))
       if p.is_file() and not p.is_symlink()}
    write('evidence/host-tools.json',host)
    outputs=[build_one(a,env) for a in ARCHES]
    if source_identity()!=source: raise ValueError('Source changed during build')
    if base.receipt.verify_toolchain(base.TOOLCHAIN,base.ARCHIVE)!=toolchain: raise ValueError('Toolchain changed')
    check=base.desktop.validate_tools(base.TOOLCHAIN,list(ARCHES),env)
    if any(check[k]!=host[k] for k in check): raise ValueError('Host tools changed')
    preservation={}
    for label,root in [('old',OLD),('fix',FIX)]:
        original=json.loads((HERE/f'evidence/{label}-workspace-before.json').read_text())
        after=prep.snapshot(root)
        changed=[p for p in original.keys()|after.keys() if original.get(p)!=after.get(p)]
        preservation[label]={'path':str(root),'file_or_link_count':len(after),'changed':changed,'preserved':not changed}
        if changed: raise ValueError('Sealed input changed: '+label)
    write('evidence/preservation.json',preservation)
    budget()
    write('evidence/budget.json',{'jobs':2,'overall_limit_seconds':2700,'max_new_logical_bytes':2*1024**3,
        'minimum_free_bytes':8*1024**3,'samples':budget_samples})
    write('replacement-identity.json',{'wine_pin':base.PIN,'status':'inactive-static-audited',
        'incremental_baseline_source_sha256':BASELINE,'final_source_sha256':FINAL,
        'incremental_patch_sha256':PATCH,'outputs':outputs,'installed':False,'runtime_tested':False,
        'guest_execution':False,'published':False,'bitwise_reproducibility_established':False})
    print('ALL THREE INACTIVE REPLACEMENTS BUILT AND STATIC-AUDITED',flush=True)

if __name__=='__main__': main()
