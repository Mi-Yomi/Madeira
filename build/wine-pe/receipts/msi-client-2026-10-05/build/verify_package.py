#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Read-only verification of retained source, linker, candidate and old inputs."""
from pathlib import Path
import argparse, json, sys
sys.dont_write_bytecode=True
import prepare_inputs as prep
import build_msi_client as build

HERE=Path(__file__).resolve().parent
def read(name): return json.loads((HERE/name).read_text())
def require(ok,msg):
    if not ok: raise ValueError(msg)
def hashes(p,info):
    actual=build.sha(p)
    return actual['sha256']==info['sha256'] and actual['bytes']==info.get('bytes',info.get('size'))

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    source=read('evidence/source-inputs.json')
    for name,info in source['wine_files'].items(): require(hashes(HERE/'wine'/name,info),'Source mismatch: '+name)
    for name,info in source['recipe_inputs'].items(): require(hashes(HERE/name,info),'Recipe input mismatch: '+name)
    result={'source_files':len(source['wine_files']),'recipe_inputs':len(source['recipe_inputs']),
            'architectures':{},'preservation':{},'runtime_tested':False}
    manifest=read('replacement-identity.json')
    for output in manifest['outputs']:
        arch=output['architecture']
        require(hashes(HERE/output['path'],output),'Candidate identity mismatch')
        require(hashes(HERE/output['replaces']['path'],output['replaces']),'Original snapshot identity mismatch')
        require(build.contract(HERE/output['path'])==build.contract(HERE/output['replaces']['path']),'Contract mismatch')
        link=read(f'evidence/{arch}-link-inputs.json')
        for path,info in link['explicit_link_inputs'].items(): require(hashes(Path(path),info),'Link input mismatch: '+path)
        expected=read(f'evidence/{arch}-build-files.json')
        require(prep.snapshot(HERE/f'build-{arch}')==expected,'Generated build files differ: '+arch)
        audit=read(f'evidence/{arch}-symbol-audit.json')
        require(audit['passed'] and audit['modules']['msi.dll']['sha256']==output['sha256'],'Audit not bound to candidate')
        result['architectures'][arch]={'explicit_link_inputs':len(link['explicit_link_inputs']),
            'retained_build_files_or_links':len(expected),'output_sha256':output['sha256'],'contract_unchanged':True}
    for label,root in [('old',prep.OLD),('fix',prep.FIX)]:
        original=read(f'evidence/{label}-workspace-before.json')
        actual=prep.snapshot(root)
        require(actual==original,'Original workspace changed: '+str(root))
        result['preservation'][label]={'file_or_link_count':len(actual),'preserved':True}
    for name,wanted in [('client-normal','RESULT: 102/102 passed; 0 failed'),('client-sanitized','RESULT: 102/102 passed; 0 failed'),('client-baseline','RESULT: 56/102 passed; 46 failed')]:
        text=(HERE/'evidence'/f'{name}.log').read_text()
        require(wanted in text,'Unexpected scenario count: '+name)
    require(all(x['exit_code']==x['expected_exit_code'] for x in read('evidence/post-build-tests.json')),'Host test status mismatch')
    result['passed']=True
    if args.output:
        target=args.output.resolve()
        require(target.is_relative_to(HERE/'evidence'),'Verification output must be in local evidence')
        prep.write(target,result)
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()
