#!/usr/bin/env python3
"""Use Madeira's unchanged bounded symbol checker on one isolated FEX output."""
import argparse
import json
from pathlib import Path
import shutil
import sys

sys.dont_write_bytecode = True
w = Path(__file__).resolve().parent
sys.path.insert(0, str(w/'audit-tools'))
import symbol_audit

p = argparse.ArgumentParser()
p.add_argument('architecture', choices=['arm64ec', 'wow64'])
p.add_argument('phase', choices=['baseline', 'patched'])
a = p.parse_args()
arch = 'arm64ec' if a.architecture == 'arm64ec' else 'aarch64'
name = 'xtajit64.dll' if a.architecture == 'arm64ec' else 'xtajit.dll'
target = 'arm64ecfex' if a.architecture == 'arm64ec' else 'wow64fex'
overlay = w/f'audit-overlay-{a.architecture}-{a.phase}'
overlay.mkdir(exist_ok=False)
source = w/f'build-{a.architecture}-{a.phase}/Bin/lib{target}.dll'
shutil.copy2(source, overlay/name)
tool = Path('/workspace/scratch/94ffb2b0bb2d/madeira-desktop-overlay-build/toolchains/llvm-mingw-20260421-ucrt-ubuntu-22.04-x86_64/bin/llvm-readobj').resolve()
result = symbol_audit.audit(
    Path('/workspace/scratch/94ffb2b0bb2d/madeira-graphics-bootstrap'), arch,
    overlay, tool, w/f'evidence/symbol-audit-{a.architecture}-{a.phase}', modules=[name])
print(json.dumps({k: result[k] for k in ('architecture', 'passed', 'runtime_tested', 'counts', 'resolved_api_set_uses', 'issues')}, indent=2))
