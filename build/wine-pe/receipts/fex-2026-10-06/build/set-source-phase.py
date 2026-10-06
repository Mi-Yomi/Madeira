#!/usr/bin/env python3
"""Restore only the two reviewed Modules in this isolated FEX working tree."""
import argparse
from pathlib import Path
import shutil
from source_phase import verify_source_phase

p = argparse.ArgumentParser()
p.add_argument('phase', choices=['baseline', 'patched'])
a = p.parse_args()
w = Path(__file__).resolve().parent
# Require one of the known complete states before touching the working files.
try:
    verify_source_phase('baseline')
except AssertionError:
    verify_source_phase('patched')
for mod in ('ARM64EC', 'WOW64'):
    rel = Path(f'Source/Windows/{mod}/Module.cpp')
    shutil.copy2(w/f'{a.phase}-sources'/rel, w/'FEX'/rel)
verify_source_phase(a.phase)
print(f'Isolated FEX source verified in {a.phase} phase')
