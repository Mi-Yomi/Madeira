#!/usr/bin/env python3
"""Produce an isolated review patch; never write to the production checkout."""
from pathlib import Path
import difflib
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BASE = ROOT / 'madeira-graphics-bootstrap/build/wine-pe/receipts/msi-client-2026-10-05/build/source/custom.c'
EXPECTED = '9c6db8469d1db7d1fff83af45e4f4851238e3b09fc06055996cfbb956fd6af50'
raw = BASE.read_bytes()
assert hashlib.sha256(raw).hexdigest() == EXPECTED
baseline = raw.decode()
proposal = baseline

def replace_once(old, new):
    global proposal
    assert proposal.count(old) == 1, old
    proposal = proposal.replace(old, new, 1)

helpers = (HERE / 'proposal_helpers.inc').read_text()
replace_once('static DWORD custom_start_server(MSIPACKAGE *package, DWORD arch)',
             helpers + '\nstatic DWORD custom_start_server(MSIPACKAGE *package, DWORD arch)')
replace_once('CreateNamedPipeW(buffer, PIPE_ACCESS_DUPLEX, 0, 1, sizeof(DWORD64),',
             'CreateNamedPipeW(buffer, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, 0, 1, sizeof(DWORD64),')
replace_once('    if (!ConnectNamedPipe(pipe, NULL))\n    {\n        ret = GetLastError();\n        if (ret != ERROR_PIPE_CONNECTED) goto failed;\n    }',
             '    if ((ret = custom_connect_server( pipe, pi.hProcess ))) goto failed;')
replace_once('WriteFile(pipe, &GUID_NULL, sizeof(GUID_NULL), &size, NULL);',
             'custom_pipe_io(pipe, (void *)&GUID_NULL, sizeof(GUID_NULL), &size, TRUE);')
replace_once('WriteFile(pipe, &info->guid, sizeof(info->guid), &size, NULL);',
             'custom_pipe_io(pipe, &info->guid, sizeof(info->guid), &size, TRUE);')
replace_once('ReadFile(pipe, &thread64, sizeof(thread64), &size, NULL);',
             'custom_pipe_io(pipe, &thread64, sizeof(thread64), &size, FALSE);')
assert 'ConnectNamedPipe(pipe, NULL)' not in proposal
for call in ['ReadFile(pipe,', 'WriteFile(pipe,']:
    assert call not in proposal, call
patch = ''.join(difflib.unified_diff(baseline.splitlines(True), proposal.splitlines(True),
                                  fromfile='a/dlls/msi/custom.c', tofile='b/dlls/msi/custom.c'))
(HERE / 'baseline-custom.c').write_bytes(raw)
(HERE / 'proposed-custom.c').write_text(proposal)
(HERE / 'proposal.patch').write_text(patch)
identity = {
    'baseline_sha256': EXPECTED,
    'source_sha256': hashlib.sha256(proposal.encode()).hexdigest(),
    'patch_sha256': hashlib.sha256(patch.encode()).hexdigest(),
    'helper_sha256': hashlib.sha256(helpers.encode()).hexdigest(),
    'new_called_apis': ['CancelIoEx', 'CreateEventW', 'GetOverlappedResult', 'WaitForMultipleObjects', 'SetLastError'],
    'expected_new_imports': ['CancelIoEx', 'CreateEventW', 'GetOverlappedResult', 'WaitForMultipleObjects'],
    'set_last_error_note': 'Check Wine inline TEB implementation; MinGW ABI-only fixture imports SetLastError.',
    'runtime_tested': False,
    'primary_checkout_changed': False,
}
(HERE / 'proposal-identity.json').write_text(json.dumps(identity, indent=2) + '\n')
print(json.dumps(identity, indent=2))
