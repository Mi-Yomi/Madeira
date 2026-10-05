# Independent source review

Reviewed production source:
9c6db8469d1db7d1fff83af45e4f4851238e3b09fc06055996cfbb956fd6af50

Result: no concrete source blocker or required missing test was found for
source-only delivery. The review compared the baseline and patched function,
checked extracted production bodies, and reran the existing baseline/candidate
host executables. Every API failure is captured before logging/cleanup, every
return path assigns rc, COM and critical-section cleanup are balanced, and only
a successfully duplicated local handle is closed. Only custom_client_thread
changes; successful action results and outer policy functions are preserved.

The review initially assessed 86 scenarios. Subsequent test-only improvements
added COM teardown ordering assertions, made failed I/O zero byte counts, made
short reads populate only the reported bytes, and exercised the outer
suspend/reboot and no-more-items mappings. Final runs pass 102/102 scenarios,
with the same 46 failing baseline scenarios. Production source did not change
after independent review.

Contracts checked against primary Microsoft documentation:

- COM requires one CoUninitialize for each successful S_OK or S_FALSE initialization:
  https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex
- DUPLICATE_CLOSE_SOURCE closes the source handle even when DuplicateHandle fails:
  https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle
- ReadFile initializes the byte-count output before error checking:
  https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
- Wait failure/success/abandoned/timeout meanings:
  https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject

Remaining nonblocking limits: host-only API doubles; async cases test immediate
outer policy only; timeout/abandoned wait outcomes are synthetic for this call.
See README.md for full runtime and scope limits.
