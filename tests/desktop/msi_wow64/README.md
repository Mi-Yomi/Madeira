# Source-owned MSI cross-bitness reference

This small fixture creates a temporary x64 MSI database containing an i386 DLL
custom action. It never installs or registers a product and contains no
proprietary executable or data. Its two positive rounds must retrieve Unicode
input, resolve a built-in SID through both ANSI and Unicode APIs, and return
properties through the real MSI remote handle. MSI ordinals 144 and 145 are
required in the DLL import table. A distinct child PID and 32-bit pointer size
prove the action did not run as an in-process 64-bit substitute.

The host initializes COM on its calling thread and opens the package with
flags zero. Microsoft's restricted IGNOREMACHINESTATE handle deliberately
forbids DLL custom actions and returns 1626, so it cannot establish this
reference. The positive rounds run before the failing control, with valid
inputs and cleared proof properties retained for that final control.
See [MsiOpenPackageExW](https://learn.microsoft.com/en-us/windows/win32/api/msi/nf-msi-msiopenpackageexw).

A deliberately missing entry point must return a nonzero result and produce
none of the proof properties. A zero return alone never passes. The host
requires both property rounds and session closure, deletes its exact temporary
MSI/DLL paths and has a 60-second watchdog. A watchdog exit can leave its owned
temporary inputs behind; it is always failure.

The dedicated workflow uses the existing Microsoft C++ tools and Windows SDK
on GitHub's standard public windows-2025 runner. It is restricted to
Mi-Yomi/Madeira, compatibility/desktop-apps, and a ten-minute job limit.
There is no download/install step, cache, artifact upload, signing or IPA.

windows_reference.py copies the reviewed sources to a fresh directory under
RUNNER_TEMP, compiles the x86 DLL and x64 host, validates PE architecture,
ordinal imports and the embedded DLL bytes, then runs this fixture once.
Compiler and runtime logs and a JSON receipt remain in the temporary runner;
the successful receipt is also printed in the job log.

On a separately authorized disposable x64 Windows test environment:

    python tests/desktop/msi_wow64/windows_reference.py --work-root C:\Temp\madeira-msi-reference-new

The source-only build_msvc.cmd can be used without executing a guest.
Child CA-PROOF stderr is optional: Windows can detach the MSI server's standard
handles. Parent-side property checks and the recorded child PID are mandatory.
Windows may cache its MSI host after session close; this reference does not
prove Wine child-process teardown.

A green Windows reference establishes native Windows behavior for this exact
fixture. It does not establish Madeira/Wine execution, native WoW64/IPC
correctness, successful 1C installation, device performance or a complete
32-bit runtime. Those remain separate gates.

## Madeira-only diagnostic

`MADEIRA_I386_DIAGNOSTIC=1` selects the additional class-1010 guest-base,
SysWOW64 child identity/reuse and retained-handle child-exit checks. The default
Windows reference does not define this flag. The existing portable desktop CI
runs `tests/host/check-msi-madeira-reference.py` against the production helper
and saved-log parser without executing Windows guest code.

See [device acceptance](DEVICE-ACCEPTANCE.md) for the exact current MSI provider
identities, separate diagnostic-app prerequisites, required iPhone/JIT
observations and the limits of a successful supplied-log parse.
