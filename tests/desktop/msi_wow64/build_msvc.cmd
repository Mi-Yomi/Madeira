@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem SPDX-License-Identifier: GPL-3.0-or-later
rem Compile only. Run this from any Windows shell with Visual Studio C++ tools.
rem Creates a fresh owned msvc-build directory beside these source files.
set "PROBE_ROOT=%~dp0"
set "PROBE_OUT=%PROBE_ROOT%msvc-build"
if exist "%PROBE_OUT%" (
    echo Refusing an existing output directory: %PROBE_OUT%
    exit /b 2
)
set "PROBE_VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%PROBE_VSWHERE%" exit /b 3
for /f "usebackq delims=" %%I in (`"%PROBE_VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "PROBE_VS=%%I"
if not defined PROBE_VS exit /b 4
mkdir "%PROBE_OUT%" || exit /b 5
pushd "%PROBE_OUT%" || exit /b 6
rem Keep each target's compiler environment independent.
setlocal
call "%PROBE_VS%\Common7\Tools\VsDevCmd.bat" -no_logo -arch=x86 -host_arch=x64 || exit /b 7
cd /d "%PROBE_OUT%" || exit /b 8
cl.exe /nologo /c /std:c11 /O1 /W4 /WX /GS- /Zl /Focanary_i386.obj "%PROBE_ROOT%canary_i386.c" || exit /b 10
lib.exe /nologo /machine:x86 /def:"%PROBE_ROOT%msi_ordinals_i386.def" /out:msi-ordinals.lib || exit /b 11
link.exe /nologo /dll /nodefaultlib /machine:x86 /entry:DllMain@12 /def:"%PROBE_ROOT%canary_i386_msvc.def" /out:madeira-msi-probe-i386.dll canary_i386.obj msi-ordinals.lib msi.lib advapi32.lib kernel32.lib || exit /b 12
> canary.rc echo 1 10 "madeira-msi-probe-i386.dll"
rc.exe /nologo /fo canary.res canary.rc || exit /b 13
endlocal
setlocal
call "%PROBE_VS%\Common7\Tools\VsDevCmd.bat" -no_logo -arch=x64 -host_arch=x64 || exit /b 14
cd /d "%PROBE_OUT%" || exit /b 19
cl.exe /nologo /c /std:c11 /O1 /W4 /WX /GS- /Zl /Focanary_host.obj "%PROBE_ROOT%canary_host.c" || exit /b 15
link.exe /nologo /nodefaultlib /machine:x64 /subsystem:console /entry:start /out:madeira-msi-canary-x86_64.exe canary_host.obj canary.res msi.lib ole32.lib kernel32.lib || exit /b 16
dumpbin.exe /nologo /headers /imports /exports madeira-msi-probe-i386.dll > canary_i386_metadata.txt || exit /b 17
dumpbin.exe /nologo /headers /imports madeira-msi-canary-x86_64.exe > canary_host_metadata.txt || exit /b 18
endlocal
echo Compile-only outputs ready in %PROBE_OUT%. No executable has run.
popd
exit /b 0
