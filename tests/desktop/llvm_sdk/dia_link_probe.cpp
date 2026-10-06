// SPDX-License-Identifier: MIT
// Link-only diagnostic: this executable must never be run by the harness.
#include <windows.h>

#if !defined(_MT) || defined(_DLL) || defined(_DEBUG)
#error This diagnostic requires the release static MSVC CRT
#endif

// These source-owned declarations intentionally avoid ATL/PCH inclusion.
// The compiled COFF names must match the three real LLVM DIASession references.
HRESULT __cdecl NoRegCoCreate(LPCWSTR, REFCLSID, REFIID, void **);
extern "C" const CLSID CLSID_DiaSource;
extern "C" const IID IID_IDiaDataSource;

int main() {
  void *result = nullptr;
  // A real call retains the helper and both GUID relocations without /INCLUDE.
  // NoRegCoCreate is never executed: the workflow stops after link/inspection.
  return static_cast<int>(NoRegCoCreate(L"msdia140.dll", CLSID_DiaSource,
                                      IID_IDiaDataSource, &result));
}
