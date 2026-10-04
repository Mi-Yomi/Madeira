# Pinned LLVM 15 and DXMT graphics bootstrap

This isolated gate uses the standard public GitHub `xcode-27` ARM64 runner,
at most two compile jobs and a 45-minute total job limit. It uploads no artifacts,
creates no cache, uses no signing identity and does not modify upstream sources.
Existing native dependency CI is independent.

Run from a fresh checkout on an ARM64 Xcode 27 host:

```
git submodule update --init --recursive dxmt
bash build/llvm-ios/build.sh fetch
bash build/llvm-ios/build.sh host
bash build/dxmt-ios/generate-shaders.sh
bash build/llvm-ios/build.sh ios
python3 build/dxmt-ios/clean_build.py
```

The official Metal Toolchain must already be available. CI uses the existing
explicitly authorized Apple setup helper and fails on new terms/authentication.
LLVM is fetched from its official repository at the exact LLVM 15.0.7 commit in
`manifest.json`. `llvm-dis` and `llvm-tblgen` are built for the host first.
Each of the three raw AIR modules must decode with that LLVM 15 reader before
the longer iOS build starts; a newer Apple bitcode format must fail this gate,
not be silently accepted. Command-library shaders keep the existing Metal 3.1
and AIR macOS 14 target flags; this is build compatibility, not device proof.

The iOS stage builds the explicit 34-archive closure of BitWriter and Passes,
with LTO disabled and LLVM assembler disabled. Every object is required to be
native iOS ARM64 Mach-O, never host objects or bitcode. The DXMT fresh-build
driver rejects existing output and incremental overrides, verifies all expected
objects including D3D12 conversion objects, and merges explicit archive inputs
using Apple libtool, preserving same-named members. Hash receipts accompany the
staged combined archive; consumers must verify them after any interrupted run.

Passing does not prove final application linking, a usable IPA, 1C operation or
Blender rendering. Those are separate later gates. LLVM uses iOS 17 as its minimum;
the established DXMT recipe retains its iOS 18 minimum.
