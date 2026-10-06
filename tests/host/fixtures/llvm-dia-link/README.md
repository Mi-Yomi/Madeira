# LLVM/DIA captured evidence

`llvm-diasession.coff` is an unchanged 74,813-byte MSVC object extracted from
the already preserved official LLVM 22.1.4 Windows SDK. It is never executed or
linked by host checks. `provenance.json` records the archive/library/member
identities, archive offset and SHA-256. The fixture proves the parser recognizes
the three actual external DIA references and their relocations. Mutated copies
exercise rejected symbol, relocation, architecture and truncation cases.

The object belongs to LLVM under Apache-2.0 WITH LLVM-exception. The full LLVM
license text is retained as `LLVM-LICENSE.txt`; its exact existing official
LLVM-MinGW source and hash are disclosed separately in provenance. The fixture
was not produced by compiling a new probe.

`captured-dia-members.json` preserves headers, directives, member hashes and
defined-symbol identities from the actual Windows provider inventory run
37311092068. It shows that `guidstr.obj` owns NoRegCoCreate, `dia2_i.obj` owns the
GUIDs, and `stdafx.obj` carries MD_DynamicRelease. It is not a real link trace.

The host test deliberately constructs synthetic link/map text and uses inert
command substitutes for workflow orchestration. Only a future bounded native
Windows job can establish the actual linker output and selected members.
