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

`msvc-14.51-source-probe.coff` is the actual 1,374-byte object compiled from this
repository's MIT-licensed `dia_link_probe.cpp` on Windows in run 37470687893.
Its companion JSON records source/compiler/object/log hashes, the exact compile
command and actual raw/parsed directives. Source provenance distinguishes the
actual Windows CRLF checkout from canonical LF bytes. The object was never
linked or run. It demonstrates the two `uuid.lib` pragmas plus `LIBCMT`/`OLDNAMES`
defaults; mutations verify that unrelated libraries and dynamic CRT substitutions
remain rejected. This fixture is distinct from the upstream LLVM object above.

`msvc-14.51-lib-search-only.log` and `msvc-14.51-source-probe.map` contain the
actual captured output from the successful native link in run 37472598696.
Their companion `msvc-14.51-lib-search-only.json` records the source, tool,
provider and log identities and LF text reconstruction. The 66-line trace has
no `Loaded` records, while the map gives the three expected DIA owners. Tests
require this real pair to remain rejected as incomplete member-selection proof.
They do not invent a successful full-verbose transcript.
