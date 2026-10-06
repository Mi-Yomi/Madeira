# Reconstructed COFF archive-index fixtures

These fixtures are source-owned, inert reconstructions. They contain no captured
vendor object bytes and are never linked or executed. `reconstructed-index.json`
describes three minimal COFF headers and the symbolic inputs used to construct
both archive linker members. Two objects deliberately have the same basename.

`check-llvm-archive-index.py` builds the archive in a temporary directory, then
constructs negative variants for malformed counts, offsets, indices, ordering,
strings, padding, headers, longnames, incomplete inventories, changed files, and
resource limits. It also covers repeated symbol entries with one owner, ambiguous
symbols with different owners, disagreement between the two indices, and repeated
full member names. Every original index entry and its multiplicity is preserved.
Only a requested trigger with one distinct, agreed owner may resolve.

The canonical padding cases are intentionally separate: archive alignment uses
one LF outside an odd-size member; LLVM index alignment uses one NUL inside an
even declared size; LLVM longnames alignment uses one LF inside an even declared
size. No other trailing index/name-table bytes are accepted.

Format references:

- https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#archive-library-file-format
- https://learn.microsoft.com/en-us/cpp/build/reference/linkermember
- https://llvm.org/doxygen/ArchiveWriter_8cpp_source.html

An optional `--sdk-lib-dir PATH` check reads preserved official LLVM `.lib` files
with the existing independent provider scanner, then compares their physical
members with this parser. Archives identified by that scanner as containing
import members are reported separately, outside this static-index proof scope.
The parser rejects nonprintable symbols, including the DEL-prefixed import
null-thunk convention. Existing OS import ambiguity handling is unaffected.
The check performs no download, process execution, build,
installation, or vendor-byte output. Its results are offline parser evidence,
not a native link, SDK acceptance, provider approval, or runtime pass.

`captured-full-verbose-selection.json` preserves all selection-related events
and the relevant actual static-member inventory from the rejected revision-4
native link. Original line numbers and full log/trace hashes identify the
excerpt. It demonstrates exactly one ambiguous static load, not its resolution.

`captured-dia-linkermember.log` is actual earlier DUMPBIN text, reconstructed
from logged lines with LF. Its JSON binds the captured text to separately
recorded DIA COFF symbol definitions and offsets. Those expected mappings test
the native text reader; they are not invented raw vendor archive bytes.
