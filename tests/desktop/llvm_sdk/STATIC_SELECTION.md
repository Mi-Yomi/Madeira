# Exact static archive member selection

The full-verbose DIA diagnostic in
[run 37475203743](https://github.com/Mi-Yomi/Madeira/actions/runs/37475203743)
recorded 320 loaded members, including 225 static-member loads. Every load has
a `Found` context. Exactly one static load is ambiguous by basename:

`Found _handle_nan` → `Referenced in libucrt.lib(ceil.obj)` →
`Loaded libucrt.lib(libm_error.obj)`.

The exact recorded `libucrt.lib` is 43,342,854 bytes with SHA-256
`ea2ffa5d9b1ebc3fa76f34c364471750db8951b341dbccbc1bef628ef1a20e39`.
The two candidates are ordinary `mt` at archive-header offset 41071970,
35,537 bytes, and `mt_fma` at offset 42511290, 35,616 bytes. Both have x64 code
and no recorded CRT/default/import directives. Those equal policy properties
do not identify the chosen member. The linker later discards all six named
functions from this member, including `_handle_nan`, so the final map cannot
resolve its archive offset.

No existing result proves which candidate was loaded. The correction adds a
bounded metadata proof for **every** ambiguous static load in the complete
trace. It does not choose the first basename, force a member, modify an archive
or change the link command. Existing CRT, DIA, PE-import and runtime boundaries
remain in effect. The request token remains unchanged until an explicit run is
requested separately.

## Proof chain

1. Bind each `Found`, optional `Referenced in`, and `Loaded` block to the same
   verified archive search context. Retain raw/demangled display text and the
   exact decorated symbol. Basename labels collect every matching member,
   including archives mixing bare and full stored names. Physical header offset
   is the object identity; duplicate member names are never dictionary keys.
2. Read both archive linker directories from the same hash-recorded archive.
   Independently scan physical headers and compare complete names/offsets/sizes
   with the earlier provider inventory. Validate counts, boundaries, offset
   ordering, 1-based indices, symbol ordering, canonical padding and hashes.
3. Preserve every symbol entry and multiplicity in both directories. The two
   directories must agree on symbol-owner sets. Duplicate entries with one
   owner are not silently erased; multiple distinct owners for the requested
   trigger remain rejected. The second directory's unique owner must match one
   of the loaded label's candidates. Microsoft documents the
   [two directory formats and preferred second index](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#second-linker-member).
4. Run the already selected `dumpbin /linkermember` as a reader and compare both
   native entry multisets, counts and offsets with the byte-parsed directories.
   [Microsoft documents](https://learn.microsoft.com/en-us/cpp/build/reference/linkermember)
   the first offset view and the second object-index view. Unexpected/missing
   native output rejects; no parser fallback invents mappings.
5. Read each ambiguous candidate transiently in memory. Record its full name,
   header offset, size/hash, actual trigger-symbol records and section/COMDAT
   metadata. The selected candidate must strongly define the exact trigger;
   undefined, common, weak/alias, conflicting or unsupported definitions reject.
   Directives, machine and section counts must match the earlier inventory.
6. Recheck archive hashes and bind the proof back to that exact loaded event.
   Only then can the existing selected-member CRT and DIA gates continue.
   Record all unresolved groups before failing; an early valid group cannot hide
   a later ambiguous or malformed one.

Loading an archive member and retaining its code after COMDAT/dead-code
processing are distinct claims. This proves extraction identity, not a surviving
implementation, ABI compatibility or runtime success.

The existing OS-import ambiguity treatment is unchanged. Two actual native
`Found` roots use the DEL-prefixed `*_NULL_THUNK_DATA` spelling; it is retained
only within the verified OS-import context. The static archive reader continues
to reject nonprintable symbol names and is not invoked for those import groups.

## Evidence and bounds

New records include `STATIC_SELECTION_SCOPE`, `STATIC_ARCHIVE_INDEX`,
`STATIC_INDEX_NATIVE_LINE`, `STATIC_INDEX_NATIVE_MATCH`,
`STATIC_CANDIDATE_METADATA`, `STATIC_SELECTION_PROOF`, failures and a summary.
Vendor object code/data bytes are never emitted, encoded, copied out or executed.
Only index/symbol/header metadata and hashes are retained. Source-owned probe
capture remains separate under its existing 128 KiB cap.

After verifying the provider hash, the bounded native DUMPBIN text is captured
before the custom raw reader runs. `STATIC_INDEX_NATIVE_CAPTURE` binds that text
and labels raw-index validation as not yet evaluated. A raw-format rejection
therefore retains native evidence while still blocking every proof/acceptance
gate. Unsupported directory/name padding reports bounded metadata offsets,
lengths, at most 16 prefix bytes in hex and a digest; object payload bytes are
never included. Header/alignment failures retain only their metadata context.

The captured native DIA text validates the symbol/offset **display**, not raw
directory/name-table padding. Raw padding coverage comes from the preserved
LLVM SDK archives and explicitly reconstructed fixtures. Only the existing
canonical rules are accepted: one external LF after odd archive members, one
internal NUL after an odd consumed index payload, and one internal LF after an
odd complete longnames table. Microsoft UCRT writer-specific padding remains
unverified; unsupported forms reject rather than being normalized or guessed.

Existing ten-minute workflow, seven-minute watchdog, process/memory containment,
64 MiB work limit, 8 MiB command logs, 32 MiB evidence limit and 3 GiB free-space
floor remain unchanged. New inner caps are 16 indexed providers, 128 ambiguous
loads, 64 candidates per load, 64 MiB aggregate candidate bytes, 8 MiB per
candidate, 16 MiB per index/name table, one million indexed entries, and 100,000
archive members. Each native index read has a 45-second deadline. All caps are
stops, not permissions to expand the existing overall job budget.

Archive dates are inert metadata and never determine a boundary or selection.
Raw date text and header/payload hashes are retained. The parser accepts ordinary
decimal/blank dates and the exact `-1` sentinel interpretation consistent with
the captured native `FFFFFFFFFFFFFFFF` display; other malformed forms reject
with raw date bytes/hash. The native archive's actual sentinel serialization
has not been observed, and this is not a claim that the raw Microsoft header
dialect has already passed this reader.

### File identity failure evidence

Revision 5 stopped in three reconstructed test fixtures at the unchanged
five-field `stat`/`fstat` equality check. The two content hashes had already
matched, but the failing fields and exact Python version were not recorded.
That result proves neither archive mutation nor a particular Windows cause.

On an identity mismatch, `ARCHIVE_IDENTITY_EVIDENCE` now carries the four
original observations, all six pairwise field differences, both content hashes,
and bounded Python/Windows version metadata in the rejecting exception. All
stat scalars are decimal strings (or null when unavailable), preserving
nanoseconds and 128-bit file IDs in JSON consumers. The actual gate still
compares native integer values. Birth/access times and file attributes are
diagnostic only. There are no extra file observations or retries, and no
payload bytes or paths in this record. The failure message, including its JSON
evidence and fixed prefix, is capped at 8 KiB; an
overflow records only its size/hash and still rejects. Existing overall log
and evidence caps continue to apply.

[CPython 3.12.10 path stat](https://github.com/python/cpython/blob/0cc81280367df838c4b199f8f0378837165071c2/Modules/posixmodule.c#L2138)
overwrites change time with birth time for compatibility, whereas its
[handle stat implementation](https://github.com/python/cpython/blob/0cc81280367df838c4b199f8f0378837165071c2/Python/fileutils.c#L1271)
retains native `ChangeTime`. Microsoft defines `CreationTime`, `LastWriteTime`
and `ChangeTime` as [separate fields](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_basic_info).
This is a plausible cross-API discrepancy, not the established cause of the
revision-5 failure. The diagnostic must show stable path-to-path and
handle-to-handle observations, only cross-API `st_ctime_ns` disagreement, and
the expected birthtime relationship before that explanation is supported for
the actual sample. No identity field is removed or normalized by this change.

## Verification boundary

The fixtures separate actual captured evidence from reconstructions:

- The complete selection-event excerpt from revision 4 preserves all 320 loads,
  every corresponding `Found`/referrer/search event, and all 226 candidate rows
  needed for its 225 static loads. Its lone ambiguity stays unresolved locally
- The actual earlier DIA DUMPBIN output is checked against separately captured
  DIA symbol definitions. It validates native text parsing, not unseen raw DIA
  directory bytes
- Reconstructed archives exercise both index formats, duplicate names/symbols,
  conflicting owners, invalid offsets/indices, malformed headers/strings/padding,
  native-reader disagreement, strong-definition/COMDAT mismatch and limits

The pure reader also passed 240 preserved official LLVM SDK static archives,
4,041 objects and 460,252 distinct-per-archive symbols. Six import archives were
explicitly outside scope. This is offline parser evidence, not validation of the
installed UCRT archive or a new native link.

No full SDK/MCJIT, Mesa, Blender, Wine/FEX or iOS result follows. All 117 provider
findings remain unapproved; even a successful minimal DIA result cannot stand in
for complete LLVM selected-member proof.
