# Neutral COFF collection witnesses

`neutral-crt-captured-evidence.json` retains the actual raw headers and native
`dumpbin /headers /symbols /directives /relocations` output for the first members
of `libcmt.lib` and `oldnames.lib`, collected on Windows on 2026-10-05. Its source
file name and SHA-256 identify the preserved diagnostic log. The native text
records reproduce each captured native-reader SHA-256 when joined with LF and
one final LF.

The two `*-neutral-reconstructed.json` files are **reconstructed format
witnesses, not genuine compiler output**. The original CRT member bytes were
not retained. They preserve the captured 56-byte header, size and symbol
expectations. The missing section-characteristics word and all symbol,
auxiliary and string-table bytes are constructed from the native-reader
description; unretained `.debug$S` payloads are zero-filled. Their own digests
differ from the original member digests. These witnesses establish parser
behavior for the captured structure, not byte-for-byte inspection of a CRT
object, CodeView content, link selection, or ABI compatibility.

The [Microsoft PE/COFF format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types)
describes machine 0 as applicable to any machine type. Collection is deliberately
narrower: regular COFF only; zero sections or one exact read-only discardable
`.debug$S` section with flags `0x42100040`; no relocation or line-number tables;
one untyped undefined external and one weak alias using search mode 3; and only
the local absolute `@comp.id` / `@feat.00` tags (required with the debug section).
The section-free form preserves the earlier inert test case. Unknown layouts,
code/data/import/directive sections and non-alias weak searches remain rejected.

`neutral_cases.py` supplies both host checks with the same negative mutations.
The inventory check additionally verifies that later archive members are still
read and that their CRT directives and wrong architectures still fail closed.
Every neutral member retains machine `0x0000` and `provider_approved: false`;
successful evidence collection is not provider or link approval.
