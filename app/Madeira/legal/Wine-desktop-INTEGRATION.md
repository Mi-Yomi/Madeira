# Experimental Wine desktop source-tree integration

Six source-built Wine modules are added to each of the AArch64 and ARM64EC
resource farms: avifil32, msftedit, msvfw32, netprofm, riched20 and sensapi.
No original DLL is replaced. This is source-tree integration only. It does not
establish app linking, installation, runtime, rendering, COM/installer, network,
1C or Blender compatibility. No IPA, signing or guest execution was performed.

## Exact build and source record

- Wine revision: `4f5b19718f4de88ecc5cb0dc08b119497a67ba8f`
- Wine source tree: `91d4283d3287eda28daf932254db8c6a790a8eb4`
- Corresponding source: https://github.com/willfaust/wine/tree/4f5b19718f4de88ecc5cb0dc08b119497a67ba8f
- Madeira build base: `62b0895cb87fda94e6307fa2bdbdbfc32d28d31d`
- Published tooling reference: [`f30087cddb51e1e0be0d62e134cb023192fee15d`](https://github.com/Mi-Yomi/Madeira/commit/f30087cddb51e1e0be0d62e134cb023192fee15d)
- Complete sealed 55-file evidence: `build/wine-pe/receipts/desktop-2026-10-05/`
  in the corresponding Madeira source checkout
- SHA-256 of that package's `SHA256SUMS`:
  `a0f56fd773375a2c2cc2bd76d01db0fbf28973ca1d7bf36a7dd6dbd6c9a02023`

The bundled `Wine-desktop-SOURCE-REBUILD.md` is a byte-exact copy of the sealed
rebuild record. Its references to `source-inputs.json`, `provenance.json`,
`toolchain-receipt.json` and `rebuild-inputs/` are relative to the complete
evidence directory above, not this minimal app legal folder. Keep that package
and complete corresponding Wine source available with any redistribution.
The sealed captured recipe files and source-input hashes are authoritative for
these DLLs. The later published tooling reference includes validation hardening
and is not asserted to be byte-identical to every sealed build input. Independent
clean-run, host/path/time-independent bitwise reproducibility is not established.

## Notices and validation limits

The original Wine notices are bundled without modification as
`Wine-LGPL-2.1.txt`, `Wine-LICENSE-MADEIRA.md` and
`Wine-compiler-rt-LICENSE.txt`. The bundled `THIRD-PARTY-NOTICES.md` merges the
current LGPL Wine-branch and compiler-rt information, preserving its existing
local StikJIT, idevice and Rust notice references. The integrity checks and these
records do not determine overall redistribution or relinking compliance.

The reviewed overlay has no new direct dependency gaps. The unchanged complete
farms still have 14 AArch64 and 11 ARM64EC normal/delay/forwarder dependency gaps.
These are recorded individually in the sealed architecture inventory reports;
there is no full-farm closure or device-compatibility claim.

The source gate requires all twelve DLLs, exact matching Wine notices, the
reviewed merged notice, this record and the complete sealed evidence to be
tracked. It rejects missing, substituted, untracked and wrong-architecture
additions. It does not provide an arbitrary overlay bypass. Packaging remains
separately disabled unless explicitly authorized.
