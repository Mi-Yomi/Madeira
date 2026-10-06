# Playport FEX guard backports

These two patches adapt Playport v0.3.3 commit
`e962e9b75b04503dfbf476e76cb7264d19368ed2` to Madeira's unchanged willfaust/FEX
pin `1adb337a2f2270434ba731346438c072337a5d5f`.

- `../0005-wow64-smc-write-fault-only.patch`: Playport <dev@playport.invalid>,
  [original 0020 patch](https://github.com/playportdev/playport/blob/e962e9b75b04503dfbf476e76cb7264d19368ed2/patches/fex/0020-WOW64-leave-a-guest-s-read-fault-in-an-RWX-interval-.patch).
  Keep the target's original host-space address and require write faults at the
  existing thread/SMC gate; do not import an extra guest-window translation.
- `../0006-arm64ec-require-jit-rw-alias.patch`: The Playport authors
  <dev@playport.dev>,
  [original 0007 patch](https://github.com/playportdev/playport/blob/e962e9b75b04503dfbf476e76cb7264d19368ed2/patches/fex/0007-ARM64EC-refuse-to-start-on-iOS-without-the-JIT-pool-.patch).
  Return failure before InitCore on the existing zero-offset path and use a
  fixed diagnostic with a bounded length. Retain valid-alias parsing/behavior.

Playport's [pinned licensing statement](https://github.com/playportdev/playport/blob/e962e9b75b04503dfbf476e76cb7264d19368ed2/docs/LICENSING.md)
licenses its own FEX patch lines under GPL-3.0-or-later with the additional
permission preserved verbatim in `PLAYPORT-LICENSE-EXCEPTION.md`.
`PLAYPORT-LICENSE` is the verbatim license from that commit. These permissions
do not relicense another author's work. Original FEX portions retain MIT;
Madeira fork contributions retain their own GPL/additional-permission terms
in the pinned FEX `LICENSE-MADEIRA.md`.

The complete unmodified Module.cpp copies in
`tests/host/fixtures/fex-pe/{ARM64EC,WOW64}/` retain their original notices,
with full source URLs and blob identities in that directory's provenance.
They include upstream and Madeira fork source, before these Playport repairs.
`LICENSES/MIT-FEX.txt`, the top-level `LICENSE` and `LICENSE-EXCEPTION.md`, and
the pinned fork's license notice continue to apply to their respective code.

For corresponding-source distribution retain the unchanged FEX pin, the five
ordered source repairs and manifest, these notices/license texts, fixture
provenance, and the applicable rebuild scripts and verified PE build receipts.
Source integration alone does not prove inclusion in a native archive, DLL
or packaged IPA.
