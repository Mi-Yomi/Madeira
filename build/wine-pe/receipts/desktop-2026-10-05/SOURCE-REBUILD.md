# Rebuild this uninstalled Wine desktop overlay

Wine commit: `4f5b19718f4de88ecc5cb0dc08b119497a67ba8f`; Git tree: `91d4283d3287eda28daf932254db8c6a790a8eb4`.
Madeira base commit: `62b0895cb87fda94e6307fa2bdbdbfc32d28d31d`.
`source-inputs.json` contains SHA-256 hashes of every actual Wine source file
and captured build input. Wine blobs/modes were checked against the pinned tree.
`rebuild-inputs/` includes local recipe additions not present at the base commit.
`toolchain-receipt.json` binds all extracted files/links to the official archive.
`provenance.json` separately records host tools; this is not a hermetic host image.

1. Clone https://github.com/Mi-Yomi/Madeira.git and check out
   `62b0895cb87fda94e6307fa2bdbdbfc32d28d31d`. Initialize only its exact Wine submodule:
   `git submodule update --init wine`. Keep Wine adjacent to `build/`.
2. Verify this package with `sha256sum -c SHA256SUMS` (or a SHA-256 equivalent).
   Copy `rebuild-inputs/.` into the Madeira checkout, preserving relative paths.
   Keep the complete corresponding Wine source at https://github.com/willfaust/wine.git
   and the exact revision above available when redistributing the binaries.
3. Supply the host compiler, make, bison 3.0+, flex, m4 and shell tools recorded in
   `provenance.json`. Relocated bison needs its matching package data and M4;
   a wrapper's hash alone does not capture those external host dependencies.
4. Obtain `llvm-mingw-20260421-ucrt-ubuntu-22.04-x86_64.tar.xz` from https://github.com/mstorsjo/llvm-mingw/releases/download/20260421/llvm-mingw-20260421-ucrt-ubuntu-22.04-x86_64.tar.xz.
   Its expected SHA-256 is `f8b8cce779affeab47bcaec6ce6e9e768b166094a366123ef64b2d0b389cc121`. Verify before extraction or
   execution. The recipe rechecks both archive and extracted installation.
5. From the fresh Madeira root run, with new output and actual absolute paths:

   python3 build/wine-pe/build_desktop.py --build --arch aarch64 --arch arm64ec --jobs 2 --toolchain /path/to/llvm-mingw/bin --toolchain-archive /path/to/llvm-mingw-20260421-ucrt-ubuntu-22.04-x86_64.tar.xz --output /new/path/desktop-overlay

6. Run `python3 tests/host/check-guest-dll-inventory.py`,
   `python3 tests/host/check-desktop-symbol-audit.py` and
   `python3 tests/host/check-desktop-build-receipts.py`.
   Review provenance, notices, symbol audits and LLVM metadata, including
   unchanged pre-existing full-farm closure gaps. Static audits are not Wine
   loader, implementation, ABI, installer/COM or device tests.

All files other than SHA256SUMS itself are listed in SHA256SUMS. The checksum
index is an integrity record, not a digital signature or an external trust root.
Host/path/time-independent bitwise reproducibility is NOT established; it needs
at least two independently clean matching runs. No app resources, guest runtime,
IPA, installation, signing or publication are part of this recipe.
Keep original license notices, complete corresponding source and rebuild inputs
with any integration; this record does not settle redistribution/relinking duties.
