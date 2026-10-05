# Rebuild the two inactive provider DLLs

The inputs and exact command arguments are recorded under `evidence/`.
This recipe assumes the sibling `madeira-desktop-overlay-build` contains its
original, clean Wine checkout and verified LLVM-MinGW/prerequisite installation,
and `madeira-graphics-bootstrap` contains the recorded primary farms. It makes
no downloads. Rechecking against a changed farm is a new audit snapshot.

1. Verify this result using `sha256sum -c SHA256SUMS` from this directory.
2. Prepare a fresh sibling working directory, preserving these recipe files,
   `tools/`, `reference-inputs/`, `licenses/` and `build/madeira_cfg.h`.
   Copy the original clean `wine/` checkout into it with its independent Git
   metadata; do not write into or build within the original checkout. The exact
   Wine commit is `4f5b19718f4de88ecc5cb0dc08b119497a67ba8f`. Full original source
   is retained in this result's `wine/` for an offline rebuild.
3. Create an empty `evidence/` directory. Do not copy prior `candidate/`,
   `build-aarch64/` or `build-arm64ec/` directories into a fresh attempt.
4. Run `python3 build_loader_providers.py --build`. The recipe verifies all
   actual source blobs/modes against the exact pin and original tree, verifies
   every extracted toolchain member against the original official archive,
   records host/prerequisite inputs, and checks original farm preservation.
   It runs the two host-only backend tests before PE compilation, then audits
   each candidate's imports/exports using the parser and LLVM independently.
5. Review the new JSON/log evidence and required API checks. Never copy a
   partial or failed attempt into app resources. These candidates are not
   installed by the script. There is no guest/device execution or publication.

LLVM-MinGW archive: `llvm-mingw-20260421-ucrt-ubuntu-22.04-x86_64.tar.xz`,
82,139,820 bytes, SHA-256
`f8b8cce779affeab47bcaec6ce6e9e768b166094a366123ef64b2d0b389cc121`.
The verified upstream download URL and full extracted-member receipt are in
`evidence/toolchain-receipt.json`. No tool installation occurs in this recipe.

The receipt utility and symbol parser are preserved copies of the established
desktop-overlay tooling. `reference-inputs/base-build-recipe.py` is the original
bounded isolated MSI recipe used as the basis for this narrower recipe; it is
retained for provenance and is not executed. `check_avicap_absence.py` compiles
exact extracted source functions into a host-only harness. Its zero-handle
dispatcher check is static, not an ARM64 instruction execution test.

This result does not assert path/time/host-independent bitwise reproducibility.
Original license texts are preserved; complete corresponding Wine source,
local recipes, and applicable relinking material must remain available for any
later redistribution. The primary MSI integration was not changed.
