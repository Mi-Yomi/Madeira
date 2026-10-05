# Independent read-only artifact review

Reviewed 2026-10-05. Result: no blocking findings.

- Exact baseline, incremental patch and final custom.c hashes match. Applying
  the incremental patch in memory reconstructs the final source
- All three DLLs and custom.o files match receipts. All 234 explicit link-input
  records match, including the retained generated spec objects
- Independently reparsed original/replacement contracts match: 296 exports
  each; 327/328/328 normal imported symbols; no delay imports
- ARM64EC custom.o has machine 0xa641. The final PE has AMD64 on-disk machine
  0x8664 with valid CHPE v2 metadata, a 320-byte load config and two code-map entries
- All 10,958 Wine source files, 64 recipe inputs, 5,392 generated build entries,
  8,282 toolchain entries and 403 host/prerequisite records match
- Both preserved workspaces remain unchanged: all 16,911 original provider
  workspace entries and all 43 source-review entries, with no additions/removals
- Reversing only the generated Makefile's `-v -save-temps` insertion reproduces
  each recorded pre-instrumentation hash
- README, reproduction steps and verifier are consistent. The read-only
  `verify_package.py` invocation passes
- All 167 compact-seal entries checked at review time matched. The reviewed
  pre-review-report seal SHA-256 was
  `2d6f08da9db171b43aea425284cb6286c0145a1cccadf5319490b68498b2839a`

This report was added after review and the compact package was then resealed.
The final current seal is `SHA256SUMS`; the hash above identifies the reviewed
payload before this report and its README pointer were added.

Limits remain accurately stated: MSI-specific static coverage, non-hermetic
host inputs, no bitwise reproducibility guarantee and no guest/runtime proof.
