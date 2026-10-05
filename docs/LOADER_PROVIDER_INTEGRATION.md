# Reviewed AVICAP32 and ACTIVEDS integration

The October 5, 2026 change adds only avicap32.dll and activeds.dll for AArch64
and ARM64EC after the reviewed desktop and MSI additions. Exact names/hashes
are fixed in build/wine-pe/verify_loader_integration.py. Editing a resource
manifest cannot authorize a different DLL. No core DLL or notice is replaced.

## Source and evidence

Wine stays at 4f5b19718f4de88ecc5cb0dc08b119497a67ba8f, tree
91d4283d3287eda28daf932254db8c6a790a8eb4. These four DLLs use pristine source;
the separate MSI custom.c patch is irrelevant to these providers. The original
offline build retains complete source. The bundled manifest identifies all
10,958 source files by Git blob, mode, size and SHA-256; the source repository
remains available at the unchanged Wine gitlink. Preserve corresponding source
and applicable relinking material with redistribution; a manifest is not a
substitute. See app/Madeira/legal/Wine-loader-INTEGRATION.md for notices.

The loader receipt contains 60 files: the original 54 indexed build files
plus unchanged SHA256SUMS under build/, four combined-farm JSON reports and the
outer SHA256SUMS. The original build seal is
d3f405e38d8a4749e54ee6aab53fd034400424b8233555500dfde3cbdaca08ae;
the integration seal is
033316ebff397f5988935ecc653171c25f0341aecb856a79a2190abb6b694df5.
The original desktop 55-file and MSI 109-file seals remain byte-exact.
Historical paths/revisions in the nested receipt describe the original build.
The receipt is at build/wine-pe/receipts/loader-2026-10-05/.

The combined inventories contain 150 AArch64 and 159 ARM64EC PE modules.
Independent LLVM counts agree with the complete symbol parser: AVICAP32 has
32 imports/four exports; ACTIVEDS has 54 imports/28 exports. All 86 imports per
architecture resolve through the actual combined farm, including API sets and
dependency forwarders. No candidate delay imports or export forwarders exist.
The historical desktop 14/11 missing module edges are still checked; MSI closes
only setupapi's cabinet delay edge, leaving exactly 13/10. These four additions
leave those residual gaps unchanged.

## Static checks and read-only handoff

```sh
python3 tests/host/check-loader-integration.py
python3 -O tests/host/check-loader-integration.py
python3 tests/host/check-desktop-integration.py
python3 tests/host/check-msi-integration.py
python3 build/wine-pe/verify_desktop_integration.py
```

The app gate requires tracked receipts, exact hashes/architecture, both original
baselines and the actual full farm. It rejects partial copies, absent notices,
symlinks, arbitrary additions, core substitutions, edited/incomplete audits and
i386 payloads. App evidence separately records the loader seal and four hashes.

Before integration, use the read-only planner against a reviewed MSI target:

```sh
python3 build/wine-pe/plan_loader_integration.py --stage /path/to/loader-receipt --root /path/to/msi-target
```

It emits 65 add-only copies: four providers, one source/rebuild notice and
60 evidence files. Three existing Wine notices must match and remain unchanged.
A separate source patch adds the integration notice/record, validators, tests
and docs. No recipe is executed by the planner.

Apply only if every source-patch pre-state hash matches, all copy destinations
are absent, and original farm/notices and Wine pin still match. Preserve
unrelated changes; a mismatch requires fresh review. Roll back new files only
when current identities still match handoff post-states; reverse source changes
only when their complete post-states still match. Recheck old seals and the
applicable complete validator after integration/rollback. i386 stays inactive.

## Behavior and limits

AVICAP32 closes the measured module/name gap. Its inspected unavailable-backend
path returns failure without altering caller buffers; retained ASan/UBSan host
checks cover 24 calls. No camera backend, permission request, enumeration success
or capture success is added. DLL attach/window registration and real ARM64/EC
Unix-call dispatch need an owned iOS load/unload and unavailable-device canary.

ACTIVEDS ordinal 3 supplies real ADsGetObject dispatch. It supplies no WinNT/LDAP
provider and adds no provider registration, account creation or successful service-user setup;
several other APIs remain unimplemented. No COM registration occurred.
Blender startup, 1C success, package readiness and Wine/iOS application support
remain unproven. No guest execution, app/IPA build or signing was performed.
