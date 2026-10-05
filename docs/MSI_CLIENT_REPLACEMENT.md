# Reviewed MSI custom-client failure integration

This layer replaces exactly two msi.dll files after the existing desktop, MSI
and AVICAP32/ACTIVEDS integrations. It preserves their complete receipts and
all existing app notices byte-for-byte. No historical source or audit is edited
to claim it built the newer binaries. i386 remains inactive outside the app.

## Fixed source and provider identities

The Wine revision remains 4f5b19718f4de88ecc5cb0dc08b119497a67ba8f.
Only custom_client_thread changes relative to the earlier reviewed MSI source.
The old custom.c hash is
31c63ede3acf225cfe4d9d772a00b752e82410ebcb060f58f0bfbc9f9e2ea0c5;
the new source hash is
9c6db8469d1db7d1fff83af45e4f4851238e3b09fc06055996cfbb956fd6af50.
The incremental patch hash is
6dc3802f26e98a0cc03462b989e2d3619b74f9374d325784009c1df5a8623ebe.

| App resource | Bytes | Before SHA-256 | After SHA-256 |
| --- | ---: | --- | --- |
| aarch64-windows/msi.dll | 1572864 | 12bbe1e84a6ef12b6775f1e081e69e404736d9be5b118fa322d989d9f1b93221 | c04b4aa74963caa1043229c8d2fbf4b4a09c94a7684107335cddb5fde2b2356a |
| arm64ec-windows/msi.dll | 1769472 | 30fca59166929f1300d7708d45d56b401e680d0318b0ce7d7ff754987177f30d | 3c69a7becb0ee31974fb7b0cf9785095b0d3d77551a87dd337257358c37924ae |

The inactive i386 provider is 1208320 bytes, SHA-256
1fe600254f476fb48e9b9694f7b4e9ef7b7bdc1980358cc5d0727186d9dc2b23.
It appears only in the sealed build evidence, never in app/Madeira/i386-windows.

## Provenance and unchanged contracts

The build seal is
55f90bf94f2a67a1c9c25bf1dbb29311e2277e2d1d996d54a8753b538cae8833.
Its 168 payload files and original SHA256SUMS are retained unchanged under
build/wine-pe/receipts/msi-client-2026-10-05/build/. The outer integration seal,
98c5adfb9a4e8bee95eadfcf390898eb7cc49059a4c436de86d29c4bfe61cc23,
adds two current-farm inventories, two MSI symbol audits, two LLVM dumps and
an integration notice, for 177 files including the outer index. Eight compiler
logs are legitimately empty; the new bounded verifier permits only those exact
paths to be zero-byte files. Historical verifiers are unchanged in that regard.

Both complete farms still contain 150/159 modules. Their complete static
dependency graph and architecture reports match the previous loader stage
except for the two fixed MSI hash identities. The residual missing-module
edges remain 13/10. The new MSI audits bind every current resolver input,
including the later loader additions, and resolve 327/328 imported symbols.
All 296 export names, ordinals and forwarders per architecture and all normal
and delay import symbol contracts match the original provider PE bytes.

The app resource gate retains all tracked-resource and no-i386 checks. The
guest receipt binds the new seal, source hash, both old identities and both
new identities while retaining the earlier desktop, MSI and loader seals.
The link diagnostic compares that exact same receipt contract to the current
source gate and final app bytes. No packaging or execution authority is added.

The complete pinned Wine source and applicable relinking material remain
required for redistribution. The compact receipt contains the changed source,
both patches, complete source identities, build recipes, object/link input
identities, toolchain provenance, host tests, independent review and notices.
It is not by itself a full source or LGPL compliance distribution. Existing
Wine, compiler-rt, zlib and toolchain notices remain unchanged; four new app
notices add the incremental patch, modifications, rebuild and integration notes.

## Read-only handoff and rollback

Before writing any integration files, run the reviewed planner from the
integration source directory against the still-unmodified target. Use the
source patch only with its exact file preconditions:

```sh
python3 /path/to/integration/build/wine-pe/plan_msi_client_integration.py --stage /path/to/msi-client-receipt --root /path/to/reviewed-loader-checkout
```

The planner performs no writes and emits 183 copy operations: two exact MSI
replacements, four new notices, and 177 new receipt files. It verifies the
complete previous farm and all historical seals before returning the plan.
Every non-replacement destination must be absent. No arbitrary module/hash
map is accepted. The integration JSON is part of the separate source patch;
apply it together with the planned files, then run the final validator.

Rollback restores the two old binaries from the unchanged historical MSI
receipt only when the current bytes still equal their exact after identities.
Remove added evidence and notices only when their identities still equal the
plan. Reverse source edits only when their complete after identities match.
Preserve unrelated changes and re-review any mismatch. After rollback, remove
the empty new receipt directory and revalidate the original loader stage.

```sh
python3 tests/host/check-msi-client-integration.py
python3 -O tests/host/check-msi-client-integration.py
python3 tests/host/check-msi-integration.py
python3 tests/host/check-loader-integration.py
python3 tests/host/check-desktop-integration.py
python3 tests/host/check-app-bootstrap.py
python3 tests/host/check-app-link-diagnostic.py
python3 build/wine-pe/verify_desktop_integration.py
```

The new mutation suite exercises unauthorized before/after changes, additional
providers, partial replacement, historical record rewriting, changed/untracked
source or audits, symlinks, missing notices, graph changes, core substitutions,
i386 case variants, the read-only plan, forward application, guarded rollback
and byte preservation with core.autocrlf=true.

102/102 production-derived host scenarios pass normally and with the recorded
sanitizer setup; the old baseline fails 46. Ordinary successful custom actions
and supported 64-bit behavior are covered at that host-control-flow level.
Guest custom actions, Wine/iOS behavior, actual app linking, device support,
Blender, 1C and package readiness remain unverified. No guest execution,
app/IPA build, signing, download or publication forms part of this integration.
