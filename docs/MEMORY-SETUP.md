# Memory+ setup

**Settings → Memory+ → Memory+ setup** checks the signed running process and
shows current advisory memory headroom. The developer interface's **Memory+
setup** action opens the same page with a **Done** button. It refreshes on entry,
when returning to the app, every two seconds while visible and active, and when
**Check again** is tapped.

The green entitlement result comes from `EntitlementStatus.check()` and the
running process's code signature, not from `Madeira.entitlements` in the source
tree. A missing entitlement and a failed entitlement query both display **not
detected**. This is a read-only setup page, not an account or signing client.
The underlying entitlement reader now balances both retained Core Foundation
Create/Copy results, so repeated checks do not leak their task/value objects.

- **Available now** is a fresh `os_proc_available_memory()` sample through
  `jit_available_memory()`. It is additional allocatable memory at that instant,
  not the total process limit, guaranteed usable memory, or free system RAM.
  Zero is displayed as unavailable or exhausted, never as a measured zero-RAM
  device. The app does not allocate memory to test the limit.
- **Device physical RAM** is shown separately. It is not used to infer the app's
  memory limit, including on an iPhone 16 Pro Max or iOS 27.
- **Extended virtual addressing** is a separate signed entitlement. Address
  space is not physical RAM. It is not required to turn the Memory+ badge green.
- In the simulator, the page asks for an on-device check. In LiveContainer it
  explains that the host process owns the entitlement and hides the guest bundle
  identifier as a signing target. Its separate instructions target the host's
  build, App ID, provisioning profile and reinstall, preserving host data.

## What activation requires

Madeira already requests
`com.apple.developer.kernel.increased-memory-limit`. The signing App ID,
provisioning profile and installed signature must support the capability. After
enabling it for the correct App ID, regenerate the profile and re-sign/reinstall
using the same signing account and bundle identifier. Back up games and saves
first; deleting Madeira is not part of these instructions. Reopen Madeira to
verify the installed result. Account eligibility and device behavior must be
verified rather than inferred from a version number.

The installed bundle identifier is shown because sideloaders can rewrite it.
The page neither uploads that value nor collects Apple credentials. External
documentation opens only through a user-selected link. It does not modify an
Apple account, provisioning profile, device security setting or JIT setup.

## GetMoreRAM integration assessment

The official project is [hugeBlack/GetMoreRam](https://github.com/hugeBlack/GetMoreRam).
At audited commit
[`52f5e964cf262dd1b8f4a1b93cde22b79a1fdd3f`](https://github.com/hugeBlack/GetMoreRam/tree/52f5e964cf262dd1b8f4a1b93cde22b79a1fdd3f),
its App ID model invokes StosSign's Apple account API to enable
`INCREASED_MEMORY_LIMIT`. Its README then requires reinstalling through
SideStore/AltStore. It does not grant memory to an already-running process.
The audited app declares no external activation URL scheme.

This is distinct from Madeira's existing built-in JIT helper: JIT uses a paired
debugger connection to the running Madeira process; it does not provision an
Apple account capability or re-sign Madeira.

No GetMoreRAM code or dependency has been copied or bundled here. Neither the
audited GetMoreRAM tree nor its pinned StosSign dependency
[`01dd7bc4f5084ade9e2ebbc7e338dc2e3f454d77`](https://github.com/stossy11/StosSign/tree/01dd7bc4f5084ade9e2ebbc7e338dc2e3f454d77)
contains a license grant. Permission and a dependency/license review are needed
before directly redistributing them. A future independently implemented signing
client would additionally require an account-security design, explicit account
and App ID confirmation, secure user-controlled authentication, and a supported
re-sign/reinstall workflow. This patch does not claim that full integration.

## Primary references

- [Apple: Increased Memory Limit](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.kernel.increased-memory-limit)
- [Apple: os_proc_available_memory](https://developer.apple.com/documentation/os/os_proc_available_memory)
- [Apple: Extended Virtual Addressing](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.kernel.extended-virtual-addressing)
- [GetMoreRAM activation code](https://github.com/hugeBlack/GetMoreRam/blob/52f5e964cf262dd1b8f4a1b93cde22b79a1fdd3f/GetMoreRam/AppIDViewModel.swift)
- [GetMoreRAM installation requirements](https://github.com/hugeBlack/GetMoreRam/blob/52f5e964cf262dd1b8f4a1b93cde22b79a1fdd3f/README.md)

## Verification

`python3 tests/host/check-memory-setup.py` compiles the exact presentation model
and exercises signed-entitlement/headroom independence, unavailable samples,
simulator and hosted installations, and renamed/missing bundle identifiers. It
also checks runtime sampling, navigation, refresh and build/CI wiring.
`--source-only` is an explicitly limited fallback when Swift is unavailable.
`--ios-typecheck` checks the complete SwiftUI file and the actual entitlement
reader declarations against the iPhoneOS SDK with only runtime dependencies
stubbed. Both compiled modes are wired into the macOS CI job.

Before shipping, build with the iOS SDK and inspect the page on device in both
interfaces, with and without the signed entitlement, after background/foreground
and repeated navigation. Re-sign/reinstall verification requires the user's
signing workflow; no account mutation is part of host tests. Check small screens,
large Dynamic Type, VoiceOver, link return and **Check again**. Do not represent
host tests as proof of an increased memory limit on a real iPhone.
