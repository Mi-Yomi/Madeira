# Standalone softpipe package: inactive source proposal

This path preserves the already successful Windows softpipe recipe while
retaining a usable standalone test folder and its corresponding source evidence.
It does not change the ordinary reference workflow or use Actions artifacts or
caches. No build, external write, upload or target execution is authorized by
merely landing these files: `delivery-request.json` is disabled by default.

## Review and activation

1. Review and commit the implementation with the disabled request. Let the
   resulting exact commit be S. This is the reviewed source commit, not an old
   Windows run or the IPA's source commit. Complete source and license review
   before activation; the runtime/source packages have not been assembled yet.
2. Identify the exact already delivered fixed IPA by its receipt's SHA-256.
   The request records that hash. This workflow does not modify that IPA.
3. Generate the proposed draft body offline with
   `python tests/desktop/mesa_wgl/softpipe_release.py draft-body --source-commit S --request-id ID --target-ipa-sha256 HASH`.
   A separately authorized parent action may create the exact empty draft
   prerelease in Mi-Yomi/Madeira, targeting S. Keep its audience restricted to
   existing repository writers. No release-creation method exists in this patch.
4. After the parent's final review, change only `delivery-request.json` in a
   single new commit whose sole parent is S. Set enabled true, source_commit S,
   the reviewed request ID, the exact existing release ID, and target IPA hash.
   Publishing that request-only commit to compatibility/desktop-apps is the
   explicit start action. This dedicated push pattern does not depend on a
   workflow_dispatch UI entry that exists only on another branch.
5. Before compilation the job verifies the current branch, request-only parent
   relationship, fixed repo/branch, exact draft ID/tag/body/target, unpublished
   draft status, absent Git tag ref, and empty asset list. An existing tag is
   rejected because a draft's target_commitish alone does not bind that tag.
   A stale or occupied draft stops the job.
   An inactive request uses only the small read-only validation job; its
   Windows build/upload job is skipped.
6. Download the four completed assets and verify hashes before handing them to
   the user. Keep the release unpublished. A partial failure is not delivery;
   inspect it before proposing another explicitly reviewed request. The code
   never overwrites, deletes, retries, or publishes remote state.

The job uses only the standard Windows runner and the current job's ephemeral
GitHub token, exposed solely to the draft-check and upload steps. It does not
request or generate a token, persist credentials, change access permissions,
or use unverified Actions artifact storage quota. Budget: a 35-minute job,
unchanged reference's 22-minute internal limit, two compile workers, 6 GiB work
ceiling, 128 MiB maximum per deliverable, and fixed four-asset inventory.

## Deliverables

- `Madeira-softpipe-test.zip`: exactly the source-built x64 opengl32.dll,
  libgallium_wgl.dll and wgl-canary.exe, instructions, upstream notices,
  runtime checksums, limits, and the full Windows reference receipt
- `Madeira-softpipe-source.zip`: unchanged official Mesa 26.2.4 source archive,
  exact canary and packaging/build recipes, GPL notices for the reused static
  audit scripts, all source hashes, upstream notices, toolchain input pins,
  actual build options/cross file, and this job's bounded build/runtime logs
- `provenance.json`: reviewed source/request/run/destination/IPA identities,
  package and recipe hashes, binary evidence via the full reference receipt,
  and explicit untested stages
- `SHA256SUMS`: hashes of the two ZIPs and provenance file

No compiler installation or commercial software accompanies the runtime.
Source and runtime are deliberately separate to keep the iPhone download
practical. Retain both as one delivery. Mesa's full original sources preserve
individual copyright/license annotations; the runtime also receives whole-tree
license texts and copyright/license comment attribution, plus the exact
LLVM-MinGW distribution and x64 runtime notices. The packager fails if the
required upstream notice files are absent. The source package is not a license
to omit notices from the runtime package or to claim a public-release audit.

The package is deterministically ordered with a fixed ZIP timestamp for the
same input bytes. Neither bit-for-bit reproducibility of the DLLs nor equality
to the lost Windows-run binaries is claimed. A new run has new provenance.

## iPhone use and acceptance

`SOFTPIPE-TEST.txt` is the runtime guide. It binds the test to the fixed delivered
IPA hash, requires a cold Desktop-mode session before driver initialization,
and keeps the three files app-local. No DLL is copied over system32.

Double-clicking the EXE, or using `--interactive` alone, runs legacy softpipe
checks, hides only its solely owned console, shows a small foreground window, and holds the
GDI quadrants and each of the two GL frames for seven seconds. The end dialog
can be dismissed by touch. A fresh local report beside the EXE records only
canary diagnostics and is never uploaded automatically. Closing the test
window early ends the held sequence with a failed checkpoint. Cleanup restores
only the console state changed by this process; a shared parent console is
never hidden. The explicit
automated CI modes keep their previous execution/hold behavior.

The interactive UI, report file creation, actual FEX/Wine execution and iPhone
display remain untested until that runtime occurs. Existing automated GDI and
GL readback tests cannot certify the interactive UI or the compositor. Manual
observation of the quadrants, blue frame and purple frame is recorded separately
from the programmatic pass; the program always leaves
`compositor_display_proven=false`. If pixels read back correctly but are not
visible, that is a presentation failure. Source review identifies a GDI route,
not a successful iPhone execution or a Blender-ready renderer.

## Local validation without a build

Run `python tests/host/check-softpipe-delivery.py` and the existing
`python tests/host/check-mesa-windows-reference.py`. They exercise request,
archive, receipt, and destination rejection cases without network access or
target execution. A Windows compile/runtime build and real output packaging
must still run after authorized activation; these portable checks do not
substitute for those stages.
