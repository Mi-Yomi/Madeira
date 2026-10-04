#!/usr/bin/env python3
"""Portable repair failure injection, reporter semantics and platform isolation.

Fixture revisions/hashes are substituted in memory only; the production CLI
has no bypass or source/spec override. No network or Apple SDK is needed.
"""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
loader = importlib.util.spec_from_file_location("fex_source_repairs", ROOT / "build/fex-ios/apply-source-repairs.py")
module = importlib.util.module_from_spec(loader)
loader.loader.exec_module(module)
FIXTURE = Path(__file__).with_name("fixtures") / "fex-ios-reporters.cpp"


class FEXSourceRepairTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="FEX source repair ")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.source = self.root / "FEX"
        self.source.mkdir()
        self.spec = copy.deepcopy(module.SPEC)
        self.repair = self.spec["repairs"][0]
        self.entry, = self.repair["files"]
        self.target = self.source / self.entry["path"]
        self.target.parent.mkdir(parents=True)
        self.original = FIXTURE.read_bytes()
        self.previous_patched = self.original.replace(
            b"  /* iOS-Madeira ml304 (task #51): REPORT", b"#ifdef FEX_IOS_HOST\n  /* iOS-Madeira ml304 (task #51): REPORT"
        ).replace(b"\n\n  /* iOS-Madeira: refuse", b"\n#endif\n\n  /* iOS-Madeira: refuse")
        guard = b"#if defined(ENABLE_FEX_ALLOCATOR) && ENABLE_FEX_ALLOCATOR\n"
        self.patched = self.previous_patched.replace(
            b"/* iOS-Madeira ml622: mirror", guard + b"/* iOS-Madeira ml622: mirror", 1
        ).replace(b"int rpm_cas_snapshot_take(struct rpm_cas_snapshot* out);\n}\n",
                  b"int rpm_cas_snapshot_take(struct rpm_cas_snapshot* out);\n}\n#endif\n", 1
        ).replace(b"      /* iOS-Madeira ml622: drain", guard + b"      /* iOS-Madeira ml622: drain", 1
        ).replace(b"                            Snap.fail_changed, Snap.fail_unchanged, Snap.fail_invalid);\n        }\n      }\n",
                  b"                            Snap.fail_changed, Snap.fail_unchanged, Snap.fail_invalid);\n        }\n      }\n#endif\n", 1)
        self.target.write_bytes(self.original)
        self.caspal_repair = self.spec["repairs"][1]
        self.caspal_entry, = self.caspal_repair["files"]
        self.caspal_target = self.source / self.caspal_entry["path"]
        self.caspal_target.parent.mkdir(parents=True)
        self.caspal_original = FIXTURE.with_name("fex-caspal-diagnostic.cpp").read_bytes()
        self.caspal_patched = self.caspal_original.replace(
            b"  MEMORY_BASIC_INFORMATION mbi {};", b"#ifdef _WIN32\n  MEMORY_BASIC_INFORMATION mbi {};"
        ).replace(b"                    mbi.Protect, type, mbi.State);\n", b'''                    mbi.Protect, type, mbi.State);
#else
  LogMan::Msg::EFmt("[caspal128] MISALIGNED-UNSUPPORTED Size={} addrReg=x{} addr={:#x} misalign={} "
                    "crosses16B={}",
                    Size, AddressReg, GPRs[AddressReg], GPRs[AddressReg] & 15,
                    (GPRs[AddressReg] & 15) ? "yes" : "no");
#endif
''')
        self.caspal_target.write_bytes(self.caspal_original)
        self.cmake_repair = self.spec["repairs"][2]
        self.cmake_entry, = self.cmake_repair["files"]
        self.cmake_target = self.source / self.cmake_entry["path"]
        self.cmake_original = FIXTURE.with_name("fex-rpmalloc-target.cmake").read_bytes()
        self.cmake_patched = self.cmake_original.replace(b"if (ENABLE_FEX_ALLOCATOR)\n", b"if (ENABLE_FEX_ALLOCATOR)\n"
            b"  # Core drains rpmalloc diagnostics only when their real provider is linked.\n"
            b"  set_property(SOURCE Interface/Core/Core.cpp APPEND PROPERTY COMPILE_DEFINITIONS ENABLE_FEX_ALLOCATOR=1)\n")
        self.cmake_target.write_bytes(self.cmake_original)
        (self.source / ".gitignore").write_text("/build-ios/\n")
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "Pinned source fixture")
        self.spec["source_revision"] = self.git("rev-parse", "HEAD").decode().strip()
        self.entry["original_sha256"] = module.sha256(self.original)
        self.entry["patched_sha256"] = module.sha256(self.patched)
        self.entry["previous_patched_sha256"] = [module.sha256(self.previous_patched)]
        self.caspal_entry["original_sha256"] = module.sha256(self.caspal_original)
        self.caspal_entry["patched_sha256"] = module.sha256(self.caspal_patched)
        self.cmake_entry["original_sha256"] = module.sha256(self.cmake_original)
        self.cmake_entry["patched_sha256"] = module.sha256(self.cmake_patched)
        for repair in self.spec["repairs"]:
            patch = self.root / repair["patch"]
            patch.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / repair["patch"], patch)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(module, "ROOT", self.root).start()
        mock.patch.object(module, "SPEC", self.spec).start()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.source), *args], stderr=subprocess.PIPE)

    def reject(self, message):
        before = {path: path.read_bytes() for path in (self.target, self.caspal_target, self.cmake_target)}
        record = self.source / module.RECORD
        previous_record = record.read_bytes() if record.exists() else None
        with self.assertRaisesRegex(ValueError, message):
            module.apply(self.source)
        for path, data in before.items():
            self.assertEqual(path.read_bytes(), data)
        self.assertEqual(record.read_bytes() if record.exists() else None, previous_record)

    def test_symlink_aliased_temporary_staging_root(self):
        # macOS commonly returns /var/... from TemporaryDirectory while resolve()
        # produces /private/var/.... Reproduce that alias on every host platform.
        storage = self.root / "temporary-storage"
        storage.mkdir()
        alias = self.root / "temporary-alias"
        alias.symlink_to(storage, target_is_directory=True)
        real_temporary_directory = tempfile.TemporaryDirectory
        real_checked_path = module.checked_path
        staged_roots = []
        def aliased_temporary_directory(*args, **kwargs):
            kwargs["dir"] = str(alias)
            return real_temporary_directory(*args, **kwargs)
        def observe_checked_path(root, relative, description):
            if description == "Staged FEX repair source":
                staged_roots.append(root)
                self.assertNotEqual(root, root.resolve())
                # This is the failing old predicate: resolved target, lexical root.
                self.assertFalse((root / relative).resolve().is_relative_to(root))
            return real_checked_path(root, relative, description)
        with mock.patch.object(module.tempfile, "TemporaryDirectory", side_effect=aliased_temporary_directory), \
                mock.patch.object(module, "checked_path", side_effect=observe_checked_path):
            module.apply(self.source)
            module.apply(self.source)
        self.assertTrue(staged_roots)
        self.assertEqual(self.target.read_bytes(), self.patched)
        self.assertEqual(self.caspal_target.read_bytes(), self.caspal_patched)
        self.assertEqual(json.loads((self.source / module.RECORD).read_text()), self.spec)
        self.assertEqual(self.git("diff", "--cached"), b"")

    def test_aliased_root_still_rejects_symlinked_file_and_parent_escape(self):
        outside = self.root / "outside-source"
        outside.mkdir()
        (outside / "source.cpp").write_bytes(self.original)
        alias = self.root / "source-alias"
        alias.symlink_to(self.source, target_is_directory=True)
        (self.source / "linked.cpp").symlink_to(outside / "source.cpp")
        (self.source / "escape").symlink_to(outside, target_is_directory=True)
        self.assertFalse((alias / "escape/source.cpp").is_symlink())
        for relative in ("linked.cpp", "escape/source.cpp"):
            with self.subTest(path=relative):
                with self.assertRaisesRegex(ValueError, "regular file within its checkout"):
                    module.checked_path(alias, relative, "FEX repair source")
        self.assertEqual((outside / "source.cpp").read_bytes(), self.original)

    def test_core_patch_only_adds_three_feature_guards(self):
        patch = (ROOT / self.repair["patch"]).read_bytes()
        self.assertEqual(module.sha256(patch), self.repair["patch_sha256"])
        added = [line for line in patch.decode().splitlines() if line.startswith("+") and not line.startswith("+++")]
        removed = [line for line in patch.decode().splitlines() if line.startswith("-") and not line.startswith("---")]
        self.assertEqual(added, ["+#if defined(ENABLE_FEX_ALLOCATOR) && ENABLE_FEX_ALLOCATOR", "+#endif",
                                "+#ifdef FEX_IOS_HOST", "+#endif",
                                "+#if defined(ENABLE_FEX_ALLOCATOR) && ENABLE_FEX_ALLOCATOR", "+#endif"])
        self.assertEqual(removed, [])

    def test_clean_patch_idempotence_and_provenance(self):
        module.apply(self.source)
        self.assertEqual(self.target.read_bytes(), self.patched)
        record = self.source / module.RECORD
        self.assertEqual(json.loads(record.read_text()), self.spec)
        first = record.read_bytes()
        module.apply(self.source)
        self.assertEqual(record.read_bytes(), first)
        self.assertEqual(self.target.read_bytes(), self.patched)
        self.assertEqual(self.git("rev-parse", "HEAD").decode().strip(), self.spec["source_revision"])
        self.assertEqual(self.git("diff", "--cached"), b"")
        self.assertEqual(self.caspal_target.read_bytes(), self.caspal_patched)
        self.assertEqual(self.cmake_target.read_bytes(), self.cmake_patched)
        self.assertEqual(self.git("diff", "--name-only").decode().splitlines(),
                         sorted([self.entry["path"], self.caspal_entry["path"], self.cmake_entry["path"]]))

    def test_upgrade_exact_previous_repaired_core(self):
        self.target.write_bytes(self.previous_patched)
        self.caspal_target.write_bytes(self.caspal_patched)
        module.apply(self.source)
        module.apply(self.source)
        self.assertEqual(self.target.read_bytes(), self.patched)
        self.assertEqual(self.cmake_target.read_bytes(), self.cmake_patched)
        self.assertEqual(json.loads((self.source / module.RECORD).read_text()), self.spec)
        self.assertEqual(self.git("diff", "--cached"), b"")

    def test_previous_core_with_any_unreviewed_edit_rejected(self):
        self.target.write_bytes(self.previous_patched + b"// local change\n")
        self.reject("working source hash")

    def test_prior_core_upgrade_does_not_bypass_later_patch_preflight(self):
        self.target.write_bytes(self.previous_patched)
        self.cmake_entry["patched_sha256"] = "0" * 64
        self.reject("repaired source hash mismatch")

    def test_prior_core_upgrade_rolls_back_on_record_failure(self):
        self.target.write_bytes(self.previous_patched)
        real_write = module.atomic_write
        def fail_record(target, data):
            if target == self.source / module.RECORD:
                raise OSError("injected record failure")
            real_write(target, data)
        with mock.patch.object(module, "atomic_write", side_effect=fail_record):
            with self.assertRaisesRegex(OSError, "injected record failure"):
                module.apply(self.source)
        self.assertEqual(self.target.read_bytes(), self.previous_patched)
        self.assertEqual(self.cmake_target.read_bytes(), self.cmake_original)

    def test_wrong_revision_rejected(self):
        self.spec["source_revision"] = "0" * 40
        self.reject("Unexpected FEX revision")

    def test_wrong_committed_source_rejected(self):
        self.entry["original_sha256"] = "0" * 64
        self.reject("committed source hash mismatch")

    def test_unexpected_source_edit_and_partial_repair_rejected(self):
        for data in (self.original + b"// local edit\n", self.patched.replace(b"#endif\n\n  /* iOS-Madeira: refuse", b"\n  /* iOS-Madeira: refuse")):
            self.target.write_bytes(data)
            self.reject("working source hash")

    def test_other_tracked_source_edit_rejected(self):
        (self.source / ".gitignore").write_text("local change\n")
        self.reject("tracked FEX source modifications")

    def test_modified_patch_rejected(self):
        with (self.root / self.repair["patch"]).open("ab") as out:
            out.write(b"\n")
        self.reject("patch hash mismatch")

    def test_failed_patch_tool_does_not_record_success(self):
        real_git = module.git
        def fail(source, *args):
            if args[:2] == ("apply", "--check"):
                raise subprocess.CalledProcessError(1, "git apply --check", stderr=b"fixture mismatch")
            return real_git(source, *args)
        with mock.patch.object(module, "git", side_effect=fail), self.assertRaises(subprocess.CalledProcessError):
            module.apply(self.source)
        self.assertEqual(self.target.read_bytes(), self.original)
        self.assertFalse((self.source / module.RECORD).exists())

    def test_noop_patch_tool_cannot_record_success(self):
        real_git = module.git
        def noop(source, *args):
            return b"" if args[:1] == ("apply",) else real_git(source, *args)
        with mock.patch.object(module, "git", side_effect=noop):
            self.reject("repaired source hash mismatch")

    def test_uninitialized_submodule_rejected(self):
        child = self.source / "uninitialized"
        child.mkdir()
        with self.assertRaisesRegex(ValueError, "initialized Git checkout"):
            module.apply(child)

    def test_symlink_source_rejected(self):
        other = self.root / "outside.cpp"
        other.write_bytes(self.original)
        self.target.unlink()
        self.target.symlink_to(other)
        self.reject("regular file within its checkout")

    def test_original_reproduces_native_compile_failure(self):
        result = subprocess.run(["c++", "-std=c++20", "-fsyntax-only", str(self.target)], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("IosFfsBypassLog", result.stderr)
        self.assertIn("IosCbEntryLog", result.stderr)

    def test_repaired_native_ec_and_wow64_reporters(self):
        module.apply(self.source)
        # Separate producers prove the declarations retain their C linkage.
        producer = self.root / "producer.cpp"
        producer.write_text('''#include <cstdint>
#ifdef FEX_IOS_HOST
extern "C" {
uint64_t IosCbEntryLog[8] {};
#ifdef ARCHITECTURE_arm64ec
uint64_t IosFfsBypassLog[4] {};
uint64_t IosJitReverseTranslate(uint64_t value) { return value; }
#endif
}
#endif
''')
        main = self.root / "main.cpp"
        main.write_text('#include "' + str(self.target) + '"\n' + '''
#include <cassert>
int main() {
  using namespace FEXCore::Context;
  constexpr uint64_t good = 0x123456;
  assert(Report(good) == good);
  assert(ffs_reports == 0 && callback_reports == 0);
  assert(Report(8) == 0 && invalid_reports == 1);
#ifdef FEX_IOS_HOST
  IosCbEntryLog[6] = 1;
#ifdef ARCHITECTURE_arm64ec
  IosFfsBypassLog[0] = 1;
#endif
  assert(Report(good) == good);
  assert(callback_reports == 1);
#ifdef ARCHITECTURE_arm64ec
  assert(ffs_reports == 1);
#else
  assert(ffs_reports == 0); // Existing WoW64 zeroed fallback remains inert.
#endif
  Report(good);
  assert(callback_reports == 1); // Unchanged count never repeats a report.
  for (unsigned i = 2; i < 20; ++i) {
    IosCbEntryLog[6] = i;
#ifdef ARCHITECTURE_arm64ec
    IosFfsBypassLog[0] = i;
#endif
    Report(good);
  }
  assert(callback_reports == 8);
#ifdef ARCHITECTURE_arm64ec
  assert(ffs_reports == 12);
#else
  assert(ffs_reports == 0);
#endif
#else
  assert(ffs_reports == 0 && callback_reports == 0);
#endif
  assert(Report(0) == 0 && invalid_reports == 2);
}
''')
        for name, defines in (("native", []), ("wow64", ["-DFEX_IOS_HOST"]),
                              ("arm64ec", ["-DFEX_IOS_HOST", "-DARCHITECTURE_arm64ec"])):
            with self.subTest(mode=name):
                executable = self.root / name
                result = subprocess.run(["c++", "-std=c++20", *defines, str(main), str(producer), "-o", str(executable)], text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                subprocess.run([str(executable)], check=True)

    def test_upgrade_from_already_applied_core_repair(self):
        complete = self.spec["repairs"]
        self.spec["repairs"] = complete[:1]
        module.apply(self.source)
        self.assertEqual(self.target.read_bytes(), self.patched)
        self.assertEqual(self.caspal_target.read_bytes(), self.caspal_original)
        self.spec["repairs"] = complete
        module.apply(self.source)
        self.assertEqual(self.target.read_bytes(), self.patched)
        self.assertEqual(self.caspal_target.read_bytes(), self.caspal_patched)
        self.assertEqual(json.loads((self.source / module.RECORD).read_text()), self.spec)
        self.assertEqual(self.git("diff", "--cached"), b"")

    def test_later_patch_hash_rejected_before_any_source_write(self):
        with (self.root / self.caspal_repair["patch"]).open("ab") as output:
            output.write(b"\n")
        self.reject("patch hash mismatch")

    def test_later_working_edit_rejected_before_any_source_write(self):
        self.caspal_target.write_bytes(self.caspal_original + b"// local edit\n")
        self.reject("working source hash")

    def test_later_partial_in_file_repair_rejected(self):
        self.caspal_target.write_bytes(self.caspal_original.replace(
            b"  MEMORY_BASIC_INFORMATION mbi {};", b"#ifdef _WIN32\n  MEMORY_BASIC_INFORMATION mbi {};"))
        self.reject("working source hash")

    def test_partial_multi_file_repair_rejected(self):
        self.target.write_bytes(self.patched)
        self.repair["files"].append(self.caspal_entry)
        self.spec["repairs"] = [self.repair]
        self.reject("Partial FEX source repair")

    def test_later_expected_result_rejected_before_any_source_write(self):
        self.caspal_entry["patched_sha256"] = "0" * 64
        self.reject("repaired source hash mismatch")

    def test_later_patch_tool_failure_preserves_both_inputs(self):
        real_git = module.git
        def fail_later(source, *args):
            if args[:2] == ("apply", "--check") and Path(args[-1]).name == "1.patch":
                raise subprocess.CalledProcessError(1, "git apply --check", stderr=b"second repair mismatch")
            return real_git(source, *args)
        with mock.patch.object(module, "git", side_effect=fail_later), self.assertRaises(subprocess.CalledProcessError):
            module.apply(self.source)
        self.assertEqual(self.target.read_bytes(), self.original)
        self.assertEqual(self.caspal_target.read_bytes(), self.caspal_original)
        self.assertFalse((self.source / module.RECORD).exists())

    def test_later_failure_preserves_previous_repair_and_record(self):
        complete = self.spec["repairs"]
        self.spec["repairs"] = complete[:1]
        module.apply(self.source)
        self.spec["repairs"] = complete
        self.caspal_entry["patched_sha256"] = "0" * 64
        self.reject("repaired source hash mismatch")
        self.assertEqual(self.target.read_bytes(), self.patched)
        self.assertEqual(self.caspal_target.read_bytes(), self.caspal_original)

    def test_duplicate_repair_and_overlapping_file_rejected(self):
        original_id = self.caspal_repair["id"]
        self.caspal_repair["id"] = self.repair["id"]
        self.reject("Duplicate or empty")
        self.caspal_repair["id"] = original_id
        self.caspal_repair["files"] = [self.entry]
        self.reject("files must be disjoint")

    def test_patch_touching_unlisted_file_rejected_before_checkout_write(self):
        patch = self.root / self.caspal_repair["patch"]
        with patch.open("ab") as output:
            output.write(b"diff --git a/unlisted.cpp b/unlisted.cpp\nnew file mode 100644\n--- /dev/null\n+++ b/unlisted.cpp\n@@ -0,0 +1 @@\n+unexpected\n")
        self.caspal_repair["patch_sha256"] = module.sha256(patch.read_bytes())
        self.reject("patch changed unexpected paths")
        self.assertFalse((self.source / "unlisted.cpp").exists())

    def test_later_patch_cannot_modify_other_repairs_source(self):
        patch = self.root / self.caspal_repair["patch"]
        relative = self.entry["path"]
        with patch.open("a") as output:
            output.write(f"diff --git a/{relative} b/{relative}\n--- a/{relative}\n+++ b/{relative}\n"
                         "@@ -1,3 +1,3 @@\n-// SPDX-License-Identifier: MIT\n+// unexpected edit\n"
                         " // The line above retains the upstream notice from Core.cpp; it is not a\n"
                         " // blanket grant for the fork additions or the new regression harness.\n")
        self.caspal_repair["patch_sha256"] = module.sha256(patch.read_bytes())
        self.reject("changed another repair's source")

    def test_patch_symlink_and_path_escape_rejected(self):
        patch = self.root / self.caspal_repair["patch"]
        outside = self.root / "outside.patch"
        outside.write_bytes(patch.read_bytes())
        patch.unlink()
        patch.symlink_to(outside)
        self.reject("patch must be a regular file")
        self.caspal_repair["patch"] = "../outside.patch"
        self.reject("Invalid FEX repair patch path")

    def test_concurrent_source_edit_is_not_overwritten(self):
        real_git = module.git
        concurrent = self.original + b"// concurrent source edit\n"
        def edit_during_preflight(source, *args):
            result = real_git(source, *args)
            if args[:1] == ("apply",) and Path(args[-1]).name == "1.patch":
                self.target.write_bytes(concurrent)
            return result
        with mock.patch.object(module, "git", side_effect=edit_during_preflight):
            with self.assertRaisesRegex(ValueError, "changed during repair preflight"):
                module.apply(self.source)
        self.assertEqual(self.target.read_bytes(), concurrent)
        self.assertEqual(self.caspal_target.read_bytes(), self.caspal_original)
        self.assertFalse((self.source / module.RECORD).exists())

    def test_staged_edit_hidden_by_worktree_revert_rejected(self):
        self.target.write_bytes(self.original + b"// staged source edit\n")
        self.git("add", self.entry["path"])
        self.target.write_bytes(self.original)
        staged_before = self.git("diff", "--cached")
        self.reject("staged FEX source modifications")
        self.assertEqual(self.git("diff", "--cached"), staged_before)

    def test_concurrent_unrelated_tracked_edit_rejected(self):
        real_git = module.git
        def edit_during_preflight(source, *args):
            result = real_git(source, *args)
            if args[:1] == ("apply",) and Path(args[-1]).name == "1.patch":
                (self.source / ".gitignore").write_text("concurrent edit\n")
            return result
        with mock.patch.object(module, "git", side_effect=edit_during_preflight):
            self.reject("tracked FEX source modifications")
        self.assertEqual((self.source / ".gitignore").read_text(), "concurrent edit\n")

    def test_repair_preserves_source_file_modes(self):
        self.target.chmod(0o640)
        self.caspal_target.chmod(0o600)
        module.apply(self.source)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.caspal_target.stat().st_mode & 0o777, 0o600)

    def test_caspal_original_reproduces_native_windows_type_failure(self):
        result = subprocess.run(["c++", "-std=c++20", "-fsyntax-only", str(self.caspal_target)], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("MEMORY_BASIC_INFORMATION", result.stderr)
        self.assertIn("VirtualQuery", result.stderr)

    def test_caspal_patch_only_adds_platform_diagnostic_branch(self):
        patch = (ROOT / self.caspal_repair["patch"]).read_bytes()
        self.assertEqual(module.sha256(patch), self.caspal_repair["patch_sha256"])
        removed = [line for line in patch.decode().splitlines() if line.startswith("-") and not line.startswith("---")]
        self.assertEqual(removed, [])
        additions = "\n".join(line[1:] for line in patch.decode().splitlines() if line.startswith("+") and not line.startswith("+++"))
        self.assertNotIn("FEX_IOS_HOST", additions)
        self.assertNotIn("RunCASPAL", additions)
        self.assertEqual(additions.count("#ifdef _WIN32"), 1)
        self.assertEqual(additions.count("#else"), 1)
        self.assertEqual(additions.count("#endif"), 1)
        module.apply(self.source)
        self.assertEqual(self.caspal_patched.split(b"static bool HandleCASPAL", 1)[1],
                         self.caspal_original.split(b"static bool HandleCASPAL", 1)[1])

    def test_caspal_windows_diagnostic_preprocessor_equivalence(self):
        # This checks exact Windows branch preservation without fake Windows
        # types, linking/running a PE fixture, or claiming a MinGW build passed.
        original = self.root / "caspal-original.cpp"
        original.write_bytes(self.caspal_original)
        module.apply(self.source)
        for flags in ([], ["-DFEX_IOS_HOST"], ["-DFEX_IOS_HOST", "-DARCHITECTURE_arm64ec"]):
            with self.subTest(defines=flags):
                command = ["c++", "-std=c++20", "-E", "-P", "-D_WIN32", *flags]
                before = subprocess.check_output([*command, str(original)])
                after = subprocess.check_output([*command, str(self.caspal_target)])
                self.assertEqual(after, before)

    def test_caspal_native_bounded_diagnostic_and_unchanged_registers(self):
        module.apply(self.source)
        result = subprocess.run(["c++", "-std=c++20", "-fsyntax-only", str(self.caspal_target)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        native = subprocess.check_output(["c++", "-std=c++20", "-E", "-P", str(self.caspal_target)])
        for name in (b"MEMORY_BASIC_INFORMATION", b"VirtualQuery", b"MEM_MAPPED", b"LPCVOID"):
            self.assertNotIn(name, native)
        # Run only the exact diagnostic, not a surrogate emulation algorithm.
        main = self.root / "caspal-native.cpp"
        main.write_bytes(self.caspal_target.read_bytes().split(b"static bool HandleCASPAL", 1)[0] + b'''
#include <array>
#include <cassert>
int main() {
  using namespace LogMan::Msg;
  std::array<uint64_t, 32> registers {};
  registers[11] = 0x1001;
  IosLogUnimplementedCASPAL(0, registers.data(), 11);
  assert(diagnostic_count == 0);
  registers[11] = 0x1010;
  IosLogUnimplementedCASPAL(1, registers.data(), 11);
  assert(diagnostic_count == 0);
  for (unsigned offset = 1; offset <= 15; ++offset) {
    registers[11] = 0x1000 + offset;
    auto before = registers;
    IosLogUnimplementedCASPAL(1, registers.data(), 11);
    assert(registers == before);
    assert(diagnostic_count == (offset <= 8 ? offset : 8));
    if (offset <= 8) {
      assert(last_size == 1 && last_register == 11);
      assert(last_address == 0x1000 + offset && last_misalignment == offset);
      assert(last_crosses == "yes");
      assert(last_format.find("MISALIGNED-UNSUPPORTED") != std::string_view::npos);
      assert(last_format.find("Size={}") != std::string_view::npos);
      assert(last_format.find("addrReg=x{}") != std::string_view::npos);
      assert(last_format.find("addr={:#x}") != std::string_view::npos);
      assert(last_format.find("misalign={}") != std::string_view::npos);
      assert(last_format.find("crosses16B={}") != std::string_view::npos);
      assert(last_format.find("region") == std::string_view::npos);
    }
  }
}
''')
        executable = self.root / "caspal-native"
        subprocess.run(["c++", "-std=c++20", str(main), "-o", str(executable)], check=True)
        subprocess.run([str(executable)], check=True)


    def test_noncanonical_source_and_patch_paths_rejected(self):
        original = self.caspal_entry["path"]
        for relative in ("./" + original, original.replace("/", "//", 1), original.replace("/", "\\", 1)):
            with self.subTest(path=relative):
                self.caspal_entry["path"] = relative
                self.reject("Invalid FEX repair source path")
        self.caspal_entry["path"] = original
        self.caspal_repair["patch"] = "./" + self.caspal_repair["patch"]
        self.reject("Invalid FEX repair patch path")

    def test_later_source_write_failure_rolls_back_first_repair(self):
        real_write = module.atomic_write
        def fail_second(target, data):
            if target == self.caspal_target:
                raise OSError("injected second source write failure")
            real_write(target, data)
        with mock.patch.object(module, "atomic_write", side_effect=fail_second):
            with self.assertRaisesRegex(OSError, "second source write failure"):
                module.apply(self.source)
        self.assertEqual(self.target.read_bytes(), self.original)
        self.assertEqual(self.caspal_target.read_bytes(), self.caspal_original)
        self.assertFalse((self.source / module.RECORD).exists())
        module.apply(self.source)
        self.assertEqual(self.target.read_bytes(), self.patched)
        self.assertEqual(self.caspal_target.read_bytes(), self.caspal_patched)

    def test_provenance_write_failure_rolls_back_all_sources(self):
        real_write = module.atomic_write
        record = self.source / module.RECORD
        def fail_record(target, data):
            if target == record:
                raise OSError("injected provenance write failure")
            real_write(target, data)
        with mock.patch.object(module, "atomic_write", side_effect=fail_record):
            with self.assertRaisesRegex(OSError, "provenance write failure"):
                module.apply(self.source)
        self.assertEqual(self.target.read_bytes(), self.original)
        self.assertEqual(self.caspal_target.read_bytes(), self.caspal_original)
        self.assertFalse(record.exists())

    def test_post_provenance_failure_restores_prior_repair_and_record(self):
        complete = self.spec["repairs"]
        self.spec["repairs"] = complete[:1]
        module.apply(self.source)
        record = self.source / module.RECORD
        old_record = record.read_bytes()
        self.spec["repairs"] = complete
        real_write = module.atomic_write
        def fail_after_record(target, data):
            real_write(target, data)
            if target == record and data != old_record:
                raise OSError("injected failure after provenance replace")
        with mock.patch.object(module, "atomic_write", side_effect=fail_after_record):
            with self.assertRaisesRegex(OSError, "after provenance replace"):
                module.apply(self.source)
        self.assertEqual(self.target.read_bytes(), self.patched)
        self.assertEqual(self.caspal_target.read_bytes(), self.caspal_original)
        self.assertEqual(record.read_bytes(), old_record)

    def test_rollback_failure_is_explicit_and_records_no_success(self):
        real_write = module.atomic_write
        def fail_commit_and_rollback(target, data):
            if target == self.caspal_target:
                raise OSError("injected commit failure")
            if target == self.target and data == self.original:
                raise OSError("injected rollback failure")
            real_write(target, data)
        with mock.patch.object(module, "atomic_write", side_effect=fail_commit_and_rollback):
            with self.assertRaisesRegex(ValueError, "rollback incomplete:.*rollback failure"):
                module.apply(self.source)
        self.assertEqual(self.target.read_bytes(), self.patched)
        self.assertEqual(self.caspal_target.read_bytes(), self.caspal_original)
        self.assertFalse((self.source / module.RECORD).exists())
        module.apply(self.source)  # The exact completed prior repair remains resumable.
        self.assertEqual(self.caspal_target.read_bytes(), self.caspal_patched)

    def test_rollback_preserves_a_concurrent_source_edit(self):
        real_write = module.atomic_write
        concurrent = self.patched + b"// concurrent edit after first write\n"
        def concurrent_edit(target, data):
            if target == self.caspal_target:
                self.target.write_bytes(concurrent)
                raise OSError("injected commit failure")
            real_write(target, data)
        with mock.patch.object(module, "atomic_write", side_effect=concurrent_edit):
            with self.assertRaisesRegex(ValueError, "rollback incomplete:.*changed concurrently"):
                module.apply(self.source)
        self.assertEqual(self.target.read_bytes(), concurrent)
        self.assertEqual(self.caspal_target.read_bytes(), self.caspal_original)
        self.assertFalse((self.source / module.RECORD).exists())

    def test_provenance_symlink_and_invalid_parent_rejected_before_write(self):
        record = self.source / module.RECORD
        external = self.root / "outside-record"
        external.write_text("do not replace\n")
        record.parent.mkdir()
        record.symlink_to(external)
        self.reject("provenance must be a regular file")
        self.assertEqual(external.read_text(), "do not replace\n")
        record.unlink()
        record.parent.rmdir()
        outside_dir = self.root / "outside-directory"
        outside_dir.mkdir()
        record.parent.symlink_to(outside_dir, target_is_directory=True)
        self.reject("provenance must be a regular file")
        self.assertEqual(list(outside_dir.iterdir()), [])
        record.parent.unlink()
        record.parent.write_text("not a directory\n")
        self.reject("provenance must be a regular file")


if __name__ == "__main__":
    unittest.main(verbosity=2)
