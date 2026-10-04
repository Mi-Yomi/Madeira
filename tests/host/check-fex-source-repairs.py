#!/usr/bin/env python3
"""Portable patch/revision failure injection and host C++ reporter semantics.

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
        self.root = Path(self.tmp.name)
        self.source = self.root / "FEX"
        self.source.mkdir()
        self.spec = copy.deepcopy(module.SPEC)
        self.repair, = self.spec["repairs"]
        self.entry, = self.repair["files"]
        self.target = self.source / self.entry["path"]
        self.target.parent.mkdir(parents=True)
        self.original = FIXTURE.read_bytes()
        self.patched = self.original.replace(
            b"  /* iOS-Madeira ml304 (task #51): REPORT", b"#ifdef FEX_IOS_HOST\n  /* iOS-Madeira ml304 (task #51): REPORT"
        ).replace(b"\n\n  /* iOS-Madeira: refuse", b"\n#endif\n\n  /* iOS-Madeira: refuse")
        self.target.write_bytes(self.original)
        (self.source / ".gitignore").write_text("/build-ios/\n")
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "Pinned source fixture")
        self.spec["source_revision"] = self.git("rev-parse", "HEAD").decode().strip()
        self.entry["original_sha256"] = module.sha256(self.original)
        self.entry["patched_sha256"] = module.sha256(self.patched)
        patch = self.root / self.repair["patch"]
        patch.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / self.repair["patch"], patch)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(module, "ROOT", self.root).start()
        mock.patch.object(module, "SPEC", self.spec).start()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.source), *args], stderr=subprocess.PIPE)

    def reject(self, message):
        before = self.target.read_bytes()
        with self.assertRaisesRegex(ValueError, message):
            module.apply(self.source)
        self.assertEqual(self.target.read_bytes(), before)
        self.assertFalse((self.source / module.RECORD).exists())

    def test_patch_is_exactly_two_preprocessor_lines(self):
        patch = (ROOT / self.repair["patch"]).read_bytes()
        self.assertEqual(module.sha256(patch), self.repair["patch_sha256"])
        added = [line for line in patch.decode().splitlines() if line.startswith("+") and not line.startswith("+++")]
        removed = [line for line in patch.decode().splitlines() if line.startswith("-") and not line.startswith("---")]
        self.assertEqual(added, ["+#ifdef FEX_IOS_HOST", "+#endif"])
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
        self.assertEqual(self.git("diff", "--name-only").decode().splitlines(), [self.entry["path"]])

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
