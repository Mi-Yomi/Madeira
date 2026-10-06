#!/usr/bin/env python3
"""Fail-closed workflow boundaries for the explicitly requested IPA delivery."""
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/unsigned-ipa-delivery.yml"


def validate(text):
    events = text.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]
    assert re.findall(r"^  ([a-z_]+):", events, re.M) == ["workflow_dispatch", "push"]
    assert re.findall(r"^      - (.+)$", events, re.M) == [
        ".github/workflows/unsigned-ipa-delivery.yml", "build/app-ios/ipa-delivery-request.json"]
    assert text.count("permissions:\n") == 2
    assert text.count("  unsigned-ipa:\n") == 1
    before, job = text.split("  unsigned-ipa:\n")
    header, steps = job.split("    steps:\n", 1)
    assert "permissions:\n  contents: read\n" in before
    assert before.split("permissions:\n", 1)[1].split("\n\n", 1)[0] == "  contents: read"
    assert "contents: write" not in before
    assert "    permissions:\n      contents: write\n" in header
    assert header.split("    permissions:\n", 1)[1].split("    needs:", 1)[0] == "      contents: write\n"
    assert "    runs-on: xcode-27\n" in header
    assert "    timeout-minutes: 60\n" in header
    assert "    needs: portable-validation\n" in header
    gate = "github.repository == 'Mi-Yomi/Madeira' && github.event.repository.private == false && github.ref == 'refs/heads/compatibility/desktop-apps'"
    assert text.count(gate) == 2
    assert "      - build/app-ios/ipa-delivery-request.json\n" in before
    assert "    branches: [compatibility/desktop-apps]\n" in before
    assert "  cancel-in-progress: false\n" in before
    for required in ("JOBS: '2'", "BUILD_JOBS: '2'", "CMAKE_BUILD_PARALLEL_LEVEL: '2'",
                     "CARGO_BUILD_JOBS: '2'", "MAKEFLAGS: -j2"):
        assert required in header
    assert text.count("uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262") == 2
    assert text.count("persist-credentials: false") == 2
    assert text.count("fetch-depth: 0") == 2
    assert "submodules: recursive" in steps
    for forbidden in ("actions/upload-artifact", "actions/download-artifact", "actions/cache", "secrets.",
                      "continue-on-error", "-large", "-xlarge", "release create", "release edit", "--clobber",
                      "allowProvisioningUpdates", "exportArchive", "codesign --", "-license accept"):
        assert forbidden not in text, forbidden
    stages = ("deliver_unsigned.py --mode request", "deliver_unsigned.py --mode draft-check",
              "check-i386-native-contract.py -v", "link_diagnostic.py native",
              "build/llvm-ios/build.sh fetch", "build/dxmt-ios/generate-shaders.sh preflight",
              "build/llvm-ios/build.sh host", "build/dxmt-ios/generate-shaders.sh\n",
              "build/llvm-ios/build.sh ios", "build/dxmt-ios/clean_build.py",
              "build/app-ios/build_unsigned.py", "--package\n", "deliver_unsigned.py --mode verify",
              "deliver_unsigned.py --mode upload")
    offsets = [steps.index(stage) for stage in stages]
    assert offsets == sorted(offsets)
    assert steps.count('GH_TOKEN: ${{ github.token }}') == 2
    for block in steps.split("      - name: ")[1:]:
        if "GH_TOKEN:" in block:
            assert ("--mode draft-check" in block) != ("--mode upload" in block)
        if "--mode upload" in block:
            assert "MADEIRA_DRAFT_ID: ${{ steps.draft.outputs.release_id }}" in block
            assert '--release-id "$MADEIRA_DRAFT_ID"' in block
        if "if:" in block:
            assert block.startswith("Collect bounded native diagnostics\n")
    assert steps.count('--native-receipt "$NATIVE_ARTIFACT_DIR/provenance.json"') == 3
    assert 'python3 tests/host/check-unsigned-ipa-delivery.py' in before and 'python3 tests/host/check-unsigned-ipa-delivery.py' in steps
    assert 'python3 tests/host/check-unsigned-ipa-workflow.py' in before and 'python3 tests/host/check-unsigned-ipa-workflow.py' in steps


class WorkflowTests(unittest.TestCase):
    def test_delivery_boundaries(self):
        validate(WORKFLOW.read_text())

    def test_mutations_are_rejected(self):
        text = WORKFLOW.read_text()
        replacements = (("contents: read", "contents: write"), ("timeout-minutes: 60", "timeout-minutes: 600"),
                        ("runs-on: xcode-27", "runs-on: xcode-27-large"),
                        ("persist-credentials: false", "persist-credentials: true"),
                        ("fetch-depth: 0", "fetch-depth: 1"), ("MAKEFLAGS: -j2", "MAKEFLAGS: -j8"),
                        ("private == false", "private == true"), ("cancel-in-progress: false", "cancel-in-progress: true"),
                        ("--mode draft-check", "--mode request"), ("--package\n", "\n"),
                        ("link_diagnostic.py native", ".github/ci/native-bootstrap.sh"),
                        ('--release-id "$MADEIRA_DRAFT_ID"', '--release-id 1'),
                        ("  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request:\n"),
                        ("      - .github/workflows/unsigned-ipa-delivery.yml\n", ""),
                        ("      - build/app-ios/ipa-delivery-request.json\n", "      - app/**\n"),
                        ("  contents: read\n", "  contents: read\n  actions: write\n"),
                        ("      contents: write\n", "      contents: write\n      id-token: write\n"))
        for before, after in replacements:
            with self.subTest(before=before), self.assertRaises((AssertionError, ValueError)):
                validate(text.replace(before, after, 1))

    def test_embedded_shell_syntax(self):
        text = WORKFLOW.read_text()
        blocks = re.findall(r"        run: \|\n((?:          .*\n|\n)+)", text)
        self.assertGreaterEqual(len(blocks), 10)
        for block in blocks:
            shell = "\n".join(line[10:] if line else "" for line in block.splitlines()) + "\n"
            result = subprocess.run(["bash", "-n"], input=shell, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
