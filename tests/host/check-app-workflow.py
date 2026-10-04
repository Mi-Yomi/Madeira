#!/usr/bin/env python3
"""Portable resource/scope guardrails for the same-workspace app build."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class WorkflowTests(unittest.TestCase):
    def test_bounded_public_runner_without_storage_or_credentials(self):
        text = (ROOT / ".github/workflows/unsigned-app-bootstrap.yml").read_text()
        for required in ("runs-on: xcode-27", "timeout-minutes: 45", "contents: read", "persist-credentials: false",
                         "branches: [compatibility/desktop-apps]", "github.event.repository.private == false",
                         "submodules: recursive", "CMAKE_BUILD_PARALLEL_LEVEL: '2'", "MAKEFLAGS: -j2"):
            self.assertIn(required, text)
        for forbidden in ("actions/upload-artifact", "actions/download-artifact", "actions/cache", "-large", "-xlarge",
                          "secrets.", "continue-on-error", "allowProvisioningUpdates", "exportArchive", "codesign --",
                          "-license accept", "fetch-converter.sh", "cloud_threads"):
            self.assertNotIn(forbidden, text)

    def test_required_stage_order_and_same_runner_receipt(self):
        text = (ROOT / ".github/workflows/unsigned-app-bootstrap.yml").read_text().split("  unsigned-app:", 1)[1]
        steps = ["python3 tests/host/check-app-bootstrap.py", "run: bash .github/ci/native-bootstrap.sh",
                 "bash build/llvm-ios/build.sh fetch", "bash build/dxmt-ios/generate-shaders.sh preflight",
                 "bash build/llvm-ios/build.sh host", "bash build/dxmt-ios/generate-shaders.sh\n",
                 "run: bash build/llvm-ios/build.sh ios", "run: python3 build/dxmt-ios/clean_build.py",
                 "python3 build/app-ios/build_unsigned.py"]
        offsets = [text.index(step) for step in steps]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn('--native-receipt "$NATIVE_ARTIFACT_DIR/provenance.json"', text)
        for name in ("products", "intermediates", "stage"):
            self.assertIn(f'--{name} "$RUNNER_TEMP/madeira-app-{name}"', text)
        self.assertNotIn("if:", text[text.index("- name: Build and validate native"):text.index("- name: Collect bounded")])


if __name__ == "__main__": unittest.main()
