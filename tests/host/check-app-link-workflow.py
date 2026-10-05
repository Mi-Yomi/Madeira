#!/usr/bin/env python3
"""Portable scope and resource guardrails for the separate no-IPA diagnostic."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
TEXT = (ROOT / ".github/workflows/app-link-diagnostic.yml").read_text()
JOB = TEXT.split("  app-link-diagnostic:\n", 1)[1]


class WorkflowTests(unittest.TestCase):
    def test_only_specific_request_or_workflow_push_triggers(self):
        trigger = TEXT.split("permissions:", 1)[0]
        self.assertIn("  workflow_dispatch:\n", trigger)
        self.assertIn("branches: [compatibility/desktop-apps]", trigger)
        paths = re.findall(r"^      - (.+)$", trigger, re.M)
        self.assertEqual(paths, [".github/workflows/app-link-diagnostic.yml", "build/app-ios/link-diagnostic-request.json"])
        for event in ("pull_request:", "workflow_run:", "schedule:", "inputs:"):
            self.assertNotIn(event, trigger)

    def test_public_authorized_fork_branch_and_standard_bounded_runner(self):
        condition = "if: github.repository == 'Mi-Yomi/Madeira' && github.event.repository.private == false && github.ref == 'refs/heads/compatibility/desktop-apps'"
        self.assertEqual(TEXT.count(condition), 2)
        self.assertIn("needs: portable-validation", JOB)
        self.assertIn("    runs-on: xcode-27\n    timeout-minutes: 45\n", JOB)
        self.assertEqual(re.findall(r"^    runs-on: (.+)$", TEXT, re.M), ["ubuntu-latest", "xcode-27"])
        self.assertIn("contents: read", TEXT)
        self.assertEqual(TEXT.count("persist-credentials: false"), 2)
        for key in ("JOBS", "BUILD_JOBS", "CMAKE_BUILD_PARALLEL_LEVEL", "CARGO_BUILD_JOBS"):
            self.assertIn(f"      {key}: '2'\n", JOB)
        self.assertIn("MAKEFLAGS: -j2", JOB)
        for forbidden in ("matrix:", "actions/cache", "actions/upload-artifact", "actions/download-artifact", "secrets.",
                          "-large", "continue-on-error", "allowProvisioning", "exportArchive", "codesign --", "--package",
                          "-license accept", "fetch-converter.sh", "build_unsigned.py", "ditto ", " zip "):
            self.assertNotIn(forbidden, TEXT)

    def test_full_app_workflow_remains_paused(self):
        old = (ROOT / ".github/workflows/unsigned-app-bootstrap.yml").read_text().split("  unsigned-app:\n", 1)[1]
        self.assertIn("    if: false\n", old.split("    steps:\n", 1)[0])

    def test_dependency_gates_are_unconditional_and_ordered_before_link(self):
        steps = ["python3 build/app-ios/link_diagnostic.py request", "python3 build/wine-pe/verify_desktop_integration.py",
                 "python3 tests/host/check-desktop-integration.py", "python3 tests/host/check-app-link-diagnostic.py",
                 "python3 tests/host/check-app-link-workflow.py", "python3 tests/host/check-app-bootstrap.py",
                 "python3 build/app-ios/link_diagnostic.py native", "bash build/llvm-ios/build.sh fetch",
                 "bash build/dxmt-ios/generate-shaders.sh preflight", "bash build/llvm-ios/build.sh host",
                 "bash build/dxmt-ios/generate-shaders.sh\n", "run: bash build/llvm-ios/build.sh ios",
                 "run: python3 build/dxmt-ios/clean_build.py", "python3 build/app-ios/link_diagnostic.py build"]
        offsets = [JOB.index(step) for step in steps]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn("submodules: recursive", JOB)
        gate_steps = JOB[JOB.index("- name: Verify integration"):JOB.index("- name: Independently scan")]
        self.assertNotIn("if:", gate_steps)
        self.assertIn('--native-receipt "$NATIVE_ARTIFACT_DIR/provenance.json"', JOB)
        native = (ROOT / ".github/ci/native-bootstrap.sh").read_text()
        self.assertIn("ensure-metal-toolchain.py --allow-install", native)

    def test_final_scan_is_always_run_and_success_requires_receipt_recheck(self):
        scan = JOB.split("      - name: Independently scan", 1)[1].split("      - name:", 1)[0]
        verify = JOB.split("      - name: Independently verify", 1)[1].split("      - name:", 1)[0]
        self.assertIn("        if: always()\n", scan)
        self.assertIn("        if: always() && steps.link.outcome == 'success'\n", verify)
        self.assertIn("link_diagnostic.py scan", scan)
        self.assertIn("link_diagnostic.py verify", verify)
        for output in ("products", "intermediates", "diagnostics"):
            self.assertEqual(JOB.count(f'--{output} "$RUNNER_TEMP/madeira-link-{output}"'), 3)
        self.assertIn("id: link", JOB)


if __name__ == "__main__":
    unittest.main()
