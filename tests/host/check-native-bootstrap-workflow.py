#!/usr/bin/env python3
"""Fixtures for strict header prep, bounded logs and workflow guardrails."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]


class HeaderPrepTests(unittest.TestCase):
    def exercise(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / ".github/ci/prepare-wine-headers.sh"
            script.parent.mkdir(parents=True)
            shutil.copy2(ROOT / script.relative_to(root), script)
            (root / "wine").mkdir()
            binaries = root / "bin"
            binaries.mkdir()
            scripts = {
                root / "wine/configure": '''#!/bin/bash
set -eu
printf '%s\\n' "$@" >> "$TRACE"
case "$MODE" in configure-fails) exit 23;; esac
mkdir -p include
printf config > include/config.h
''',
                binaries / "xcrun": '''#!/bin/bash
printf '/usr/bin/clang\\n'
''',
                binaries / "make": '''#!/bin/bash
set -eu
printf 'make %s\\n' "$*" >> "$TRACE"
case "$MODE" in make-fails) exit 24;; esac
for header in dwrite.h dwrite_1.h dwrite_2.h dwrite_3.h mfobjects.h mftransform.h; do
  if [ "$MODE" = missing-header ] && [ "$header" = mftransform.h ]; then continue; fi
  printf generated > "include/$header"
done
''',
            }
            for path, content in scripts.items():
                path.write_text(content)
                path.chmod(0o755)
            trace = root / "trace"
            env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ["PATH"], JOBS="2", MODE=mode, TRACE=str(trace))
            result = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True)
            text = trace.read_text() if trace.exists() else ""
            if mode == "ok":
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(text.count("make -j2 include/all"), 2)
                self.assertIn("--enable-archs=aarch64", text)
                self.assertIn("--enable-archs=arm64ec", text)
                self.assertFalse((root / "wine/build-arm64ec").is_symlink())
                again = subprocess.run(["bash", str(script)], env=env, capture_output=True)
                self.assertNotEqual(again.returncode, 0)
            else:
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("--enable-archs=arm64ec", text)

    def test_both_real_header_trees(self):
        self.exercise("ok")

    def test_configure_error_fatal(self):
        self.exercise("configure-fails")

    def test_make_error_fatal(self):
        self.exercise("make-fails")

    def test_missing_header_fatal(self):
        self.exercise("missing-header")


class LogTests(unittest.TestCase):
    def test_live_log_bounded_and_tail_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "log"
            data = b"start\n" + b"a" * (12 * 1024 * 1024) + b"\nimportant final failure\n"
            result = subprocess.run(["python3", str(ROOT / ".github/ci/native-log-stream.py"), str(path)], input=data, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertLessEqual(path.stat().st_size, 8 * 1024 * 1024)
            self.assertLessEqual(len(result.stdout), 8 * 1024 * 1024)
            self.assertTrue(path.read_bytes().startswith(b"start\n"))
            self.assertTrue(path.read_bytes().endswith(b"important final failure\n"))


class WorkflowTests(unittest.TestCase):
    def test_metal_setup_uses_explicit_authorized_opt_in(self):
        text = (ROOT / ".github/ci/native-bootstrap.sh").read_text()
        self.assertIn('python3 .github/ci/ensure-metal-toolchain.py --allow-install --log-dir "$NATIVE_LOG_DIR"', text)
        self.assertNotIn("-license accept", text)
        self.assertNotIn("-runFirstLaunch", text)
        self.assertNotIn("# Optional Metal probe:", text)

    def test_runtime_paths_initialized_in_step_context(self):
        text = (ROOT / ".github/workflows/native-bootstrap.yml").read_text()
        self.assertNotIn("${{ runner.", text)
        step = text.split("- name: Initialize diagnostics", 1)[1].split("- name: Checkout", 1)[0]
        script = textwrap.dedent(step.split("run: |", 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "runner temp with spaces"
            runtime.mkdir()
            exports = root / "github-env"
            result = subprocess.run(["bash", "-eu", "-c", script], capture_output=True, text=True,
                                    env=dict(os.environ, RUNNER_TEMP=str(runtime), GITHUB_ENV=str(exports)))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(exports.read_text().splitlines(), [
                f"NATIVE_LOG_DIR={runtime}/madeira-native-logs",
                f"NATIVE_ARTIFACT_DIR={runtime}/madeira-native-artifacts",
            ])
            self.assertTrue((runtime / "madeira-native-logs/scope.txt").is_file())

    def test_macos_helper_gate_precedes_dependency_builds(self):
        text = (ROOT / ".github/workflows/native-bootstrap.yml").read_text()
        native = text.split("  native:\n", 1)[1]
        checkout = native.index("- name: Checkout pinned source")
        gate = native.index("- name: Check repair and header helpers on macOS")
        build = native.index("- name: Build native dependencies")
        self.assertLess(checkout, gate)
        self.assertLess(gate, build)
        step = native[gate:build]
        self.assertIn("timeout-minutes: 2", step)
        self.assertNotIn("continue-on-error", step)
        self.assertNotIn("if:", step)
        for script in ("check-fex-source-repairs.py", "check-native-bootstrap-workflow.py",
                       "check-native-bootstrap-artifacts.py"):
            self.assertIn("python3 tests/host/" + script, step)
        self.assertIn("timeout-minutes: 45", native)
        self.assertIn("timeout-minutes: 35", native)

    def test_no_automatic_artifact_upload_or_broadened_permissions(self):
        text = (ROOT / ".github/workflows/native-bootstrap.yml").read_text()
        self.assertIn("runs-on: xcode-27", text)
        self.assertIn("timeout-minutes: 45", text)
        self.assertIn("timeout-minutes: 35", text)
        self.assertIn("branches: [compatibility/desktop-apps]", text)
        self.assertIn("contents: read", text)
        self.assertNotIn("write", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("default: false", text)
        for line in text.splitlines():
            if "if:" in line and ("always() &&" in line or "success() &&" in line):
                self.assertIn("github.event_name == 'workflow_dispatch' && inputs.upload_artifacts", line)
            if "uses:" in line:
                self.assertRegex(line, r"@[0-9a-f]{40}(?: |$)")
        for variable in ("JOBS", "BUILD_JOBS", "CMAKE_BUILD_PARALLEL_LEVEL", "CARGO_BUILD_JOBS"):
            self.assertIn(f"{variable}: '2'", text)
        self.assertEqual(text.count("retention-days: 3"), 2)


if __name__ == "__main__":
    unittest.main()
