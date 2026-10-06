"""Offline production-source inputs and compiler runner for FEX guard tests."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).with_name("fixtures") / "fex-pe"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def repaired_sources(architecture):
    """Validate full pinned snapshots, then apply the real repair in isolation.

    The production manifest's revision and hashes are never substituted. Git is
    used only to check/apply a patch in a disposable directory; FEX is not read.
    """
    provenance = json.loads((FIXTURES / "provenance.json").read_text())
    spec = json.loads((ROOT / "build/fex-ios/source-repairs.json").read_text())
    require(provenance["schema_version"] == 1, "Unknown fixture provenance schema")
    for key in ("source_repository", "source_revision"):
        require(provenance[key] == spec[key], f"Fixture {key} disagrees with production manifest")
    entries = [entry for entry in provenance["files"] if entry["fixture"] == f"{architecture}/Module.cpp"]
    require(len(entries) == 1, "Missing or duplicate fixture provenance")
    entry, = entries
    relative = f"Source/Windows/{architecture}/Module.cpp"
    require(entry["source_path"] == relative, "Unexpected fixture source path")
    source_url = (spec["source_repository"].removesuffix(".git") + "/blob/"
                  + spec["source_revision"] + "/" + relative)
    require(entry["source_url"] == source_url, "Unexpected fixture source URL")
    original = (FIXTURES / entry["fixture"]).read_bytes()
    require(digest(original) == entry["sha256"], "Fixture source SHA-256 mismatch")
    blob = hashlib.sha1(f"blob {len(original)}\0".encode() + original).hexdigest()
    require(blob == entry["git_blob_sha1"], "Fixture upstream Git blob mismatch")
    matches = [(repair, item) for repair in spec["repairs"] for item in repair["files"]
               if item["path"] == relative]
    require(len(matches) == 1, "Missing or duplicate production guard repair")
    repair, item = matches[0]
    require(len(repair["files"]) == 1, "Guard repair must own exactly its production module")
    require(digest(original) == item["original_sha256"], "Fixture disagrees with production original hash")
    patch = ROOT / repair["patch"]
    require(digest(patch.read_bytes()) == repair["patch_sha256"], "Production patch SHA-256 mismatch")
    with tempfile.TemporaryDirectory(prefix="FEX guard source ") as temporary:
        stage = Path(temporary)
        target = stage / relative
        target.parent.mkdir(parents=True)
        target.write_bytes(original)
        for arguments in (("--check",), ()):
            subprocess.run(["git", "-C", str(stage), "apply", *arguments, str(patch)], check=True)
        require({p.relative_to(stage).as_posix() for p in stage.rglob("*") if p.is_file()} == {relative},
                "Guard patch changed unexpected source files")
        patched = target.read_bytes()
    require(digest(patched) == item["patched_sha256"], "Production repaired source SHA-256 mismatch")
    return original.decode(), patched.decode()


def replace_once(text, old, new):
    require(text.count(old) == 1, f"Mutation anchor must be unique: {old!r}")
    return text.replace(old, new, 1)


def run_harness(source, work, label, expected_failures, total, ios=False):
    """Require an ordinary executable result and exact case/failure counts."""
    cpp = work / (label + ".cpp")
    executable = work / label
    cpp.write_text(source)
    compiler = shlex.split(os.environ.get("CXX", "c++"))
    require(bool(compiler), "CXX must name a C++ compiler")
    command = [*compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic"]
    if ios:
        command.append("-DFEX_IOS_HOST")
    subprocess.run([*command, str(cpp), "-o", str(executable)], check=True)
    result = subprocess.run([str(executable)], text=True, capture_output=True, check=False)
    match = re.fullmatch(r"(\d+) extracted-production cases; failures=(\d+)\n", result.stdout)
    require(match is not None, f"{label}: missing case summary\n{result.stdout}\n{result.stderr}")
    observed = tuple(map(int, match.groups()))
    expected_status = 1 if expected_failures else 0
    require(result.returncode == expected_status and observed == (total, expected_failures),
            f"{label}: status={result.returncode}, cases/failures={observed}, "
            f"expected={(total, expected_failures)}\n{result.stderr}")
    print(f"{label}: {total} cases, {expected_failures} expected failures", flush=True)
