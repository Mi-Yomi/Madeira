#!/usr/bin/env python3
"""Apply only the reviewed native build repair to the exact pinned FEX source.

No network, pin changes, commits, or reset/cleanup. Unexpected source revisions,
edits, or patch bytes fail closed before CMake. Repeated runs accept only the
exact reviewed result and revalidate it before recording its provenance.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SPEC = json.loads((Path(__file__).with_name("source-repairs.json")).read_text())
RECORD = Path("build-ios/madeira-source-repairs.json")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args], stderr=subprocess.PIPE)


def apply(source):
    source = source.resolve()
    # An uninitialized submodule must not resolve to Madeira's enclosing Git tree.
    if Path(git(source, "rev-parse", "--show-toplevel").decode().strip()).resolve() != source:
        raise ValueError("FEX must be an initialized Git checkout")
    revision = git(source, "rev-parse", "HEAD").decode().strip()
    if revision != SPEC["source_revision"]:
        raise ValueError(f"Unexpected FEX revision: {revision}")

    repair, = SPEC["repairs"]
    entry, = repair["files"]
    relative = entry["path"]
    target = source / relative
    patch = ROOT / repair["patch"]
    if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(source):
        raise ValueError("FEX repair source must be a regular file within its checkout")
    if patch.is_symlink() or not patch.is_file() or not patch.resolve().is_relative_to(ROOT):
        raise ValueError("FEX repair patch must be a regular file within Madeira")
    if sha256(patch.read_bytes()) != repair["patch_sha256"]:
        raise ValueError("FEX repair patch hash mismatch")
    if sha256(git(source, "show", "HEAD:" + relative)) != entry["original_sha256"]:
        raise ValueError("FEX committed source hash mismatch")
    changed = set(git(source, "diff", "--name-only", "--no-renames", "-z", "HEAD").decode().split("\0")) - {""}
    if changed - {relative}:
        raise ValueError("Unexpected tracked FEX source modifications")
    actual = sha256(target.read_bytes())
    if actual not in (entry["original_sha256"], entry["patched_sha256"]):
        raise ValueError("Unexpected FEX working source hash")
    if actual == entry["original_sha256"]:
        git(source, "apply", "--check", str(patch))
        git(source, "apply", str(patch))
    if sha256(target.read_bytes()) != entry["patched_sha256"]:
        raise ValueError("FEX repaired source hash mismatch")

    record = source / RECORD
    record.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=record.parent, delete=False) as out:
        temporary = Path(out.name)
        try:
            json.dump(SPEC, out, indent=2)
            out.write("\n")
            out.flush()
            temporary.replace(record)
        finally:
            temporary.unlink(missing_ok=True)
    print(f"FEX source repair verified: {repair['id']} ({revision}); record: {record}")


def main():
    if len(sys.argv) != 1:
        raise ValueError("No arguments accepted; repairs apply only to this Madeira checkout's FEX")
    apply(ROOT / "FEX")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"FEX source repair failed: {exc}", file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            print(exc.stderr.decode(errors="replace"), file=sys.stderr)
        sys.exit(1)
