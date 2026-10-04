#!/usr/bin/env python3
"""Apply reviewed native build repairs to the exact pinned FEX source.

No network, pin changes, commits, or reset/cleanup. Validate every listed input
and patch in isolation before changing the checkout. Repairs own disjoint files;
each repair must be wholly original or wholly applied. Ordered repairs already
applied by a previous build remain accepted when a new repair is added. Commit
errors roll back our own writes; concurrent edits are preserved and reported.
"""
import hashlib
import json
from pathlib import Path
import stat
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


def checked_path(root, relative, description):
    if not isinstance(relative, str):
        raise ValueError(f"Invalid {description} path")
    path = Path(relative)
    if (path.is_absolute() or not path.parts
            or "\\" in relative or path.as_posix() != relative or ".." in path.parts):
        raise ValueError(f"Invalid {description} path")
    # Trusted bases can be OS aliases (macOS /var -> /private/var). Compare
    # canonical paths while still rejecting symlinked targets and parent escapes.
    root = root.resolve()
    target = root / path
    if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(root):
        raise ValueError(f"{description} must be a regular file within its checkout")
    return target


def check_tracked_edits(source, allowed):
    if git(source, "diff", "--cached", "--name-only", "-z"):
        raise ValueError("Unexpected staged FEX source modifications")
    changed = set(git(source, "diff", "--name-only", "--no-renames", "-z", "HEAD").decode().split("\0")) - {""}
    if changed - allowed:
        raise ValueError("Unexpected tracked FEX source modifications")


def atomic_write(target, data):
    mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else 0o644
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as out:
        temporary = Path(out.name)
        try:
            out.write(data)
            out.flush()
            temporary.chmod(mode)
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)


def read_record(source):
    record = source / RECORD
    if (record.is_symlink() or record.parent.is_symlink() or not record.resolve().is_relative_to(source)
            or (record.exists() and not record.is_file()) or (record.parent.exists() and not record.parent.is_dir())):
        raise ValueError("FEX repair provenance must be a regular file within its checkout")
    return record.read_bytes() if record.exists() else None


def commit_repairs(source, targets, before, prepared, repairs, record_before):
    record = source / RECORD
    record_data = (json.dumps(SPEC, indent=2) + "\n").encode()
    if read_record(source) != record_before:
        raise ValueError("FEX provenance changed during repair preflight")
    try:
        for _, _, paths in repairs:
            for relative in paths:
                if before[relative] != prepared[relative]:
                    atomic_write(targets[relative], prepared[relative])
        for relative in targets:
            if checked_path(source, relative, "FEX repair source").read_bytes() != prepared[relative]:
                raise ValueError("FEX repaired source hash mismatch")
        record.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(record, record_data)
        if read_record(source) != record_data:
            raise ValueError("FEX repair provenance write mismatch")
    except BaseException as error:
        # Restore only this operation's exact writes. Never overwrite a concurrent
        # edit, including a replaced/symlinked target or a new provenance record.
        rollback_errors = []
        try:
            actual = read_record(source)
            if actual != record_before:
                if actual != record_data:
                    raise ValueError("provenance changed concurrently")
                if record_before is None:
                    record.unlink()
                else:
                    atomic_write(record, record_before)
                if read_record(source) != record_before:
                    raise ValueError("provenance restoration failed")
        except (ValueError, OSError) as rollback_error:
            rollback_errors.append(str(rollback_error))
        for relative in reversed(targets):
            try:
                target = checked_path(source, relative, "FEX repair source")
                actual = target.read_bytes()
                if actual != before[relative]:
                    if actual != prepared[relative]:
                        raise ValueError(f"{relative} changed concurrently")
                    atomic_write(target, before[relative])
                    if checked_path(source, relative, "FEX repair source").read_bytes() != before[relative]:
                        raise ValueError(f"{relative} restoration failed")
            except (ValueError, OSError) as rollback_error:
                rollback_errors.append(str(rollback_error))
        if rollback_errors:
            raise ValueError("FEX repair commit failed; rollback incomplete: " + "; ".join(rollback_errors)) from error
        raise


def apply(source):
    source = source.resolve()
    # An uninitialized submodule must not resolve to Madeira's enclosing Git tree.
    if Path(git(source, "rev-parse", "--show-toplevel").decode().strip()).resolve() != source:
        raise ValueError("FEX must be an initialized Git checkout")
    revision = git(source, "rev-parse", "HEAD").decode().strip()
    if revision != SPEC["source_revision"]:
        raise ValueError(f"Unexpected FEX revision: {revision}")

    originals, before, targets, expected = {}, {}, {}, {}
    repairs, identifiers = [], set()
    for repair in SPEC["repairs"]:
        if repair["id"] in identifiers or not repair["files"]:
            raise ValueError("Duplicate or empty FEX source repair")
        identifiers.add(repair["id"])
        patch = checked_path(ROOT, repair["patch"], "FEX repair patch")
        patch_bytes = patch.read_bytes()
        if sha256(patch_bytes) != repair["patch_sha256"]:
            raise ValueError("FEX repair patch hash mismatch")
        states, paths = set(), []
        for entry in repair["files"]:
            relative = entry["path"]
            if relative in targets:
                raise ValueError("FEX repair files must be disjoint")
            target = checked_path(source, relative, "FEX repair source")
            original = git(source, "show", "HEAD:" + relative)
            if sha256(original) != entry["original_sha256"]:
                raise ValueError("FEX committed source hash mismatch")
            data = target.read_bytes()
            actual = sha256(data)
            if actual == entry["original_sha256"]:
                states.add("original")
            elif actual == entry["patched_sha256"]:
                states.add("patched")
            elif actual in entry.get("previous_patched_sha256", []):
                # Only exact reviewed prior outputs may be upgraded. Preflight
                # still reconstructs the current result from committed bytes.
                states.add("previous:" + str(entry["previous_patched_sha256"].index(actual)))
            else:
                raise ValueError("Unexpected FEX working source hash")
            originals[relative], before[relative], targets[relative] = original, data, target
            expected[relative] = entry["patched_sha256"]
            paths.append(relative)
        if len(states) != 1:
            raise ValueError("Partial FEX source repair")
        repairs.append((repair["id"], patch_bytes, paths))

    if not repairs:
        raise ValueError("No FEX source repairs specified")
    check_tracked_edits(source, targets.keys())
    record_before = read_record(source)

    # Apply all patches to committed bytes in a disposable directory, including
    # previously applied repairs. This verifies every patch/result before the
    # first checkout write and cannot silently accept a broken later repair.
    # Keep patches outside the staging tree so its exact file set is checkable.
    with tempfile.TemporaryDirectory(prefix="FEX repair preflight ") as directory:
        temporary = Path(directory)
        stage = temporary / "source"
        stage.mkdir()
        staged_bytes = dict(originals)
        for relative, data in originals.items():
            staged = stage / relative
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(data)
        for number, (identifier, patch_bytes, paths) in enumerate(repairs):
            patch = temporary / f"{number}.patch"
            patch.write_bytes(patch_bytes)
            git(stage, "apply", "--check", str(patch))
            git(stage, "apply", str(patch))
            actual_paths = {str(path.relative_to(stage)) for path in stage.rglob("*") if path.is_file() or path.is_symlink()}
            if actual_paths != targets.keys():
                raise ValueError("FEX repair patch changed unexpected paths")
            for relative in targets:
                staged = checked_path(stage, relative, "Staged FEX repair source")
                data = staged.read_bytes()
                if relative in paths:
                    if sha256(data) != expected[relative]:
                        raise ValueError("FEX repaired source hash mismatch")
                elif data != staged_bytes[relative]:
                    raise ValueError("FEX repair patch changed another repair's source")
                staged_bytes[relative] = data

        # A concurrent edit during preflight must never be overwritten.
        for relative, target in targets.items():
            if checked_path(source, relative, "FEX repair source").read_bytes() != before[relative]:
                raise ValueError("FEX source changed during repair preflight")
        if git(source, "rev-parse", "HEAD").decode().strip() != revision:
            raise ValueError("FEX revision changed during repair preflight")
        check_tracked_edits(source, targets.keys())
        commit_repairs(source, targets, before, staged_bytes, repairs, record_before)

    record = source / RECORD
    print(f"FEX source repairs verified: {', '.join(repair[0] for repair in repairs)} ({revision}); record: {record}")


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
