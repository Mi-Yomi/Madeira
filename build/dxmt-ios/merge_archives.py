#!/usr/bin/env python3
"""Validate explicit LLVM/DXMT archives, merge without member-name loss, then stage."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "llvm-ios"))
import common


def stage_files(sources):
    """Prepare every file first, atomically replace each, roll back on exceptions.

    POSIX has no multi-file rename transaction. No destination changes until all
    temporary copies are complete and hash checked. On a caught staging failure,
    restore every old file (or absence). A process/host crash between renames must
    be detected by the consumer's receipt/hash gate; this is not crash-atomic.
    """
    prepared, backups, replaced, retained = {}, {}, [], set()
    try:
        for destination, source in sources.items():
            if destination.is_symlink() or (destination.exists() and not destination.is_file()):
                raise ValueError(f"Refusing unsafe output destination: {destination}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            handle, temporary = tempfile.mkstemp(prefix="." + destination.name + ".stage-", dir=destination.parent)
            os.close(handle)
            prepared[destination] = Path(temporary)
            shutil.copyfile(common.regular_file(source), temporary)
            if common.sha256(temporary) != common.sha256(source):
                raise ValueError(f"Staging copy differs: {destination}")
            if destination.exists():
                handle, backup = tempfile.mkstemp(prefix="." + destination.name + ".old-", dir=destination.parent)
                os.close(handle)
                backups[destination] = Path(backup)
                shutil.copyfile(destination, backup)
                if common.sha256(backup) != common.sha256(destination):
                    raise ValueError(f"Backup differs: {destination}")
        try:
            for destination, temporary in prepared.items():
                os.replace(temporary, destination)
                replaced.append(destination)
        except BaseException as error:
            failures = []
            for destination in reversed(replaced):
                try:
                    if destination in backups:
                        os.replace(backups[destination], destination)
                        del backups[destination]
                    else:
                        destination.unlink()
                except OSError as rollback_error:
                    if destination in backups:
                        retained.add(backups[destination])
                    failures.append(f"{destination}: {rollback_error}")
            if failures:
                raise OSError("Staging rollback incomplete; recovery backups retained: " +
                              "; ".join(failures) + "; backups=" + str(sorted(map(str, retained)))) from error
            raise
    finally:
        for temporary in [*prepared.values(), *backups.values()]:
            if temporary not in retained and temporary.exists(): temporary.unlink()


def merge(unix_archive, object_count=None):
    root, native = common.ROOT, common.native_validator()
    unix_info = native.validate_archive(unix_archive)
    if object_count is not None and unix_info["object_members"] != object_count:
        raise ValueError("DXMT archive member count does not match the fresh object manifest")
    llvm = common.verify_llvm_archives()
    llvm_paths = [root / path for path in llvm]
    expected = unix_info["object_members"] + sum(item["object_members"] for item in llvm.values())
    directory = Path(tempfile.mkdtemp(prefix=".merge-", dir=root / "build/dxmt-ios"))
    try:
        combined = directory / "libdxmt_combined.a"
        # Apple libtool reads each archive directly and preserves repeated basenames.
        # Never use ar -x + *.o, which silently overwrites same-named LLVM members.
        common.run(["xcrun", "--sdk", "iphoneos", "libtool", "-static", "-o", combined, unix_archive, *llvm_paths])
        info = native.validate_archive(combined)
        if info["object_members"] != expected:
            raise ValueError(f"Merged member count {info['object_members']} != input sum {expected}")
        data = {"schema_version": 1, "manifest_sha256": common.sha256(common.MANIFEST_PATH),
                "dxmt_revision": common.manifest()["dxmt_revision"],
                "llvm_revision": common.manifest()["revision"],
                "unix_archive": unix_info, "llvm_archives": llvm, "combined_archive": info,
                "input_object_members": expected}
        receipt = directory / "graphics-build.json"
        common.write_json(receipt, data)
        stage_files({root / "build/dxmt-ios/libdxmt_unix.a": unix_archive,
                     root / "build/dxmt-ios/libdxmt_combined.a": combined,
                     root / "app/Madeira/libdxmt_combined.a": combined,
                     root / "build/dxmt-ios/graphics-build.json": receipt})
        print(f"Staged matching validated iOS ARM64 DXMT/LLVM archives ({expected} objects)")
        return data
    finally:
        shutil.rmtree(directory)


def archive_objects(objects, output):
    native = common.native_validator()
    if not objects or len(set(objects)) != len(objects):
        raise ValueError("Expected a nonempty unique DXMT object list")
    for path in objects:
        native.macho_ios_object(common.regular_file(path).read_bytes(), str(path))
    if output.exists():
        raise ValueError(f"DXMT archive output must be fresh: {output}")
    common.run(["xcrun", "--sdk", "iphoneos", "libtool", "-static", "-o", output, *objects])
    data = native.validate_archive(output)
    if data["object_members"] != len(objects):
        raise ValueError("DXMT archive lost one or more fresh object members")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("unix_archive", type=Path)
    args = parser.parse_args()
    try: merge(args.unix_archive)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__": main()
