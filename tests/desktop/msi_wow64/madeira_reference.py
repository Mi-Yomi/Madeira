#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate Madeira diagnostic-canary output; never execute or enable a runtime.

This parser checks a transcript, not its device identity or binary provenance.
An acceptance receipt must additionally bind the log to the exact diagnostic
app, native archives, farm, canary, launch mode, device and process exit status.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from windows_reference import MAX_LOG, PREFIX, verify_proof


def verify_madeira_proof(log, returncode):
    baseline = verify_proof(log, returncode)
    children = baseline["child_pids"]
    if children[0] != children[1]:
        raise ValueError("The two rounds must observe one retained child process")
    rows = []
    for line in log.splitlines():
        if not line.startswith(PREFIX):
            continue
        row = line[len(PREFIX):].strip()
        if row.startswith("CA-PROOF "):
            continue  # Optional child stderr, never an acceptance condition.
        match = re.fullmatch(r"(.+) ([0-9]{1,10})", row)
        if not match or int(match[2]) > 0xffffffff:
            raise ValueError("Malformed diagnostic proof row")
        rows.append((match[1], int(match[2])))
    expected_labels = ["START parent-pid", "PASS parent-guest-base-zero"]
    for _ in range(2):
        expected_labels += ["ACTION positive-return", "PASS child-syswow64-image",
                            "PASS child-guest-base-high", "PASS child-guest-base-low",
                            "PASS child-pid", "PASS positive-round"]
    expected_labels += ["PASS missing-export-rejected", "PASS session-close",
                        "PASS child-exit", "PASS final"]
    if [label for label, _ in rows] != expected_labels:
        raise ValueError("Missing, repeated, unexpected or reordered diagnostic proof")
    if rows[1][1] != 0:
        raise ValueError("The native parent must have no guest window")
    bases = []
    for start in (2, 8):
        if rows[start + 1][1] != children[0]:
            raise ValueError("The image proof must identify the retained child")
        high, low = rows[start + 2][1], rows[start + 3][1]
        base = (high << 32) | low
        if low or not 0x100000000 <= base <= 0xffffffffffffffff - 0xffffffff:
            raise ValueError("Unaligned, invalid or wrapping four-GiB guest window")
        bases.append(base)
    if bases[0] != bases[1] or rows[-2][1] != children[0]:
        raise ValueError("Child window changed or exit proof identifies another process")
    return {**baseline, "guest_base": bases[0], "native_parent_guest_base": 0,
            "syswow64_msiexec_image_verified": True,
            "child_process_termination_proven": True,
            "source": "supplied log only; bind to device/build receipt separately",
            "scope": "source-owned MSI cross-bitness diagnostic; no application support claim"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--exit-code", type=int, required=True)
    args = parser.parse_args()
    if args.log.is_symlink() or not args.log.is_file() or not 0 < args.log.stat().st_size <= MAX_LOG:
        parser.error("Expected a regular nonempty diagnostic log no larger than 1 MiB")
    try:
        with args.log.open("rb") as stream:
            data = stream.read(MAX_LOG + 1)
        if len(data) > MAX_LOG:
            raise ValueError("Diagnostic log grew beyond the size limit")
        print(json.dumps(verify_madeira_proof(data.decode("utf-8", errors="strict"), args.exit_code), indent=2))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Madeira diagnostic proof rejected: {exc}\n")


if __name__ == "__main__":
    main()
