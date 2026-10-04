#!/usr/bin/env python3
"""Collect bounded, allowlisted compiler diagnostics, never environments/objects.

Autoconf config.log and CMake configure dumps are deliberately excluded: their
variable/cache sections may contain an inherited environment. Configure stdout,
compiler stderr and make logs are sufficient for this first-stage diagnosis.
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEST = Path(os.environ["NATIVE_LOG_DIR"])
DEST.mkdir(parents=True, exist_ok=True)
PER_FILE = 2 * 1024 * 1024
TOTAL = 16 * 1024 * 1024 - 64 * 1024  # reserve final disk/limit receipts
PATTERNS = (
    "build/gnutls-ios/obj/*-configure.log", "build/gnutls-ios/obj/*-make.log",
    "build/ffmpeg/obj/configure.log", "build/ffmpeg/obj/make.log",
    "build/ntdll-unix/obj/*.err", "build/win32u-unix/obj/*.err", "build/wineserver/obj/*.err", "build/wineserver/obj/base/*.err", "build/wineserver/obj/err-*.txt",
)
# Budget includes the already bounded live log and explicit provenance files.
used = sum(p.stat().st_size for p in DEST.rglob("*") if p.is_file())
summary_remaining = 256 * 1024
for source in sorted({p for pattern in PATTERNS for p in ROOT.glob(pattern)}):
    if not source.is_file() or source.is_symlink() or source.stat().st_size == 0:
        continue
    if used + 256 >= TOTAL:
        (DEST / "diagnostic-limit.txt").write_text("Additional compiler diagnostics omitted at 16 MiB limit.\n")
        break
    target = DEST / "compiler" / source.relative_to(ROOT)
    target.parent.mkdir(parents=True, exist_ok=True)
    limit = min(PER_FILE, TOTAL - used)
    with source.open("rb") as stream:
        data = stream.read(limit)
        if source.stat().st_size > limit:
            marker = b"\n[... middle truncated by CI log size limit ...]\n"
            remaining = limit - len(marker)
            head, tail = remaining // 2, remaining - remaining // 2
            stream.seek(-tail, 2)
            data = data[:head] + marker + stream.read(tail)
    target.write_bytes(data)
    used += len(data)
    # No artifact upload is needed to see useful failures in the native job log.
    if summary_remaining > 0:
        excerpt = b"\n".join(data.splitlines()[-25:])[-min(summary_remaining, 16 * 1024):]
        print(f"\n=== {source.relative_to(ROOT)} (last lines) ===")
        print(excerpt.decode("utf-8", errors="replace"))
        summary_remaining -= len(excerpt)
print(f"Collected {used} bytes of allowlisted compiler diagnostics")

manifest = DEST / "provenance-inputs.json"
if manifest.is_file():
    import json
    source = json.loads(manifest.read_text())
    print("\n=== Provenance (explicit fields only) ===")
    for key in ("source_url", "source_commit", "submodules", "freetype", "llvm_mingw", "tool_versions", "disk_bytes"):
        print(f"{key}: {json.dumps(source[key], sort_keys=True)}")
