#!/usr/bin/env python3
"""Reject omitted GnuTLS unixlibs before publishing libntdll_unix.a.

Apple nm's portable -g listing includes undefined references. Require actual
external data definitions for both native and WoW64 tables in each object, and
references to the static GnuTLS shim so crypt32's no-GnuTLS fallback cannot pass.
This is a link-contract check, not a TLS correctness or runtime security test.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess


def parse_symbols(output: str) -> dict[str, set[str]]:
    """Read only complete nm records; a mention or undefined symbol isn't data."""
    symbols: dict[str, set[str]] = {}
    for line in output.splitlines():
        match = re.fullmatch(r"\s*(?:([0-9a-fA-F]+)\s+)?([A-Za-z?])\s+(\S+)\s*", line)
        if match:
            address, kind, name = match.groups()
            if kind != "U" and address is None:
                continue
            symbols.setdefault(name, set()).add(kind)
    return symbols


def check_symbols(output: str, prefix: str) -> None:
    symbols = parse_symbols(output)
    for suffix in ("unix_call_funcs", "unix_call_wow64_funcs"):
        name = f"_{prefix}_{suffix}"
        # Mach-O constant pointer arrays are normally S (__const) or D; accept
        # read-only data too, but not U, local data, absolute symbols or code.
        if symbols.get(name) not in ({"D"}, {"R"}, {"S"}):
            raise ValueError(f"missing external data definition: {name}")
    for suffix in ("dlopen", "dlsym", "dlclose"):
        name = f"_ios_gnutls_{suffix}"
        if symbols.get(name) != {"U"}:
            raise ValueError(f"missing static GnuTLS shim reference: {name}")
    for name in ("___wine_unix_call_funcs", "___wine_unix_call_wow64_funcs"):
        if symbols.get(name, set()) - {"U"}:
            raise ValueError(f"unrenamed unixlib table: {name}")


def check_objects(directory: Path, nm: str) -> None:
    for prefix in ("bcrypt", "secur32", "crypt32"):
        obj = directory / f"{prefix}_unixlib.o"
        if not obj.is_file() or not obj.stat().st_size:
            raise ValueError(f"missing or empty crypto object: {obj}")
        result = subprocess.run([nm, "-g", str(obj)], text=True,
                                capture_output=True, check=False)
        if result.returncode:
            raise ValueError(f"{obj.name}: nm failed ({result.returncode}): {result.stderr.strip()}")
        try:
            check_symbols(result.stdout, prefix)
        except ValueError as exc:
            raise ValueError(f"{obj.name}: {exc}") from exc
        print(f"Verified {obj.name}: native/WoW64 tables and static GnuTLS shim")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nm", required=True, help="Apple/LLVM nm executable")
    parser.add_argument("directory", type=Path, help="compiled ntdll unix object directory")
    args = parser.parse_args()
    try:
        check_objects(args.directory, args.nm)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Crypto unixlib link contract failed: {exc}") from exc


if __name__ == "__main__":
    main()
