#!/usr/bin/env python3
"""Opt-in evidence wrapper for selected normal native C compilations.

The wrapper runs the caller's existing compiler command. It records the actual
object, command/compiler identity, and pre/post dependency bytes. The NSI TU
also emits Clang's record layouts from that same compilation. This is an audit
record from a trusted build job, not a signed or independently reproduced build.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inputs(depfile, root):
    text = depfile.read_text().replace("\\\n", "")
    if not text.startswith("madeira_contract: "):
        raise ValueError("unrecognized compiler dependency output")
    paths = sorted({(root / p).resolve() for p in shlex.split(text.split(": ", 1)[1])})
    if not paths or sum(p.stat().st_size for p in paths) > 128 * 1024 * 1024:
        raise ValueError("empty/oversized compiler dependency set")
    return {str(p.relative_to(root)) if p.is_relative_to(root) else str(p): digest(p) for p in paths}


def capture(root, record, source, output, command):
    root, source, output = root.resolve(), source.resolve(), output.resolve()
    if not source.is_relative_to(root) or not output.is_relative_to(root):
        raise ValueError("source and object must be inside the build checkout")
    if not command or not Path(command[0]).is_absolute() or not Path(command[0]).is_file():
        raise ValueError("pass the absolute real Clang path, not xcrun or a shell wrapper")
    args = command[1:]
    if any(a.startswith(("@", "-flto", "-M")) for a in args) or args.count("-c") != 1 or args.count("-o") != 1:
        raise ValueError("capture requires one ordinary non-LTO compilation, no response/dependency flags")
    oi = args.index("-o")
    if oi + 1 >= len(args) or Path(args[oi + 1]).resolve() != output or str(source) not in args:
        raise ValueError("compiler source/output differ from the requested evidence")
    if not source.is_file() or output.is_symlink() or record.exists():
        raise ValueError("missing source, unsafe output, or existing capture record")
    # Remove an old object before compilation so a failed compile cannot leave
    # a stale success artifact for archive collection. Only this output is touched.
    if output.exists():
        output.unlink()
    record.parent.mkdir(parents=True, exist_ok=True)
    base = [a for i, a in enumerate(args) if a != "-c" and i not in (oi, oi + 1)]
    with tempfile.TemporaryDirectory(prefix="madeira-contract-") as tmp:
        pre, post = Path(tmp) / "pre.d", Path(tmp) / "post.d"
        subprocess.run([command[0], *base, "-M", "-MT", "madeira_contract", "-MF", str(pre)],
                       cwd=root, check=True, timeout=120, capture_output=True)
        before = inputs(pre, root)
        compiler = digest(Path(command[0]))
        invocation = [*command, "-MD", "-MT", "madeira_contract", "-MF", str(post)]
        if source.name == "nsi_unixlib_ios.c":
            invocation += ["-Xclang", "-fdump-record-layouts-complete"]
        result = subprocess.run(invocation, cwd=root, check=True, timeout=240, capture_output=True, text=True)
        after = inputs(post, root)
        if before != after or compiler != digest(Path(command[0])):
            raise ValueError("compiler inputs changed while compiling")
        if not output.is_file() or not output.stat().st_size:
            raise ValueError("compiler did not produce an object")
        document = {"schema": 1, "source": str(source.relative_to(root)),
                    "object": str(output.relative_to(root)), "object_sha256": digest(output),
                    "compiler": str(Path(command[0]).resolve()), "compiler_sha256": compiler,
                    "arguments": command[1:], "dependency_sha256": before,
                    "record_layouts": result.stdout if source.name == "nsi_unixlib_ios.c" else ""}
        record.write_text(json.dumps(document, indent=2) + "\n")
        if result.stderr:
            print(result.stderr, end="")
    return document


def report_failure_output(exc):
    """Print bounded captured tails only; never dump command or environment."""
    limit = 32 * 1024
    for name in ("stdout", "stderr"):
        value = getattr(exc, name, None)
        if not value:
            continue
        data = value[-limit:] if isinstance(value, bytes) else value[-limit:].encode("utf-8", errors="replace")
        # Invalid bytes may expand to replacement characters. Rebound the UTF-8
        # payload after decoding, without cutting a character at its beginning.
        tail = data.decode("utf-8", errors="replace").encode("utf-8")[-limit:].decode("utf-8", errors="ignore")
        sys.stderr.write(f"Captured compiler {name} (last at most {limit} bytes):\n")
        sys.stderr.write(tail)
        if not tail.endswith("\n"):
            sys.stderr.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        capture(args.root, args.record, args.source, args.output, command)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        report_failure_output(exc)
        reason = (f"compiler exited with status {exc.returncode}" if isinstance(exc, subprocess.CalledProcessError)
                  else f"compiler timed out after {exc.timeout} seconds")
        raise SystemExit(f"Native compilation capture failed: {reason}") from exc
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"Native compilation capture failed: {exc}") from exc


if __name__ == "__main__":
    main()
