#!/usr/bin/env python3
"""Drain build output safely while bounding its stored and console log to 8 MiB."""
import sys
from pathlib import Path

HEAD_LIMIT = 6 * 1024 * 1024
TAIL_LIMIT = 2 * 1024 * 1024 - 256
path = Path(sys.argv[1])
head_used = 0
tail = bytearray()
with path.open("wb") as stream:
    while chunk := sys.stdin.buffer.read1(16 * 1024):
        first = chunk[:max(0, HEAD_LIMIT - head_used)]
        if first:
            stream.write(first)
            stream.flush()
            sys.stdout.buffer.write(first)
            sys.stdout.buffer.flush()
            head_used += len(first)
        rest = chunk[len(first):]
        tail.extend(rest)
        if len(tail) > TAIL_LIMIT:
            del tail[:-TAIL_LIMIT]
    if tail:
        marker = b"\n[CI log reached its head limit; final bounded output follows]\n"
        stream.write(marker + tail)
        sys.stdout.buffer.write(marker + tail)
        sys.stdout.buffer.flush()
