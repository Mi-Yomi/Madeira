#!/bin/bash
# Generate pinned raw AIR headers, verify LLVM15 can read them, then command metallib.
set -euo pipefail
exec python3 "$(cd "$(dirname "$0")" && pwd)/generate_shaders.py" "$@"
