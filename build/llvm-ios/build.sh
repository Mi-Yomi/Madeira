#!/bin/bash
# Pinned LLVM source / host tools / native iOS archives. See README.md.
set -euo pipefail
exec python3 "$(cd "$(dirname "$0")" && pwd)/build_llvm.py" "$@"
