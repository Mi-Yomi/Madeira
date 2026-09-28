#!/bin/bash
# Best effort: pull the x64 VC++ 2015-2022 runtime DLLs out of Microsoft's
# redistributable into app/Madeira/x86_64-vcruntime (see tools/fetch-vcruntime.md).
set -eu
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DST="$R/app/Madeira/x86_64-vcruntime"
T="$(mktemp -d)"
curl -fsSL -o "$T/vc_redist.x64.exe" https://aka.ms/vs/17/release/vc_redist.x64.exe
7zz x -y "$T/vc_redist.x64.exe" -o"$T/x" >/dev/null
# Unpack nested cabinets/containers until nothing new appears.
for pass in 1 2 3; do
    find "$T/x" -type f ! -name '*.dll' ! -name '*.done' | while read -r f; do
        [ -e "$f.done" ] && continue
        7zz x -y "$f" -o"$f.d" >/dev/null 2>&1 || true
        touch "$f.done"
    done
done
find "$T/x" -type f ! -name '*.done' | sed "s|$T/x/||" | head -80
WANT="concrt140 msvcp140 msvcp140_1 msvcp140_2 msvcp140_atomic_wait msvcp140_codecvt_ids vcamp140 vccorlib140 vcomp140 vcruntime140 vcruntime140_1 vcruntime140_threads"
got=0
for w in $WANT; do
    # Inside the MSI cabinets files are named e.g. "vcruntime140_amd64" or "vcruntime140.dll".
    f=$(find "$T/x" -type f \( -iname "$w.dll" -o -iname "${w}_amd64" -o -iname "${w}.dll_amd64" -o -iname "${w}_x64" \) | head -1)
    if [ -n "$f" ] && head -c2 "$f" | grep -q MZ; then
        cp "$f" "$DST/$w.dll"; got=$((got+1))
    else
        echo "missing $w"
    fi
done
echo "vcruntime: $got/12"
