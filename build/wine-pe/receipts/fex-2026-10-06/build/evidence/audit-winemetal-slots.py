#!/usr/bin/env python3
"""Run Playport's source-only ABI name/order check against pinned Madeira DXMT.

Usage: audit-winemetal-slots.py PLAYPORT_ROOT DXMT_SOURCE_SNAPSHOT
The normalization is specific to willfaust/dxmt 020a848080b861266e04fc0e5f7f6d921614037c.
No runtime integration, code generation, or ABI pointer-layout proof is implied.
Playport tools/slots.py is GPL-3.0-or-later; its unchanged source is loaded here.
"""
import ast
from pathlib import Path
import shutil
import sys
import tempfile


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    playport, target = map(Path, sys.argv[1:])
    source = playport / "tools/slots.py"
    tree = ast.parse(source.read_text())
    # The check() function needs only stdlib modules; phonelib is for pp's CLI default.
    tree.body = [node for node in tree.body if not (
        isinstance(node, ast.Import) and any(name.name == "phonelib" for name in node.names)
    )]
    namespace = {}
    exec(compile(tree, str(source), "exec"), namespace)
    raw = namespace["check"](target)
    print(f"Unadapted Playport check: {raw[0]} slots, {raw[1]} calls, {len(raw[2])} name mismatches")

    original_words = namespace["words"]
    namespace["words"] = lambda name: original_words(name.removesuffix("32"))
    original_same = namespace["same"]
    namespace["same"] = lambda a, b: ({a, b} == {"WMTNop", "_d3d9_nop"}) or original_same(a, b)
    result = namespace["check"](target)
    print(f"Target-normalized check: {result[0]} slots, {result[1]} calls, {len(result[2])} mismatches")
    for mismatch in result[2]:
        print(mismatch)
    assert result == (151, 146, []), result

    with tempfile.TemporaryDirectory(prefix="slot-mutations-", dir=Path(__file__).parent) as temporary:
        work = Path(temporary)
        snapshot = work / "dxmt"
        shutil.copytree(target, snapshot)
        table = snapshot / "src/winemetal/unix/winemetal_unix.c"
        original = table.read_text()
        mutation = original.replace(
            "    &_NSObject_retain,\n    &_NSObject_release,",
            "    &_NSObject_release,\n    &_NSObject_retain,",
            1,
        )
        assert mutation != original
        table.write_text(mutation)
        bad = namespace["check"](snapshot)[2]
        assert any("native _NSObject_release, wow64 _NSObject_retain" in item for item in bad), bad
        assert any("thunk NSObject_retain, native _NSObject_release" in item for item in bad), bad
        print("Mutation test: native slot swap is rejected by both table and thunk comparisons")
        table.write_text(original)
        wow_start = original.index("const void *__wine_unix_call_wow64_funcs[]")
        mutation = original[:wow_start] + original[wow_start:].replace(
            "    &_NSObject_retain,\n    &_NSObject_release,",
            "    &_NSObject_release,\n    &_NSObject_retain,",
            1,
        )
        assert mutation != original
        table.write_text(mutation)
        bad = namespace["check"](snapshot)[2]
        assert any("native _NSObject_retain, wow64 _NSObject_release" in item for item in bad), bad
        print("Mutation test: WOW64-only slot swap is rejected")
    print("PASS: pinned-source slot order and thunk names agree after target-specific normalization")


if __name__ == "__main__":
    main()
