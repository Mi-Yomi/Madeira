#!/usr/bin/env python3
"""Reject incompatible PE caches and check the effective iOS Module.cpp command.

This checks configuration only, never claims that a PE object/DLL was built.
The source-repair record in build-ios also remains a source-only record.
"""
import json
from pathlib import Path
import re
import shlex
import shutil
import sys

ROOT = Path(__file__).resolve().parents[2]


def check(condition, message):
    if not condition:
        raise ValueError(message)


def cache_values(path):
    values = {}
    for line in path.read_text().splitlines():
        if line and not line.startswith(("#", "//")) and "=" in line:
            key, value = line.split("=", 1)
            values[key.split(":", 1)[0]] = value
    return values


def compiler_path(name):
    path = shutil.which(name)
    check(path is not None, f"Required LLVM-MinGW compiler is absent: {name}")
    path = Path(path).absolute()
    # Preserve the architecture-named driver symlink, which sets the target.
    return str(path.parent.resolve() / path.name)


def verify_module_flags(argv, architecture, triple):
    required = {"FEX_IOS_HOST": "1", "FEX_GUEST_WINDOW": "1" if architecture == "wow64" else None,
                "ARCHITECTURE_arm64ec": "1" if architecture == "arm64ec" else None}
    seen = set()
    flags = iter(argv[1:])
    for flag in flags:
        # These modes can hide definitions or target overrides from this
        # intentionally small checker. Fail closed instead of guessing.
        check(not flag.startswith(("@", "-Wp,", "--config")) and flag not in ("-Xpreprocessor", "-Xclang"),
              "Unexpanded or forwarded PE compiler flags cannot be verified")
        if flag in ("-target", "--target"):
            check(next(flags, None) == triple, "Conflicting production PE compiler target")
        elif flag.startswith(("-target=", "--target=")):
            check(flag.split("=", 1)[1] == triple, "Conflicting production PE compiler target")
        elif flag.startswith(("-D", "-U")):
            value = next(flags, "") if flag in ("-D", "-U") else flag[2:]
            name, equal, definition = value.partition("=")
            if name in required:
                check(flag.startswith("-D") and required[name] is not None and
                      (definition if equal else "1") == required[name], f"Conflicting production PE definition: {name}")
                seen.add(name)
    check(seen == {name for name, value in required.items() if value is not None},
          "Production PE command lacks required iOS/architecture/guest-window definitions")


def verify(build, architecture, after=False):
    build = Path(build).resolve()
    source = ROOT / "FEX"
    triple = "arm64ec-w64-mingw32" if architecture == "arm64ec" else "aarch64-w64-mingw32"
    expected_compilers = {language: compiler_path(triple + suffix) for language, suffix in
                          (("C", "-clang"), ("CXX", "-clang++"), ("ASM", "-clang"))}
    cache = build / "CMakeCache.txt"
    if not cache.exists():
        check(not after, "PE configure did not produce CMakeCache.txt")
        check(not build.exists() or not any(build.iterdir()),
              "PE build directory has files without a CMake cache; choose an empty FEX_PE_BUILD_DIR")
        return
    values = cache_values(cache)
    expected = {"CMAKE_GENERATOR": "Ninja", "MINGW_TRIPLE": triple,
                "CMAKE_HOME_DIRECTORY": str(source),
                "CMAKE_TOOLCHAIN_FILE": str(source / "Data/CMake/toolchain_mingw.cmake")}
    for key, value in expected.items():
        check(values.get(key) == value,
              f"Incompatible PE cache {key}: expected {value}; choose an empty FEX_PE_BUILD_DIR")
    # CMake's toolchain sets C/C++ as normal variables, so they may be absent
    # from the cache. Inspect its generated compiler identity files as well.
    for language, compiler in expected_compilers.items():
        key = f"CMAKE_{language}_COMPILER"
        recorded = []
        if key in values:
            recorded.append(values[key])
        for path in (build / "CMakeFiles").glob(f"*/CMake{language}Compiler.cmake"):
            recorded.extend(re.findall(r"^set\(" + key + r' "([^"\n]+)"\)', path.read_text(), re.M))
        check(bool(recorded) and all(item == compiler for item in recorded),
              f"Incompatible PE {language} compiler; choose an empty FEX_PE_BUILD_DIR")
    if not after:
        return
    for key, value in {"FEX_IOS_HOST_BUILD": "ON", "ENABLE_GUEST_WINDOW": "OFF" if architecture == "arm64ec" else "ON",
                       "ENABLE_LTO": "OFF", "ENABLE_JEMALLOC_GLIBC_ALLOC": "OFF"}.items():
        check(values.get(key) == value, f"PE configure did not set {key}={value}")
    for language in expected_compilers:
        check(shlex.split(values.get(f"CMAKE_{language}_FLAGS", "")) == ["-DFEX_IOS_HOST"],
              f"PE {language} flags do not explicitly enable FEX_IOS_HOST")
    commands = json.loads((build / "compile_commands.json").read_text())
    module = source / "Source/Windows" / ("ARM64EC" if architecture == "arm64ec" else "WOW64") / "Module.cpp"
    selected = [entry for entry in commands if Path(entry["file"]).resolve() == module]
    check(len(selected) == 1, "Expected exactly one production Module.cpp compile command")
    command = selected[0]
    argv = command.get("arguments") or shlex.split(command["command"])
    check(Path(command["directory"]).resolve() == build, "Unexpected PE compilation directory")
    check(argv[0] == expected_compilers["CXX"], "Unexpected production PE C++ compiler")
    verify_module_flags(argv, architecture, triple)
    crt = source / "Source/Windows/Common/CRT/CRT_iOS.cpp"
    check(any(Path(entry["file"]).resolve() == crt for entry in commands), "PE iOS CRT was not selected")


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ("before", "after") or sys.argv[3] not in ("arm64ec", "wow64"):
        raise SystemExit("Usage: check-pe-configuration.py before|after BUILD_DIR arm64ec|wow64")
    try:
        verify(sys.argv[2], sys.argv[3], after=sys.argv[1] == "after")
    except (ValueError, OSError, KeyError) as error:
        raise SystemExit(f"FEX PE configuration rejected: {error}") from error


if __name__ == "__main__":
    main()
