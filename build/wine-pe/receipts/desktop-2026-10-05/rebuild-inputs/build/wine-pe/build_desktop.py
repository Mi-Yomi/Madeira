#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Build six desktop Wine DLLs from the exact submodule pin into a NEW staging
folder. Defaults to printing a plan. Does not download, install into the app,
modify Wine sources, build an IPA, sign or publish anything.

PE file targets, --strip-debug and the ARM64EC typelib alias follow upstream
Madeira build-modules.sh (b4bf4198/5137e8b1). A bounded module allowlist also
prevents replacing DXMT, Madeira-D3D12, FEX or specially padded ntdll images.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from guest_inventory import ARCHES, ROOT, PE, audit_farm, manifest, read_pe_bytes
import build_receipt as receipt
import symbol_audit

TRIPLES = {"aarch64": "aarch64-w64-mingw32", "arm64ec": "arm64ec-w64-mingw32", "i386": "i686-w64-mingw32", "x86_64": "x86_64-w64-mingw32"}
LICENSE_FILES = {
    "COPYING.LIB": "Wine-LGPL-2.1.txt",
    "LICENSE-MADEIRA.md": "Wine-LICENSE-MADEIRA.md",
    "libs/compiler-rt/LICENSE.TXT": "Wine-compiler-rt-LICENSE.txt",
}
CONFIGURE = ["--without-x", "--without-vulkan", "--without-freetype", "--without-gnutls", "--without-gstreamer", "--disable-tests"]


def command(argv, cwd=None, env=None):
    out, err = receipt.bounded_output(argv, cwd=cwd, env=env)
    return (out + err).decode(errors="replace").strip()


def plan(root, arches, toolchain, jobs, archive=None):
    modules = manifest()["profiles"]["desktop"]
    return {"schema_version": 1, "wine_revision": manifest()["wine_revision"],
            "profile": "desktop", "jobs": jobs, "toolchain": str(toolchain),
            "toolchain_archive": str(archive) if archive is not None else None,
            "required_evidence": ["source-inputs.json", "toolchain-receipt.json", "SOURCE-REBUILD.md",
                                  "SHA256SUMS", "rebuild-inputs/", "licenses/", "symbol audits", "LLVM metadata"],
            "architectures": [{"arch": arch, "configure": [str(root / "wine/configure"), "--enable-archs=" + arch] + CONFIGURE,
                "targets": [f"dlls/{m}/{arch}-windows/{m}.dll" for m in modules],
                "strip": [str(toolchain / (TRIPLES[arch] + "-strip")), "--strip-debug"]} for arch in arches]}


def validate_source(root, git=None):
    git = git or shutil.which("git")
    if not git:
        raise ValueError("git is required for exact source verification")
    git_env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    git_env["GIT_NO_REPLACE_OBJECTS"] = "1"
    wine = root / "wine"
    expected = manifest()["wine_revision"]
    if not (wine / "configure").is_file():
        raise ValueError("Wine submodule is not initialized; restore the recorded submodule (no download is performed here)")
    if Path(command([git, "--no-replace-objects", "-C", wine, "rev-parse", "--show-toplevel"], env=git_env)) != wine.resolve():
        raise ValueError("wine is not its own git checkout")
    gitlink = command([git, "--no-replace-objects", "-C", root, "ls-tree", "HEAD", "wine"], env=git_env).split()
    if len(gitlink) != 4 or gitlink[:3] != ["160000", "commit", expected]:
        raise ValueError("repository Wine gitlink differs from the reviewed desktop manifest")
    if command([git, "--no-replace-objects", "-C", wine, "rev-parse", "HEAD"], env=git_env) != expected:
        raise ValueError("Wine checkout is not at the reviewed pin")
    if command([git, "--no-replace-objects", "-C", wine, "status", "--porcelain", "--untracked-files=no"], env=git_env):
        raise ValueError("Wine tracked sources are modified; use a clean pinned checkout")
    if not (root / "build/madeira_cfg.h").is_file():
        raise ValueError("Wine needs Madeira's adjacent build/madeira_cfg.h; a standalone Wine clone is insufficient")
    for module in manifest()["profiles"]["desktop"]:
        path = wine / "dlls" / module / "Makefile.in"
        if not re.search(r"^MODULE\s*=\s*" + re.escape(module) + r"\.dll\s*$", path.read_text(), re.M):
            raise ValueError(f"unexpected Wine module definition: {module}")
    for relative in LICENSE_FILES:
        if not (wine / relative).is_file():
            raise ValueError(f"missing Wine license: {relative}")
    return expected


def build_environment(toolchain, arches):
    # Do not inherit compiler/cache/make overrides: otherwise provenance can
    # hash one toolchain while configure silently invokes another compiler.
    keep = ("HOME", "USER", "LOGNAME", "TMPDIR", "TMP", "TEMP", "DEVELOPER_DIR")
    env = {key: os.environ[key] for key in keep if key in os.environ}
    env.update(PATH=str(toolchain) + os.pathsep + os.defpath,
               LC_ALL="C", CONFIG_SITE="/dev/null", CFLAGS="-O2", CROSSCFLAGS="-g -O2")
    # Resolve optional relocated host prerequisites once, then exclude ambient
    # PATH directories from configure/make helper discovery. Cross tools must
    # come from the verified installation; remaining utilities are system tools.
    host_path = os.environ.get("PATH", os.defpath)
    host_names = {"CC": "cc", "CXX": "c++", "CPP": "cpp", "LD": "ld", "AR": "ar",
                  "RANLIB": "ranlib", "STRIP": "strip", "BISON": "bison", "FLEX": "flex",
                  "M4": "m4", "MAKE": "make", "GIT": "git", "CONFIG_SHELL": "sh"}
    for variable, name in host_names.items():
        path = shutil.which(name, path=host_path)
        if not path:
            raise ValueError(f"host tool {name} is required on PATH (nothing is installed automatically)")
        env[variable] = os.path.abspath(path)
    pkg_config = shutil.which("pkg-config", path=host_path)
    env["PKG_CONFIG"] = os.path.abspath(pkg_config) if pkg_config else "false"
    for arch in set(arches) | ({"x86_64"} if "arm64ec" in arches else set()):
        # A target-prefixed override suppresses Wine's automatic Windows/MSVC
        # target selection and leaves ARM64EC in MinGW/GNU mode. The pinned
        # headers then select x86 inline assembly. Unprefixed clang lets Wine
        # add its explicit -target <arch>-windows flags, with no source patch.
        env[arch + "_CC"] = str(toolchain / "clang")
    return env


def validate_tools(toolchain, arches, env):
    version = command([env["BISON"], "--version"], env=env).splitlines()[0]
    match = re.search(r"\b(\d+)\.(\d+)", version)
    if not match or tuple(map(int, match.groups())) < (3, 0):
        raise ValueError("bison 3.0+ is required; the macOS system bison is too old")
    records = {"host_tools": {}, "compiler_environment": {
        k: v for k, v in env.items() if k not in ("HOME", "USER", "LOGNAME", "TMPDIR", "TMP", "TEMP")}}
    for variable in ("CC", "CXX", "CPP", "LD", "AR", "RANLIB", "STRIP", "BISON", "FLEX", "M4", "MAKE", "GIT", "CONFIG_SHELL", "PKG_CONFIG"):
        if env[variable] == "false":
            continue
        path = Path(env[variable])
        records["host_tools"][variable] = {"path": str(path), "resolved_path": str(path.resolve()), **receipt.hash_file(path)}
        if variable in ("CC", "CXX", "CPP", "BISON", "FLEX", "M4", "MAKE", "GIT", "PKG_CONFIG"):
            records["host_tools"][variable]["version"] = command([path, "--version"], env=env).splitlines()[0]
    paths = [toolchain / name for name in ("clang", "ld.lld", "llvm-readobj")]
    for arch in sorted(set(arches) | ({"x86_64"} if "arm64ec" in arches else set())):
        paths.extend(toolchain / (TRIPLES[arch] + "-" + suffix)
                     for suffix in (("clang", "strip") if arch in arches else ("clang",)))
    for path in paths:
        if not path.is_file() or not os.access(path, os.X_OK) or not path.resolve().is_relative_to(toolchain.parent):
            raise ValueError(f"missing/nonlocal toolchain executable: {path}")
        records[path.name] = {"path": str(path), "resolved_path": str(path.resolve()),
                              "version": command([path, "--version"], env=env).splitlines()[0],
                              **receipt.hash_file(path)}
    records["host_tools"]["PYTHON"] = {"path": sys.executable, "resolved_path": str(Path(sys.executable).resolve()),
                                       "version": sys.version, **receipt.hash_file(Path(sys.executable))}
    records["host_system"] = {"system": platform.system(), "release": platform.release(), "machine": platform.machine()}
    records["limits"] = "Host tool executables are recorded separately; external host headers, libraries, wrapper data and OS are not a hermetic image."
    return records


def run_logged(argv, cwd, env, log):
    try:
        subprocess.run(argv, cwd=cwd, env=env, check=True, stdout=log, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        log.flush()
        # Failed staging is removed; keep bounded compiler diagnostics visible.
        with Path(log.name).open("rb") as failed_log:
            failed_log.seek(max(0, Path(log.name).stat().st_size - 12000))
            tail = failed_log.read(12000).decode(errors="replace")
        raise ValueError(f"build command failed ({exc.returncode}): {argv}\n{tail}") from exc


def stage_outputs(build_tree, destination, arch, modules, strip, env):
    """Validate all outputs before publishing any staged DLL. No app writes."""
    destination.mkdir()
    for module in modules:
        src = build_tree / f"dlls/{module}/{arch}-windows/{module}.dll"
        if src.is_symlink() or not src.is_file():
            raise ValueError(f"missing/nonregular fresh build output: {src}")
        output = destination / (module + ".dll")
        shutil.copyfile(src, output)
        command([strip, "--strip-debug", output], env=env)
        image = PE(read_pe_bytes(output))
        if image.architecture() != arch:
            raise ValueError(f"{module}.dll is not {arch}; no cross-architecture fallback is permitted")
        image.dependencies()  # Reject malformed import/forwarder tables before staging.


def build(root, arches, toolchain, jobs, output, archive=None):
    if output.exists() or output.is_symlink():
        raise ValueError("output must not exist; fresh staging prevents stale binaries satisfying this build")
    if not 1 <= jobs <= 2:
        raise ValueError("desktop builds are bounded to one or two compile jobs")
    protected = (root / "app").resolve()
    if output.resolve().is_relative_to(protected) or protected.is_relative_to(output.resolve()):
        raise ValueError("output must be outside app resources")
    # Verify bytes before executing any selected cross-toolchain program.
    toolchain_receipt = receipt.verify_toolchain(toolchain, archive)
    # Toolchain first in PATH lets Wine discover the PE cross compiler. Host CC
    # remains Wine's normal host tool; do not point CC at an iOS compiler.
    env = build_environment(toolchain, arches)
    revision = validate_source(root, env["GIT"])
    versions = validate_tools(toolchain, arches, env)
    recipe = plan(root, arches, toolchain, jobs, archive)
    source = receipt.capture_source(root, env["GIT"], revision)
    modules = manifest()["profiles"]["desktop"]
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".desktop-stage-", dir=output.parent) as temp:
        stage = Path(temp) / "result"
        stage.mkdir()
        receipt.capture_inputs(root, stage, source)
        receipt.write_json(stage / "toolchain-receipt.json", toolchain_receipt)
        reports, symbols = [], []
        for item in recipe["architectures"]:
            arch = item["arch"]
            # Source-relative includes in Madeira Wine require the actual wine/
            # checkout to remain adjacent to build/. The build tree is disposable.
            with tempfile.TemporaryDirectory(prefix="build-desktop-" + arch + "-", dir=root / "wine") as work:
                work = Path(work)
                logfile = stage / (arch + "-build.log")
                with logfile.open("w") as log:
                    run_logged(item["configure"], work, env, log)
                    if arch == "arm64ec":
                        typelib = work / "dlls/stdole2.tlb"
                        typelib.mkdir(parents=True, exist_ok=True)
                        (typelib / "aarch64-windows").symlink_to("arm64ec-windows", target_is_directory=True)
                    if not item["targets"]:
                        raise ValueError("refusing make without explicit PE targets")
                    run_logged([env["MAKE"], "-j" + str(jobs)] + item["targets"], work, env, log)
                stage_outputs(work, stage / (arch + "-windows"), arch, modules,
                              toolchain / (TRIPLES[arch] + "-strip"), env)
            report = audit_farm(root / "app/Madeira" / (arch + "-windows"), arch,
                                {m + ".dll" for m in modules}, stage / (arch + "-windows"))
            if report["errors"] or report["missing_required"]:
                raise ValueError(f"invalid combined {arch} inventory: {report['errors']}; {report['missing_required']}")
            reports.append(report)
            receipt.write_json(stage / (arch + "-inventory.json"), report)
            symbols.append(symbol_audit.audit(root, arch, stage / (arch + "-windows"),
                                               toolchain / "llvm-readobj", stage, modules=modules, env=env))
            audited_inputs = {name: {key: value[key] for key in ("bytes", "sha256", "architecture")}
                              for name, value in report["modules"].items()}
            if symbols[-1]["input_modules"] != audited_inputs:
                raise ValueError(f"{arch} farm/overlay changed between inventory and symbol audit")
        # Keep the source/license identity beside the uninstalled binaries.
        licenses = stage / "licenses"
        licenses.mkdir()
        for relative, name in LICENSE_FILES.items():
            shutil.copyfile(root / "wine" / relative, licenses / name)
        shutil.copyfile(root / "THIRD-PARTY-NOTICES.md", licenses / "Madeira-THIRD-PARTY-NOTICES.md")
        record = {"recipe": recipe, "wine_revision": revision, "tools": versions,
                  "staged_only": True, "runtime_tested": False, "overlay_audit": reports,
                  "symbol_audit": [{"architecture": r["architecture"], "counts": r["counts"], "issues": r["issues"]} for r in symbols],
                  "source_receipt": "source-inputs.json", "toolchain_receipt": "toolchain-receipt.json",
                  "bitwise_reproducibility_established": False,
                  "limits": "This is a six-DLL overlay, not a complete i386 farm or a runtime compatibility claim."}
        (stage / "provenance.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        receipt.write_rebuild(stage, source, toolchain_receipt, recipe)
        # Detect source/tool substitutions during the build before publication.
        validate_source(root, env["GIT"])
        if receipt.capture_source(root, env["GIT"], revision) != source:
            raise ValueError("source/build inputs changed during compilation")
        if receipt.verify_toolchain(toolchain, archive) != toolchain_receipt:
            raise ValueError("toolchain changed during compilation")
        if validate_tools(toolchain, arches, env) != versions:
            raise ValueError("recorded host/cross tool changed during compilation")
        for arch, report in zip(arches, reports):
            if audit_farm(root / "app/Madeira" / (arch + "-windows"), arch,
                          {m + ".dll" for m in modules}, stage / (arch + "-windows")) != report:
                raise ValueError(f"{arch} farm/overlay changed before publication")
        receipt.seal_stage(stage, arches, modules, source, LICENSE_FILES)
        # Publish the entire stage only after every requested build and PE check
        # succeeded. A failed second architecture cannot publish a partial set.
        if output.exists() or output.is_symlink():
            raise ValueError("output appeared during compilation; refusing to replace it")
        stage.rename(output)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", action="append", choices=ARCHES)
    parser.add_argument("--toolchain", type=Path, default=ROOT / "toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--toolchain-archive", type=Path, help="original reviewed official archive; required for --build")
    parser.add_argument("--output", type=Path, default=ROOT / "build/wine-pe/out/desktop")
    parser.add_argument("--build", action="store_true", help="actually compile; otherwise print the plan only")
    args = parser.parse_args()
    if not 1 <= args.jobs <= 2:
        parser.error("--jobs must be 1 or 2")
    arches = list(dict.fromkeys(args.arch or ["aarch64", "arm64ec"]))
    toolchain = args.toolchain.resolve()
    if not args.build:
        print(json.dumps(plan(ROOT, arches, toolchain, args.jobs, args.toolchain_archive), indent=2))
        return 0
    try:
        record = build(ROOT, arches, toolchain, args.jobs, Path(os.path.abspath(args.output)), args.toolchain_archive)
        print(f"Staged source-built DLLs at {args.output}; app resources were not changed.")
        gaps = sum(len(r["missing_dependencies"]) for r in record["overlay_audit"])
        print(f"Combined farm audit: {gaps} unresolved dependency edges; see provenance.json.")
        print("No Wine/installer/device test has run; the stage does not establish application compatibility.")
        return 0
    except (ValueError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f"ERROR: {exc}; no stage published", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
