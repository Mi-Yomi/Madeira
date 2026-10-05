#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Madeira Converter Exception: see LICENSE-EXCEPTION.md
"""Portable executable-byte/failure-injection tests; no compiler, Wine or network."""
from pathlib import Path
import json
import struct
import subprocess
import sys
import tempfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "build/wine-pe"))
import guest_inventory as inventory
import build_desktop as builder


def pe(arch="aarch64", imports=(), delayed=(), forwards=(), api_sets=None):
    """Small file-backed PE with real directory layouts, never executed."""
    data = bytearray(0x2200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    is64 = arch != "i386"
    optional = 240 if is64 else 224
    machine = {"aarch64": 0xaa64, "arm64ec": 0x8664, "x86_64": 0x8664, "i386": 0x14c}[arch]
    struct.pack_into("<HH", data, 0x84, machine, 1)
    struct.pack_into("<H", data, 0x94, optional)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20b if is64 else 0x10b)
    image_base = 0x180000000 if is64 else 0x400000
    struct.pack_into("<Q" if is64 else "<I", data, opt + (24 if is64 else 28), image_base)
    struct.pack_into("<I", data, opt + 60, 0x200)
    fixed = 112 if is64 else 96
    struct.pack_into("<I", data, opt + fixed - 4, 16)
    name = b".apiset" if api_sets is not None else b".rdata"
    struct.pack_into("<8sIIII", data, opt + optional, name, 0x2000, 0x1000, 0x2000, 0x200)
    cursor = 0x1300

    def rva(offset):
        return offset - 0x200 + 0x1000

    def add_string(text):
        nonlocal cursor
        value = rva(cursor)
        encoded = text.encode("ascii") + b"\0"
        data[cursor:cursor + len(encoded)] = encoded
        cursor += len(encoded)
        return value

    def directory(index, offset, size):
        struct.pack_into("<II", data, opt + fixed + index * 8, rva(offset), size)

    for index, start, width, names in ((1, 0x300, 20, imports), (13, 0x500, 32, delayed)):
        if not names:
            continue
        directory(index, start, (len(names) + 1) * width)
        for i, text in enumerate(names):
            off = start + i * width
            if index == 13:
                struct.pack_into("<II", data, off, 1, add_string(text))
            else:
                struct.pack_into("<I", data, off + 12, add_string(text))
    if forwards:
        directory(0, 0x700, 0x200)
        struct.pack_into("<I", data, 0x700 + 20, len(forwards))
        struct.pack_into("<I", data, 0x700 + 28, rva(0x740))
        pos = 0x780
        for i, text in enumerate(forwards):
            struct.pack_into("<I", data, 0x740 + i * 4, rva(pos))
            encoded = text.encode("ascii") + b"\0"
            data[pos:pos + len(encoded)] = encoded
            pos += len(encoded)
    if arch == "arm64ec":
        directory(10, 0xa00, 208)
        struct.pack_into("<I", data, 0xa00, 208)
        struct.pack_into("<Q", data, 0xa00 + 200, image_base + rva(0xb00))
        struct.pack_into("<I", data, 0xb00, 2)
    if api_sets is not None:
        # Dedicated schema-only image; this fixture uses no other directories.
        base = 0x200
        struct.pack_into("<7I", data, base, 6, 0x1000, 0, len(api_sets), 28, 0, 31)
        offset = 28 + len(api_sets) * 24
        for i, (contract, hosts) in enumerate(api_sets.items()):
            values = offset
            offset += len(hosts) * 20
            nbytes = contract.encode("utf-16le")
            name_offset = offset
            data[base + offset:base + offset + len(nbytes)] = nbytes
            offset += len(nbytes)
            struct.pack_into("<6I", data, base + 28 + i * 24, 0, name_offset, len(nbytes), len(contract.rsplit("-", 1)[0].encode("utf-16le")), values, len(hosts))
            for j, (alias, host) in enumerate(hosts):
                a, h = alias.encode("utf-16le"), host.encode("utf-16le")
                aoff = offset
                data[base + offset:base + offset + len(a)] = a
                offset += len(a)
                hoff = offset
                data[base + offset:base + offset + len(h)] = h
                offset += len(h)
                struct.pack_into("<5I", data, base + values + j * 20, 0, aoff, len(a), hoff, len(h))
    return bytes(data)


def rejects(call, exception=ValueError):
    try:
        call()
    except exception:
        return
    raise AssertionError("invalid input unexpectedly accepted")


class TrackedScandir:
    """Lazy iterator that detects overconsumption and requires explicit closure."""
    def __init__(self, names, max_next, failure=None, fail_after=0):
        self.names = iter(names)
        self.max_next, self.failure, self.fail_after = max_next, failure, fail_after
        self.next_calls = self.consumed = 0
        self.entered = self.closed = False
        self.exit_type = None

    def __enter__(self):
        assert not self.entered
        self.entered = True
        return self

    def __exit__(self, kind, value, traceback):
        assert not self.closed
        self.closed = True
        self.exit_type = kind

    def __iter__(self):
        return self

    def __next__(self):
        assert self.entered and not self.closed
        self.next_calls += 1
        assert self.next_calls <= self.max_next, "directory scan exceeded limit + 1"
        if self.failure is not None and self.consumed == self.fail_after:
            raise self.failure
        name = next(self.names)
        self.consumed += 1
        return Path(name)  # Only DirEntry.name is needed; no cached stat data.


for arch in (*inventory.ARCHES, "x86_64"):
    image = inventory.PE(pe(arch, ["KERNEL32.DLL"], ["delay.dll"], ["cryptsp.#10"]))
    assert image.architecture() == arch
    assert image.dependencies() == [("cryptsp.dll", "forwarder"), ("delay.dll", "delay"), ("kernel32.dll", "import")]
for value in (b"", b"MZ", pe()[:200]):
    rejects(lambda: inventory.PE(value))
bad = bytearray(pe()); struct.pack_into("<I", bad, 0x3c, 0xffffff00)
rejects(lambda: inventory.PE(bad))
bad = bytearray(pe()); struct.pack_into("<I", bad, 0x98 + 108, 100)
rejects(lambda: inventory.PE(bad))
bad = bytearray(pe("arm64ec")); struct.pack_into("<Q", bad, 0xa00 + 200, 0x180ffffff)
rejects(lambda: inventory.PE(bad).architecture())
bad = bytearray(pe("arm64ec")); struct.pack_into("<I", bad, 0xb00, 99)
rejects(lambda: inventory.PE(bad).architecture())
bad = bytearray(pe("arm64ec")); struct.pack_into("<Q", bad, 0xa00 + 200, 0x180002ffc)
struct.pack_into("<I", bad, 0x21fc, 2)  # version-only metadata at EOF
rejects(lambda: inventory.PE(bad).architecture())
bad = bytearray(pe("arm64ec")); struct.pack_into("<II", bad, 0xb04, 0xffffff00, 1)
rejects(lambda: inventory.PE(bad).architecture())
bad = bytearray(pe(imports=["a.dll"])); struct.pack_into("<I", bad, 0x98 + 112 + 8 + 4, 20)
rejects(lambda: inventory.PE(bad).dependencies())
bad = bytearray(pe(delayed=["a.dll"])); struct.pack_into("<I", bad, 0x500, 2)
rejects(lambda: inventory.PE(bad).dependencies())
rejects(lambda: inventory.PE(pe(imports=["../a.dll"])).dependencies())
rejects(lambda: inventory.PE(pe(forwards=["badforward"])).dependencies())
for short in (0, 1, 39):
    bad = bytearray(pe(forwards=["missing.Func"]))
    struct.pack_into("<I", bad, 0x98 + 112 + 4, short)
    rejects(lambda: inventory.PE(bad).dependencies())
bad = bytearray(pe(forwards=["missing.Func"]))
struct.pack_into("<I", bad, 0x98 + 112, 0)
rejects(lambda: inventory.PE(bad).dependencies())
bad = bytearray(pe(forwards=["missing.Func"]))
struct.pack_into("<I", bad, 0x98 + 112 + 4, 0x85)  # cuts the forwarder string
rejects(lambda: inventory.PE(bad).dependencies())
with mock.patch.object(Path, "read_text", return_value=json.dumps({"schema_version": 1, "profiles": {"desktop": []}})):
    rejects(inventory.manifest)
with mock.patch.dict(builder.os.environ, {"arm64ec_CC": "/wrong/clang", "CC": "/wrong/host", "MAKEFLAGS": "-e", "CROSSCFLAGS": "-O0"}), \
     mock.patch.object(builder.shutil, "which", side_effect=lambda name, **kwargs: "/fixture/" + name):
    env = builder.build_environment(Path("/verified/bin"), ["arm64ec"])
    assert env["arm64ec_CC"] == "/verified/bin/clang"
    assert env["x86_64_CC"] == "/verified/bin/clang"
    assert env["CC"] != "/wrong/host" and "MAKEFLAGS" not in env and env["CROSSCFLAGS"] == "-g -O2"
print("PASS: PE32/PE32+, CHPE ARM64EC identity, all three dependency kinds and malformed bounds")

with tempfile.TemporaryDirectory(prefix="madeira-guest-test-") as temp:
    root = Path(temp)
    farm = root / "farm"; farm.mkdir()
    (farm / "APP.DLL").write_bytes(pe(imports=["api-ms-test.dll"], delayed=["later.dll"], forwards=["forward.Func"]))
    (farm / "host.dll").write_bytes(pe())
    (farm / "apisetschema.dll").write_bytes(pe(api_sets={"api-ms-test": [("", "wrong.dll"), ("app.dll", "host.dll")]}))
    report = inventory.audit_farm(farm, "aarch64", {"msftedit.dll"})
    assert not report["errors"], report
    assert report["missing_required"] == ["msftedit.dll"]
    assert {d["dependency"] for d in report["missing_dependencies"]} == {"later.dll", "forward.dll"}
    (farm / "APP.DLL").write_bytes(pe(imports=["api-ms-test-l1-1-9.dll"]))
    (farm / "apisetschema.dll").write_bytes(pe(api_sets={"api-ms-test-l1-1-0": [("nonempty-default.dll", "host.dll")]}))
    assert not inventory.audit_farm(farm, "aarch64")["missing_dependencies"]
    (farm / "APP.DLL").write_bytes(pe(imports=["api-ms-test.dll"]))
    (farm / "app.dll").write_bytes(pe())
    assert "case-colliding" in " ".join(inventory.audit_farm(farm, "aarch64")["errors"])
    (farm / "app.dll").unlink()
    (farm / "linked.dll").symlink_to(farm / "host.dll")
    assert "not a regular module" in " ".join(inventory.audit_farm(farm, "aarch64")["errors"])
    (farm / "linked.dll").unlink()
    (farm / "apisetschema.dll").unlink()
    assert any(d["reason"] == "unresolved API-set" for d in inventory.audit_farm(farm, "aarch64")["missing_dependencies"])
    (farm / "api-ms-test.dll").write_bytes(pe())
    assert not inventory.audit_farm(farm, "aarch64")["missing_dependencies"]
    (farm / "apisetschema.dll").write_bytes(pe(api_sets={"api-ms-test": []}))
    assert inventory.audit_farm(farm, "aarch64")["missing_dependencies"]
    (farm / "api-ms-test.dll").unlink()
    (farm / "apisetschema.dll").unlink()
    (farm / "msftedit.dll").write_bytes(pe("i386"))
    assert inventory.audit_farm(farm, "aarch64")["errors"]
    (farm / "msftedit.dll").write_bytes(pe("x86_64"))
    assert inventory.audit_farm(farm, "arm64ec", {"msftedit.dll"})["errors"]
    assert inventory.audit_farm(root / "absent", "i386", {"ntdll.dll"})["missing_required"] == ["ntdll.dll"]
    # A malformed API-set count/entry must not escape namespace bounds.
    bad = bytearray(pe(api_sets={"api-ms-test": [("", "host.dll")]}))
    struct.pack_into("<I", bad, 0x200 + 12, 0xffffffff)
    rejects(lambda: inventory.PE(bad).api_sets())
    print("PASS: case-insensitive farms, duplicates/symlinks, architecture rejection and API-set alias/default resolution")

    with mock.patch.object(inventory, "MAX_PE_BYTES", 1):
        assert inventory.audit_farm(farm, "aarch64")["errors"]
    with mock.patch.object(inventory, "MAX_FARM_BYTES", 1):
        assert inventory.audit_farm(farm, "aarch64")["errors"]
    with mock.patch.object(inventory, "MAX_FARM_FILES", 0):
        assert inventory.audit_farm(farm, "aarch64")["errors"]
    print("PASS: PE/farm byte and directory-entry budgets precede reads")

    bounded = root / "bounded"; bounded.mkdir()
    (bounded / "z.DLL").write_bytes(pe())
    (bounded / "a.dll").write_bytes(pe())
    (bounded / ".gitkeep").write_text("")
    read_pe_bytes = inventory.read_pe_bytes
    # The same bound applies independently to a base farm or an overlay. Ban
    # both eager APIs even on runtimes where Path.iterdir already uses scandir.
    with mock.patch.object(inventory.os, "listdir", side_effect=AssertionError("eager listdir")), \
         mock.patch.object(Path, "iterdir", side_effect=AssertionError("Path.iterdir is not bounded")):
        for folder, overlay in ((bounded, None), (root / "absent", bounded)):
            # Also exercise real os.scandir under the eager-API guards.
            report = inventory.audit_farm(folder, "aarch64", overlay=overlay)
            assert not report["errors"] and list(report["modules"]) == ["a.dll", "z.dll"]
            scan = TrackedScandir(("z.DLL", "a.dll", ".gitkeep"), 4)
            reads = []

            def read_after_close(path):
                assert scan.closed, "directory handle retained during PE reads"
                reads.append(path.name)
                return read_pe_bytes(path)

            with mock.patch.object(inventory, "MAX_FARM_FILES", 3), \
                 mock.patch.object(inventory.os, "scandir", return_value=scan) as scandir, \
                 mock.patch.object(inventory, "read_pe_bytes", side_effect=read_after_close):
                report = inventory.audit_farm(folder, "aarch64", overlay=overlay)
                assert not report["errors"] and reads == ["a.dll", "z.DLL"]
                scandir.assert_called_once_with(bounded)
            assert scan.consumed == 3 and scan.next_calls == 4 and scan.closed and scan.exit_type is None

            # An unbounded source of ignored names must consume just limit + 1
            # entries, close, and reject the entire directory before PE reads.
            for limit in (0, 3):
                scan = TrackedScandir(iter(lambda: "ignored.txt", None), limit + 1)
                with mock.patch.object(inventory, "MAX_FARM_FILES", limit), \
                     mock.patch.object(inventory.os, "scandir", return_value=scan), \
                     mock.patch.object(inventory, "read_pe_bytes", side_effect=AssertionError("must not read overflow")):
                    report = inventory.audit_farm(folder, "aarch64", overlay=overlay)
                assert report["errors"] == [f"farm directory exceeds entry-count budget: {bounded}"]
                assert not report["modules"]
                assert scan.consumed == scan.next_calls == limit + 1 and scan.closed

            # Mid-scan failures discard partial results and preserve a useful
            # directory-specific error, while unexpected exceptions still close.
            for failure in (PermissionError("injected scan failure"), RuntimeError("injected scan failure")):
                scan = TrackedScandir(("a.dll", "z.DLL"), 4, failure, fail_after=1)
                with mock.patch.object(inventory.os, "scandir", return_value=scan), \
                     mock.patch.object(inventory, "read_pe_bytes", side_effect=AssertionError("must not read partial scan")):
                    if isinstance(failure, OSError):
                        report = inventory.audit_farm(folder, "aarch64", overlay=overlay)
                        assert report["errors"] == [f"cannot enumerate farm directory: {bounded}: {failure}"]
                        assert not report["modules"]
                    else:
                        rejects(lambda: inventory.audit_farm(folder, "aarch64", overlay=overlay), RuntimeError)
                assert scan.consumed == 1 and scan.next_calls == 2 and scan.closed
                assert scan.exit_type is type(failure)

            with mock.patch.object(inventory.os, "scandir", side_effect=PermissionError("injected open failure")):
                report = inventory.audit_farm(folder, "aarch64", overlay=overlay)
            assert report["errors"] == [f"cannot enumerate farm directory: {bounded}: injected open failure"]
            assert not report["modules"]
        scan = TrackedScandir((), 1)
        with mock.patch.object(inventory, "MAX_FARM_FILES", 0), \
             mock.patch.object(inventory.os, "scandir", return_value=scan):
            report = inventory.audit_farm(bounded, "aarch64")
        assert not report["errors"] and not report["modules"]
        assert scan.consumed == 0 and scan.next_calls == 1 and scan.closed
    print("PASS: lazy farm/overlay scans stop at limit + 1, close on success/overflow/error and never use eager enumeration")

    # Exercise the entire build orchestration with synthetic outputs, while the
    # real source validator/tool invocations remain separately fail-closed.
    (root / "wine").mkdir()
    for relative in builder.LICENSE_FILES:
        notice = root / "wine" / relative
        notice.parent.mkdir(parents=True, exist_ok=True)
        notice.write_text("fixture notice " + relative)
    (root / "THIRD-PARTY-NOTICES.md").write_text("fixture notices")
    output = root / "stage"
    calls = []
    current_arch = None
    fail = {"make": False, "strip": False, "wrong_arch": False, "second_arch": False}

    def fake_run(argv, cwd, env, log):
        global current_arch
        calls.append(argv)
        if "--enable-archs=" in " ".join(argv):
            current_arch = next(a.split("=", 1)[1] for a in argv if a.startswith("--enable-archs="))
        if argv[0] == "make":
            if fail["make"] or (fail["second_arch"] and current_arch == "arm64ec"):
                raise ValueError("injected compile failure")
            for target in argv[2:]:
                p = cwd / target
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(pe("i386" if fail["wrong_arch"] else current_arch))

    def fake_command(argv, **kwargs):
        if fail["strip"]:
            raise ValueError("injected strip failure")
        return ""

    with mock.patch.object(builder, "validate_source", return_value=inventory.manifest()["wine_revision"]), \
         mock.patch.object(builder, "build_environment", return_value={"MAKE": "make", "GIT": "git"}), \
         mock.patch.object(builder.receipt, "verify_toolchain", return_value={}), \
         mock.patch.object(builder.receipt, "capture_source", return_value={}), \
         mock.patch.object(builder.receipt, "capture_inputs"), \
         mock.patch.object(builder.receipt, "write_rebuild"), \
         mock.patch.object(builder.receipt, "seal_stage"), \
         mock.patch.object(builder.symbol_audit, "audit", side_effect=lambda root, arch, overlay, *a, **kw: {"architecture": arch, "counts": {}, "issues": [], "input_modules": {name: {k: value[k] for k in ("bytes", "sha256", "architecture")} for name, value in inventory.audit_farm(root / "app/Madeira" / (arch + "-windows"), arch, {m + ".dll" for m in inventory.PROFILES["desktop"]}, overlay)["modules"].items()}}), \
         mock.patch.object(builder, "validate_tools", return_value={"fixture": True}), \
         mock.patch.object(builder, "run_logged", side_effect=fake_run), \
         mock.patch.object(builder, "command", side_effect=fake_command):
        result = builder.build(root, ["aarch64", "arm64ec", "i386"], root / "tc", 2, output)
        assert result["staged_only"] and not result["runtime_tested"]
        for arch in inventory.ARCHES:
            assert len(list((output / (arch + "-windows")).glob("*.dll"))) == 6
        for source, name in builder.LICENSE_FILES.items():
            assert (output / "licenses" / name).read_bytes() == (root / "wine" / source).read_bytes()
        assert not (root / "app").exists()
        rejects(lambda: builder.build(root, ["aarch64"], root / "tc", 2, output))
        for failure in fail:
            fail[failure] = True
            target = root / ("failed-" + failure)
            rejects(lambda: builder.build(root, ["aarch64", "arm64ec"], root / "tc", 2, target))
            assert not target.exists()
            fail[failure] = False
        assert not list((root / "wine").glob("build-desktop-*"))
    for argv in calls:
        if argv[0] == "make":
            assert all("-windows/" in t and t.endswith(".dll") for t in argv[2:])
            assert all(not t.endswith("/all") for t in argv)
    rejects(lambda: builder.validate_source(root))
    # Source validation uses git's actual pin/dirty-tree interface; no git
    # network or source mutation is needed for these failure injections.
    (root / "wine/configure").write_text("fixture configure")
    (root / "build").mkdir()
    (root / "build/madeira_cfg.h").write_text("fixture header")
    for module in inventory.PROFILES["desktop"]:
        path = root / "wine/dlls" / module / "Makefile.in"
        path.parent.mkdir(parents=True)
        path.write_text("MODULE = " + module + ".dll\n")
    pin = inventory.manifest()["wine_revision"]
    source_state = {"gitlink": pin, "checkout": pin, "dirty": ""}
    def source_command(argv, **kwargs):
        if "--show-toplevel" in argv:
            return str(root / "wine")
        if "ls-tree" in argv:
            return "160000 commit " + source_state["gitlink"] + "\twine"
        if "rev-parse" in argv:
            return source_state["checkout"]
        return source_state["dirty"]
    with mock.patch.object(builder, "command", side_effect=source_command):
        assert builder.validate_source(root) == pin
        notice = root / "wine/libs/compiler-rt/LICENSE.TXT"
        content = notice.read_text()
        notice.unlink()
        rejects(lambda: builder.validate_source(root))
        notice.write_text(content)
        for field in source_state:
            saved = source_state[field]
            source_state[field] = "modified"
            rejects(lambda: builder.validate_source(root))
            source_state[field] = saved
        (root / "wine/dlls/msftedit/Makefile.in").write_text("MODULE = wrong.dll\n")
        rejects(lambda: builder.validate_source(root))
    # A leaf symlink, even one targeting a nonexistent directory, is not a
    # fresh output directory and must remain untouched.
    link = root / "output-link"
    link.symlink_to(root / "not-created", target_is_directory=True)
    rejects(lambda: builder.build(root, ["aarch64"], root / "tc", 2, link))
    assert not (root / "not-created").exists()
    print("PASS: fresh staging, second-architecture/strip failures, pin/dirty-source gates and no app mutation")

    tools = root / "tools"; tools.mkdir()
    for name in ("clang", "ld.lld", "llvm-readobj", "arm64ec-w64-mingw32-clang", "arm64ec-w64-mingw32-strip"):
        path = tools / name; path.write_text("fixture tool"); path.chmod(0o755)
    with mock.patch.object(builder.shutil, "which", return_value="/fixture/bison"):
        env = builder.build_environment(tools, ["arm64ec"])
    bison_version = ["bison (GNU Bison) 3.8.2"]
    def tool_command(argv, **kwargs):
        return bison_version[0] if "bison" in str(argv[0]) else "fixture tool 1.0"
    with mock.patch.object(builder.shutil, "which", return_value="/fixture/bison"), \
         mock.patch.object(builder.receipt, "hash_file", return_value={"bytes": 12, "sha256": "0" * 64}), \
         mock.patch.object(builder, "command", side_effect=tool_command):
        rejects(lambda: builder.validate_tools(tools, ["arm64ec"], env))  # missing x64 companion
        path = tools / "x86_64-w64-mingw32-clang"; path.write_text("fixture companion"); path.chmod(0o755)
        records = builder.validate_tools(tools, ["arm64ec"], env)
        assert len(records["x86_64-w64-mingw32-clang"]["sha256"]) == 64
        assert len(records["clang"]["sha256"]) == 64
        (tools / "clang").unlink()
        rejects(lambda: builder.validate_tools(tools, ["arm64ec"], env))
        (tools / "clang").write_text("fixture tool")
        (tools / "clang").chmod(0o755)
        bison_version[0] = "bison (GNU Bison) 2.3"
        rejects(lambda: builder.validate_tools(tools, ["arm64ec"], env))
    print("PASS: toolchain companion validation, executable hashes and old-bison rejection")

    script = ROOT / "build/wine-pe/guest_inventory.py"
    for flags in (["--require-components"], ["--require-closure"]):
        run = subprocess.run([sys.executable, script, "--bundle", str(root / "empty"), *flags], capture_output=True)
        assert run.returncode == 1
    run = subprocess.run([sys.executable, ROOT / "build/wine-pe/build_desktop.py", "--arch", "i386"], capture_output=True, text=True, check=True)
    assert json.loads(run.stdout)["architectures"][0]["arch"] == "i386"
    print("PASS: strict completeness/closure gates reject empty farms; dry-run works without Wine/toolchain")

for arch in inventory.ARCHES:
    report = inventory.audit_farm(ROOT / "app/Madeira" / (arch + "-windows"), arch)
    assert not report["errors"], report["errors"]
    print(f"PASS: parsed actual {arch} farm ({report['module_count']} PE modules; {len(report['missing_dependencies'])} reported dependency gaps)")
