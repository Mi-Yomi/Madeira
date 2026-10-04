#!/usr/bin/env python3
"""Record explicit provenance and fail-closed verify the native dependency set.

The archive reader needs no Apple tools, so malformed/mixed/host-only archive
fixtures run on any host. Every non-index member must be an arm64 Mach-O object
with an explicit iOS platform load command; unknown bitcode/empty archives fail.
"""
from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
FREETYPE_COMMIT = "42608f77f20749dd6ddc9e0536788eaad70ea4b5"
MINGW_NAME = "llvm-mingw-20260421-ucrt-macos-universal"
MINGW_SHA256 = "bd85a3975723815cef28dbbd2ca2cb0c926f6b348a12a0453f39f7af273cb3f7"
EXPECTED_ARCHIVES = (
    "FEX/build-ios/FEXCore/Source/libFEXCore.a",
    "FEX/build-ios/FEXCore/Source/libFEXCore_Base.a",
    "FEX/build-ios/FEXCore/Source/libJemallocLibs.a",
    "FEX/build-ios/External/fmt/libfmt.a",
    "FEX/build-ios/External/cephes/libcephes_128bit.a",
    "FEX/build-ios/External/xxhash/cmake_unofficial/libxxhash.a",
    "FEX/build-ios/External/SoftFloat-3e/libsoftfloat_3e.a",
    "build/freetype-ios/build/libfreetype.a",
    *(f"app/Madeira/lib{name}.a" for name in (
        "ntdll_unix", "win32u_unix", "wineserver", "gmp", "nettle", "hogweed",
        "gnutls", "avformat", "avcodec", "swresample", "avutil", "madeira_rppairing")),
)
MAX_BUNDLE_BYTES = 400 * 1024 * 1024
INDEX_NAMES = {"/", "//", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED",
               "__.SYMDEF_64", "__.SYMDEF_64 SORTED"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def macho_ios_object(data: bytes, label: str) -> None:
    if len(data) < 32 or data[:4] != b"\xcf\xfa\xed\xfe":
        magic = data[:4].hex()
        kind = {b"BC\xc0\xde": "LLVM bitcode", b"\xde\xc0\x17\x0b": "LLVM bitcode wrapper"}.get(data[:4], "unknown format")
        raise ValueError(f"{label}: not a little-endian 64-bit Mach-O object (magic={magic}, {kind})")
    _, cpu, subtype, filetype, count, size, _, _ = struct.unpack_from("<8I", data)
    if cpu != 0x0100000C or subtype & 0xFFFFFF != 0 or filetype != 1:
        raise ValueError(f"{label}: expected arm64 (not arm64e) MH_OBJECT")
    end = 32 + size
    if end > len(data) or count > size // 8:
        raise ValueError(f"{label}: invalid load-command bounds")
    offset, platforms = 32, []
    for _ in range(count):
        if offset + 8 > end:
            raise ValueError(f"{label}: truncated load command")
        command, length = struct.unpack_from("<2I", data, offset)
        if length < 8 or length % 8 or offset + length > end:
            raise ValueError(f"{label}: invalid load-command size")
        if command == 0x32:  # LC_BUILD_VERSION
            if length < 24:
                raise ValueError(f"{label}: truncated LC_BUILD_VERSION")
            platform, _, _, tools = struct.unpack_from("<4I", data, offset + 8)
            if length != 24 + tools * 8:
                raise ValueError(f"{label}: malformed LC_BUILD_VERSION tools")
            platforms.append(platform)
        elif command in (0x24, 0x25, 0x2F, 0x30):
            if length != 16:
                raise ValueError(f"{label}: malformed minimum-platform command")
            platforms.append({0x24: 1, 0x25: 2, 0x2F: 3, 0x30: 4}[command])
        offset += length
    if offset != end or not platforms or any(platform != 2 for platform in platforms):
        raise ValueError(f"{label}: missing or non-iOS platform {platforms}")


def validate_archive(path: Path) -> dict:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{path}: missing regular archive")
    if path.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError(f"{path}: archive exceeds the 400 MiB staging limit")
    data = path.read_bytes()
    if data[:8] != b"!<arch>\n":
        raise ValueError(f"{path}: missing regular ar signature (thin/fat not accepted)")
    offset, count, names = 8, 0, b""
    while offset < len(data):
        if offset + 60 > len(data):
            raise ValueError(f"{path}: truncated ar header")
        header = data[offset:offset + 60]
        if header[58:60] != b"`\n":
            raise ValueError(f"{path}: invalid ar member header")
        name = header[:16].decode("ascii").rstrip()
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError as exc:
            raise ValueError(f"{path}: invalid ar member length") from exc
        offset += 60
        if size < 0 or offset + size > len(data):
            raise ValueError(f"{path}: truncated ar member")
        member = data[offset:offset + size]
        offset += size
        if size % 2:
            if data[offset:offset + 1] != b"\n":
                raise ValueError(f"{path}: missing ar alignment byte")
            offset += 1
        if name.startswith("#1/"):  # BSD extended filenames
            name_len = int(name[3:])
            if name_len <= 0 or name_len > len(member):
                raise ValueError(f"{path}: invalid BSD filename length")
            name = member[:name_len].rstrip(b"\0").decode("utf-8")
            member = member[name_len:]
        elif name == "//":
            names = member
        elif re.fullmatch(r"/\d+", name):  # GNU filename table reference
            name_offset = int(name[1:])
            if name_offset >= len(names):
                raise ValueError(f"{path}: invalid GNU filename offset")
            stop = names.find(b"/\n", name_offset)
            if stop < 0:
                raise ValueError(f"{path}: unterminated GNU filename")
            name = names[name_offset:stop].decode("utf-8")
        elif name not in INDEX_NAMES:
            name = name.removesuffix("/")
        if name in INDEX_NAMES:
            continue
        macho_ios_object(member, f"{path.name}({name})")
        count += 1
    if not count:
        raise ValueError(f"{path}: empty or index-only archive")
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
            "object_members": count, "architecture": "arm64", "platform": "iOS"}


def command(*args: str, cwd: Path = ROOT) -> str:
    return subprocess.check_output(args, cwd=cwd, text=True, stderr=subprocess.STDOUT).strip()


def source_modules(root: Path = ROOT) -> list[dict]:
    result = []
    module_file = root / ".gitmodules"
    if not module_file.exists():
        return result
    config = configparser.ConfigParser(interpolation=None)
    config.read(module_file)
    for section in config.sections():
        path, url = config[section]["path"], config[section]["url"]
        if Path(path).is_absolute() or ".." in Path(path).parts:
            raise ValueError("Unsafe submodule path")
        if not re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+", url):
            raise ValueError(f"Expected a public HTTPS GitHub submodule: {path}")
        directory = root / path
        pinned = command("git", "ls-tree", "HEAD", "--", path, cwd=root).split()[2]
        actual = command("git", "rev-parse", "HEAD", cwd=directory)
        if actual != pinned:
            raise ValueError(f"Submodule {path} differs from its exact gitlink")
        result.append({"path": str(directory.relative_to(ROOT)), "repository": url,
                       "commit": actual})
        result.extend(source_modules(directory))
    return result


FEX_REPAIR_SPEC = "build/fex-ios/source-repairs.json"
FEX_REPAIR_RECORD = "FEX/build-ios/madeira-source-repairs.json"
FEX_NATIVE_INPUTS = ("build/fex-ios/build.sh", "build/fex-ios/check-native-object.py", ".github/ci/native-artifacts.py")
FEX_NATIVE_OBJECT_PATHS = {
    "source": "FEX/FEXCore/Source/Common/JitSymbols.cpp",
    "compile_database": "FEX/build-ios/compile_commands.json",
    "production_object": "FEX/build-ios/FEXCore/Source/CMakeFiles/FEXCore_object.dir/Common/JitSymbols.cpp.o",
}


def repair_file(base: Path, relative: str) -> Path:
    if not isinstance(relative, str) or any(part in ("", ".", "..") for part in relative.split("/")) or "\\" in relative:
        raise ValueError("Unsafe FEX repair path")
    path = base / relative
    if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(base.resolve()):
        raise ValueError(f"Missing or unsafe FEX repair file: {relative}")
    return path


def fex_repair_spec() -> tuple[dict, list[str]]:
    spec = json.loads(repair_file(ROOT, FEX_REPAIR_SPEC).read_text())
    if spec.get("schema_version") != 1 or spec.get("component") != "FEX" or not re.fullmatch(r"[0-9a-f]{40}", spec.get("source_revision", "")):
        raise ValueError("Invalid FEX repair specification")
    inputs = [FEX_REPAIR_SPEC, "build/fex-ios/apply-source-repairs.py"]
    if not isinstance(spec.get("repairs"), list) or not spec["repairs"]:
        raise ValueError("Empty FEX repair specification")
    for repair in spec["repairs"]:
        patch = repair_file(ROOT, repair["patch"])
        if sha256(patch) != repair["patch_sha256"]:
            raise ValueError("FEX repair patch differs from its specification")
        inputs.append(repair["patch"])
    return spec, inputs


def verified_fex_repairs(document: dict) -> dict:
    spec, inputs = fex_repair_spec()
    for name in inputs:
        if sha256(repair_file(ROOT, name)) != document.get("input_sha256", {}).get(name):
            raise ValueError(f"FEX repair input changed since provenance recording: {name}")
    sources = [item for item in document.get("submodules", []) if item.get("path") == "FEX"]
    if len(sources) != 1 or sources[0]["commit"] != spec["source_revision"] or sources[0]["repository"] != spec["source_repository"]:
        raise ValueError("FEX repair does not match recorded submodule")
    if command("git", "rev-parse", "HEAD", cwd=ROOT / "FEX") != spec["source_revision"]:
        raise ValueError("FEX revision changed after provenance recording")
    if json.loads(repair_file(ROOT, FEX_REPAIR_RECORD).read_text()) != spec:
        raise ValueError("Applied FEX repair metadata differs from reviewed specification")
    names = []
    for repair in spec["repairs"]:
        for item in repair["files"]:
            if item["path"] in names:
                raise ValueError("Duplicate FEX repaired source")
            names.append(item["path"])
            if sha256(repair_file(ROOT / "FEX", item["path"])) != item["patched_sha256"]:
                raise ValueError(f"FEX repaired source differs from verified result: {item['path']}")
    changed = set(command("git", "diff", "--name-only", "--no-renames", "HEAD", cwd=ROOT / "FEX").splitlines())
    if changed != set(names):
        raise ValueError("FEX tracked changes differ from reviewed repair files")
    return spec



def verified_fex_native_object(document: dict, path: Path) -> dict:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 64 * 1024:
        raise ValueError("Missing or oversized FEX native-object evidence")
    receipt = json.loads(path.read_text())
    if (receipt.get("schema_version") != 1 or receipt.get("status") != "passed"
            or receipt.get("evidence_kind") != "fresh-same-source-thinlto-reproduction"):
        raise ValueError("Invalid FEX native-object evidence")
    configuration = receipt.get("native_configuration", {})
    if configuration != {"enable_lto": False, "architecture": "arm64", "deployment_target": "17.0", "ipo_flags": []}:
        raise ValueError("FEX native configuration does not establish non-LTO device objects")
    for name in FEX_NATIVE_INPUTS:
        if sha256(repair_file(ROOT, name)) != document.get("input_sha256", {}).get(name):
            raise ValueError(f"FEX native build helper changed since provenance recording: {name}")
    if receipt.get("helper_sha256") != document.get("input_sha256", {}).get("build/fex-ios/check-native-object.py"):
        raise ValueError("FEX native-object evidence does not match its reviewed helper")
    if receipt.get("sdk_path") != document.get("tool_versions", {}).get("iphoneos_sdk_path"):
        raise ValueError("FEX native-object SDK differs from recorded Apple SDK")
    for kind, name in FEX_NATIVE_OBJECT_PATHS.items():
        item = receipt.get(kind, {})
        if item.get("path") != name or item.get("sha256") != sha256(repair_file(ROOT, name)):
            raise ValueError(f"FEX native-object evidence changed: {kind}")
    if receipt["production_object"].get("format") != "Mach-O arm64 iOS":
        raise ValueError("FEX production-object evidence is not a native iOS object")
    object_path = repair_file(ROOT, FEX_NATIVE_OBJECT_PATHS["production_object"])
    if object_path.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("FEX production object exceeds staging bound")
    macho_ios_object(object_path.read_bytes(), "FEX native-object evidence")
    reproduction = receipt.get("reproduction", {})
    if (reproduction.get("format") != "LLVM bitcode"
            or reproduction.get("magic_hex") not in ("4243c0de", "dec0170b")
            or not re.fullmatch(r"[0-9a-f]{64}", reproduction.get("sha256", ""))
            or reproduction.get("added_flag") != "-flto=thin"
            or reproduction.get("target_triple") != "arm64-apple-ios17.0.0"
            or reproduction.get("override_module_is_error") is not True
            or reproduction.get("reader_exit_code") != 0
            or reproduction.get("strict_validator_rejected") is not True):
        raise ValueError("FEX reproduction does not establish rejected iOS ThinLTO bitcode")
    if not re.fullmatch(r"[0-9a-f]{64}", receipt.get("compiler", {}).get("sha256", "")):
        raise ValueError("FEX reproduction lacks compiler identity")
    return receipt


def metal_receipt(path: Path) -> dict:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise ValueError("Missing or oversized Metal setup receipt")
    receipt = json.loads(path.read_text())
    if receipt.get("schema") != 1 or receipt.get("status") != "available" or receipt.get("smoke_test", {}).get("status") != "passed":
        raise ValueError("Metal setup receipt does not establish available compiler and shader smoke")
    for name in ("metal-compiler", "metallib-linker"):
        tool = receipt.get("verified_executables", {}).get(name, {})
        if tool.get("verification_passed") is not True or tool.get("requirement") != "anchor apple" or not re.fullmatch(r"[0-9a-f]{64}", tool.get("sha256", "")):
            raise ValueError(f"Missing verified Apple component evidence: {name}")
    return receipt


def record(path: Path, ready: bool) -> None:
    repo = os.environ.get("GITHUB_REPOSITORY", "Mi-Yomi/Madeira")
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo):
        raise ValueError("Invalid repository slug")
    source = command("git", "rev-parse", "HEAD")
    # First record requires an unmodified source tree; configure/build output may
    # later regenerate tracked symtabs/notices, and those are hashed separately.
    if command("git", "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("Expected a clean source checkout before building")
    status = command("git", "submodule", "status", "--recursive")
    if any(line[0] in "-+U" for line in status.splitlines()):
        raise ValueError("Submodules must all be initialized at their exact pins")
    tools = {
        "xcode": ["xcodebuild", "-version"],
        "apple_clang": ["xcrun", "--sdk", "iphoneos", "clang", "--version"],
        "iphoneos_sdk": ["xcrun", "--sdk", "iphoneos", "--show-sdk-version"],
        "iphoneos_sdk_path": ["xcrun", "--sdk", "iphoneos", "--show-sdk-path"],
        "macos_sdk": ["xcrun", "--sdk", "macosx", "--show-sdk-version"],
        "cmake": ["cmake", "--version"], "ninja": ["ninja", "--version"],
        "python": ["python3", "--version"], "rustc": ["rustc", "--version", "--verbose"],
        "cargo": ["cargo", "--version"], "rustup": ["rustup", "--version"],
        "os": ["sw_vers"], "architecture": ["uname", "-m"],
    }
    if ready:
        tools.update({"bison": ["bison", "--version"], "flex": ["flex", "--version"],
                      "homebrew_packages": ["brew", "list", "--versions", "bison", "flex"],
                      "llvm_mingw": [str(ROOT / "toolchains" / MINGW_NAME / "bin/arm64ec-w64-mingw32-clang"), "--version"],
                      "rust_targets": ["rustup", "target", "list", "--installed"]})
        if command("git", "rev-parse", "HEAD", cwd=ROOT / "research/freetype") != FREETYPE_COMMIT:
            raise ValueError("FreeType source differs from its pin")
    tracked_inputs = [".github/ci/ensure-metal-toolchain.py", "build/rppairing-ios/Cargo.lock", "build/gnutls-ios/src/SHA256SUMS",
                      "build/ffmpeg/src/SHA256SUMS", ".github/workflows/native-bootstrap.yml"]
    tracked_inputs += [str(p.relative_to(ROOT)) for directory in ("build/gnutls-ios/src", "build/ffmpeg/src")
                       for p in (ROOT / directory).glob("*.tar.*")]
    _, repair_inputs = fex_repair_spec()
    tracked_inputs += repair_inputs
    tracked_inputs += FEX_NATIVE_INPUTS
    usage = shutil.disk_usage(ROOT)
    document = {
        "schema": 1, "stage": "native-dependencies-only", "recorded_utc": datetime.now(timezone.utc).isoformat(),
        "source_repository": f"https://github.com/{repo}", "source_commit": source,
        "source_url": f"https://github.com/{repo}/tree/{source}",
        "rebuild_script": ".github/ci/native-bootstrap.sh", "submodules": source_modules(),
        "freetype": {"repository": "https://github.com/freetype/freetype", "commit": FREETYPE_COMMIT},
        "llvm_mingw": {"url": f"https://github.com/mstorsjo/llvm-mingw/releases/download/20260421/{MINGW_NAME}.tar.xz",
                       "sha256": MINGW_SHA256},
        "input_sha256": {name: sha256(ROOT / name) for name in sorted(tracked_inputs)},
        "tool_versions": {name: command(*args) for name, args in tools.items()},
        "runner": {key: os.environ.get(key, "") for key in ("ImageOS", "ImageVersion", "RUNNER_ARCH")},
        "run": {key: os.environ.get(key, "") for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_REF")},
        "compile_jobs": int(os.environ.get("JOBS", "2")), "dependencies_ready": ready,
        "disk_bytes": {"total": usage.total, "used": usage.used, "free": usage.free},
    }
    if ready:
        receipt_path = Path(os.environ["NATIVE_LOG_DIR"]) / "metal-toolchain-provenance.json"
        document["metal_toolchain"] = metal_receipt(receipt_path)
        document["metal_receipt_sha256"] = sha256(receipt_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n")
    print(f"Recorded exact source/tool provenance: {path}")


def crypto_symbols(path: Path) -> dict:
    entries = re.findall(r'\{\s*"(gnutls_[A-Za-z0-9_]+)",\s*&ios_gts_\d+\s*\}', path.read_text())
    required = {"gnutls_global_init", "gnutls_init", "gnutls_handshake", "gnutls_cipher_init", "gnutls_x509_crt_init"}
    missing = required - set(entries)
    if missing or len(entries) != len(set(entries)):
        raise ValueError(f"Generated GnuTLS table is incomplete/duplicated; missing {sorted(missing)}")
    return {"entry_count": len(entries), "sha256": sha256(path), "required_bootstrap_symbols": sorted(required)}


def collect(provenance: Path, output: Path) -> None:
    if output.exists():
        raise ValueError("Refusing an existing artifact output directory")
    document = json.loads(provenance.read_text())
    if not document["dependencies_ready"] or document["source_commit"] != command("git", "rev-parse", "HEAD"):
        raise ValueError("Provenance does not match the prepared source")
    source_repairs = verified_fex_repairs(document)
    fex_native_object = verified_fex_native_object(document, provenance.parent / "fex-native-object.json")
    verified = {}
    for name in EXPECTED_ARCHIVES:
        verified[name] = validate_archive(ROOT / name)
        print(f"Verified iOS arm64 archive: {name} ({verified[name]['object_members']} objects)")
    # Explicit notices only; never sweep the source/object trees into artifacts.
    required_notices = ["LICENSE", "LICENSE-EXCEPTION.md", "THIRD-PARTY-NOTICES.md",
                        "wine/COPYING.LIB", "wine/LICENSE-MADEIRA.md", "FEX/LICENSE-MADEIRA.md",
                        "research/freetype/LICENSE.TXT", "research/freetype/docs/FTL.TXT",
                        "research/freetype/docs/GPLv2.TXT", "app/Madeira/legal/LICENSES-rppairing-crates.txt"]
    for name in required_notices:
        if not (ROOT / name).is_file():
            raise ValueError(f"Missing license/notice: {name}")
    notices = set(required_notices)
    for pattern in ("LICENSES/*.txt", "FEX/LICENSE*", "FEX/External/*/LICENSE*", "FEX/External/*/COPYING*",
                    "build/gnutls-ios/obj/gmp-*/COPYING*", "build/gnutls-ios/obj/nettle-*/COPYING*",
                    "build/gnutls-ios/obj/gnutls-*/COPYING*", "build/ffmpeg/obj/ffmpeg-*/COPYING*",
                    "build/ffmpeg/obj/ffmpeg-*/LICENSE.md"):
        notices.update(str(p.relative_to(ROOT)) for p in ROOT.glob(pattern) if p.is_file())
    bundle_bytes = sum(item["bytes"] for item in verified.values()) + sum((ROOT / name).stat().st_size for name in notices)
    # Leave 1 MiB for the final manifest/README and archive-container overhead.
    if bundle_bytes + 1024 * 1024 > MAX_BUNDLE_BYTES:
        raise ValueError(f"Bundle size {bundle_bytes} exceeds the 400 MiB staging limit")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=output.name + ".tmp-", dir=output.parent))
    for name in EXPECTED_ARCHIVES:
        destination = temporary / "libraries" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, destination)
    for name in sorted(notices):
        destination = temporary / "notices" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, destination)
    document.update({"source_repairs": source_repairs,
                     "fex_native_object": fex_native_object,
                     "crypto_symbol_table": crypto_symbols(ROOT / "build/crypto-unix/gnutls_symtab_ios.c"),
                     "verified_utc": datetime.now(timezone.utc).isoformat(), "archives": verified,
                     "notice_sha256": {name: sha256(ROOT / name) for name in sorted(notices)},
                     "generated_inputs_sha256": {
                         name: sha256(ROOT / name) for name in (
                             "build/crypto-unix/gnutls_symtab_ios.c",
                             "wine/build-macos/include/config.h", "wine/build-arm64ec/include/config.h")},
                     "staged_payload_bytes": bundle_bytes,
                     "completion_scope": "Native static dependencies only. No full app link, IPA, signing, device, 1C or Blender validation."})
    (temporary / "provenance.json").write_text(json.dumps(document, indent=2) + "\n")
    (temporary / "README.txt").write_text(
        "Madeira native iOS ARM64 dependency bundle\n\n"
        "This is not an app or IPA. No 1C/Blender runtime result is implied.\n"
        "Every archive member was checked for arm64 and an iOS load command.\n"
        "See provenance.json for exact source/submodule commits, input hashes,\n"
        "tool versions, build script and library hashes. Corresponding sources\n"
        "and build scripts are at its source_url; tracked tarball paths and\n"
        "Cargo.lock identify the remaining pinned sources. FreeType uses the\n"
        "explicit freetype.repository and freetype.commit. License texts are\n"
        "under notices/. Fork-specific notices take precedence over historical\n"
        "summaries in the top-level third-party notice. No Apple converter or\n"
        "Microsoft VC runtime binaries are included.\n")
    temporary.rename(output)
    print(f"Staged {len(verified)} verified libraries and provenance: {bundle_bytes} bytes ({bundle_bytes / 1024**2:.1f} MiB) in {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    recording = sub.add_parser("record")
    recording.add_argument("path", type=Path)
    recording.add_argument("--ready", action="store_true")
    sub.add_parser("crypto-symbols")
    staging = sub.add_parser("collect")
    staging.add_argument("provenance", type=Path)
    staging.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "record":
            record(args.path, args.ready)
        elif args.action == "collect":
            collect(args.provenance, args.output)
        else:
            print(json.dumps(crypto_symbols(ROOT / "build/crypto-unix/gnutls_symtab_ios.c"), sort_keys=True))
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
