#!/usr/bin/env python3
"""Fail-closed local Debug app gate after native20 and graphics in one checkout.

This does not build guest PE binaries, sign, export, install, upload or use a
cache. The resulting IPA is an unsigned packaging experiment, not a device or
1C/Blender success result. Apple's tracked converter retains its original bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import struct
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "build/llvm-ios"), str(ROOT / "build/dxmt-ios")]
import common
import generate_shaders

CONVERTER = "d3d12/libmetalirconverter.dylib"
CONVERTER_SHA256 = "073f903be98e973ff38f4d79f2c48d61ef938754a77b1caedda79c9f05a068c2"
FRAMEWORK_SOURCE = "app/Frameworks/StikJIT.xcframework/ios-arm64/StikJIT.framework/StikJIT"
GENERATED_LICENSES = {"licenses/LICENSE-MADEIRA-GPL-3.0.txt": "COPYING",
                      "licenses/LICENSE-MADEIRA-EXCEPTION.txt": "LICENSE-EXCEPTION.md"}
RESOURCE_DIRS = ("nls", "aarch64-windows", "arm64ec-windows", "i386-windows", "d3d12", "licenses", "legal")
RESOURCE_FILES = ("prefix-template.tar.gz", "cacert.pem", "madeira-jit.js", "Madeira JIT.shortcut")
REQUIRED_NOTICES = (*GENERATED_LICENSES, "d3d12/NOTICE.txt", "d3d12/METAL-SHADER-CONVERTER-AGREEMENT.txt",
                    "d3d12/LICENSE-metal-shader-converter-headers.txt", "licenses/THIRD-PARTY-NOTICES.txt",
                    "licenses/LLVM-Apache-2.0-with-exception.txt", "legal/THIRD-PARTY-NOTICES.md",
                    "legal/LICENSES-rppairing-crates.txt", "legal/LICENSE-StikJIT-MPL-2.0.txt")
GRAPHICS_RECEIPTS = ("toolchains/llvm-host-build/madeira-build.json", "toolchains/llvm-ios-build/madeira-build.json",
                     "build/dxmt-ios/shader-headers/provenance.json", "build/dxmt-ios/graphics-build.json")
SCOPE = ("Unsigned Debug app link and local IPA packaging only. Tracked guest PE binaries reused, not source-rebuilt; "
         "32-bit runtime missing; x86_64 VC runtime absent. No installation, device, rendering, JIT, 1C or Blender validation.")


def regular(path):
    path = Path(path)
    if path.is_symlink() or any(p.is_symlink() for p in path.parents) or not path.is_file():
        raise ValueError(f"Missing or unsafe regular file: {path}")
    return path


def digest(path):
    return common.sha256(regular(path))


def document(path):
    path = regular(path)
    if not 0 < path.stat().st_size <= 4 * 1024 * 1024:
        raise ValueError(f"Missing or oversized JSON receipt: {path}")
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"Receipt must be an object: {path}")
    return data


def relative_file(base, name):
    if not isinstance(name, str) or "\\" in name or not name or any(p in ("", ".", "..") for p in name.split("/")):
        raise ValueError("Unsafe receipt path")
    path = base / name
    if not path.resolve().is_relative_to(base.resolve()):
        raise ValueError("Receipt path leaves its source directory")
    return regular(path)


def hashes_match(mapping, base=ROOT):
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError("Expected nonempty input hash map")
    for name, expected in mapping.items():
        if not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected) or digest(relative_file(base, name)) != expected:
            raise ValueError(f"Input changed or lacks SHA-256 evidence: {name}")


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def fresh_outputs(products, intermediates, stage):
    paths = [Path(p).absolute() for p in (products, intermediates, stage)]
    if any(".." in p.parts for p in paths):
        raise ValueError("Output paths must not contain parent traversal")
    # Resolve conventional macOS /var and /tmp aliases in the parent, never a
    # leaf symlink. Existing output leaves (including dangling links) still fail.
    paths = [p.parent.resolve() / p.name for p in paths]
    for path in paths:
        if path.exists() or path.is_symlink() or any(p.is_symlink() for p in path.parents):
            raise ValueError(f"Output must be a fresh non-symlink path: {path}")
        if ROOT.resolve().is_relative_to(path.resolve()):
            raise ValueError("Output cannot contain the source checkout")
    for index, path in enumerate(paths):
        for other in paths[index + 1:]:
            if path.is_relative_to(other) or other.is_relative_to(path):
                raise ValueError("Products, intermediates and stage must be separate, non-nested paths")
    return paths


def tree_files(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError(f"Missing or unsafe directory: {directory}")
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError(f"Unexpected special file in bundle/input: {path}")
        if path.is_file():
            result[path.relative_to(directory).as_posix()] = digest(path)
    return result


def resource_inputs():
    """Only tracked resource bytes plus the two explicitly generated licences."""
    base = ROOT / "app/Madeira"
    names = git("ls-files", "-z", "--", *["app/Madeira/" + n for n in (*RESOURCE_DIRS, *RESOURCE_FILES)]).split("\0")
    expected = {name.removeprefix("app/Madeira/"): digest(ROOT / name) for name in names if name}
    for name in RESOURCE_FILES:
        if name not in expected or regular(base / name).stat().st_size == 0:
            raise ValueError(f"Missing tracked resource: {name}")
    for directory in RESOURCE_DIRS:
        actual = {f"{directory}/{name}": value for name, value in tree_files(base / directory).items()}
        required = {name: value for name, value in expected.items() if name.startswith(directory + "/")}
        # Native bootstrap regenerates its tracked Rust notice; its matching
        # native receipt was already checked. No arbitrary untracked payloads.
        required.update({name: digest(ROOT / source) for name, source in GENERATED_LICENSES.items()
                         if name.startswith(directory + "/")})
        if actual != required:
            raise ValueError(f"Resource directory differs from tracked/staged inventory: {directory}")
        expected.update(required)
    if not set(REQUIRED_NOTICES).issubset(expected):
        raise ValueError("Required converter/licence notices missing from resource inventory")
    pe = {name: value for name, value in expected.items() if name.endswith((".dll", ".exe"))}
    for directory in ("aarch64-windows", "arm64ec-windows"):
        if not any(name.startswith(directory + "/") for name in pe):
            raise ValueError(f"Tracked guest PE payload missing: {directory}")
    if any(name.startswith("i386-windows/") for name in pe):
        raise ValueError("This gate does not accept an unverified 32-bit runtime")
    for name in pe:
        with regular(base / name).open("rb") as stream:
            if stream.read(2) != b"MZ":
                raise ValueError(f"Tracked guest payload is not a PE image: {name}")
    if tree_files(base / "x86_64-vcruntime"):
        raise ValueError("This gate requires an empty x86_64-vcruntime placeholder")
    return expected, pe


def verify_archives(native, actual, expected):
    if not isinstance(actual, dict) or set(actual) != set(expected):
        raise ValueError("Receipt does not contain the exact required archive set")
    for name in expected:
        if native.validate_archive(relative_file(ROOT, name)) != actual[name]:
            raise ValueError(f"Archive differs from validated receipt: {name}")


def prerequisites(native_receipt):
    native = common.native_validator()
    data = document(native_receipt)
    commit = git("rev-parse", "HEAD")
    if (data.get("schema") != 1 or data.get("stage") != "native-dependencies-only" or
            data.get("dependencies_ready") is not True or data.get("source_commit") != commit or
            not re.fullmatch(r"[0-9a-f]{40}", commit) or
            data.get("source_repository") != "https://github.com/Mi-Yomi/Madeira" or
            data.get("source_url") != f"https://github.com/Mi-Yomi/Madeira/tree/{commit}"):
        raise ValueError("Native receipt lacks matching fork/source metadata")
    if os.environ.get("GITHUB_SHA", commit) != commit:
        raise ValueError("Checkout differs from this run's source commit")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_REF"):
        if os.environ.get(key) and data.get("run", {}).get(key) != os.environ[key]:
            raise ValueError("Native receipt is from a different workflow run or attempt")
    if data.get("submodules") != native.source_modules():
        raise ValueError("Source submodules differ from native receipt")
    for field in ("input_sha256", "notice_sha256", "generated_inputs_sha256"):
        hashes_match(data.get(field), ROOT)
    if native.verified_fex_repairs(data) != data.get("source_repairs"):
        raise ValueError("FEX repair evidence changed")
    if native.verified_fex_native_build(data) != data.get("fex_native_build"):
        raise ValueError("FEX generated build evidence changed")
    verify_archives(native, data.get("archives"), native.EXPECTED_ARCHIVES)
    generated = ROOT / "FEX/build-ios/include"
    headers = {f"FEX/build-ios/include/{name}": value for name, value in tree_files(generated).items()
               if name.endswith((".h", ".hpp", ".inc", ".inl"))}
    required_headers = {"FEX/build-ios/include/FEXCore/Config/ConfigValues.inl",
                        "FEX/build-ios/include/FEXCore/Config/ConfigOptions.inl"}
    if not required_headers.issubset(headers) or any(not regular(ROOT / name).stat().st_size for name in required_headers):
        raise ValueError("FEX generated ConfigValues/ConfigOptions headers missing; keep the native build tree")
    allowed_changes = set(data["generated_inputs_sha256"]) | set(data["notice_sha256"]) | set(data["archives"])
    changed = set(filter(None, git("diff", "--name-only", "--ignore-submodules=all", "HEAD", "--").splitlines()))
    if changed - allowed_changes:
        raise ValueError("Tracked sources changed since the native source record: " + ", ".join(sorted(changed - allowed_changes)))
    spec = common.manifest()
    common.check_dxmt()
    common.check_revision(ROOT / "toolchains/llvm-project", spec["revision"])
    host = document(ROOT / GRAPHICS_RECEIPTS[0])
    ios = document(ROOT / GRAPHICS_RECEIPTS[1])
    for stage, receipt in (("host", host), ("ios", ios)):
        if (receipt.get("schema_version") != 1 or receipt.get("stage") != stage or
                receipt.get("revision") != spec["revision"] or receipt.get("repository") != spec["repository"] or
                receipt.get("manifest_sha256") != digest(common.MANIFEST_PATH)):
            raise ValueError(f"LLVM {stage} source receipt mismatch")
    if set(host.get("outputs", {})) != {"llvm-dis", "llvm-tblgen"}:
        raise ValueError("LLVM host receipt lacks exact host tools")
    hashes_match(host["outputs"], ROOT / "toolchains/llvm-host-build/bin")
    expected_llvm = [f"toolchains/llvm-ios-build/lib/lib{name}.a" for name in spec["archives"]]
    verify_archives(native, ios.get("outputs"), expected_llvm)
    generate_shaders.validate()
    graphics = document(ROOT / GRAPHICS_RECEIPTS[3])
    if (graphics.get("schema_version") != 1 or graphics.get("manifest_sha256") != digest(common.MANIFEST_PATH) or
            graphics.get("dxmt_revision") != spec["dxmt_revision"] or graphics.get("llvm_revision") != spec["revision"]):
        raise ValueError("Graphics source receipt mismatch")
    verify_archives(native, graphics.get("llvm_archives"), expected_llvm)
    for name, key in (("build/dxmt-ios/libdxmt_unix.a", "unix_archive"),
                      ("build/dxmt-ios/libdxmt_combined.a", "combined_archive"),
                      ("app/Madeira/libdxmt_combined.a", "combined_archive")):
        if native.validate_archive(relative_file(ROOT, name)) != graphics.get(key):
            raise ValueError(f"Graphics archive differs from receipt: {name}")
    count = graphics["unix_archive"]["object_members"] + sum(x["object_members"] for x in graphics["llvm_archives"].values())
    if graphics.get("input_object_members") != count or graphics["combined_archive"]["object_members"] != count:
        raise ValueError("Combined graphics archive lost members")
    if digest(ROOT / "app/Madeira" / CONVERTER) != CONVERTER_SHA256:
        raise ValueError("Tracked Apple converter hash mismatch")
    snapshot = {name: item["sha256"] for name, item in data["archives"].items()}
    snapshot.update({name: item["sha256"] for name, item in ios["outputs"].items()})
    snapshot.update(headers)
    snapshot.update({name: digest(ROOT / name) for name in (*GRAPHICS_RECEIPTS, FRAMEWORK_SOURCE,
                    "build/dxmt-ios/libdxmt_unix.a", "build/dxmt-ios/libdxmt_combined.a", "app/Madeira/libdxmt_combined.a",
                    "app/Madeira.xcodeproj/project.pbxproj")})
    return {"source_commit": commit, "native_receipt_sha256": digest(native_receipt),
            "graphics_receipt_sha256": {name: digest(ROOT / name) for name in GRAPHICS_RECEIPTS},
            "prerequisite_sha256": snapshot, "scope": SCOPE}


def macho_image(path, filetype):
    """Reuse the strict archive parser's ARM64/iOS checks for linked images."""
    raw = regular(path).read_bytes()
    if len(raw) < 32 or struct.unpack_from("<I", raw, 12)[0] != filetype:
        raise ValueError(f"Wrong Mach-O image type: {path}")
    data = bytearray(raw)
    struct.pack_into("<I", data, 12, 1)
    common.native_validator().macho_ios_object(data, str(path))
    return hashlib.sha256(raw).hexdigest()


def bundle_plist(directory, executable, package_type):
    data = plistlib.loads(regular(directory / "Info.plist").read_bytes())
    if (not isinstance(data, dict) or data.get("CFBundleExecutable") != executable or
            data.get("CFBundlePackageType") != package_type or not data.get("CFBundleIdentifier") or
            "$" in data["CFBundleIdentifier"] or data.get("CFBundleSupportedPlatforms") != ["iPhoneOS"]):
        raise ValueError(f"Invalid built bundle metadata: {directory}")
    return data


def validate_app(app, resources, framework_hash):
    files = tree_files(app)
    if app.name != "Madeira.app" or not files:
        raise ValueError("Expected a nonempty Madeira.app")
    for name in files:
        if "_CodeSignature" in PurePosixPath(name).parts or name.endswith(".mobileprovision"):
            raise ValueError("Signing/provisioning artifacts are outside this unsigned gate")
    app_info = bundle_plist(app, "Madeira", "APPL")
    helper = app / "PlugIns/MadeiraJITHelper.appex"
    helper_info = bundle_plist(helper, "MadeiraJITHelper", "XPC!")
    framework = app / "Frameworks/StikJIT.framework"
    framework_info = bundle_plist(framework, "StikJIT", "FMWK")
    if (helper_info["CFBundleIdentifier"] != app_info["CFBundleIdentifier"] + ".JITHelper" or
            framework_info["CFBundleIdentifier"] != app_info["CFBundleIdentifier"] + ".StikJIT" or
            helper_info.get("NSExtension", {}).get("NSExtensionPointIdentifier") != "com.apple.ar.viewer"):
        raise ValueError("Embedded helper/framework identity or extension point mismatch")
    images = {}
    for name, kind in (("Madeira", 2), ("PlugIns/MadeiraJITHelper.appex/MadeiraJITHelper", 2),
                       ("Frameworks/StikJIT.framework/StikJIT", 6), (CONVERTER, 6)):
        images[name] = macho_image(app / name, kind)
        if not regular(app / name).stat().st_mode & 0o111:
            raise ValueError(f"Bundle executable has no execute permission: {name}")
    if images[CONVERTER] != CONVERTER_SHA256 or images["Frameworks/StikJIT.framework/StikJIT"] != framework_hash:
        raise ValueError("Embedded converter or StikJIT changed")
    if not set(REQUIRED_NOTICES).issubset(resources):
        raise ValueError("Package evidence lacks required licence notices")
    hashes_match(resources, app)
    if any(not regular(app / name).stat().st_size for name in REQUIRED_NOTICES):
        raise ValueError("Empty licence notice in package")
    for directory in RESOURCE_DIRS:
        expected = {name.removeprefix(directory + "/"): value for name, value in resources.items() if name.startswith(directory + "/")}
        if tree_files(app / directory) != expected:
            raise ValueError(f"Unexpected/missing copied resource payload: {directory}")
    if tree_files(app / "x86_64-vcruntime"):
        raise ValueError("Unexpected VC runtime payload")
    if not regular(app / "Assets.car").stat().st_size:
        raise ValueError("Compiled asset catalog missing")
    with regular(app / "default.metallib").open("rb") as stream:
        if stream.read(4) != b"MTLB":
            raise ValueError("Compiled app Metal library missing or malformed")
    # Also reject host/simulator/bitcode surprises in any additional embedded
    # Mach-O images (e.g. Swift runtime dylibs emitted by Xcode).
    for name in files:
        with regular(app / name).open("rb") as stream:
            magic = stream.read(4)
        if magic in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf") and name not in images:
            images[name] = macho_image(app / name, 6)
    return {"images_sha256": images, "files_sha256": files}


def verify_zip(path, payload):
    expected = {"Payload/" + name: value for name, value in tree_files(payload).items()}
    if not expected or not all(name.startswith("Payload/Madeira.app/") for name in expected):
        raise ValueError("Stage must contain Payload/Madeira.app only")
    if {p.name for p in payload.iterdir()} != {"Madeira.app"}:
        raise ValueError("Unexpected Payload entry")
    directories = {"Payload/", *("Payload/" + p.relative_to(payload).as_posix() + "/"
                                  for p in payload.rglob("*") if p.is_dir())}
    empty_directories = {"Payload/" + p.relative_to(payload).as_posix() + "/"
                         for p in payload.rglob("*") if p.is_dir() and not any(p.iterdir())}
    seen, actual = set(), {}
    with zipfile.ZipFile(regular(path)) as archive:
        for entry in archive.infolist():
            name = entry.filename
            parts = name.rstrip("/").split("/")
            if name in seen or any(p in ("", ".", "..") for p in parts) or "\\" in name or not name.startswith("Payload/"):
                raise ValueError("Duplicate or unsafe ZIP entry")
            seen.add(name)
            mode = entry.external_attr >> 16
            if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)) or entry.flag_bits & 1:
                raise ValueError("Unsafe/encrypted ZIP entry")
            if entry.is_dir():
                if name not in directories:
                    raise ValueError("Unexpected ZIP directory")
                continue
            if name not in expected or entry.file_size != regular(payload.parent / name).stat().st_size:
                raise ValueError(f"Unexpected ZIP content: {name}")
            if (mode & 0o111) != (regular(payload.parent / name).stat().st_mode & 0o111):
                raise ValueError(f"ZIP executable permissions changed: {name}")
            with archive.open(entry) as stream:
                h = hashlib.sha256()
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    h.update(block)
                actual[name] = h.hexdigest()  # reading the complete stream checks CRC too
    if actual != expected or not empty_directories.issubset(seen):
        raise ValueError("IPA payload is missing or differs from validated app")
    return digest(path)


def build_command(products, intermediates):
    return ["xcodebuild", "-project", "app/Madeira.xcodeproj", "-target", "Madeira", "-configuration", "Debug",
            "-sdk", "iphoneos", "-arch", "arm64", "-jobs", "2", "-hideShellScriptEnvironment",
            f"SYMROOT={products}", f"OBJROOT={intermediates}", "CODE_SIGNING_ALLOWED=NO", "CODE_SIGNING_REQUIRED=NO",
            "CODE_SIGN_IDENTITY=", "DEVELOPMENT_TEAM=", "PROVISIONING_PROFILE_SPECIFIER=", "build"]


def run(args):
    print("+ " + " ".join(map(str, args)), flush=True)
    return subprocess.run(list(map(str, args)), cwd=ROOT, env=common.environment(), check=True)


def build(native_receipt, products, intermediates, stage):
    products, intermediates, stage = fresh_outputs(products, intermediates, stage)
    native_receipt = native_receipt.parent.resolve() / native_receipt.name
    evidence = prerequisites(native_receipt)
    if sys.platform != "darwin" or git("rev-parse", "--show-toplevel") != str(ROOT):
        raise ValueError("App build requires the same macOS source checkout as native/graphics")
    xcode = subprocess.check_output(["xcodebuild", "-version"], env=common.environment(), text=True)
    sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-version"], env=common.environment(), text=True).strip()
    architecture = subprocess.check_output(["uname", "-m"], text=True).strip()
    if not xcode.startswith("Xcode 27") or not sdk.startswith("27.") or architecture != "arm64":
        raise ValueError("Expected the standard Xcode 27 ARM64 runner with iPhoneOS 27 SDK")
    # Reuse the native FEX build tree; restoring archives alone is insufficient.
    placeholder = ROOT / "app/Madeira/x86_64-vcruntime"
    if placeholder.exists() and tree_files(placeholder):
        raise ValueError("Refusing existing VC runtime content")
    placeholder.mkdir(exist_ok=True)
    run(["bash", "build/stage-licenses.sh"])
    resources, pe = resource_inputs()
    source_names = git("ls-files", "-z", "--", "app", "build/app-ios", "build/stage-licenses.sh").split("\0")
    source_snapshot = {name: digest(ROOT / name) for name in source_names if name}
    evidence.update({"app_source_sha256": source_snapshot, "resources_sha256": resources, "guest_pe": {"status": "tracked-reused-not-source-rebuilt", "sha256": pe}})
    command = build_command(products, intermediates)
    run(command)
    # Fail if any prerequisites were replaced while Xcode was running.
    hashes_match(evidence["prerequisite_sha256"], ROOT)
    hashes_match(evidence["app_source_sha256"], ROOT)
    if git("rev-parse", "HEAD") != evidence["source_commit"]:
        raise ValueError("Source commit changed during app build")
    if digest(native_receipt) != evidence["native_receipt_sha256"]:
        raise ValueError("Native receipt changed during app build")
    app = products / "Debug-iphoneos/Madeira.app"
    framework_hash = evidence["prerequisite_sha256"][FRAMEWORK_SOURCE]
    built = validate_app(app, resources, framework_hash)
    # Recheck before creating; never reuse a prior stage or package.
    if stage.exists() or stage.is_symlink():
        raise ValueError("Package stage appeared during build")
    stage.mkdir(parents=True)
    payload = stage / "Payload"
    payload.mkdir()
    run(["ditto", "--norsrc", app, payload / "Madeira.app"])
    staged = validate_app(payload / "Madeira.app", resources, framework_hash)
    if staged != built:
        raise ValueError("Staged app differs from validated product")
    ipa = stage / "Madeira-unsigned.ipa"
    run(["ditto", "-c", "-k", "--norsrc", "--keepParent", payload, ipa])
    evidence.update({"schema_version": 1, "status": "passed", "build_command": command,
                     "app": built, "ipa_sha256": verify_zip(ipa, payload), "ipa_bytes": ipa.stat().st_size,
                     "signing": "disabled; pre-existing vendor converter signature/bytes preserved"})
    (stage / "provenance.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": "passed", "source_commit": evidence["source_commit"], "ipa_sha256": evidence["ipa_sha256"],
                      "ipa_bytes": evidence["ipa_bytes"], "tracked_guest_pe_files": len(pe), "scope": SCOPE}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-receipt", type=Path, required=True)
    parser.add_argument("--products", type=Path, required=True)
    parser.add_argument("--intermediates", type=Path, required=True)
    parser.add_argument("--stage", type=Path, required=True)
    args = parser.parse_args()
    try:
        build(args.native_receipt, args.products, args.intermediates, args.stage)
    except (ValueError, OSError, KeyError, TypeError, plistlib.InvalidFileException, zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
