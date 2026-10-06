#!/usr/bin/env python3
"""Verify one requested unsigned IPA, then deliver only to a private draft.

request, draft-body and verify are offline. draft-check uses GET requests only;
upload may attach assets to an existing empty draft using installed gh and the
current job's GH_TOKEN. Release metadata is never changed. There is no publish,
credential creation, permission change, overwrite, remote cleanup or retry path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import build_unsigned as gate

ROOT = gate.ROOT
REPOSITORY = "Mi-Yomi/Madeira"
SOURCE_REF = "refs/heads/compatibility/desktop-apps"
BASE_CODE_COMMIT = "d8037faa7c2153ed172da685f94ee5eb4d9a0cc5"
REQUEST_PATH = "build/app-ios/ipa-delivery-request.json"
ALLOWED_CHANGES = frozenset((
    '.github/workflows/unsigned-ipa-delivery.yml',
    '.gitignore',
    'build/app-ios/LINK-DIAGNOSTIC.md',
    'build/app-ios/README.md',
    'build/app-ios/build_unsigned.py',
    'build/app-ios/deliver_unsigned.py',
    'build/app-ios/ipa-delivery-request.json',
    'build/app-ios/link_diagnostic.py',
    'build/madeira-dock/build.sh',
    'build/madeira-dock/verified_build.py',
    'docs/MADEIRA_DOCK.md',
    'tests/host/check-app-bootstrap.py',
    'tests/host/check-app-link-diagnostic.py',
    'tests/host/check-desktop-integration.py',
    'tests/host/check-msi-integration.py',
    'tests/host/check-dock-contract.py',
    'tests/host/check-dock-packaging.py',
    'tests/host/check-unsigned-ipa-delivery.py',
    'tests/host/check-unsigned-ipa-workflow.py',
))
ASSETS = ("Madeira-unsigned.ipa", "provenance.json", "SHA256SUMS")
OUTPUTS = frozenset((*ASSETS, "release-notes.md", "verification.json"))
MAX_ASSET_BYTES = 2 * 1024 ** 3  # Each GitHub release asset must be strictly smaller.
MAX_RELEASE_PAGES = 5  # Fail closed if a complete list needs more than 500 entries.
MSI_LAYERS = ("desktop", "msi", "loader", "msi_client", "msi_startup")
SOURCE_PATHS = ("app", "build/app-ios", "build/stage-licenses.sh", "build/wine-pe", "build/madeira-dock")
SIGNING = "disabled; pre-existing vendor converter signature/bytes preserved"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def expected_request():
    return {"schema_version": 1, "repository": REPOSITORY, "source_ref": SOURCE_REF,
            "base_code_commit": BASE_CODE_COMMIT, "package_unsigned": True,
            "delivery": "draft-prerelease", "publish": False,
            "required_msi_layers": list(MSI_LAYERS)}


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def source_identity(sha):
    require(isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha),
            "Source commit must be exactly 40 lowercase hexadecimal characters")
    return {"source_commit": sha, "source_url": f"https://github.com/{REPOSITORY}/tree/{sha}",
            "tag": f"unsigned-ipa-20261006-{sha[:12]}"}


def preflight(*, clean=False):
    request = gate.document(ROOT / REQUEST_PATH)
    require(json_bytes(request) == json_bytes(expected_request()), "Unexpected IPA delivery request")
    env = os.environ
    require(env.get("GITHUB_ACTIONS") == "true" and env.get("GITHUB_REPOSITORY") == REPOSITORY
            and env.get("GITHUB_REF") == SOURCE_REF
            and env.get("GITHUB_EVENT_NAME") in ("push", "workflow_dispatch"),
            "Delivery is restricted to the fixed Actions repository and source branch")
    sha = env.get("GITHUB_SHA", "")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) and gate.git("rev-parse", "HEAD") == sha,
            "Checkout differs from GITHUB_SHA")
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        require(re.fullmatch(r"[1-9][0-9]*", env.get(name, "")), "Missing Actions run identity")
    require(gate.git("merge-base", BASE_CODE_COMMIT, "HEAD") == BASE_CODE_COMMIT,
            "Source does not descend from the reviewed app code")
    changed = set(filter(None, gate.git("diff", "--name-only", "--no-renames", "-z",
                                       BASE_CODE_COMMIT, "HEAD", "--").split("\0")))
    require(changed and changed <= ALLOWED_CHANGES and REQUEST_PATH in changed,
            "Delivery request changes source outside the reviewed Dock packaging allowlist")
    if clean:
        require(not gate.git("diff", "--name-only", "--ignore-submodules=all", "HEAD", "--"),
                "Request checkout has uncommitted tracked changes")
    return {**source_identity(sha), "run_id": env["GITHUB_RUN_ID"], "run_attempt": env["GITHUB_RUN_ATTEMPT"]}


def directory(path):
    path = Path(path).absolute()
    require(".." not in path.parts and not path.is_symlink() and path.is_dir()
            and not any(parent.is_symlink() for parent in path.parents), "Unsafe or missing directory")
    return path


def identity(path):
    path = gate.regular(path)
    size = path.stat().st_size
    require(0 < size < MAX_ASSET_BYTES, "Release asset must be nonempty and smaller than 2 GiB")
    return {"bytes": size, "sha256": gate.digest(path)}


def source_snapshot():
    names = gate.git("ls-files", "-z", "--", *SOURCE_PATHS).split("\0")
    return {name: gate.digest(ROOT / name) for name in names if name}


def verify_package(stage, native_receipt):
    context = preflight()
    stage = directory(stage)
    require({p.name for p in stage.iterdir()} == {"Payload", *ASSETS[:2]},
            "Package stage must contain only Payload, IPA and provenance.json")
    receipt = gate.document(stage / "provenance.json")
    prerequisite = gate.prerequisites(native_receipt)
    required_keys = {*prerequisite, "app_source_sha256", "resources_sha256", "guest_pe", "dock_build",
        "schema_version", "status", "build_command", "app", "packaging", "signing", "ipa_sha256", "ipa_bytes"}
    require(set(receipt) == required_keys and type(receipt.get("schema_version")) is int
            and receipt.get("schema_version") == 1 and receipt.get("status") == "passed"
            and receipt.get("source_commit") == context["source_commit"]
            and receipt.get("scope") == gate.PACKAGE_SCOPE
            and receipt.get("signing") == SIGNING
            and receipt.get("packaging") == {"requested": True, "status": "passed"}
            and receipt["packaging"]["requested"] is True, "Receipt is not the exact passed unsigned package contract")
    require(all(receipt[key] == value for key, value in prerequisite.items() if key != "scope"),
            "Native/graphics prerequisite evidence differs from the package")
    sources = source_snapshot()
    require(sources and receipt["app_source_sha256"] == sources, "App source inventory changed")
    resources, pe = gate.resource_inputs()  # Includes all five sealed integration validators.
    dock_evidence = gate.dock_inputs()
    require(receipt["dock_build"] == dock_evidence,
            "Dock evidence differs from this job's validated source-built host/notices")
    require(not gate.DOCK_RESOURCES & resources.keys(), "Generated Dock files entered the sealed source farm")
    resources = {**resources, **gate.dock_resources(dock_evidence)}
    guest = gate.guest_pe_evidence(pe)
    require(guest["status"] == "tracked-existing-plus-reviewed-desktop-msi-loader-client-and-startup-fixes"
            and all(guest.get(layer + "_stage_seal_sha256") for layer in MSI_LAYERS),
            "All reviewed desktop/MSI/loader/client/startup layers are required")
    require(receipt["resources_sha256"] == resources and receipt["guest_pe"] == guest,
            "Resource or guest PE evidence differs from the validated source")
    command = receipt["build_command"]
    require(isinstance(command, list) and all(isinstance(arg, str) for arg in command),
            "Invalid unsigned build command")
    outputs = [arg.split("=", 1)[1] for arg in command if arg.startswith(("SYMROOT=", "OBJROOT="))]
    require(len(outputs) == 2 and all(Path(p).is_absolute() and ".." not in Path(p).parts for p in outputs)
            and command == gate.build_command(*outputs), "Receipt does not describe the unsigned Debug device build")
    app = gate.validate_app(stage / "Payload/Madeira.app", resources,
                            prerequisite["prerequisite_sha256"][gate.FRAMEWORK_SOURCE])
    require(app == receipt["app"], "Staged app differs from the built app receipt")
    ipa = identity(stage / ASSETS[0])  # Bound size before ZIP processing.
    require(type(receipt["ipa_bytes"]) is int and ipa == {"bytes": receipt["ipa_bytes"], "sha256": receipt["ipa_sha256"]}
            and gate.verify_zip(stage / ASSETS[0], stage / "Payload") == ipa["sha256"],
            "IPA bytes or ZIP payload differ from the package receipt")
    gate.hashes_match(sources, ROOT)
    gate.hashes_match(prerequisite["prerequisite_sha256"], ROOT)
    require(gate.dock_inputs() == dock_evidence, "Dock inputs changed during package verification")
    require(preflight() == context and gate.digest(native_receipt) == receipt["native_receipt_sha256"],
            "Source/run/native receipt changed during package verification")
    return context, {ASSETS[0]: ipa, ASSETS[1]: identity(stage / ASSETS[1])}


def release_notes(source_commit):
    source = source_identity(source_commit)["source_url"]
    blob = f"https://github.com/{REPOSITORY}/blob/{source_commit}"
    lines = ["Reserved draft prerelease for an unsigned experimental Madeira IPA; restricted to existing repository writers.",
        "This draft may be empty or incomplete. Delivery is complete only after the workflow verifies all three uploaded assets by downloading and hashing them.",
        "If attached, the approved assets will be Madeira-unsigned.ipa, provenance.json and SHA256SUMS.",
        "Delivery requires static app/bundle/ZIP integrity checks. This pipeline does not sign, install or test device launch, rendering, JIT, 1C or Blender.",
        "This replacement requires the pinned source-built Dock host and its notices in the final app, restoring the missing Steam/Dock bundle entry. Valve client components still download separately on device.",
        "The planned package preserves the tracked vendor converter bytes/signature. The 32-bit runtime and x86_64 VC runtime remain absent; full-farm dependency gaps remain.",
        "To install a delivered IPA, sideload with development signing and get-task-allow, retain/provision the MadeiraJITHelper extension, re-sign embedded code, then enable JIT.",
        "This draft does not establish runtime compatibility, complete redistribution/relinking compliance, or public release approval.",
        "", f"Source commit: {source}",
        "After upload, SHA256SUMS records the exact hashes of the IPA and original provenance.json. The Actions run/attempt will be provided separately from workflow evidence.",
        "Use provenance.json for the actual build/source evidence and package size; asset presence alone is not successful delivery verification.",
        "", "Planned bundled notices: Payload/Madeira.app/licenses/ and Payload/Madeira.app/legal/;",
        "converter terms: Payload/Madeira.app/d3d12/METAL-SHADER-CONVERTER-AGREEMENT.txt.",
        f"Madeira license: {blob}/COPYING", f"Converter exception: {blob}/LICENSE-EXCEPTION.md",
        f"Third-party licenses/source notices: {blob}/app/Madeira/licenses/THIRD-PARTY-NOTICES.txt",
        f"Third-party source details: {blob}/app/Madeira/legal/THIRD-PARTY-NOTICES.md",
        f"Build/relink instructions and remaining limits: {blob}/docs/BUILDING.md",
        f"Dock source, notices and client setup: {blob}/docs/MADEIRA_DOCK.md",
        f"Installation/signing and JIT setup: {blob}/docs/JIT.md",
        f"Pinned submodule source locations: {blob}/.gitmodules (commit gitlinks are retained at that exact source commit)",
        f"LLVM corresponding source pin and URL: {blob}/build/llvm-ios/manifest.json",
        f"Pinned Rust crate source versions: {blob}/build/rppairing-ios/Cargo.lock",
        f"FreeType source pin and remaining native build inputs: {blob}/.github/ci/native-artifacts.py",
        f"GnuTLS/Nettle/GMP source checksums: {blob}/build/gnutls-ios/src/SHA256SUMS",
        f"FFmpeg source checksums: {blob}/build/ffmpeg/src/SHA256SUMS"]
    for name in ("desktop", "MSI", "loader", "MSI-client", "MSI-startup"):
        lines.append(f"Wine {name} corresponding source/rebuild evidence: {blob}/app/Madeira/legal/Wine-{name}-SOURCE-REBUILD.md")
    return "\n".join(lines) + "\n"


def draft_body(source_commit):
    context = source_identity(source_commit)
    return {"repository": REPOSITORY, "source_ref": SOURCE_REF, **context,
            "target_commitish": source_commit, "draft": True, "prerelease": True,
            "body": release_notes(source_commit)}


def delivery_metadata(context, assets):
    sums = "".join(f"{assets[name]['sha256']}  {name}\n" for name in ASSETS[:2]).encode()
    assets = {**assets, "SHA256SUMS": {"bytes": len(sums), "sha256": hashlib.sha256(sums).hexdigest()}}
    notes = release_notes(context["source_commit"]).encode()
    receipt = {"schema_version": 1, "status": "verified-offline", **context,
               "repository": REPOSITORY, "source_ref": SOURCE_REF, "draft": True, "prerelease": True,
               "runtime_tested": False, "assets": assets,
               "notes_sha256": hashlib.sha256(notes).hexdigest()}
    return assets, {"SHA256SUMS": sums, "release-notes.md": notes, "verification.json": json_bytes(receipt)}


def prepare(stage, native_receipt, delivery):
    context, package_assets = verify_package(stage, native_receipt)
    delivery = Path(delivery).absolute()
    require(".." not in delivery.parts and not delivery.exists() and not delivery.is_symlink()
            and not any(parent.is_symlink() for parent in delivery.parents)
            and not delivery.is_relative_to(Path(stage).absolute())
            and not delivery.is_relative_to(ROOT) and not ROOT.is_relative_to(delivery),
            "Delivery directory must be fresh, outside source and package stage")
    assets, metadata = delivery_metadata(context, package_assets)
    delivery.mkdir(parents=True)
    for name in ASSETS[:2]:
        with gate.regular(Path(stage) / name).open("rb") as source, (delivery / name).open("xb") as target:
            shutil.copyfileobj(source, target, 1024 * 1024)
        require(identity(delivery / name) == assets[name], "Package changed while preparing delivery")
    for name, data in metadata.items():
        with (delivery / name).open("xb") as stream:
            stream.write(data)
    require(verify_package(stage, native_receipt) == (context, package_assets),
            "Package/source changed while preparing delivery")
    return {"status": "verified-offline", **context, "assets": assets, "draft": True, "runtime_tested": False}


def check_delivery(delivery, context, package_assets):
    delivery = directory(delivery)
    require({p.name for p in delivery.iterdir()} == OUTPUTS, "Unexpected delivery directory entries")
    assets, metadata = delivery_metadata(context, package_assets)
    for name in ASSETS:
        require(identity(delivery / name) == assets[name], "Prepared asset changed: " + name)
    for name, expected in metadata.items():
        require(gate.regular(delivery / name).read_bytes() == expected, "Prepared metadata changed: " + name)
    return assets


class GitHub:
    """Use only installed gh and the explicitly exposed ephemeral job token."""

    def __enter__(self):
        require(os.environ.get("GH_TOKEN"), "GitHub access requires this Actions job's ephemeral GH_TOKEN")
        self.executable = shutil.which("gh")
        require(self.executable, "The runner's installed GitHub CLI is required")
        self.config = tempfile.TemporaryDirectory(prefix="madeira-gh-config-")
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("GH_", "GITHUB_"))}
        self.env.update({"GH_TOKEN": os.environ["GH_TOKEN"], "GH_HOST": "github.com",
                         "GH_CONFIG_DIR": self.config.name, "GH_PROMPT_DISABLED": "1",
                         "GH_NO_UPDATE_NOTIFIER": "1", "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1"})
        return self

    def __exit__(self, *_):
        self.config.cleanup()

    def run(self, *args, data=None, output=None, timeout=600):
        result = subprocess.run([self.executable, *map(str, args)], input=data,
            stdout=output if output is not None else subprocess.PIPE, stderr=subprocess.PIPE,
            env=self.env, cwd=self.config.name, timeout=timeout, check=False)
        require(result.returncode == 0,
                "GitHub CLI failed; no retry was attempted. Inspect the draft for partial state before further action")
        return result.stdout

    def api(self, endpoint):
        args = ["api", "--hostname", "github.com", "--method", "GET",
                "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2022-11-28",
                f"repos/{REPOSITORY}/{endpoint}".rstrip("/")]
        raw = self.run(*args, timeout=60)
        require(len(raw) <= 4 * 1024 * 1024, "Oversized GitHub API response")
        return json.loads(raw)

    def download(self, asset_id, destination):
        require(type(asset_id) is int and asset_id > 0, "Invalid GitHub asset ID")
        with destination.open("xb") as stream:
            self.run("api", "--hostname", "github.com", "--method", "GET",
                "-H", "Accept: application/octet-stream", "-H", "X-GitHub-Api-Version: 2022-11-28",
                f"repos/{REPOSITORY}/releases/assets/{asset_id}", output=stream)

    def upload_asset(self, release_id, path, expected):
        require(type(release_id) is int and release_id > 0 and path.name in ASSETS,
                "Invalid release ID or unapproved asset name")
        require(identity(path) == expected, "Asset changed immediately before upload")
        # Bind the destination to the checked ID, never resolve the tag again or
        # trust a server-provided upload_url. gh authenticates *.github.com with
        # GH_TOKEN; the token is never an argument or saved credential.
        raw = self.run("api", "--hostname", "github.com", "--method", "POST", "--input", path,
            "-H", "Accept: application/vnd.github+json", "-H", "Content-Type: application/octet-stream",
            "-H", f"Content-Length: {expected['bytes']}", "-H", "X-GitHub-Api-Version: 2022-11-28",
            f"https://uploads.github.com/repos/{REPOSITORY}/releases/{release_id}/assets?name={path.name}")
        require(len(raw) <= 4 * 1024 * 1024, "Oversized GitHub upload response")
        return json.loads(raw)


def check_remote_source(github, context):
    repo = github.api("")
    require(repo.get("full_name") == REPOSITORY and repo.get("private") is False
            and repo.get("visibility") == "public", "Unexpected repository identity or visibility")
    ref = github.api("git/ref/heads/compatibility/desktop-apps")
    require(ref.get("ref") == SOURCE_REF and ref.get("object", {}).get("type") == "commit"
            and ref["object"].get("sha") == context["source_commit"], "Remote source branch moved")


def check_release(github, release_id, context):
    require(type(release_id) is int and release_id > 0, "An explicit existing draft release ID is required")
    release = github.api(f"releases/{release_id}")
    require(release.get("id") == release_id and release.get("draft") is True
            and release.get("prerelease") is True and release.get("published_at") is None
            and release.get("tag_name") == context["tag"]
            and release.get("target_commitish") == context["source_commit"],
            "Release is not the requested unpublished draft prerelease at the exact source commit")
    require(isinstance(release.get("html_url"), str)
            and release["html_url"].startswith(f"https://github.com/{REPOSITORY}/releases/"),
            "Unexpected release URL")
    body = release.get("body")
    require(isinstance(body, str), "Draft release body must be text")
    body = body.replace("\r\n", "\n")  # HTML forms may normalize line endings.
    require("\r" not in body and body == release_notes(context["source_commit"]),
            "Draft release body differs from the exact offline source-derived text")
    return release


def find_draft(github, context):
    """Prove uniqueness over a complete bounded list; never infer a missing ID."""
    matches, seen = [], set()
    for page in range(1, MAX_RELEASE_PAGES + 1):
        rows = github.api(f"releases?per_page=100&page={page}")
        require(isinstance(rows, list) and len(rows) <= 100, "Invalid release-list response")
        for row in rows:
            require(isinstance(row, dict) and type(row.get("id")) is int and row["id"] > 0
                    and isinstance(row.get("tag_name"), str) and row["id"] not in seen,
                    "Invalid or unstable release pagination")
            seen.add(row["id"])
            if row["tag_name"] == context["tag"]:
                matches.append(row["id"])
        require(len(matches) <= 1, "More than one release has the requested deterministic tag")
        if len(rows) < 100:
            break
    else:
        raise ValueError("Release list exceeds the bounded discovery limit; uniqueness is not established")
    require(len(matches) == 1, "Matching pre-created draft is absent; do not start the long build")
    release = check_release(github, matches[0], context)
    require(github.api(f"releases/{matches[0]}/assets?per_page=100") == [],
            "Matching draft already has assets; refusing a rebuild/overwrite or blind retry")
    return release


def draft_check():
    context = preflight(clean=True)
    with GitHub() as github:
        check_remote_source(github, context)
        release = find_draft(github, context)
        check_remote_source(github, context)
    require(preflight(clean=True) == context, "Source/run changed during draft discovery")
    return {"status": "empty-draft-verified", **context, "release_id": release["id"],
            "release_url": release["html_url"], "draft": True, "prerelease": True}


def check_asset_inventory(rows, assets):
    require(isinstance(rows, list) and len(rows) == len(assets) and set(assets) <= set(ASSETS)
            and all(isinstance(row, dict) for row in rows)
            and {row.get("name") for row in rows} == set(assets),
            "Draft asset inventory differs from this exact delivery step")
    for row in rows:
        name = row["name"]
        require(type(row.get("id")) is int and row["id"] > 0 and row.get("state") == "uploaded"
                and type(row.get("size")) is int and row["size"] == assets[name]["bytes"],
                "Uploaded asset ID/state/size mismatch: " + name)
        require(row.get("digest") in (None, "", "sha256:" + assets[name]["sha256"]),
                "GitHub asset digest mismatch: " + name)
    require(len({row["id"] for row in rows}) == len(assets), "Duplicate release asset IDs")
    # Downloads legitimately change download_count; compare only asset identity.
    return {row["name"]: row["id"] for row in rows}


def upload(stage, native_receipt, delivery, release_id):
    context, package_assets = verify_package(stage, native_receipt)
    delivery = directory(delivery)
    assets = check_delivery(delivery, context, package_assets)
    with GitHub() as github:
        check_remote_source(github, context)
        check_release(github, release_id, context)
        require(github.api(f"releases/{release_id}/assets?per_page=100") == [],
                "Draft already has assets; refusing overwrite or blind retry")
        require(verify_package(stage, native_receipt) == (context, package_assets),
                "Package/source changed before upload")
        check_delivery(delivery, context, package_assets)
        uploaded_assets, uploaded_ids = {}, {}
        for name in ASSETS:
            check_release(github, release_id, context)
            require(check_asset_inventory(github.api(f"releases/{release_id}/assets?per_page=100"), uploaded_assets) == uploaded_ids,
                    "Draft asset inventory changed before upload; refusing overwrite")
            created = github.upload_asset(release_id, delivery / name, assets[name])
            check_release(github, release_id, context)
            uploaded_ids.update(check_asset_inventory([created], {name: assets[name]}))
            uploaded_assets[name] = assets[name]
            require(check_asset_inventory(github.api(f"releases/{release_id}/assets?per_page=100"), uploaded_assets) == uploaded_ids,
                    "Draft asset inventory changed after upload")
        uploaded = github.api(f"releases/{release_id}/assets?per_page=100")
        asset_ids = check_asset_inventory(uploaded, assets)
        with tempfile.TemporaryDirectory(prefix="madeira-download-check-") as temporary:
            # Resolve this trusted fresh root's macOS /var ancestor alias only;
            # asset paths are still checked by regular() without resolving them.
            temporary_root = Path(temporary).resolve(strict=True)
            for row in uploaded:
                name = row["name"]
                expected = assets[name]
                destination = temporary_root / name
                github.download(row.get("id"), destination)  # Always independently hash the downloaded bytes.
                require(identity(destination) == expected, "Downloaded asset differs: " + name)
        check_remote_source(github, context)
        release = check_release(github, release_id, context)
        require(check_asset_inventory(github.api(f"releases/{release_id}/assets?per_page=100"), assets) == asset_ids,
                "Release asset metadata changed during download verification")
        require(verify_package(stage, native_receipt) == (context, package_assets),
                "Package/source changed during delivery")
        check_delivery(delivery, context, package_assets)
    return {"status": "draft-delivered-and-downloaded-verified", **context,
            "release_id": release_id, "release_url": release["html_url"],
            "draft": True, "prerelease": True, "runtime_tested": False, "assets": assets}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("request", "draft-body", "draft-check", "verify", "upload"), required=True)
    parser.add_argument("--source-commit", help="Exact 40-hex source SHA for offline draft-body mode only")
    parser.add_argument("--stage", type=Path)
    parser.add_argument("--native-receipt", type=Path)
    parser.add_argument("--delivery", type=Path)
    parser.add_argument("--release-id", type=int, help="Explicit existing empty draft release ID; never a published release")
    args = parser.parse_args()
    require(args.mode == "draft-body" or args.source_commit is None,
            "Explicit source SHA is allowed only in offline draft-body mode")
    if args.mode in ("request", "draft-body", "draft-check"):
        require(not any((args.stage, args.native_receipt, args.delivery)) and args.release_id is None,
                "Request/draft-body/draft-check modes take no artifact paths or release ID")
        if args.mode == "draft-body":
            result = draft_body(args.source_commit)
        else:
            result = ({"status": "request-verified", **preflight(clean=True)}
                      if args.mode == "request" else draft_check())
    else:
        require(args.stage and args.native_receipt and args.delivery, "Package modes require stage, native receipt and delivery paths")
        if args.mode == "verify":
            require(args.release_id is None, "Offline verification does not take a release ID")
            result = prepare(args.stage, args.native_receipt, args.delivery)
        else:
            result = upload(args.stage, args.native_receipt, args.delivery, args.release_id)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from error
