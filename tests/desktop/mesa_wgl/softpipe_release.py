#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Future reviewed delivery to one pre-created, unpublished draft release.

No release creation, publication, metadata edits, overwrite, deletion, automatic
retry, credential creation, or Actions artifact/cache storage is implemented.
All remote modes require an activated request; the checked-in request is inert.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import softpipe_package as package


def body(context):
    return ("Private draft softpipe test delivery for existing repository writers only.\n"
            "Keep this release unpublished. No IPA, installation, Blender, or iPhone runtime success is supplied.\n"
            "The Windows reference proves backing pixels only; interactive iPhone visibility needs manual confirmation.\n"
            "Delivery is complete only after every asset is downloaded and independently hash-verified.\n"
            "Approved assets: " + ", ".join(package.ASSETS) + ".\n"
            "Preserve both ZIPs together, including sources and third-party notices.\n"
            "Reviewed source: https://github.com/" + package.REPOSITORY + "/tree/" + context["source_commit"] + "\n"
            "Request: " + context["request_id"] + "\n"
            "Target previously delivered IPA SHA-256: " + context["target_ipa_sha256"] + "\n")


class GitHub:
    def __enter__(self):
        package.require(os.environ.get("GH_TOKEN"), "Only the current job's ephemeral GitHub token may be used")
        self.gh = shutil.which("gh")
        package.require(self.gh, "The preinstalled GitHub CLI is required; no download fallback")
        self.config = tempfile.TemporaryDirectory(prefix="softpipe-gh-")
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("GH_", "GITHUB_"))}
        self.env.update(GH_TOKEN=os.environ["GH_TOKEN"], GH_HOST="github.com", GH_CONFIG_DIR=self.config.name,
                        GH_PROMPT_DISABLED="1", GH_NO_UPDATE_NOTIFIER="1", GH_NO_EXTENSION_UPDATE_NOTIFIER="1")
        return self

    def __exit__(self, *_):
        self.config.cleanup()

    def run(self, *args, destination=None, timeout=90):
        result = subprocess.run([self.gh, *map(str, args)], stdout=destination or subprocess.PIPE,
                                stderr=subprocess.PIPE, env=self.env, cwd=self.config.name,
                                timeout=timeout, check=False)
        package.require(result.returncode == 0, "GitHub request failed; inspect partial draft state before any new request")
        if destination is None:
            package.require(len(result.stdout) <= 4 * 1024**2, "Oversized GitHub response")
        return result.stdout

    def get(self, suffix):
        return json.loads(self.run("api", "--hostname", "github.com", "--method", "GET",
                                  "-H", "X-GitHub-Api-Version: 2022-11-28",
                                  "repos/" + package.REPOSITORY + "/" + suffix))

    def upload(self, release_id, path, expected):
        package.require(type(release_id) is int and release_id > 0 and path.name in package.ASSETS and
                        package.identity(path) == expected, "Unapproved or changed upload")
        return json.loads(self.run("api", "--hostname", "github.com", "--method", "POST", "--input", path,
                         "-H", "Content-Type: application/octet-stream", "-H", "X-GitHub-Api-Version: 2022-11-28",
                         "https://uploads.github.com/repos/" + package.REPOSITORY + "/releases/" +
                         str(release_id) + "/assets?name=" + path.name, timeout=180))

    def download(self, asset_id, path):
        package.require(type(asset_id) is int and asset_id > 0, "Invalid returned asset ID")
        with path.open("xb") as stream:
            self.run("api", "--hostname", "github.com", "--method", "GET", "-H", "Accept: application/octet-stream",
                     "-H", "X-GitHub-Api-Version: 2022-11-28",
                     "repos/" + package.REPOSITORY + "/releases/assets/" + str(asset_id),
                     destination=stream, timeout=180)


def check_release_value(release, context):
    package.require(release.get("id") == context["release_id"] and release.get("draft") is True and
                    release.get("prerelease") is True and release.get("published_at") is None and
                    release.get("tag_name") == context["tag"] and release.get("target_commitish") == context["source_commit"] and
                    isinstance(release.get("body"), str) and release["body"].replace("\r\n", "\n") == body(context),
                    "Draft destination/source/body changed or was published")
    package.require(isinstance(release.get("html_url"), str) and
                    release["html_url"].startswith("https://github.com/" + package.REPOSITORY + "/releases/"),
                    "Unexpected draft URL")
    return release


def check_destination(github, context):
    repo = github.get("")
    package.require(repo.get("full_name") == package.REPOSITORY and repo.get("private") is False,
                    "Wrong repository")
    branch = github.get("git/ref/heads/compatibility/desktop-apps")
    package.require(branch.get("ref") == package.REF and branch.get("object", {}).get("type") == "commit" and
                    branch["object"].get("sha") == context["request_commit"],
                    "Request branch moved; do not build or deliver stale output")
    # Draft target_commitish does not bind an already-existing Git tag. This
    # delivery uses a new unpublished tag only, so require its ref to be absent.
    package.require(github.get("git/matching-refs/tags/" + context["tag"]) == [],
                    "Draft tag already exists; its target is not covered by this new-draft contract")
    return check_release_value(github.get("releases/" + str(context["release_id"])), context)


def asset_inventory(rows, expected, ids=None):
    package.require(isinstance(rows, list) and len(rows) == len(expected) and
                    all(isinstance(x, dict) for x in rows) and {x.get("name") for x in rows} == set(expected),
                    "Draft asset inventory changed")
    found = {}
    for row in rows:
        name = row["name"]
        package.require(type(row.get("id")) is int and row["id"] > 0 and row.get("state") == "uploaded" and
                        type(row.get("size")) is int and row["size"] == expected[name]["bytes"] and
                        row.get("digest") in (None, "", "sha256:" + expected[name]["sha256"]), "Asset metadata mismatch")
        found[name] = row["id"]
    package.require(len(set(found.values())) == len(found) and (ids is None or found == ids), "Asset identity changed")
    return found


def remote(mode, output=None):
    context = package.preflight()
    package.require(context["enabled"], "Delivery request is inactive")
    suffix = "releases/" + str(context["release_id"]) + "/assets?per_page=100"
    with GitHub() as github:
        release = check_destination(github, context)
        asset_inventory(github.get(suffix), {})  # No rebuilding into an occupied draft.
        if mode == "draft-check":
            return {"status": "empty-private-draft-verified", "release_id": context["release_id"]}
        verified = package.verify_delivery(output, context)
        uploaded, ids = {}, {}
        for name in package.ASSETS:
            package.require(package.preflight() == context, "Request changed")
            package.require(package.verify_delivery(output, context) == verified, "Local package changed")
            check_destination(github, context)
            asset_inventory(github.get(suffix), uploaded, ids)
            item = github.upload(context["release_id"], Path(output) / name, verified["assets"][name])
            new_id = asset_inventory([item], {name: verified["assets"][name]})
            uploaded[name] = verified["assets"][name]
            ids.update(new_id)
            check_destination(github, context)
            asset_inventory(github.get(suffix), uploaded, ids)
        with tempfile.TemporaryDirectory(prefix="softpipe-download-") as tmp:
            for name, asset_id in ids.items():
                path = Path(tmp) / name
                github.download(asset_id, path)
                package.require(package.identity(path) == uploaded[name], "Downloaded bytes differ: " + name)
        release = check_destination(github, context)
        asset_inventory(github.get(suffix), uploaded, ids)
        package.require(package.verify_delivery(output, context) == verified and package.preflight() == context,
                        "Package/source changed during upload")
        return {"status": "private-draft-delivered-download-verified", "release_id": context["release_id"],
                "release_url": release["html_url"], "assets": uploaded, "limits": package.LIMITS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("draft-body", "draft-check", "upload"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--source-commit")
    parser.add_argument("--request-id")
    parser.add_argument("--target-ipa-sha256")
    args = parser.parse_args()
    if args.mode == "draft-body":
        context = json.loads((package.HERE / "delivery-request.json").read_text())
        context.update(enabled=True, source_commit=args.source_commit, request_id=args.request_id,
                       target_ipa_sha256=args.target_ipa_sha256, release_id=1)
        package.request_value(context)
        context["tag"] = "softpipe-test-" + context["request_id"] + "-" + context["source_commit"][:12]
        result = {"tag_name": context["tag"], "target_commitish": context["source_commit"],
                  "draft": True, "prerelease": True, "body": body(context)}
    else:
        package.require(not any((args.source_commit, args.request_id, args.target_ipa_sha256)), "Identity comes only from the request")
        package.require((args.output is not None) == (args.mode == "upload"), "Output directory is required only for upload")
        result = remote(args.mode, args.output)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        raise SystemExit(str(exc)) from exc
