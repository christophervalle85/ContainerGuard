"""Publish validated archives without rebuilds or execution of image payloads."""

import base64
import json
import os
import tempfile
from pathlib import Path

from scripts.releases.artifacts import read_json_file
from scripts.releases.candidate import release_context
from scripts.releases.commands import command
from scripts.releases.identity import (
    SERVICES,
    release_image,
    release_tags,
    validate_source,
)
from scripts.releases.registry import Registry
from scripts.releases.supply_chain import manifest, oci

ROOT = Path(__file__).resolve().parents[2]


def recheck_source(version, commit):
    # Fetch into a private ref so a moved remote tag cannot hide behind checkout.
    command(
        [
            "git",
            "fetch",
            "--no-tags",
            "origin",
            "+refs/heads/main:refs/remotes/origin/main",
            f"+refs/tags/{version}:refs/release-verify/tag",
        ],
        timeout=60,
    )
    actual = command(
        ["git", "rev-parse", "--verify", "refs/release-verify/tag^{commit}"],
        capture=True,
    ).strip()
    if actual != commit:
        raise ValueError("Remote release tag moved")
    validate_source(version, commit, repository=ROOT)


def preflight_tags(version: str, commit: str, *, registry=None):
    registry = registry or Registry()
    tags = release_tags(version, commit)
    for service in SERVICES:
        for tag in tags:
            if registry.manifest(service, tag, allow_missing=True) is not None:
                raise ValueError("Release destination already exists")


def verify_identity(actual, expected):
    if (
        actual.get("digest") != expected["manifest_digest"]
        or any(
            actual.get(key) != expected[key]
            for key in ("image_id", "diff_ids", "platform")
        )
        or actual.get("labels") != expected["labels"]
    ):
        raise ValueError("Published image differs from checked candidate")


def verify_publication_context(version, commit):
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_REPOSITORY") != "christophervalle85/ContainerGuard"
        or os.environ.get("GITHUB_EVENT_NAME") != "push"
        or os.environ.get("GITHUB_REF") != "refs/tags/" + version
        or os.environ.get("GITHUB_SHA") != commit
        or not os.environ.get("GITHUB_RUN_ID", "").isdigit()
    ):
        raise ValueError("Untrusted publication event")


def publish_candidate(
    directory: Path, *, version: str, commit: str, dry_run: bool
) -> dict:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Unsafe candidate directory")
    partial = directory / "partial-publication.json"
    if partial.exists() or partial.is_symlink():
        raise ValueError("Previous partial publication requires investigation")
    release_path = directory / "release.json"
    if release_path.exists() or release_path.is_symlink():
        raise ValueError("Previous release output already exists")
    document = read_json_file(directory / "handoff.json")
    # Only local dry runs may use the seal's run metadata as qualification input.
    # Hosted publication derives every context field from guarded operator inputs.
    context = release_context(
        version, commit, document.get("context") if dry_run else None
    )
    handoff = manifest.validate_handoff(document, directory, context=context)
    recheck_source(version, commit)
    registry = Registry()
    preflight_tags(version, commit, registry=registry)
    if dry_run:
        return {
            "dry_run": True,
            "version": version,
            "commit": commit,
            "checked_destinations": 6,
        }
    credential, actor = os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_ACTOR")
    if not credential or not actor:
        raise ValueError("Publisher credentials unavailable")
    verify_publication_context(version, commit)
    if os.environ.get("GITHUB_WORKFLOW_REF") != (
        "christophervalle85/ContainerGuard/.github/workflows/release.yml@refs/tags/"
        + version
    ):
        raise ValueError("Untrusted publication workflow")
    images, uploaded, attempted = {}, [], []
    with tempfile.TemporaryDirectory(prefix="containerguard-publisher-") as scratch:
        authfile = Path(scratch) / "auth.json"
        authfile.write_text(
            json.dumps(
                {
                    "auths": {
                        "ghcr.io": {
                            "auth": base64.b64encode(
                                (actor + ":" + credential).encode()
                            ).decode()
                        }
                    }
                }
            )
        )
        authfile.chmod(0o600)
        try:
            manifest.validate_handoff(handoff, directory, context=context)
            recheck_source(version, commit)
            preflight_tags(version, commit, registry=registry)
            remaining_findings = manifest.read_checked_findings(handoff, directory)
            for service in SERVICES:
                item = handoff["images"][service]
                path = directory / item["archive"]["path"]
                expected = oci.inspect_canonical(path)
                if any(
                    expected[k] != item["identity"][k]
                    for k in ("manifest_digest", "image_id", "diff_ids", "platform")
                ) or any(
                    expected[k] != item["archive"][k] for k in ("sha256", "size_bytes")
                ):
                    raise ValueError("Sealed archive changed before publication")
                identity = None
                for tag in release_tags(version, commit):
                    reference = release_image(service) + ":" + tag
                    if registry.manifest(service, tag, allow_missing=True) is not None:
                        raise ValueError("Release destination became occupied")
                    attempted.append(reference)
                    digest = oci.copy_preserving_digest(
                        path,
                        reference,
                        authfile=authfile,
                        expected_identity={
                            **{
                                key: item["identity"][key]
                                for key in (
                                    "manifest_digest",
                                    "image_id",
                                    "diff_ids",
                                    "platform",
                                )
                            },
                            **{
                                key: item["archive"][key]
                                for key in ("sha256", "size_bytes")
                            },
                        },
                    )
                    uploaded.append(reference)
                    if digest != expected["manifest_digest"]:
                        raise ValueError("Published manifest digest changed")
                    actual = registry.manifest(service, tag)
                    verify_identity(actual, expected)
                    identity = actual
                images[service] = {
                    **identity,
                    "reference": release_image(service) + "@" + identity["digest"],
                    "tags": list(release_tags(version, commit)),
                    "evidence": {
                        kind: {
                            **item[kind],
                            "predicate_type": manifest.PREDICATE_TYPES[kind],
                        }
                        for kind in manifest.KINDS
                    },
                }
            result = {
                "schema_version": 2,
                "version": version,
                "commit": commit,
                "platform": "linux/amd64",
                "images": images,
                "remaining_findings": remaining_findings,
                "checks_url": "https://github.com/christophervalle85/ContainerGuard/actions/runs/"
                + context["run_id"],
                "build_context": context,
            }
            manifest.validate_release(result, version=version, commit=commit)
            with release_path.open("x") as output:
                output.write(json.dumps(result, indent=2) + "\n")
        except BaseException:
            with partial.open("x") as output:
                output.write(
                    json.dumps(
                        {
                            "version": version,
                            "commit": commit,
                            "uploaded": uploaded,
                            "attempted": attempted,
                            "complete": False,
                        },
                        indent=2,
                    )
                    + "\n"
                )
            raise
    return result
