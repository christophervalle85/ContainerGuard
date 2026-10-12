"""Publish validated archives without rebuilds or execution of image payloads."""

import json
import os
import tempfile
from pathlib import Path

from scripts.releases.artifacts import read_json_file, validate_handoff
from scripts.releases.checks import verify_evidence
from scripts.releases.commands import command
from scripts.releases.identity import (
    SERVICES,
    release_image,
    release_tags,
    validate_source,
)
from scripts.releases.registry import Registry

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
    if any(
        actual.get(key) != expected[key]
        for key in ("image_id", "diff_ids", "platform", "labels")
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
    (directory / "release.json").unlink(missing_ok=True)
    handoff = validate_handoff(
        read_json_file(directory / "handoff.json"),
        directory,
        version=version,
        commit=commit,
    )
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
    images, uploaded, attempted = {}, [], []
    with tempfile.TemporaryDirectory(prefix="containerguard-publisher-") as scratch:
        environment = {**os.environ, "DOCKER_CONFIG": scratch}
        try:
            command(
                ["docker", "login", "ghcr.io", "--username", actor, "--password-stdin"],
                input=credential.encode(),
                env=environment,
            )
            # Revalidate immediately before loading, never execute the images.
            validate_handoff(handoff, directory, version=version, commit=commit)
            recheck_source(version, commit)
            preflight_tags(version, commit, registry=registry)
            for service in SERVICES:
                expected = handoff["images"][service]
                command(
                    [
                        "docker",
                        "image",
                        "load",
                        "--input",
                        str(directory / expected["archive"]),
                    ],
                    timeout=180,
                    env=environment,
                )
                version_ref = release_image(service) + ":" + version
                loaded = command(
                    ["docker", "image", "inspect", "--format", "{{.Id}}", version_ref],
                    capture=True,
                    env=environment,
                ).strip()
                if loaded not in (expected["image_id"], expected["manifest_digest"]):
                    raise ValueError("Loaded candidate image mismatch")
                identity = None
                for tag in release_tags(version, commit):
                    reference = release_image(service) + ":" + tag
                    if tag != version:
                        command(
                            ["docker", "image", "tag", loaded, reference],
                            env=environment,
                        )
                    if registry.manifest(service, tag, allow_missing=True) is not None:
                        raise ValueError("Release destination became occupied")
                    attempted.append(reference)
                    command(
                        ["docker", "image", "push", reference],
                        timeout=300,
                        env=environment,
                    )
                    uploaded.append(reference)
                    actual = registry.manifest(service, tag)
                    verify_identity(actual, expected)
                    if identity is not None and identity["digest"] != actual["digest"]:
                        raise ValueError("Published tags point to different manifests")
                    identity = actual
                images[service] = {
                    **identity,
                    "reference": release_image(service) + "@" + identity["digest"],
                    "tags": list(release_tags(version, commit)),
                }
        except BaseException:
            (directory / "partial-publication.json").write_text(
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
    result = {
        "schema_version": 1,
        "version": version,
        "commit": commit,
        "platform": "linux/amd64",
        "images": images,
        "remaining_findings": verify_evidence(directory, handoff["images"]),
        "checks_url": "https://github.com/christophervalle85/ContainerGuard/actions/runs/"
        + os.environ["GITHUB_RUN_ID"],
    }
    (directory / "release.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
