"""Canonical release names and source ancestry checks."""

import re
import subprocess
from pathlib import Path

SERVICES = ("api", "worker", "frontend")
SOURCE = "https://github.com/christophervalle85/ContainerGuard"
VERSION = re.compile(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
COMMIT = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def validate_version(value: str) -> str:
    if not isinstance(value, str) or len(value) > 64 or not VERSION.fullmatch(value):
        raise ValueError("Invalid release version")
    return value


def validate_commit(value: str) -> str:
    if not isinstance(value, str) or not COMMIT.fullmatch(value):
        raise ValueError("Invalid source commit")
    return value


def release_image(service: str) -> str:
    if service not in SERVICES:
        raise ValueError("Invalid release service")
    return "ghcr.io/christophervalle85/containerguard-" + service


def release_tags(version: str, commit: str) -> tuple[str, str]:
    return validate_version(version), "sha-" + validate_commit(commit)


def validate_source(tag: str, event_commit: str, *, repository: Path) -> str:
    validate_version(tag)
    validate_commit(event_commit)
    try:
        resolved = subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "rev-parse",
                "--verify",
                f"refs/tags/{tag}^{{commit}}",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        ).stdout.strip()
        if resolved != event_commit:
            raise ValueError("Release source mismatch")
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "merge-base",
                "--is-ancestor",
                resolved,
                "refs/remotes/origin/main",
            ],
            capture_output=True,
            timeout=15,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        raise ValueError("Release source is not verified on main") from None
    return resolved
