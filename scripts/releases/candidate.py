"""Build, gate, inspect and exercise exact images without registry writes."""

import json
import os
import subprocess
import sys
from pathlib import Path

from scripts.releases.artifacts import inspect_image_archive, write_handoff
from scripts.releases.commands import command
from scripts.releases.disclosure import check_disclosure
from scripts.releases.identity import (
    SERVICES,
    SOURCE,
    release_image,
    validate_commit,
    validate_source,
    validate_version,
)
from scripts.releases.smoke import exercise_stack

ROOT = Path(__file__).resolve().parents[2]


class CandidateBlocked(ValueError):
    """A completed vulnerability gate blocked this candidate."""


def verify_candidate_source(version, commit):
    validate_version(version)
    validate_commit(commit)
    if command(["git", "rev-parse", "HEAD"], capture=True).strip() != commit:
        raise ValueError("Candidate checkout source mismatch")
    # Publication candidates must originate in the same-repository tag workflow.
    if os.environ.get("GITHUB_ACTIONS") == "true":
        if (
            os.environ.get("GITHUB_REPOSITORY") != "christophervalle85/ContainerGuard"
            or os.environ.get("GITHUB_EVENT_NAME") != "push"
            or os.environ.get("GITHUB_REF") != "refs/tags/" + version
            or os.environ.get("GITHUB_SHA") != commit
        ):
            raise ValueError("Untrusted candidate event")
        validate_source(version, commit, repository=ROOT)
        if command(
            ["git", "status", "--porcelain", "--untracked-files=normal"], capture=True
        ).strip():
            raise ValueError("Release checkout is not clean")


def build_candidate(version: str, commit: str, output: Path) -> Path:
    verify_candidate_source(version, commit)
    # Fresh output only: never leave a previous handoff eligible after a failure.
    if output.exists() and any(output.iterdir()):
        raise ValueError("Candidate output must be empty")
    output.mkdir(parents=True, exist_ok=True)
    images, identities = {}, {}
    try:
        for service in SERVICES:
            reference = release_image(service) + ":" + version
            context = "frontend" if service == "frontend" else "."
            labels = {
                "source": SOURCE,
                "revision": commit,
                "version": version,
                "description": "ContainerGuard " + service,
            }
            args = [
                "docker",
                "build",
                "--platform",
                "linux/amd64",
                "--provenance=false",
                "-f",
                "Dockerfile." + service,
                "-t",
                reference,
            ]
            for name, value in labels.items():
                args += ["--label", "org.opencontainers.image." + name + "=" + value]
            command(args + [context], timeout=1200)
            identities[service] = command(
                ["docker", "image", "inspect", "--format", "{{.Id}}", reference],
                capture=True,
            ).strip()
            try:
                command(
                    [
                        sys.executable,
                        "-m",
                        "scripts.scan_security",
                        "--kind",
                        "image",
                        "--input",
                        identities[service],
                        "--target",
                        identities[service],
                        "--output-dir",
                        str(output / (service + "-security")),
                    ],
                    timeout=650,
                )
            except subprocess.CalledProcessError as error:
                if error.returncode == 1:
                    raise CandidateBlocked(
                        "Image vulnerability gate blocked publication"
                    ) from None
                raise
            archive = output / (service + ".tar")
            command(
                ["docker", "image", "save", "--output", str(archive), reference],
                timeout=180,
            )
            check_disclosure(archive, output / (service + "-disclosure.json"))
            images[service] = inspect_image_archive(archive)
            if identities[service] not in (
                images[service]["image_id"],
                images[service]["manifest_digest"],
            ):
                raise ValueError("Candidate archive identity changed")
        smoke = exercise_stack(identities, workspace=output / "verification")
        (output / "smoke.json").write_text(json.dumps(smoke, indent=2) + "\n")
        for service in SERVICES:
            reference = release_image(service) + ":" + version
            if (
                command(
                    ["docker", "image", "inspect", "--format", "{{.Id}}", reference],
                    capture=True,
                ).strip()
                != identities[service]
            ):
                raise ValueError("Checked candidate identity changed")
        return write_handoff(images, output, version=version, commit=commit)
    except BaseException:
        (output / "handoff.json").unlink(missing_ok=True)
        # Rejected archives cannot accidentally be picked up by an upload step.
        for service in SERVICES:
            (output / (service + ".tar")).unlink(missing_ok=True)
        raise
