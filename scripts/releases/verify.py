"""Verify public digest pulls with empty Docker auth and an owned fresh stack."""

import json
import os
import tempfile
from pathlib import Path

from scripts.releases.commands import command
from scripts.releases.compose import validate_release
from scripts.releases.identity import SERVICES
from scripts.releases.publish import verify_identity
from scripts.releases.registry import Registry
from scripts.releases.smoke import exercise_stack


def verify_published(manifest: dict, workspace: Path) -> dict:
    validate_release(manifest)
    images = {service: manifest["images"][service]["reference"] for service in SERVICES}
    with tempfile.TemporaryDirectory(
        prefix="containerguard-anonymous-auth-"
    ) as directory:
        (Path(directory) / "config.json").write_text('{"auths":{}}\n')
        environment = {
            key: value
            for key, value in os.environ.items()
            if key not in ("GITHUB_TOKEN", "GH_TOKEN", "DOCKER_AUTH_CONFIG")
        }
        environment["DOCKER_CONFIG"] = directory
        registry = Registry(anonymous=True)
        for service in SERVICES:
            expected = manifest["images"][service]
            command(
                ["docker", "pull", "--platform", "linux/amd64", images[service]],
                timeout=300,
                env=environment,
            )
            verify_identity(registry.manifest(service, expected["digest"]), expected)
            raw = command(
                [
                    "docker",
                    "image",
                    "inspect",
                    "--format",
                    "{{json .}}",
                    images[service],
                ],
                capture=True,
                env=environment,
            )
            info = json.loads(raw)
            actual = {
                # Registry verification above binds the manifest to its config;
                # Docker's local ID may name either one, depending on its store.
                "image_id": expected["image_id"]
                if info["Id"] == expected["digest"]
                else info["Id"],
                "diff_ids": info["RootFS"]["Layers"],
                "platform": info["Os"] + "/" + info["Architecture"],
                "labels": info["Config"].get("Labels") or {},
            }
            verify_identity(actual, expected)
    result = exercise_stack(images, workspace=workspace)
    result["anonymous_pulls"] = True
    result["version"] = manifest["version"]
    return result
