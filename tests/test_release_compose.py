import copy
import json

import pytest

from scripts.releases.compose import release_notes, render_compose
from scripts.releases.identity import SOURCE
from tests.test_release_artifacts import COMMIT


def release_manifest():
    return {
        "schema_version": 1,
        "version": "v1.0.0",
        "commit": COMMIT,
        "platform": "linux/amd64",
        "checks_url": "https://github.com/christophervalle85/ContainerGuard/actions/runs/123",
        "remaining_findings": {
            service: {"LOW": 1} for service in ("api", "worker", "frontend")
        },
        "images": {
            service: {
                "digest": "sha256:" + str(n) * 64,
                "reference": "ghcr.io/christophervalle85/"
                f"containerguard-{service}@sha256:" + str(n) * 64,
                "image_id": "sha256:" + "a" * 64,
                "diff_ids": ["sha256:" + "b" * 64],
                "platform": "linux/amd64",
                "tags": ["v1.0.0", "sha-" + COMMIT],
                "labels": {
                    "org.opencontainers.image.source": SOURCE,
                    "org.opencontainers.image.revision": COMMIT,
                    "org.opencontainers.image.version": "v1.0.0",
                    "org.opencontainers.image.description": "ContainerGuard " + service,
                },
            }
            for n, service in enumerate(("api", "worker", "frontend"), 1)
        },
    }


def test_compose_uses_only_digests_and_internal_datastores():
    manifest = release_manifest()
    document = json.loads(render_compose(manifest))
    services = document["services"]
    for service in ("api", "worker", "frontend"):
        assert services[service]["image"] == manifest["images"][service]["reference"]
    assert services["migrate"]["image"] == services["api"]["image"]
    assert not services["db"].get("ports") and not services["redis"].get("ports")
    assert services["worker"]["stop_grace_period"] == "650s"
    assert services["api"]["ports"][0]["host_ip"] == "127.0.0.1"
    assert "build" not in json.dumps(document) and "docker.sock" not in json.dumps(
        document
    )
    assert "${POSTGRES_PASSWORD" in services["db"]["environment"]["POSTGRES_PASSWORD"]
    assert "environment" not in services["frontend"]


@pytest.mark.parametrize(
    "mutation",
    ["missing", "extra", "digest", "reference", "commit", "platform", "url", "count"],
)
def test_untrusted_manifest_cannot_change_installation(mutation):
    manifest = release_manifest()
    if mutation == "missing":
        del manifest["images"]["worker"]
    elif mutation == "extra":
        manifest["images"]["attacker"] = copy.deepcopy(manifest["images"]["api"])
    elif mutation == "digest":
        manifest["images"]["api"]["digest"] = "sha256:bad"
    elif mutation == "reference":
        manifest["images"]["api"]["reference"] = "evil.invalid/image:latest"
    elif mutation == "commit":
        manifest["images"]["api"]["labels"]["org.opencontainers.image.revision"] = (
            "b" * 40
        )
    elif mutation == "platform":
        manifest["platform"] = "linux/arm64"
    elif mutation == "url":
        manifest["checks_url"] = "https://evil.invalid"
    elif mutation == "count":
        manifest["remaining_findings"]["api"]["HIGH"] = -1
    with pytest.raises(ValueError):
        render_compose(manifest)


def test_notes_link_to_tagged_docs_and_exact_identities():
    manifest = release_manifest()
    notes = release_notes(manifest)
    assert "/blob/v1.0.0/docs/releases.md" in notes
    assert COMMIT in notes
    assert all(image["reference"] in notes for image in manifest["images"].values())
