"""Validate published identities and render a standalone, digest-only install."""

import json
import re

from scripts.releases.identity import (
    DIGEST,
    SERVICES,
    SOURCE,
    release_image,
    release_tags,
)
from scripts.releases.smoke import stack_document


def validate_release(manifest: dict) -> dict:
    try:
        if (
            not isinstance(manifest, dict)
            or set(manifest)
            != {
                "schema_version",
                "version",
                "commit",
                "platform",
                "images",
                "remaining_findings",
                "checks_url",
            }
            or type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1
            or manifest["platform"] != "linux/amd64"
        ):
            raise ValueError("Invalid release manifest")
        tags = list(release_tags(manifest["version"], manifest["commit"]))
        if not re.fullmatch(
            r"https://github\.com/christophervalle85/ContainerGuard/actions/runs/[0-9]+",
            manifest["checks_url"],
        ):
            raise ValueError("Invalid release check link")
        if set(manifest["images"]) != set(SERVICES) or set(
            manifest["remaining_findings"]
        ) != set(SERVICES):
            raise ValueError("Invalid release services")
        for service in SERVICES:
            image = manifest["images"][service]
            if (
                set(image)
                != {
                    "digest",
                    "image_id",
                    "diff_ids",
                    "platform",
                    "labels",
                    "reference",
                    "tags",
                }
                or not DIGEST.fullmatch(image["digest"])
                or not DIGEST.fullmatch(image["image_id"])
                or image["reference"] != release_image(service) + "@" + image["digest"]
                or image["platform"] != "linux/amd64"
                or image["tags"] != tags
                or not isinstance(image["diff_ids"], list)
                or not all(DIGEST.fullmatch(value) for value in image["diff_ids"])
            ):
                raise ValueError("Invalid published image identity")
            required = {
                "org.opencontainers.image.source": SOURCE,
                "org.opencontainers.image.revision": manifest["commit"],
                "org.opencontainers.image.version": manifest["version"],
                "org.opencontainers.image.description": "ContainerGuard " + service,
            }
            if any(
                image["labels"].get(key) != value for key, value in required.items()
            ):
                raise ValueError("Published source identity mismatch")
            counts = manifest["remaining_findings"][service]
            if (
                not isinstance(counts, dict)
                or set(counts) - {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
                or any(type(value) is not int or value < 0 for value in counts.values())
            ):
                raise ValueError("Invalid remaining findings")
        return manifest
    except (KeyError, TypeError, AttributeError):
        raise ValueError("Invalid release manifest") from None


def render_compose(manifest: dict) -> str:
    validate_release(manifest)
    images = {service: manifest["images"][service]["reference"] for service in SERVICES}
    document = stack_document(
        images,
        "containerguard-release-verify-000000000000",
        "${POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD}",
    )
    document["name"] = "containerguard-release"
    for service, port, variable in (
        ("api", 8000, "API_PORT"),
        ("frontend", 8080, "FRONTEND_PORT"),
    ):
        document["services"][service]["ports"][0]["published"] = (
            "${" + variable + ":-" + str(port) + "}"
        )
    return json.dumps(document, indent=2) + "\n"


def release_notes(manifest: dict) -> str:
    validate_release(manifest)
    lines = [
        "ContainerGuard " + manifest["version"],
        "",
        "Pull and run the API, worker and dashboard locally without rebuilding source.",
        "",
        "Source: `"
        + manifest["commit"]
        + "`. Platform: `linux/amd64` (amd64 emulation on Apple Silicon).",
        "",
        "[Installation and recovery]("
        + SOURCE
        + "/blob/"
        + manifest["version"]
        + "/docs/releases.md).",
        "[Architecture]("
        + SOURCE
        + "/blob/"
        + manifest["version"]
        + "/docs/architecture/releases.md).",
        "[Required checks](" + manifest["checks_url"] + ").",
        "",
        "Images:",
        "",
    ]
    for service in SERVICES:
        image = manifest["images"][service]
        counts = manifest["remaining_findings"][service]
        lines += [
            "- `" + image["reference"] + "`",
            "  Tags: `"
            + "`, `".join(image["tags"])
            + "`. Remaining findings: "
            + ", ".join(
                severity + "=" + str(counts.get(severity, 0))
                for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
            )
            + ".",
        ]
    lines += [
        "",
        "Download release.json and compose.release.yaml below. "
        "Runtime configuration is generated separately; no credentials are included.",
        "",
        "This draft must stay unpublished until the owner makes the packages public "
        "and verifies anonymous pulls plus the no-build workflow. Checks are dated "
        "observations. PostgreSQL, Redis and builder images are outside the "
        "application runtime vulnerability gate. Signing, provenance, cloud hosting "
        "and independent second-developer setup verification are not claimed.",
        "",
    ]
    return "\n".join(lines)
