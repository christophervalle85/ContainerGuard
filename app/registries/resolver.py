"""Read registry image indexes before selecting an image manifest."""

import json
import re
from typing import Any

from app.registries.docker_hub import fetch_docker_index, parse_docker_tag

INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}


def load_image_index(raw_document: str) -> dict[str, Any]:
    try:
        document = json.loads(raw_document)
    except json.JSONDecodeError:
        raise ValueError("Invalid image index JSON") from None
    if not isinstance(document, dict):
        raise ValueError("Image index must be an object")
    if type(document.get("schemaVersion")) is not int or document["schemaVersion"] != 2:
        raise ValueError("Unsupported image index schema")
    if document.get("mediaType") not in INDEX_MEDIA_TYPES:
        raise ValueError("Unsupported image index media type")
    manifests = document.get("manifests")
    if not isinstance(manifests, list):
        raise ValueError("Image index manifests must be a list")
    for manifest in manifests:
        if not isinstance(manifest, dict):
            raise ValueError("Each manifest descriptor must be an object")
        platform = manifest.get("platform")
        if platform is not None and not isinstance(platform, dict):
            raise ValueError("Manifest platform must be an object")
    return document


def _validated_manifest_digest(manifest: dict[str, Any]) -> str:
    if manifest.get("mediaType") not in MANIFEST_MEDIA_TYPES:
        raise ValueError("Expected an image manifest for the selected platform")
    digest = manifest.get("digest")
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
    ):
        raise ValueError("Invalid selected image digest")
    return digest


def select_amd64_digest(document: dict[str, Any]) -> str:
    candidates = []

    for manifest in document["manifests"]:
        platform = manifest.get("platform") or {}

        if (
            platform.get("os") == "linux"
            and platform.get("architecture") == "amd64"
            and platform.get("variant") in (None, "")
        ):
            candidates.append(manifest)

    if len(candidates) != 1:
        raise ValueError("Expected exactly one linux/amd64 image")

    return _validated_manifest_digest(candidates[0])


def resolve_docker_tag(image_reference: str) -> str:
    repository, tag = parse_docker_tag(image_reference)
    raw_index = fetch_docker_index(repository, tag)
    document = load_image_index(raw_index)
    digest = select_amd64_digest(document)

    return f"docker.io/{repository}@{digest}"
