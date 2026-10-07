import json
from importlib import import_module

import pytest

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
DOCKER_INDEX = "application/vnd.docker.distribution.manifest.list.v2+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
AMD64_DIGEST = "sha256:" + "a" * 64
ARM64_DIGEST = "sha256:" + "b" * 64


def descriptor(digest=AMD64_DIGEST, architecture="amd64", **platform):
    return {
        "mediaType": OCI_MANIFEST,
        "digest": digest,
        "size": 1234,
        "platform": {"os": "linux", "architecture": architecture, **platform},
    }


def index(*entries, media_type=OCI_INDEX):
    return {"schemaVersion": 2, "mediaType": media_type, "manifests": list(entries)}


@pytest.mark.parametrize("media_type", [OCI_INDEX, DOCKER_INDEX])
def test_loads_supported_image_indexes(media_type):
    resolver = import_module("app.registries.resolver")
    document = index(descriptor(), media_type=media_type)
    assert resolver.load_image_index(json.dumps(document)) == document


@pytest.mark.parametrize(
    "raw",
    [
        "not-json",
        "[]",
        json.dumps({"schemaVersion": 1, "mediaType": OCI_INDEX, "manifests": []}),
        json.dumps(index(media_type=OCI_MANIFEST)),
        json.dumps({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": {}}),
        json.dumps(index("invalid-entry")),
    ],
)
def test_rejects_invalid_index_documents(raw):
    resolver = import_module("app.registries.resolver")
    with pytest.raises(ValueError):
        resolver.load_image_index(raw)


@pytest.mark.parametrize("manifest_type", [OCI_MANIFEST, DOCKER_MANIFEST])
def test_selects_amd64_even_when_arm64_is_listed_first(manifest_type):
    resolver = import_module("app.registries.resolver")
    amd64 = descriptor()
    amd64["mediaType"] = manifest_type
    document = index(descriptor(ARM64_DIGEST, "arm64"), amd64)
    loaded = resolver.load_image_index(json.dumps(document))
    assert resolver.select_amd64_digest(loaded) == AMD64_DIGEST


def test_ignores_attestation_entries_with_unknown_platform():
    resolver = import_module("app.registries.resolver")
    document = index(descriptor(ARM64_DIGEST, "unknown", os="unknown"), descriptor())
    assert resolver.select_amd64_digest(document) == AMD64_DIGEST


@pytest.mark.parametrize(
    "entries",
    [
        [],
        [descriptor(ARM64_DIGEST, "arm64")],
        [descriptor(os="windows")],
        [descriptor(variant="v3")],
    ],
)
def test_rejects_indexes_without_a_supported_platform(entries):
    resolver = import_module("app.registries.resolver")
    with pytest.raises(ValueError, match="linux/amd64"):
        resolver.select_amd64_digest(index(*entries))


def test_rejects_ambiguous_platform_selection():
    resolver = import_module("app.registries.resolver")
    with pytest.raises(ValueError, match="linux/amd64"):
        resolver.select_amd64_digest(index(descriptor(), descriptor(ARM64_DIGEST)))


@pytest.mark.parametrize("digest", [None, "sha256:short", "sha256:" + "A" * 64])
def test_rejects_invalid_selected_digest(digest):
    resolver = import_module("app.registries.resolver")
    with pytest.raises(ValueError, match="digest"):
        resolver.select_amd64_digest(index(descriptor(digest)))


def test_rejects_a_nested_index_as_the_selected_image():
    resolver = import_module("app.registries.resolver")
    selected = descriptor()
    selected["mediaType"] = OCI_INDEX
    with pytest.raises(ValueError, match="manifest"):
        resolver.select_amd64_digest(index(selected))


def test_resolves_a_docker_hub_tag_into_a_platform_pinned_reference(monkeypatch):
    resolver = import_module("app.registries.resolver")
    document = index(descriptor(ARM64_DIGEST, "arm64"), descriptor())

    def sample_registry(repository, tag):
        assert (repository, tag) == ("library/alpine", "3.20")
        return json.dumps(document)

    monkeypatch.setattr(resolver, "fetch_docker_index", sample_registry, raising=False)
    assert resolver.resolve_docker_tag("docker.io/library/alpine:3.20") == (
        f"docker.io/library/alpine@{AMD64_DIGEST}"
    )


def test_resolution_rejects_an_image_with_no_supported_platform(monkeypatch):
    resolver = import_module("app.registries.resolver")
    monkeypatch.setattr(
        resolver,
        "fetch_docker_index",
        lambda repository, tag: json.dumps(index()),
        raising=False,
    )
    with pytest.raises(ValueError, match="linux/amd64"):
        resolver.resolve_docker_tag("docker.io/library/alpine:3.20")
