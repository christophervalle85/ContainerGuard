"""Bounded, non-extracting validation of Docker/OCI image archives."""

import gzip
import hashlib
import io
import json
import os
import stat
import tarfile
from pathlib import Path, PurePosixPath

from scripts.releases.identity import (
    DIGEST,
    SERVICES,
    SOURCE,
    release_image,
    validate_commit,
    validate_version,
)

MAX_ARCHIVE = 2 * 1024**3
MAX_TOTAL = 4 * 1024**3
MAX_JSON = 4 * 1024**2
MAX_FILE = 1024**3
MAX_EXPANDED = 8 * 1024**3
MAX_MEMBERS = 200_000
MAX_EXTENSION = 1024 * 1024
MAX_EXTENSION_CHAIN = 16
MAX_EXTENSION_TOTAL = 16 * 1024 * 1024
INFO_FIELDS = {
    "size_bytes",
    "sha256",
    "image_id",
    "manifest_digest",
    "diff_ids",
    "platform",
    "labels",
    "repo_tags",
}


def fail():
    raise ValueError("Invalid or unsupported release archive")


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail()
        result[key] = value
    return result


def read_json(raw: bytes):
    if len(raw) > MAX_JSON:
        fail()
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError):
        fail()


def read_json_file(path: Path):
    """Read a regular JSON artifact without allocating its untrusted full size."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        fail()
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON:
            fail()
        return read_json(stream.read(MAX_JSON + 1))


class TarGuard(io.RawIOBase):
    """Check raw headers before tarfile can allocate extension payloads."""

    def __init__(self, stream, *, max_file=MAX_FILE):
        self.stream = stream
        self.max_file = max_file
        self.remaining = 0
        self.headers = 0
        self.chain = 0
        self.chain_bytes = 0
        self.extension_bytes = 0
        self.ended = False

    def readable(self):
        return True

    def read(self, size=-1):
        if size < 0:
            size = 1024 * 1024
        if size == 0:
            return b""
        if self.remaining:
            raw = self.stream.read(min(size, self.remaining, 1024 * 1024))
            if not raw:
                fail()
            self.remaining -= len(raw)
            return raw
        if self.ended:
            raw = self.stream.read(min(size, 1024 * 1024))
            if any(raw):
                fail()
            return raw
        # tarfile's stream reader requests blocks of at least 512 bytes.
        # Keep the header separate so no extension data is read before validation.
        raw = self.stream.read(512)
        if not raw:
            return b""
        if len(raw) != 512:
            fail()
        if not any(raw):
            self.ended = True
            return raw
        member = tarfile.TarInfo.frombuf(raw, "utf-8", "surrogateescape")
        self.headers += 1
        if self.headers > MAX_MEMBERS or member.size < 0:
            fail()
        extension = member.type in (
            tarfile.XHDTYPE,
            tarfile.XGLTYPE,
            tarfile.GNUTYPE_LONGNAME,
            tarfile.GNUTYPE_LONGLINK,
        )
        if extension:
            self.chain += 1
            self.chain_bytes += member.size
            self.extension_bytes += member.size
            if (
                self.chain > MAX_EXTENSION_CHAIN
                or self.chain_bytes > MAX_EXTENSION
                or self.extension_bytes > MAX_EXTENSION_TOTAL
            ):
                fail()
        else:
            self.chain = self.chain_bytes = 0
            if member.size > self.max_file:
                fail()
        self.remaining = (member.size + 511) // 512 * 512
        return raw


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hash_stream(stream)


def hash_stream(stream) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def safe_name(name: str) -> str:
    if not isinstance(name, str) or "\x00" in name or "\\" in name:
        fail()
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        fail()
    return str(path)


class LayerReader(io.RawIOBase):
    def __init__(self, stream, budget):
        self.stream = stream
        self.budget = budget
        self.digest = hashlib.sha256()

    def readable(self):
        return True

    def read(self, size=-1):
        if size < 0:
            size = 1024 * 1024
        raw = self.stream.read(min(size, 1024 * 1024))
        self.budget[0] += len(raw)
        if self.budget[0] > MAX_EXPANDED:
            fail()
        self.digest.update(raw)
        return raw


def inspect_image_archive(path: Path, *, visitor=None) -> dict:
    """Validate content identity; visitor receives bounded file streams and metadata.

    Neither links nor device files are opened on the host. Layer visitors see files
    even when a later layer deletes them. All callers must exhaust each stream.
    """
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARCHIVE:
            fail()
        size = path.stat().st_size
        archive_hash = sha256_file(path)
        with path.open("rb") as raw_archive:
            hash_stream(TarGuard(raw_archive, max_file=MAX_ARCHIVE))
        with tarfile.open(path, mode="r:") as archive:
            members = {}
            for member in archive:
                name = safe_name(member.name)
                if name in members or len(members) >= MAX_MEMBERS:
                    fail()
                if member.sparse or not (member.isfile() or member.isdir()):
                    fail()
                if member.size < 0 or member.size > MAX_ARCHIVE:
                    fail()
                members[name] = member

            def stream(name):
                member = members.get(safe_name(name))
                if member is None or not member.isfile():
                    fail()
                return archive.extractfile(member)

            def document(name):
                member = members.get(name)
                if member is None or member.size > MAX_JSON:
                    fail()
                with stream(name) as handle:
                    return read_json(handle.read(MAX_JSON + 1))

            # Docker's containerd store exports a Docker manifest alongside OCI
            # blobs. Prefer its explicit single-platform selection, never guess.
            if "manifest.json" in members:
                manifest = document("manifest.json")
                if not isinstance(manifest, list) or len(manifest) != 1:
                    fail()
                entry = manifest[0]
                if set(entry) - {"Config", "RepoTags", "Layers", "LayerSources"}:
                    fail()
                config_name = entry["Config"]
                layer_names = entry["Layers"]
                tags = entry.get("RepoTags") or []
            elif "oci-layout" in members:
                if document("oci-layout") != {"imageLayoutVersion": "1.0.0"}:
                    fail()
                index = document("index.json")

                def blob(descriptor):
                    digest = descriptor["digest"]
                    if not DIGEST.fullmatch(digest):
                        fail()
                    name = "blobs/sha256/" + digest[7:]
                    if (
                        members.get(name) is None
                        or members[name].size != descriptor["size"]
                    ):
                        fail()
                    return name

                if index["schemaVersion"] != 2 or len(index["manifests"]) != 1:
                    fail()
                entry = document(blob(index["manifests"][0]))
                if entry["schemaVersion"] != 2:
                    fail()
                config_name = blob(entry["config"])
                layer_names = [blob(layer) for layer in entry["layers"]]
                tags = []
            else:
                fail()
            if not isinstance(layer_names, list) or len(set(layer_names)) != len(
                layer_names
            ):
                fail()
            # Verify every content-addressed blob, including descriptor metadata.
            for name, member in members.items():
                if name.startswith("blobs/sha256/") and member.isfile():
                    if len(name.split("/")[-1]) != 64:
                        fail()
                    with stream(name) as handle:
                        if hash_stream(handle) != name.split("/")[-1]:
                            fail()
            with stream(config_name) as handle:
                raw_config = handle.read(MAX_JSON + 1)
            config_hash = hashlib.sha256(raw_config).hexdigest()
            if config_name not in (
                config_hash + ".json",
                "blobs/sha256/" + config_hash,
            ):
                fail()
            # containerd's local image ID is the manifest digest, while the
            # classic image store uses the configuration digest. Bind both to
            # the same selected configuration and stored layers before use.
            manifest_digest = None
            if "index.json" in members:
                index = document("index.json")
                if index["schemaVersion"] != 2 or len(index["manifests"]) != 1:
                    fail()
                descriptor = index["manifests"][0]
                digest = descriptor["digest"]
                if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
                    fail()
                name = "blobs/sha256/" + digest[7:]
                if (
                    members.get(name) is None
                    or members[name].size != descriptor["size"]
                ):
                    fail()
                selected = document(name)
                if (
                    selected["schemaVersion"] != 2
                    or selected.get("mediaType")
                    not in (
                        None,
                        "application/vnd.oci.image.manifest.v1+json",
                        "application/vnd.docker.distribution.manifest.v2+json",
                    )
                    or selected["config"]["digest"] != "sha256:" + config_hash
                    or selected["config"]["size"] != len(raw_config)
                    or [
                        "blobs/sha256/" + layer["digest"][7:]
                        for layer in selected["layers"]
                    ]
                    != layer_names
                ):
                    fail()
                for layer_descriptor, layer_name in zip(
                    selected["layers"], layer_names, strict=True
                ):
                    if (
                        not DIGEST.fullmatch(layer_descriptor["digest"])
                        or members[layer_name].size != layer_descriptor["size"]
                    ):
                        fail()
                manifest_digest = digest
            config = read_json(raw_config)
            if config["os"] != "linux" or config["architecture"] != "amd64":
                fail()
            rootfs = config["rootfs"]
            diff_ids = rootfs["diff_ids"]
            if rootfs["type"] != "layers" or len(diff_ids) != len(layer_names):
                fail()
            if not all(isinstance(d, str) and DIGEST.fullmatch(d) for d in diff_ids):
                fail()
            labels = config.get("config", {}).get("Labels") or {}
            if not isinstance(labels, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in labels.items()
            ):
                fail()
            if visitor:
                visitor("metadata", io.BytesIO(raw_config), len(raw_config))
            budget, count = [0], 0
            for layer_name, diff_id in zip(layer_names, diff_ids, strict=True):
                with stream(layer_name) as stored:
                    magic = stored.read(2)
                    stored.seek(0)
                    uncompressed = (
                        gzip.GzipFile(fileobj=stored)
                        if magic == b"\x1f\x8b"
                        else stored
                    )
                    reader = LayerReader(uncompressed, budget)
                    with tarfile.open(
                        fileobj=TarGuard(reader, max_file=MAX_FILE), mode="r|"
                    ) as layer:
                        names = set()
                        for member in layer:
                            count += 1
                            name = safe_name(member.name)
                            if count > MAX_MEMBERS or name in names or member.sparse:
                                fail()
                            names.add(name)
                            if member.size < 0 or member.size > MAX_FILE:
                                fail()
                            if member.isfile():
                                with layer.extractfile(member) as handle:
                                    if visitor:
                                        visitor("file", handle, member.size)
                                    else:
                                        hash_stream(handle)
                            elif not (
                                member.isdir() or member.issym() or member.islnk()
                            ):
                                fail()
                    hash_stream(reader)  # Consume tar end padding, included in diff ID.
                    if "sha256:" + reader.digest.hexdigest() != diff_id:
                        fail()
            result = {
                "size_bytes": size,
                "sha256": archive_hash,
                "image_id": "sha256:" + config_hash,
                "manifest_digest": manifest_digest,
                "diff_ids": diff_ids,
                "platform": "linux/amd64",
                "labels": labels,
                "repo_tags": tags,
            }
            if path.stat().st_size != size or sha256_file(path) != archive_hash:
                fail()
            return result
    except (
        OSError,
        EOFError,
        tarfile.TarError,
        KeyError,
        TypeError,
        AttributeError,
        OverflowError,
    ):
        fail()


def validate_handoff(
    document: dict, directory: Path, *, version: str, commit: str
) -> dict:
    validate_version(version)
    validate_commit(commit)
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "version",
        "commit",
        "images",
        "checks_sha256",
    }:
        fail()
    if (
        document["schema_version"] != 1
        or document["version"] != version
        or document["commit"] != commit
    ):
        fail()
    images = document["images"]
    if not isinstance(images, dict) or set(images) != set(SERVICES):
        fail()
    total = 0
    for service in SERVICES:
        record = images[service]
        if not isinstance(record, dict) or set(record) != INFO_FIELDS | {"archive"}:
            fail()
        if record["archive"] != f"{service}.tar":
            fail()
        actual = inspect_image_archive(directory / record["archive"])
        if actual != {key: record[key] for key in INFO_FIELDS}:
            fail()
        labels = actual["labels"]
        required = {
            "org.opencontainers.image.source": SOURCE,
            "org.opencontainers.image.revision": commit,
            "org.opencontainers.image.version": version,
            "org.opencontainers.image.description": "ContainerGuard " + service,
        }
        if any(labels.get(key) != value for key, value in required.items()):
            fail()
        if actual["repo_tags"] != [release_image(service) + ":" + version]:
            fail()
        total += actual["size_bytes"]
    if total > MAX_TOTAL:
        fail()
    from scripts.releases.checks import verify_evidence

    checks = directory / "checks.json"
    if (
        checks.is_symlink()
        or not checks.is_file()
        or sha256_file(checks) != document["checks_sha256"]
    ):
        fail()
    verify_evidence(directory, images)
    return document


def write_handoff(
    images: dict[str, dict], output: Path, *, version: str, commit: str
) -> Path:
    from scripts.releases.checks import seal_evidence

    document = {
        "checks_sha256": seal_evidence(output, images),
        "schema_version": 1,
        "version": version,
        "commit": commit,
        "images": {
            service: {**info, "archive": f"{service}.tar"}
            for service, info in images.items()
        },
    }
    validate_handoff(document, output, version=version, commit=commit)
    path = output / "handoff.json"
    path.write_text(json.dumps(document, indent=2) + "\n")
    return path
