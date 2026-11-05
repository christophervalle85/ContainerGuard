"""Canonical OCI subject selection and digest-preserving transport.

Only copy_preserving_digest writes to a registry. Work on a private snapshot so
validation, local conversion and publication always consume identical bytes.
"""

import contextlib
import gzip
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import zlib
from pathlib import Path

from scripts.releases import artifacts as a
from scripts.releases.identity import DIGEST
from scripts.releases.supply_chain import tools

INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYERS = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
}


def _run(args):
    try:
        return subprocess.run(
            args, check=True, capture_output=True, text=True, timeout=900
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("OCI transport command failed") from None


def _command(args):
    # Also sanitize errors from injected runners, preserving the safe boundary.
    try:
        return _run(args)
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("OCI transport command failed") from None


def _skopeo():
    tools.verify_tools()
    return str(
        Path(os.environ.get("CG_RELEASE_TOOLS", tools.ROOT / ".release-tools"))
        / "skopeo"
    )


@contextlib.contextmanager
def _snapshot(path):
    with tempfile.TemporaryDirectory(prefix="cg-oci-") as directory:
        root = Path(directory)
        target = root / "canonical.tar"
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as source, target.open("wb") as output:
                import stat

                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > a.MAX_ARCHIVE:
                    a.fail()
                count = 0
                while chunk := source.read(1024 * 1024):
                    count += len(chunk)
                    if count > a.MAX_ARCHIVE:
                        a.fail()
                    output.write(chunk)
                if count != info.st_size:
                    a.fail()
            yield target, root
        except OSError:
            a.fail()


def _add(output, name, raw):
    member = tarfile.TarInfo(name)
    member.size = len(raw)
    output.addfile(member, io.BytesIO(raw))


@contextlib.contextmanager
def _validated(path, root):
    """Validate OCI graph, then delegate layer traversal to the legacy guard."""
    try:
        with path.open("rb") as raw:
            a.hash_stream(a.TarGuard(raw, max_file=a.MAX_FILE))
        with tarfile.open(path, "r:") as archive:
            members = {}
            for member in archive:
                name = a.safe_name(member.name)
                if name in members or len(members) >= a.MAX_MEMBERS:
                    a.fail()
                if member.sparse or not (member.isfile() or member.isdir()):
                    a.fail()
                if member.size < 0 or member.size > a.MAX_FILE:
                    a.fail()
                members[name] = member

            def stream(name):
                member = members.get(name)
                if member is None or not member.isfile():
                    a.fail()
                return archive.extractfile(member)

            def document(name):
                if name not in members or members[name].size > a.MAX_JSON:
                    a.fail()
                with stream(name) as handle:
                    return a.read_json(handle.read(a.MAX_JSON + 1))

            used = set()

            def blob(descriptor, media):
                if not isinstance(descriptor, dict):
                    a.fail()
                digest = descriptor.get("digest")
                size = descriptor.get("size")
                if (
                    not isinstance(digest, str)
                    or not DIGEST.fullmatch(digest)
                    or type(size) is not int
                    or size < 0
                    or descriptor.get("mediaType") not in media
                    or descriptor.get("artifactType")
                    or descriptor.get("urls")
                    or descriptor.get("annotations", {}).get(
                        "vnd.docker.reference.type"
                    )
                ):
                    a.fail()
                platform = descriptor.get("platform")
                if platform is not None and platform != {
                    "os": "linux",
                    "architecture": "amd64",
                }:
                    a.fail()
                name = "blobs/sha256/" + digest[7:]
                if name in used or name not in members or members[name].size != size:
                    a.fail()
                used.add(name)
                with stream(name) as handle:
                    if a.hash_stream(handle) != digest[7:]:
                        a.fail()
                return name

            if document("oci-layout") != {"imageLayoutVersion": "1.0.0"}:
                a.fail()
            index = document("index.json")
            with stream("index.json") as handle:
                index_digest = "sha256:" + a.hash_stream(handle)
            current = index
            depth = 0
            while True:
                if (
                    not isinstance(current, dict)
                    or current.get("schemaVersion") != 2
                    or current.get("mediaType", INDEX) != INDEX
                    or current.get("artifactType")
                    or current.get("subject")
                    or not isinstance(current.get("manifests"), list)
                    or len(current["manifests"]) != 1
                    or depth > 16
                ):
                    a.fail()
                selected = current["manifests"][0]
                name = blob(selected, {INDEX, MANIFEST})
                current = document(name)
                if selected["mediaType"] == MANIFEST:
                    break
                depth += 1
            manifest = current
            if (
                manifest.get("schemaVersion") != 2
                or manifest.get("mediaType") != MANIFEST
                or manifest.get("artifactType")
                or manifest.get("subject")
                or not isinstance(manifest.get("layers"), list)
            ):
                a.fail()
            config_name = blob(manifest["config"], {CONFIG})
            layer_names = [blob(layer, LAYERS) for layer in manifest["layers"]]
            for descriptor, name in zip(manifest["layers"], layer_names, strict=True):
                with stream(name) as handle:
                    compressed = handle.read(2) == b"\x1f\x8b"
                if compressed != descriptor["mediaType"].endswith("+gzip"):
                    a.fail()
            # A canonical archive contains exactly the validated graph; no hidden
            # unattached attestations, alternate images or Docker manifest bypass.
            expected = used | {"oci-layout", "index.json"}
            if any(m.isfile() and name not in expected for name, m in members.items()):
                a.fail()
            normalized = root / "selected.tar"
            with tarfile.open(normalized, "w") as output:
                _add(output, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
                _add(
                    output,
                    "index.json",
                    json.dumps({"schemaVersion": 2, "manifests": [selected]}).encode(),
                )
                for name in used:
                    member = members[name]
                    with stream(name) as handle:
                        output.addfile(member, handle)
            info = a.inspect_image_archive(normalized)
            info.update(
                index_digest=index_digest,
                manifest_digest=selected["digest"],
                descriptor=selected,
                sha256=a.sha256_file(path),
                size_bytes=path.stat().st_size,
            )
            yield info, archive, members, config_name, layer_names
    except (
        OSError,
        EOFError,
        tarfile.TarError,
        KeyError,
        TypeError,
        AttributeError,
        OverflowError,
        zlib.error,
    ):
        a.fail()


def inspect_canonical(path: Path) -> dict:
    with _snapshot(path) as (snapshot, root):
        with _validated(snapshot, root) as (info, *_):
            return info


def _docker_export(
    output_path, archive, members, config_name, layer_names, info, reference
):
    """Export only for the check store; canonical compressed blobs stay intact."""
    with tarfile.open(output_path, "w") as output:
        config_target = info["image_id"][7:] + ".json"
        with archive.extractfile(members[config_name]) as source:
            _add(output, config_target, source.read(a.MAX_JSON + 1))
        names = []
        for position, name in enumerate(layer_names):
            target = f"layer-{position}/layer.tar"
            names.append(target)
            with archive.extractfile(members[name]) as stored:
                magic = stored.read(2)
                stored.seek(0)
                source = (
                    gzip.GzipFile(fileobj=stored) if magic == b"\x1f\x8b" else stored
                )
                # Bounded disk spool avoids allocating decompressed layers.
                with tempfile.TemporaryFile() as spool:
                    reader = a.LayerReader(source, [0])
                    shutil.copyfileobj(reader, spool, 1024 * 1024)
                    member = tarfile.TarInfo(target)
                    member.size = spool.tell()
                    spool.seek(0)
                    output.addfile(member, spool)
        _add(
            output,
            "manifest.json",
            json.dumps(
                [{"Config": config_target, "RepoTags": [reference], "Layers": names}]
            ).encode(),
        )


def import_for_checks(path: Path, reference: str) -> dict:
    if not isinstance(reference, str) or not reference or reference.startswith("-"):
        raise ValueError("Invalid local image reference")
    with _snapshot(path) as (snapshot, root):
        with _validated(snapshot, root) as (info, archive, members, config, layers):
            exported = root / "docker.tar"
            _docker_export(exported, archive, members, config, layers, info, reference)
        _command(["docker", "image", "load", "--input", str(exported)])
        try:
            inspected = a.read_json(
                _command(["docker", "image", "inspect", reference]).encode()
            )
            if len(inspected) != 1:
                a.fail()
            runtime = inspected[0]
            if (
                runtime["Os"] != "linux"
                or runtime["Architecture"] != "amd64"
                or runtime["RootFS"]["Layers"] != info["diff_ids"]
            ):
                a.fail()
        except (KeyError, TypeError):
            a.fail()
        saved = root / "loaded.tar"
        _command(["docker", "image", "save", "--output", str(saved), reference])
        actual = a.inspect_image_archive(saved)
        if any(
            actual[key] != info[key] for key in ("image_id", "diff_ids", "platform")
        ):
            a.fail()
        return info


def copy_preserving_digest(
    path: Path,
    destination: str,
    *,
    authfile: Path,
    expected_identity: dict | None = None,
) -> str:
    if (
        not isinstance(destination, str)
        or not destination
        or destination.startswith("-")
        or "://" in destination
    ):
        raise ValueError("Invalid registry destination")
    with _snapshot(path) as (snapshot, root):
        with _validated(snapshot, root) as (info, *_):
            expected = info["manifest_digest"]
        if expected_identity is not None:
            fields = {
                "manifest_digest",
                "image_id",
                "diff_ids",
                "platform",
                "sha256",
                "size_bytes",
            }
            if (
                not isinstance(expected_identity, dict)
                or set(expected_identity) != fields
                or any(info[key] != expected_identity[key] for key in fields)
            ):
                raise ValueError("Sealed archive differs from transport snapshot")
        result = root / "digest"
        _command(
            [
                _skopeo(),
                "--override-os",
                "linux",
                "--override-arch",
                "amd64",
                "copy",
                "--preserve-digests",
                "--authfile",
                str(authfile),
                "--digestfile",
                str(result),
                "oci-archive:" + str(snapshot),
                "docker://" + destination,
            ]
        )
        try:
            returned = result.read_text() if result.stat().st_size <= 80 else ""
        except OSError:
            raise ValueError("Missing registry image digest") from None
        if returned.strip() != expected:
            raise ValueError("Registry image digest mismatch")
        return expected
