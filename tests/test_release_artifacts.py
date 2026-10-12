import hashlib
import io
import json
import tarfile

import pytest

from scripts.releases.artifacts import (
    inspect_image_archive,
    validate_handoff,
    write_handoff,
)
from scripts.releases.identity import SOURCE

COMMIT = "a" * 40


def pack(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, data in entries:
            member = tarfile.TarInfo(name)
            if isinstance(data, tarfile.TarInfo):
                member = data
                archive.addfile(member)
            else:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def image_archive(path, service="api", *, files=None, config_change=None, extra=None):
    layer = pack(files or [("app/code.py", b"print('hello')\n")])
    diff_id = "sha256:" + hashlib.sha256(layer).hexdigest()
    config = {
        "architecture": "amd64",
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        "config": {
            "Labels": {
                "org.opencontainers.image.source": SOURCE,
                "org.opencontainers.image.revision": COMMIT,
                "org.opencontainers.image.version": "v1.0.0",
                "org.opencontainers.image.description": "ContainerGuard " + service,
            }
        },
        "history": [{"created_by": "test fixture"}],
    }
    if config_change:
        config_change(config)
    raw = json.dumps(config).encode()
    config_name = hashlib.sha256(raw).hexdigest() + ".json"
    manifest = [
        {
            "Config": config_name,
            "RepoTags": [f"ghcr.io/christophervalle85/containerguard-{service}:v1.0.0"],
            "Layers": ["layer/layer.tar"],
        }
    ]
    entries = [
        (config_name, raw),
        ("layer/layer.tar", layer),
        ("manifest.json", json.dumps(manifest).encode()),
    ]
    path.write_bytes(pack(entries + (extra or [])))
    return path


def test_valid_docker_archive_tracks_configuration_and_layers(tmp_path):
    archive = image_archive(tmp_path / "api.tar")
    info = inspect_image_archive(archive)
    assert info["platform"] == "linux/amd64"
    assert info["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert info["image_id"].startswith("sha256:")
    assert len(info["diff_ids"]) == 1


@pytest.mark.parametrize("name", ["../escape", "/absolute", "app/../../escape"])
def test_rejects_traversal_without_extracting(tmp_path, name):
    path = image_archive(tmp_path / "api.tar", files=[(name, b"data")])
    with pytest.raises(ValueError):
        inspect_image_archive(path)
    assert not (tmp_path / "escape").exists()


def test_rejects_duplicate_members_and_truncated_archive(tmp_path):
    path = image_archive(tmp_path / "api.tar", extra=[("manifest.json", b"[]")])
    with pytest.raises(ValueError):
        inspect_image_archive(path)
    path.write_bytes(b"truncated tar")
    with pytest.raises(ValueError):
        inspect_image_archive(path)


def test_rejects_tampered_diff_id_and_wrong_platform(tmp_path):
    path = image_archive(
        tmp_path / "api.tar",
        config_change=lambda c: c["rootfs"].update(diff_ids=["sha256:" + "b" * 64]),
    )
    with pytest.raises(ValueError):
        inspect_image_archive(path)
    image_archive(path, config_change=lambda c: c.update(architecture="arm64"))
    with pytest.raises(ValueError):
        inspect_image_archive(path)


def test_symlink_is_not_followed_and_device_is_rejected(tmp_path):
    link = tarfile.TarInfo("app/link")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    path = image_archive(tmp_path / "api.tar", files=[("app/link", link)])
    assert inspect_image_archive(path)["platform"] == "linux/amd64"
    link.type = tarfile.CHRTYPE
    image_archive(path, files=[("app/link", link)])
    with pytest.raises(ValueError):
        inspect_image_archive(path)


def test_handoff_rejects_changed_archive_and_unknown_fields(tmp_path):
    images = {
        service: inspect_image_archive(
            image_archive(tmp_path / f"{service}.tar", service)
        )
        for service in ("api", "worker", "frontend")
    }
    prepare_evidence(tmp_path, images)
    manifest = write_handoff(images, tmp_path, version="v1.0.0", commit=COMMIT)
    document = json.loads(manifest.read_text())
    assert set(
        validate_handoff(document, tmp_path, version="v1.0.0", commit=COMMIT)["images"]
    ) == {"api", "worker", "frontend"}
    document["unknown"] = True
    with pytest.raises(ValueError):
        validate_handoff(document, tmp_path, version="v1.0.0", commit=COMMIT)
    document.pop("unknown")
    image_archive(tmp_path / "api.tar", files=[("changed", b"different")])
    with pytest.raises(ValueError):
        validate_handoff(document, tmp_path, version="v1.0.0", commit=COMMIT)


def test_bounds_are_enforced_before_reading(tmp_path, monkeypatch):
    from scripts.releases import artifacts

    path = image_archive(tmp_path / "api.tar")
    monkeypatch.setattr(artifacts, "MAX_ARCHIVE", 10)
    with pytest.raises(ValueError):
        inspect_image_archive(path)


def test_compressed_oci_archive_and_expansion_limit(tmp_path, monkeypatch):
    import gzip

    from scripts.releases import artifacts

    layer = pack([("payload", b"a" * 100_000)])
    compressed = gzip.compress(layer)
    config = json.dumps(
        {
            "os": "linux",
            "architecture": "amd64",
            "rootfs": {
                "type": "layers",
                "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()],
            },
        }
    ).encode()
    entries = []

    def blob(data, media):
        digest = hashlib.sha256(data).hexdigest()
        entries.append(("blobs/sha256/" + digest, data))
        return {"digest": "sha256:" + digest, "size": len(data), "mediaType": media}

    manifest = {
        "schemaVersion": 2,
        "config": blob(config, "application/vnd.oci.image.config.v1+json"),
        "layers": [blob(compressed, "application/vnd.oci.image.layer.v1.tar+gzip")],
    }
    index = {
        "schemaVersion": 2,
        "manifests": [
            blob(
                json.dumps(manifest).encode(),
                "application/vnd.oci.image.manifest.v1+json",
            )
        ],
    }
    path = tmp_path / "oci.tar"
    path.write_bytes(
        pack(
            entries
            + [
                ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
                ("index.json", json.dumps(index).encode()),
            ]
        )
    )
    assert inspect_image_archive(path)["platform"] == "linux/amd64"
    monkeypatch.setattr(artifacts, "MAX_EXPANDED", 1024)
    with pytest.raises(ValueError):
        inspect_image_archive(path)


def test_duplicate_json_missing_blob_and_corrupt_config_rejected(tmp_path):
    from scripts.releases.artifacts import read_json

    with pytest.raises(ValueError):
        read_json(b'{"schema":1,"schema":2}')
    path = tmp_path / "bad.tar"
    path.write_bytes(
        pack([("manifest.json", b'[{"Config":"missing.json","Layers":[]}]')])
    )
    with pytest.raises(ValueError):
        inspect_image_archive(path)
    image_archive(path)
    with tarfile.open(path) as archive:
        entries = [
            (member.name, archive.extractfile(member).read())
            for member in archive
            if member.isfile()
        ]
    entries[0] = (entries[0][0], b"{}")
    path.write_bytes(pack(entries))
    with pytest.raises(ValueError):
        inspect_image_archive(path)


def test_file_and_member_limits_and_sparse_rejection(tmp_path, monkeypatch):
    from scripts.releases import artifacts

    path = image_archive(tmp_path / "api.tar", files=[("payload", b"12345")])
    monkeypatch.setattr(artifacts, "MAX_FILE", 4)
    with pytest.raises(ValueError):
        inspect_image_archive(path)
    monkeypatch.setattr(artifacts, "MAX_FILE", 1024**3)
    monkeypatch.setattr(artifacts, "MAX_MEMBERS", 1)
    with pytest.raises(ValueError):
        inspect_image_archive(path)


def prepare_evidence(directory, images):
    from datetime import UTC, datetime

    from scripts.security_gate import evaluate_report

    (directory / "smoke.json").write_text(
        json.dumps({"passed": True, "recreation_retained": True})
    )
    for service, info in images.items():
        output = directory / (service + "-security")
        output.mkdir(exist_ok=True)
        report = {
            "SchemaVersion": 2,
            "ArtifactName": info["image_id"],
            "ArtifactType": "container_image",
            "Results": [
                {
                    "Target": "Alpine",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": [],
                }
            ],
        }
        (output / "report.json").write_text(json.dumps(report))
        summary = evaluate_report(
            report,
            [],
            target=info["image_id"],
            expected_targets=set(),
            now=datetime.now(UTC),
        )
        (output / "summary.json").write_text(json.dumps(summary))
        (output / "scanner.json").write_text(json.dumps({"Version": "0.75.0+cg.1"}))
        (directory / (service + "-disclosure.json")).write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "archive_sha256": info["sha256"],
                    "layers": len(info["diff_ids"]),
                    "files": 1,
                    "rules": {},
                    "blocked": False,
                }
            )
        )


def test_file_json_reader_bounds_reads_and_rejects_links(tmp_path, monkeypatch):
    from scripts.releases import artifacts

    path = tmp_path / "handoff.json"
    path.write_bytes(b" " * 1024)
    monkeypatch.setattr(artifacts, "MAX_JSON", 32)
    with pytest.raises(ValueError):
        artifacts.read_json_file(path)
    path.write_text('{"checked":true}')
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        artifacts.read_json_file(link)
    assert artifacts.read_json_file(path) == {"checked": True}


@pytest.mark.parametrize("inner", [False, True])
@pytest.mark.parametrize("kind", [tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME])
def test_oversized_tar_extension_rejected_before_payload_read(
    tmp_path, monkeypatch, inner, kind
):
    from scripts.releases import artifacts

    member = tarfile.TarInfo("metadata")
    member.type = kind
    member.size = 5 * 1024 * 1024
    # Only a header: rejection must occur without allocating/reading its payload.
    raw = member.tobuf(format=tarfile.GNU_FORMAT)
    monkeypatch.setattr(artifacts, "MAX_EXTENSION", 1024)
    if inner:
        import gzip

        # Exercise the stream guard directly, including decompression.
        reader = artifacts.TarGuard(
            gzip.GzipFile(fileobj=io.BytesIO(gzip.compress(raw)))
        )
        with pytest.raises(ValueError):
            with tarfile.open(fileobj=reader, mode="r|") as archive:
                list(archive)
    else:
        path = tmp_path / "bad.tar"
        path.write_bytes(raw)
        with pytest.raises(ValueError):
            inspect_image_archive(path)


def test_chained_tar_extensions_are_bounded_and_valid_long_names_work(
    tmp_path, monkeypatch
):
    from scripts.releases import artifacts

    long_name = "app/" + "segment/" * 30 + "file.py"
    assert (
        inspect_image_archive(
            image_archive(tmp_path / "valid.tar", files=[(long_name, b"code")])
        )["platform"]
        == "linux/amd64"
    )
    raw = b""
    for _ in range(5):
        member = tarfile.TarInfo("metadata")
        member.type = tarfile.GNUTYPE_LONGNAME
        member.size = 2
        raw += member.tobuf(format=tarfile.GNU_FORMAT) + b"x\x00" + bytes(510)
    monkeypatch.setattr(artifacts, "MAX_EXTENSION_CHAIN", 2)
    reader = artifacts.TarGuard(io.BytesIO(raw))
    with pytest.raises(ValueError):
        with tarfile.open(fileobj=reader, mode="r|") as archive:
            list(archive)


def containerd_archive(path, service="api", **kwargs):
    image_archive(path, service, **kwargs)
    with tarfile.open(path) as archive:
        entries = [
            (m.name, archive.extractfile(m).read()) for m in archive if m.isfile()
        ]
    docker_manifest = json.loads(dict(entries)["manifest.json"])
    selection = docker_manifest[0]
    config = dict(entries)[selection["Config"]]
    layer = dict(entries)[selection["Layers"][0]]

    def descriptor(data, media):
        digest = hashlib.sha256(data).hexdigest()
        name = "blobs/sha256/" + digest
        if name not in dict(entries):
            entries.append((name, data))
        return {"digest": "sha256:" + digest, "size": len(data), "mediaType": media}

    config_ref = descriptor(config, "application/vnd.oci.image.config.v1+json")
    layer_ref = descriptor(layer, "application/vnd.oci.image.layer.v1.tar")
    selection["Config"] = "blobs/sha256/" + config_ref["digest"][7:]
    selection["Layers"] = ["blobs/sha256/" + layer_ref["digest"][7:]]
    entries = [(name, data) for name, data in entries if name != "manifest.json"]
    entries.append(("manifest.json", json.dumps(docker_manifest).encode()))
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": config_ref,
            "layers": [layer_ref],
        }
    ).encode()
    manifest_ref = descriptor(manifest, "application/vnd.oci.image.manifest.v1+json")
    entries += [
        ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
        (
            "index.json",
            json.dumps({"schemaVersion": 2, "manifests": [manifest_ref]}).encode(),
        ),
    ]
    path.write_bytes(pack(entries))
    return path


def test_containerd_manifest_identity_is_distinct_and_bound_to_configuration(tmp_path):
    path = containerd_archive(tmp_path / "api.tar")
    info = inspect_image_archive(path)
    with tarfile.open(path) as archive:
        index = json.load(archive.extractfile("index.json"))
    assert info["manifest_digest"] == index["manifests"][0]["digest"]
    assert info["manifest_digest"] != info["image_id"]


@pytest.mark.parametrize("field", ["config", "layer"])
def test_containerd_manifest_cannot_refer_to_different_payload(tmp_path, field):
    path = containerd_archive(tmp_path / "api.tar")
    with tarfile.open(path) as archive:
        entries = {m.name: archive.extractfile(m).read() for m in archive if m.isfile()}
    index = json.loads(entries["index.json"])
    descriptor = index["manifests"][0]
    manifest = json.loads(entries["blobs/sha256/" + descriptor["digest"][7:]])
    if field == "config":
        manifest["config"]["digest"] = "sha256:" + "0" * 64
    else:
        manifest["layers"][0]["digest"] = "sha256:" + "0" * 64
    raw = json.dumps(manifest).encode()
    digest = hashlib.sha256(raw).hexdigest()
    entries["blobs/sha256/" + digest] = raw
    descriptor.update(digest="sha256:" + digest, size=len(raw))
    entries["index.json"] = json.dumps(index).encode()
    path.write_bytes(pack(entries.items()))
    with pytest.raises(ValueError):
        inspect_image_archive(path)
