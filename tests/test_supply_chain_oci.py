"""Synthetic adversarial fixtures; no network or registry writes."""

import gzip
import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

from scripts.releases.supply_chain import oci

INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def fixture(tmp_path, *, mutation=None):
    files = {}

    def blob(document, media, platform=None):
        raw = document if isinstance(document, bytes) else json.dumps(document).encode()
        d = {"mediaType": media, "digest": digest(raw), "size": len(raw)}
        if platform:
            d["platform"] = platform
        files["blobs/sha256/" + d["digest"][7:]] = raw
        return d

    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as layer:
        t = tarfile.TarInfo("hello")
        t.size = 2
        layer.addfile(t, io.BytesIO(b"hi"))
        if mutation == "duplicate-layer":
            layer.addfile(t, io.BytesIO(b"hi"))
    raw_layer = data.getvalue()
    conf = blob(
        {
            "os": "linux",
            "architecture": "arm64" if mutation == "config-platform" else "amd64",
            "rootfs": {"type": "layers", "diff_ids": [digest(raw_layer)]},
        },
        CONFIG,
    )
    lay = blob(gzip.compress(raw_layer), LAYER)
    if mutation == "media-compression":
        lay["mediaType"] = "application/vnd.oci.image.layer.v1.tar"
    manifest = blob(
        {"schemaVersion": 2, "mediaType": MANIFEST, "config": conf, "layers": [lay]},
        MANIFEST,
        {"os": "linux", "architecture": "amd64"},
    )
    selected = manifest.copy()
    if mutation == "size":
        manifest["size"] += 1
    if mutation == "attestation":
        manifest["annotations"] = {"vnd.docker.reference.type": "attestation-manifest"}
    wrapper = {"schemaVersion": 2, "mediaType": INDEX, "manifests": [manifest]}
    if mutation == "extra":
        wrapper["manifests"].append(
            {**manifest, "platform": {"os": "linux", "architecture": "arm64"}}
        )
    root = {"schemaVersion": 2, "mediaType": INDEX, "manifests": [blob(wrapper, INDEX)]}
    files["index.json"] = json.dumps(root).encode()
    if mutation == "duplicate-json":
        files["index.json"] = files["index.json"].replace(
            b'"schemaVersion": 2', b'"schemaVersion": 2, "schemaVersion": 2'
        )
    if mutation == "unsafe-path":
        files["../outside"] = b"unsafe"
    if mutation == "unreachable-blob":
        blob(b"not an image", LAYER)
    files["oci-layout"] = b'{"imageLayoutVersion":"1.0.0"}'
    if mutation == "hash":
        name = "blobs/sha256/" + lay["digest"][7:]
        raw = files[name]
        files[name] = bytes([raw[0] ^ 1]) + raw[1:]
        assert len(files[name]) == lay["size"]
        assert digest(files[name]) != lay["digest"]
    path = tmp_path / "image.tar"
    with tarfile.open(path, "w") as archive:
        for name, raw in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
        if mutation == "duplicate-archive":
            archive.addfile(info, io.BytesIO(raw))
        if mutation == "link":
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            archive.addfile(info)
    return path, selected, digest(files["index.json"]), conf["digest"]


def test_wrapper_is_not_image_subject(tmp_path):
    path, selected, root, config = fixture(tmp_path)
    actual = oci.inspect_canonical(path)
    assert actual["index_digest"] == root
    assert actual["manifest_digest"] == selected["digest"] != root
    assert actual["descriptor"] == selected
    assert actual["image_id"] == config
    assert actual["sha256"] == digest(path.read_bytes())[7:]
    assert actual["size_bytes"] == path.stat().st_size


@pytest.mark.parametrize("mutation", ["extra", "attestation", "config-platform"])
def test_extra_platform_or_attestation_rejected(tmp_path, mutation):
    with pytest.raises(ValueError):
        oci.inspect_canonical(fixture(tmp_path, mutation=mutation)[0])


@pytest.mark.parametrize(
    "mutation",
    [
        "size",
        "hash",
        "duplicate-layer",
        "duplicate-archive",
        "link",
        "media-compression",
        "duplicate-json",
        "unsafe-path",
        "unreachable-blob",
    ],
)
def test_descriptor_size_or_blob_hash_mismatch_rejected(
    tmp_path, monkeypatch, mutation
):
    monkeypatch.setattr(
        oci, "_run", lambda *a: pytest.fail("invoked before validation")
    )
    with pytest.raises(ValueError):
        oci.import_for_checks(fixture(tmp_path, mutation=mutation)[0], "owned:test")


def test_compressed_expansion_and_limits(tmp_path, monkeypatch):
    from scripts.releases import artifacts

    path = fixture(tmp_path)[0]
    monkeypatch.setattr(artifacts, "MAX_EXPANDED", 100)
    with pytest.raises(ValueError):
        oci.inspect_canonical(path)


@pytest.mark.parametrize("store", ["classic", "containerd"])
def test_import_verifies_config_and_diff_ids(tmp_path, monkeypatch, store):
    path, selected, _, config = fixture(tmp_path)
    expected = oci.inspect_canonical(path)
    calls = []

    def run(args):
        calls.append(args)
        if args[1:3] == ["image", "inspect"]:
            return json.dumps(
                [
                    {
                        "Id": config if store == "classic" else selected["digest"],
                        "Os": "linux",
                        "Architecture": "amd64",
                        "RootFS": {"Layers": expected["diff_ids"]},
                    }
                ]
            )
        if args[1:3] == ["image", "save"]:
            # Runtime export must prove config even for a manifest image ID.
            import shutil

            source = calls[0][-1].removeprefix("docker-archive:")
            shutil.copyfile(source, args[args.index("--output") + 1])
        return ""

    monkeypatch.setattr(oci, "_run", run)
    monkeypatch.setattr(oci, "_skopeo", lambda: "skopeo")
    assert (
        oci.import_for_checks(path, "owned:test")["manifest_digest"]
        == selected["digest"]
    )


@pytest.mark.parametrize("outcome", ["match", "mismatch", "failure", "missing"])
def test_copy_preserves_digest_and_fails_closed(tmp_path, monkeypatch, outcome):
    path, selected, _, _ = fixture(tmp_path)
    calls = []

    def run(args):
        calls.append(args)
        from pathlib import Path

        source = next(
            arg.removeprefix("oci-archive:")
            for arg in args
            if arg.startswith("oci-archive:")
        )
        assert Path(source).read_bytes() == path.read_bytes()
        if outcome == "failure":
            raise subprocess.CalledProcessError(
                1, args, stderr="credential must not leak"
            )
        from pathlib import Path

        if outcome == "missing":
            return ""
        Path(args[args.index("--digestfile") + 1]).write_text(
            selected["digest"] if outcome == "match" else "sha256:" + "0" * 64
        )
        return ""

    monkeypatch.setattr(oci, "_run", run)
    monkeypatch.setattr(oci, "_skopeo", lambda: "skopeo")
    if outcome == "match":
        assert (
            oci.copy_preserving_digest(
                path, "example.invalid/owned:test", authfile=tmp_path / "auth"
            )
            == selected["digest"]
        )
    else:
        with pytest.raises((ValueError, RuntimeError), match="^(?!.*credential)"):
            oci.copy_preserving_digest(
                path, "example.invalid/owned:test", authfile=tmp_path / "auth"
            )
    assert "--preserve-digests" in calls[0]
    assert "--override-os" in calls[0] and "--override-arch" in calls[0]


def test_real_local_buildx_fixture():
    path = Path(__file__).parent / "fixtures/releases/local-buildx-oci.tar"
    actual = oci.inspect_canonical(path)
    assert (
        actual["manifest_digest"]
        == "sha256:8a777e458eaff807fad9d53fe01cad8305493bd0b36ac05657b088ea89366d0b"
    )
    assert (
        actual["image_id"]
        == "sha256:34e524e1ef68a01c113fbc337a03c8bbd0928f89ba41f79381fd6d5c5c161ae6"
    )
    assert actual["index_digest"] != actual["manifest_digest"]


@pytest.mark.parametrize(
    "bound", ["MAX_ARCHIVE", "MAX_FILE", "MAX_MEMBERS", "MAX_JSON"]
)
def test_archive_limits_before_commands(tmp_path, monkeypatch, bound):
    from scripts.releases import artifacts

    path = fixture(tmp_path)[0]
    monkeypatch.setattr(artifacts, bound, 1)
    monkeypatch.setattr(oci, "_run", lambda *args: pytest.fail("invoked command"))
    with pytest.raises(ValueError):
        oci.import_for_checks(path, "owned:test")


@pytest.mark.parametrize(
    "fault", ["runtime-layers", "runtime-platform", "saved-config", "command"]
)
def test_import_rejects_conflicting_runtime_identity(tmp_path, monkeypatch, fault):
    import shutil

    path = fixture(tmp_path)[0]
    expected = oci.inspect_canonical(path)
    exported = None

    def run(args):
        nonlocal exported
        if fault == "command":
            raise subprocess.CalledProcessError(1, args, stderr="private")
        if args[1:3] == ["image", "load"]:
            exported = Path(args[-1])
        if args[1:3] == ["image", "inspect"]:
            return json.dumps(
                [
                    {
                        "Id": "sha256:" + "f" * 64,
                        "Os": "windows" if fault == "runtime-platform" else "linux",
                        "Architecture": "amd64",
                        "RootFS": {
                            "Layers": []
                            if fault == "runtime-layers"
                            else expected["diff_ids"]
                        },
                    }
                ]
            )
        if args[1:3] == ["image", "save"]:
            if fault == "saved-config":
                # A different valid config with the same layers must fail.
                with (
                    tarfile.open(exported) as source,
                    tarfile.open(args[args.index("--output") + 1], "w") as out,
                ):
                    entries = {
                        member.name: source.extractfile(member).read()
                        for member in source
                    }
                    record = json.loads(entries["manifest.json"])[0]
                    old_name = record["Config"]
                    config = json.loads(entries.pop(old_name))
                    config["config"] = {"Labels": {"unexpected": "config"}}
                    raw = json.dumps(config).encode()
                    record["Config"] = digest(raw)[7:] + ".json"
                    entries[record["Config"]] = raw
                    entries["manifest.json"] = json.dumps([record]).encode()
                    for name, raw in entries.items():
                        member = tarfile.TarInfo(name)
                        member.size = len(raw)
                        out.addfile(member, io.BytesIO(raw))
            else:
                shutil.copyfile(exported, args[args.index("--output") + 1])
        return ""

    monkeypatch.setattr(oci, "_run", run)
    with pytest.raises((ValueError, RuntimeError), match="^(?!.*private)"):
        oci.import_for_checks(path, "owned:test")


def test_copy_checks_sealed_identity_inside_transport_snapshot(tmp_path, monkeypatch):
    path = fixture(tmp_path)[0]
    sealed = oci.inspect_canonical(path)
    # Replacement stays a valid OCI archive but differs from the sealed bytes.
    with path.open("ab") as stream:
        stream.write(b"\0" * 512)
    writes = []
    monkeypatch.setattr(oci, "_command", lambda args: writes.append(args))
    with pytest.raises(ValueError, match="Sealed"):
        oci.copy_preserving_digest(
            path,
            "ghcr.io/christophervalle85/containerguard-api:v1.0.0",
            authfile=tmp_path / "auth.json",
            expected_identity={
                k: sealed[k]
                for k in (
                    "manifest_digest",
                    "image_id",
                    "diff_ids",
                    "platform",
                    "sha256",
                    "size_bytes",
                )
            },
        )
    assert writes == []
