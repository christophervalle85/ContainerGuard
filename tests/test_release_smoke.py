import hashlib
import json

import pytest

from scripts.releases.smoke import check_sbom, cleanup_stack, poll_scan, stack_document

IMAGES = {
    service: "sha256:" + str(n) * 64
    for n, service in enumerate(("api", "worker", "frontend"), 1)
}


def test_stack_has_owned_resources_and_no_development_ports():
    document = stack_document(
        IMAGES, "containerguard-release-verify-" + "a" * 12, "generated"
    )
    assert "build" not in json.dumps(document)
    assert "docker.sock" not in json.dumps(document)
    assert not document["services"]["db"].get("ports")
    assert not document["services"]["redis"].get("ports")
    assert document["services"]["api"]["ports"][0]["published"] == "0"
    assert document["services"]["migrate"]["image"] == IMAGES["api"]
    assert all("name" not in entry for entry in document["volumes"].values())


def test_cleanup_refuses_development_project_without_command(monkeypatch, tmp_path):
    commands = []
    monkeypatch.setattr(
        "scripts.releases.smoke.command", lambda *args, **kwargs: commands.append(args)
    )
    with pytest.raises(ValueError):
        cleanup_stack("containerguard", tmp_path / "compose.json")
    assert commands == []


def test_scan_timeout_and_failed_status_are_errors(monkeypatch):
    monkeypatch.setattr("scripts.releases.smoke.time.sleep", lambda _: None)
    for status in ("failed", "running"):
        with pytest.raises(ValueError):
            poll_scan(lambda path: {"status": status}, "scan", timeout=0)


def test_sbom_hash_and_size_both_required():
    raw = b'{"bomFormat":"CycloneDX"}'
    metadata = {
        "status": "available",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
    }
    assert check_sbom(metadata, raw) == metadata["sha256"]
    for changed in (raw + b" ", b"different"):
        with pytest.raises(ValueError):
            check_sbom(metadata, changed)


def test_cleanup_refuses_named_development_volume_even_with_owned_project(
    tmp_path, monkeypatch
):
    project = "containerguard-release-verify-" + "a" * 12
    document = stack_document(IMAGES, project, "generated")
    document["volumes"]["postgres_data"] = {"name": "containerguard_postgres_data"}
    config = tmp_path / "compose.json"
    config.write_text(json.dumps(document))
    calls = []
    monkeypatch.setattr(
        "scripts.releases.smoke.command", lambda *args, **kwargs: calls.append(args)
    )
    with pytest.raises(ValueError):
        cleanup_stack(project, config)
    assert not calls


def test_failed_startup_cleans_only_owned_stack_and_preserves_original_failure(
    tmp_path, monkeypatch
):
    from scripts.releases import smoke

    calls = []

    def command(args, **kwargs):
        calls.append(args)
        if "up" in args:
            raise ValueError("original startup error")

    monkeypatch.setattr(smoke, "command", command)
    with pytest.raises(ValueError, match="original startup error"):
        smoke.exercise_stack(IMAGES, workspace=tmp_path)
    assert len(calls) == 2
    assert "down" in calls[-1] and "--volumes" in calls[-1]
    assert all(args[3].startswith("containerguard-release-verify-") for args in calls)


def test_cleanup_failure_does_not_mask_startup_error(tmp_path, monkeypatch):
    from scripts.releases import smoke

    def command(args, **kwargs):
        raise ValueError("startup error" if "up" in args else "cleanup error")

    monkeypatch.setattr(smoke, "command", command)
    with pytest.raises(ValueError, match="startup error") as error:
        smoke.exercise_stack(IMAGES, workspace=tmp_path)
    assert "cleanup also failed" in error.value.__notes__[0]
