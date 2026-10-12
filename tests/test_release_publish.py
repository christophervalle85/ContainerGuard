import json

import pytest

from scripts.releases import publish
from scripts.releases.artifacts import inspect_image_archive, write_handoff
from tests.test_release_artifacts import (
    COMMIT,
    containerd_archive,
    image_archive,
    prepare_evidence,
)


@pytest.fixture
def candidate_dir(tmp_path, request):
    exporter = (
        containerd_archive
        if getattr(request, "param", "legacy") == "containerd"
        else image_archive
    )
    images = {
        service: inspect_image_archive(exporter(tmp_path / f"{service}.tar", service))
        for service in ("api", "worker", "frontend")
    }
    prepare_evidence(tmp_path, images)
    write_handoff(images, tmp_path, version="v1.0.0", commit=COMMIT)
    return tmp_path


def test_invalid_handoff_never_loads_images(candidate_dir, monkeypatch):
    calls = []
    monkeypatch.setattr(publish, "command", lambda *args, **kwargs: calls.append(args))
    (candidate_dir / "api.tar").write_bytes(b"altered")
    with pytest.raises(ValueError):
        publish.publish_candidate(
            candidate_dir, version="v1.0.0", commit=COMMIT, dry_run=True
        )
    assert calls == []


def test_dry_run_checks_all_tags_but_has_no_mutations(candidate_dir, monkeypatch):
    calls = []
    monkeypatch.setattr(publish, "recheck_source", lambda *args: None)
    monkeypatch.setattr(publish, "command", lambda *args, **kwargs: calls.append(args))
    checked = []

    class Registry:
        def manifest(self, service, tag, **kwargs):
            checked.append((service, tag))
            return None

    monkeypatch.setattr(publish, "Registry", Registry)
    result = publish.publish_candidate(
        candidate_dir, version="v1.0.0", commit=COMMIT, dry_run=True
    )
    assert result["dry_run"] is True
    assert len(checked) == 6
    assert calls == []
    assert not (candidate_dir / "release.json").exists()


def test_occupied_tag_prevents_every_push(candidate_dir, monkeypatch):
    monkeypatch.setattr(publish, "recheck_source", lambda *args: None)

    class Registry:
        def manifest(self, *args, **kwargs):
            return {"digest": "occupied"}

    monkeypatch.setattr(publish, "Registry", Registry)
    calls = []
    monkeypatch.setattr(publish, "command", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError):
        publish.publish_candidate(
            candidate_dir, version="v1.0.0", commit=COMMIT, dry_run=False
        )
    assert not calls


def test_changed_source_blocks_preflight(candidate_dir, monkeypatch):
    def changed(*args):
        raise ValueError("moved tag")

    monkeypatch.setattr(publish, "recheck_source", changed)
    with pytest.raises(ValueError):
        publish.publish_candidate(
            candidate_dir, version="v1.0.0", commit=COMMIT, dry_run=True
        )


@pytest.mark.parametrize("candidate_dir", ["legacy", "containerd"], indirect=True)
@pytest.mark.parametrize("fail_at", range(6))
def test_success_pushes_exact_images_and_partial_failure_stays_incomplete(
    candidate_dir, monkeypatch, fail_at
):
    import subprocess

    monkeypatch.setenv("GITHUB_TOKEN", "nonfunctional-test-value")
    monkeypatch.setenv("GITHUB_ACTOR", "owner")
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setattr(publish, "recheck_source", lambda *args: None)
    monkeypatch.setattr(publish, "verify_publication_context", lambda *args: None)
    handoff = json.loads((candidate_dir / "handoff.json").read_text())
    pushed = []

    class Registry:
        def manifest(self, service, tag, *, allow_missing=False):
            if allow_missing:
                return None
            expected = handoff["images"][service]
            return {
                key: expected[key]
                for key in ("image_id", "diff_ids", "platform", "labels")
            } | {
                "digest": "sha256:"
                + {"api": "1", "worker": "2", "frontend": "3"}[service] * 64
            }

    monkeypatch.setattr(publish, "Registry", Registry)

    def command(args, **kwargs):
        if "push" in args:
            pushed.append(args[-1])
        if "inspect" in args:
            return next(
                record.get("manifest_digest") or record["image_id"]
                for service, record in handoff["images"].items()
                if service in args[-1]
            )
        assert "build" not in args and "run" not in args
        return ""

    monkeypatch.setattr(publish, "command", command)
    result = publish.publish_candidate(
        candidate_dir, version="v1.0.0", commit=COMMIT, dry_run=False
    )
    assert len(pushed) == 6
    assert len(result["images"]) == 3

    failures = []

    def failing(args, **kwargs):
        if "push" in args:
            failures.append(args[-1])
            if len(failures) == fail_at + 1:
                raise subprocess.CalledProcessError(1, args)
        return command(args, **kwargs)

    monkeypatch.setattr(publish, "command", failing)
    with pytest.raises(subprocess.CalledProcessError):
        publish.publish_candidate(
            candidate_dir, version="v1.0.0", commit=COMMIT, dry_run=False
        )
    assert not (candidate_dir / "release.json").exists()
    partial = json.loads((candidate_dir / "partial-publication.json").read_text())
    assert partial["complete"] is False
    assert partial["attempted"] == pushed[: fail_at + 1]
    assert partial["uploaded"] == pushed[:fail_at]
