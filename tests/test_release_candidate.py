import subprocess

import pytest

from scripts.releases import candidate
from tests.test_release_artifacts import (
    COMMIT,
    containerd_archive,
    image_archive,
    prepare_evidence,
)


@pytest.fixture
def commands(tmp_path, monkeypatch, request):
    exporter = (
        containerd_archive
        if getattr(request, "param", "legacy") == "containerd"
        else image_archive
    )
    calls = []

    def command(args, **kwargs):
        calls.append(args)
        if args[:3] == ["docker", "image", "inspect"]:
            service = next(s for s in ("api", "worker", "frontend") if s in args[-1])
            archive = exporter(tmp_path / f"fixture-{service}.tar", service)
            info = candidate.inspect_image_archive(archive)
            return (info.get("manifest_digest") or info["image_id"]) + "\n"
        if args[:3] == ["docker", "image", "save"]:
            service = next(s for s in ("api", "worker", "frontend") if s in args[-1])
            exporter(tmp_path / "candidate" / f"{service}.tar", service)
        return ""

    monkeypatch.setattr(candidate, "command", command)
    monkeypatch.setattr(candidate, "verify_candidate_source", lambda *args: None)
    monkeypatch.setattr(candidate, "check_disclosure", lambda *args: {"blocked": False})
    monkeypatch.setattr(
        candidate, "exercise_stack", lambda *args, **kwargs: {"passed": True}
    )

    def smoke(images, *, workspace):
        directory = workspace.parent
        info = {
            service: candidate.inspect_image_archive(directory / (service + ".tar"))
            for service in ("api", "worker", "frontend")
        }
        prepare_evidence(directory, info)
        return {"passed": True, "recreation_retained": True}

    monkeypatch.setattr(candidate, "exercise_stack", smoke)
    return calls


@pytest.mark.parametrize("commands", ["legacy", "containerd"], indirect=True)
def test_candidate_builds_once_and_never_writes_registry(tmp_path, commands):
    handoff = candidate.build_candidate("v1.0.0", COMMIT, tmp_path / "candidate")
    assert handoff.is_file()
    builds = [c for c in commands if c[:2] == ["docker", "build"]]
    assert len(builds) == 3
    assert all("linux/amd64" in c for c in builds)
    assert all(f"org.opencontainers.image.revision={COMMIT}" in c for c in builds)
    assert not any("push" in c or "login" in c for c in commands)


@pytest.mark.parametrize("stage", ["build", "gate", "disclosure", "smoke", "identity"])
def test_failed_check_produces_no_handoff(tmp_path, commands, monkeypatch, stage):
    original = candidate.command
    seen = 0

    def fail_command(args, **kwargs):
        nonlocal seen
        if (stage == "build" and args[:2] == ["docker", "build"]) or (
            stage == "gate" and "scripts.scan_security" in args
        ):
            raise subprocess.CalledProcessError(1, args)
        result = original(args, **kwargs)
        if args[:3] == ["docker", "image", "inspect"]:
            seen += 1
            if stage == "identity" and seen > 3:
                return "sha256:" + "f" * 64
        return result

    monkeypatch.setattr(candidate, "command", fail_command)
    if stage in ("disclosure", "smoke"):

        def fail(*args, **kwargs):
            raise ValueError("check failed")

        monkeypatch.setattr(
            candidate,
            "check_disclosure" if stage == "disclosure" else "exercise_stack",
            fail,
        )
    with pytest.raises((ValueError, subprocess.SubprocessError)):
        candidate.build_candidate("v1.0.0", COMMIT, tmp_path / "candidate")
    assert not (tmp_path / "candidate/handoff.json").exists()
