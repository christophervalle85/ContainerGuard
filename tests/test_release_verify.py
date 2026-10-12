import json

import pytest

from scripts.releases import verify
from tests.test_release_compose import release_manifest


@pytest.mark.parametrize("store", ["legacy", "containerd"])
def test_anonymous_pull_has_empty_auth_and_never_builds(tmp_path, monkeypatch, store):
    manifest = release_manifest()
    commands = []
    monkeypatch.setenv("GITHUB_TOKEN", "nonfunctional-test-value")

    class Registry:
        def __init__(self, *, anonymous):
            assert anonymous is True

        def manifest(self, service, digest):
            return manifest["images"][service]

    monkeypatch.setattr(verify, "Registry", Registry)

    def command(args, **kwargs):
        commands.append(args)
        assert "GITHUB_TOKEN" not in kwargs["env"]
        assert json.loads(
            (verify.Path(kwargs["env"]["DOCKER_CONFIG"]) / "config.json").read_text()
        ) == {"auths": {}}
        if "inspect" in args:
            image = next(
                record
                for service, record in manifest["images"].items()
                if service in args[-1]
            )
            return json.dumps(
                {
                    "Id": image["digest"]
                    if store == "containerd"
                    else image["image_id"],
                    "RootFS": {"Layers": image["diff_ids"]},
                    "Os": "linux",
                    "Architecture": "amd64",
                    "Config": {"Labels": image["labels"]},
                }
            )
        return ""

    monkeypatch.setattr(verify, "command", command)
    monkeypatch.setattr(
        verify, "exercise_stack", lambda images, **kwargs: {"passed": True}
    )
    assert verify.verify_published(manifest, tmp_path)["anonymous_pulls"] is True
    assert sum("pull" in args for args in commands) == 3
    assert not any("build" in args for args in commands)


def test_pull_identity_mismatch_prevents_running_stack(tmp_path, monkeypatch):
    manifest = release_manifest()

    class Registry:
        def __init__(self, **kwargs):
            pass

        def manifest(self, *args):
            return {"image_id": "sha256:" + "0" * 64}

    monkeypatch.setattr(verify, "Registry", Registry)
    monkeypatch.setattr(verify, "command", lambda *args, **kwargs: "")
    ran = []
    monkeypatch.setattr(
        verify, "exercise_stack", lambda *args, **kwargs: ran.append(True)
    )
    with pytest.raises(ValueError):
        verify.verify_published(manifest, tmp_path)
    assert not ran
