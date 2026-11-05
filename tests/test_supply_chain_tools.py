from unittest.mock import Mock

import pytest


def test_wrong_tool_digest_refuses_execution(tmp_path):
    from scripts.releases.supply_chain import tools

    binary = tmp_path / "cosign"
    binary.write_bytes(b"untrusted")
    runner = Mock()
    with pytest.raises(ValueError, match="checksum"):
        tools.checked_version(binary, "0" * 64, ["version"], runner=runner)
    runner.assert_not_called()


def test_verified_binary_is_executed(tmp_path):
    import hashlib

    from scripts.releases.supply_chain import tools

    binary = tmp_path / "cosign"
    binary.write_bytes(b"trusted")
    runner = Mock(return_value=Mock(stdout="v3.1.3\n"))
    assert (
        tools.checked_version(
            binary, hashlib.sha256(b"trusted").hexdigest(), ["version"], runner=runner
        )
        == "v3.1.3"
    )
    runner.assert_called_once()


def test_tool_version_must_match_complete_version(tmp_path, monkeypatch):
    import json

    from scripts.releases.supply_chain import tools

    (tmp_path / "installed.json").write_text(
        json.dumps(
            {
                "skopeo": {
                    "sha256": "0" * 64,
                    "source_commit": tools.pins()["skopeo"]["commit"],
                    "integrity": "locally-built; not an upstream signature",
                }
            }
        )
    )
    for name in ("cosign", "buildx", "skopeo"):
        (tmp_path / name).write_bytes(b"fixture")
    monkeypatch.setattr(
        tools,
        "checked_version",
        lambda binary, *a: (
            "Version: v13.1.3"
            if binary.name == "cosign"
            else tools.pins()[binary.name]["version"]
        ),
    )
    with pytest.raises(ValueError, match="version"):
        tools._verify(tmp_path)


def test_static_skopeo_build_excludes_btrfs(tmp_path, monkeypatch):
    import hashlib
    import io
    import re
    from pathlib import Path

    from scripts.releases.supply_chain import tools

    manifest = tools.pins()
    for name in ("cosign", "buildx"):
        manifest[name]["sha256"] = hashlib.sha256(b"fixture").hexdigest()
    monkeypatch.setattr(tools, "host_check", lambda: None)
    monkeypatch.setattr(tools, "pins", lambda: manifest)
    monkeypatch.setattr(
        tools.urllib.request, "urlopen", lambda *a, **kw: io.BytesIO(b"fixture")
    )
    monkeypatch.setattr(tools, "_verify", lambda destination: {})
    configurations = []

    def build(args):
        configurations.append((Path(args[-1]) / "Dockerfile").read_text())
        output = Path(args[args.index("--output") + 1].split("dest=", 1)[1])
        output.mkdir()
        (output / "skopeo").write_bytes(b"compiled fixture")
        return ""

    monkeypatch.setattr(tools, "_run", build)
    tools.install_tools(tmp_path / "installed")
    assert len(configurations) == 1
    tags = re.search(r"-tags=([^\s]+)", configurations[0]).group(1).split(",")
    assert {"containers_image_openpgp", "exclude_graphdriver_btrfs"} <= set(tags)
