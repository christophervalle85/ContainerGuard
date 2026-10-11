"""Exercise the installer's rejection paths without network or Docker access."""

import io
import json
import platform
import sys
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def run_installer():
    # Run the exact Python payload shipped by the Bash entry point.
    source = (ROOT / "scripts/install_security_tools.sh").read_text()
    payload = source.split("<<'PYTHON'\n", 1)[1].rsplit("\nPYTHON", 1)[0]
    exec(compile(payload, "install_security_tools.sh", "exec"), {})


def test_installer_rejects_unsupported_platform_before_download(tmp_path, monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(sys, "argv", ["installer", str(tmp_path / "bin")])
    with pytest.raises(SystemExit, match="supports Linux amd64 only"):
        run_installer()
    assert not (tmp_path / "bin").exists()


def test_installer_rejects_checksum_mismatch_without_installing(tmp_path, monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(sys, "argv", ["installer", str(tmp_path / "bin")])
    monkeypatch.chdir(tmp_path)
    (tmp_path / "security").mkdir()
    (tmp_path / "security/tools.json").write_text(
        json.dumps(
            {"gitleaks": {"url": "https://example.invalid/tool", "sha256": "0" * 64}}
        )
    )
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda *a, **kw: io.BytesIO(b"modified archive")
    )
    with pytest.raises(SystemExit, match="checksum mismatch"):
        run_installer()
    assert not (tmp_path / "bin/gitleaks").exists()
