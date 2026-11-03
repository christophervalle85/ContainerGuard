import base64
import json
import os
import secrets
from pathlib import Path

import pytest

from scripts.releases.disclosure import DisclosureBlocked, check_disclosure
from tests.test_release_artifacts import image_archive


@pytest.fixture
def scanner(tmp_path, monkeypatch):
    executable = tmp_path / "gitleaks"
    executable.write_text("""#!/usr/bin/env python3
import json,os,sys,time
if sys.argv[1]=='version':
 print(os.environ.get('FAKE_VERSION','8.30.1'));sys.exit(0)
args=sys.argv[1:]
assert '--redact=100' in args and '--ignore-gitleaks-allow' in args
assert '--max-decode-depth=1' in args
assert not any(k.startswith('GITLEAKS_') for k in os.environ)
sys.stdin.buffer.read()
mode=os.environ.get('FAKE_MODE','clean')
if mode=='timeout': time.sleep(5)
p=args[args.index('--report-path')+1]
if mode=='oversize': open(p,'w').write('x'*2000000);sys.exit(0)
if mode=='invalid': open(p,'w').write('bad');sys.exit(0)
if mode=='error': sys.exit(2)
if mode=='absent': sys.exit(0)
if mode=='delayed': time.sleep(0.1)
findings=[{'RuleID':'generic-api-key','Secret':'REDACTED'}] if mode=='blocked' else []
open(p,'w').write(json.dumps(findings))
sys.exit(1 if findings else 0)
""")
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    return executable


def test_clean_summary_omits_source_data(tmp_path, scanner, monkeypatch):
    monkeypatch.setenv("GITLEAKS_CONFIG", "hostile")
    archive = image_archive(tmp_path / "api.tar")
    summary = check_disclosure(archive, tmp_path / "summary.json")
    assert summary["blocked"] is False
    assert summary["files"] == 1
    assert "hello" not in json.dumps(summary)


@pytest.mark.parametrize("mode", ["invalid", "oversize", "error", "timeout", "absent"])
def test_scanner_failure_removes_stale_success(tmp_path, scanner, monkeypatch, mode):
    from scripts.releases import disclosure

    monkeypatch.setenv("FAKE_MODE", mode)
    monkeypatch.setattr(disclosure, "PROCESS_TIMEOUT", 0.2)
    archive = image_archive(tmp_path / "api.tar")
    output = tmp_path / "summary.json"
    output.write_text('{"blocked":false}')
    with pytest.raises(ValueError):
        check_disclosure(archive, output)
    assert not output.exists()


def test_report_replacement_during_scan_is_tolerated(tmp_path, scanner, monkeypatch):
    from scripts.releases import disclosure

    monkeypatch.setenv("FAKE_MODE", "delayed")
    original_stat = Path.stat
    original_exists = Path.exists
    raced = False

    def stat_with_replacement_race(path, *args, **kwargs):
        nonlocal raced
        if path.name == "report.json" and not raced:
            raced = True
            raise FileNotFoundError(path)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", stat_with_replacement_race)
    monkeypatch.setattr(
        Path,
        "exists",
        lambda path: True if path.name == "report.json" else original_exists(path),
    )
    archive = image_archive(tmp_path / "api.tar")

    summary = disclosure.check_disclosure(archive, tmp_path / "summary.json")

    assert raced
    assert summary["blocked"] is False


def test_detection_blocks_and_retains_only_counts(tmp_path, scanner, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "blocked")
    archive = image_archive(tmp_path / "api.tar")
    output = tmp_path / "summary.json"
    with pytest.raises(DisclosureBlocked):
        check_disclosure(archive, output)
    summary = json.loads(output.read_text())
    assert summary["blocked"] is True
    assert summary["rules"]["generic-api-key"] >= 1
    assert "Secret" not in output.read_text()


def test_wrong_scanner_version_and_unavailable_fail(tmp_path, scanner, monkeypatch):
    archive = image_archive(tmp_path / "api.tar")
    monkeypatch.setenv("FAKE_VERSION", "wrong")
    with pytest.raises(ValueError):
        check_disclosure(archive, tmp_path / "summary.json")
    scanner.unlink()
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(ValueError):
        check_disclosure(archive, tmp_path / "summary.json")


def test_real_scanner_detects_runtime_generated_tokens(tmp_path, monkeypatch):
    executable = Path(os.environ.get("RELEASE_GITLEAKS", "gitleaks"))
    if executable.name == "gitleaks" and not executable.is_absolute():
        import shutil

        found = shutil.which("gitleaks")
        if not found:
            pytest.skip("Pinned Gitleaks unavailable outside release verification")
        executable = Path(found)
    monkeypatch.setenv("PATH", str(executable.parent) + os.pathsep + os.environ["PATH"])
    token = "ghp_" + secrets.token_hex(18)
    for payload in [
        f"token={token} # gitleaks:allow\n".encode(),
        b"\x00\x01token=" + token.encode() + b"\n",
        base64.b64encode(("token=" + token).encode()) + b"\n",
        b" " * (4 * 1024 * 1024 - 10) + ("token=" + token).encode() + b"\n",
    ]:
        path = image_archive(
            tmp_path / "api.tar", files=[("app/data", payload), (".wh.data", b"")]
        )
        output = tmp_path / "summary.json"
        with pytest.raises(DisclosureBlocked):
            check_disclosure(path, output)
        assert token not in output.read_text()
    path = image_archive(
        tmp_path / "api.tar",
        config_change=lambda c: c["history"].append(
            {"created_by": "ENV TOKEN=" + token}
        ),
    )
    with pytest.raises(DisclosureBlocked):
        check_disclosure(path, tmp_path / "summary.json")


def test_public_sqlalchemy_arguments_are_not_credentials(tmp_path, monkeypatch):
    executable = os.environ.get("RELEASE_GITLEAKS")
    if not executable:
        pytest.skip("Pinned Gitleaks probe is enabled in candidate verification")
    monkeypatch.setenv(
        "PATH", str(Path(executable).parent) + os.pathsep + os.environ["PATH"]
    )
    payload = (
        b"keyfunc, ignore_unpopulated_attribute=ignore_unpopulated_attribute\n"
        b"self, state, key, passive=attributes.PASSIVE_NO_INITIALIZE\n"
    )
    path = image_archive(
        tmp_path / "api.tar", files=[("public_dependency.py", payload)]
    )
    assert check_disclosure(path, tmp_path / "summary.json")["blocked"] is False


@pytest.mark.parametrize("kind", ["generic-api-key", "gitlab-pat", "duffel-api-token"])
def test_exact_exceptions_do_not_suppress_generated_credentials(
    tmp_path, monkeypatch, kind
):
    executable = os.environ.get("RELEASE_GITLEAKS")
    if not executable:
        pytest.skip("Pinned Gitleaks integration requires RELEASE_GITLEAKS")
    monkeypatch.setenv(
        "PATH", str(Path(executable).parent) + os.pathsep + os.environ["PATH"]
    )
    if kind == "gitlab-pat":
        token = "glpat-" + secrets.token_hex(10)
    elif kind == "duffel-api-token":
        token = "duffel_test_" + secrets.token_hex(22)[:43]
    else:
        token = secrets.token_hex(24)
    payload = (
        b"keyfunc, ignore_unpopulated_attribute=ignore_unpopulated_attribute\n"
        b"self, state, key, passive=attributes.PASSIVE_NO_INITIALIZE\n"
        + ('api_key="' + token + '"\n').encode()
    )
    archive = image_archive(
        tmp_path / "api.tar", files=[("dependency_and_token", payload)]
    )
    output = tmp_path / "summary.json"
    with pytest.raises(DisclosureBlocked):
        check_disclosure(archive, output)
    summary = json.loads(output.read_text())
    assert summary["rules"].get(kind, 0) >= 1
    assert token not in output.read_text()


def test_secret_in_generated_evidence_blocks_schema2_handoff(tmp_path, monkeypatch):
    from scripts.releases.supply_chain import manifest, provenance
    from tests.test_supply_chain_manifest import sealed_case

    executable = os.environ.get("RELEASE_GITLEAKS")
    if not executable:
        pytest.skip("Pinned Gitleaks integration requires RELEASE_GITLEAKS")
    monkeypatch.setenv(
        "PATH", str(Path(executable).parent) + os.pathsep + os.environ["PATH"]
    )
    context, images = sealed_case(tmp_path)
    token = "ghp_" + secrets.token_hex(18)
    path = tmp_path / "api.sbom.json"
    document = json.loads(path.read_text())
    document["metadata"]["component"]["properties"].append(
        {"name": "accidentally-generated-token", "value": token}
    )
    path.write_text(json.dumps(document))
    record = provenance.build_record(
        image=images["api"],
        context=context,
        files={"sbom": path, "provenance": tmp_path / "api.provenance.json"},
    )
    (tmp_path / "api.build-record.json").write_text(json.dumps(record))
    with pytest.raises(DisclosureBlocked) as caught:
        manifest.write_handoff(images, tmp_path, context=context)
    assert not (tmp_path / "handoff.json").exists()
    assert token not in str(caught.value)
    assert token not in (tmp_path / "evidence-disclosure.json").read_text()
