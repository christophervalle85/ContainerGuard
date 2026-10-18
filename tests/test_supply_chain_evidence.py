import json
import os
from pathlib import Path

import pytest

from tests import test_release_disclosure

scanner = test_release_disclosure.scanner


def document(tmp_path, value=None, raw=None):
    path = tmp_path / "native.json"
    path.write_bytes(
        raw if raw is not None else json.dumps(value or {"public": "fixture"}).encode()
    )
    return path


def test_exact_bytes_hashed_scanned_and_preserved(tmp_path, scanner):
    import hashlib

    from scripts.releases.supply_chain import evidence

    path = document(tmp_path, raw=b'{ "public": "fixture" }\n')
    raw = path.read_bytes()
    summary = evidence.check_disclosure([path], tmp_path / "audit.json")
    assert not summary["blocked"]
    assert summary["documents"] == [
        {"size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    ]
    assert path.read_bytes() == raw
    assert str(tmp_path) not in json.dumps(summary)


@pytest.mark.parametrize(
    "value,category",
    [
        ({"source": "https://user:secret@example.com/repo"}, "credential-url"),
        ({"source": "git://10.0.0.1/repo"}, "private-source-url"),
        ({"source": "http://localhost/repo"}, "private-source-url"),
        ({"file": "/Users/alice/private/file"}, "user-home-path"),
        ({"file": "/home/alice/.ssh/id_rsa"}, "user-home-path"),
        ({"file": "/root/.ssh/id_rsa"}, "user-home-path"),
        ({"file": "C:\\Users\\alice\\private"}, "user-home-path"),
        ({"source": "http://127.1/repo"}, "private-source-url"),
        ({"environment": "SAMPLE=value"}, "runtime-environment"),
        ({"environment": {"PASSWORD": "private value"}}, "runtime-environment"),
    ],
)
def test_privacy_failure_has_only_safe_categories(tmp_path, scanner, value, category):
    from scripts.releases.disclosure import DisclosureBlocked
    from scripts.releases.supply_chain import evidence

    path = document(tmp_path, value)
    output = tmp_path / "audit.json"
    with pytest.raises(DisclosureBlocked):
        evidence.check_disclosure([path], output)
    summary = json.loads(output.read_text())
    assert category in summary["categories"]
    assert summary["blocked"]
    assert all(
        marker not in output.read_text()
        for marker in ("alice", "PASSWORD", "secret", "10.0.0.1")
    )


@pytest.mark.parametrize(
    "kind", ["symlink", "fifo", "duplicate", "oversize", "duplicate-key"]
)
def test_unsafe_or_unbounded_inputs_fail_without_summary(tmp_path, scanner, kind):
    from scripts.releases.supply_chain import evidence

    path = document(tmp_path)
    paths = [path]
    if kind == "symlink":
        link = tmp_path / "link.json"
        link.symlink_to(path)
        paths = [link]
    elif kind == "fifo":
        fifo = tmp_path / "pipe.json"
        os.mkfifo(fifo)
        paths = [fifo]
    elif kind == "duplicate":
        paths.append(path)
    elif kind == "oversize":
        path.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    else:
        path.write_bytes(b'{"a": 1, "a": 2}')
    output = tmp_path / "audit.json"
    output.write_text('{"blocked": false}')
    with pytest.raises(ValueError):
        evidence.check_disclosure(paths, output)
    assert not output.exists()


def test_missing_detector_fails_closed(tmp_path, monkeypatch):
    from scripts.releases import disclosure
    from scripts.releases.supply_chain import evidence

    monkeypatch.setattr(disclosure.shutil, "which", lambda name: None)
    with pytest.raises(ValueError):
        evidence.check_disclosure([document(tmp_path)], tmp_path / "audit.json")


def test_exact_url_allowance_never_bypasses_credentials(tmp_path, scanner):
    from scripts.releases.disclosure import DisclosureBlocked
    from scripts.releases.supply_chain import evidence

    url = "https://user:secret@127.0.0.1/fixture"
    with pytest.raises(DisclosureBlocked):
        evidence.check_disclosure(
            [document(tmp_path, {"source": url})],
            tmp_path / "audit.json",
            allowed_source_urls=frozenset({url}),
        )


def test_real_pinned_detector_clean_and_generated_secret(tmp_path, monkeypatch):
    import secrets

    from scripts.releases.disclosure import DisclosureBlocked
    from scripts.releases.supply_chain import evidence

    executable = os.environ.get("RELEASE_GITLEAKS")
    if not executable:
        pytest.skip("Pinned real detector requires RELEASE_GITLEAKS")
    monkeypatch.setenv(
        "PATH", str(Path(executable).parent) + os.pathsep + os.environ["PATH"]
    )
    path = document(tmp_path)
    assert not evidence.check_disclosure([path], tmp_path / "audit.json")["blocked"]
    token = "ghp_" + secrets.token_hex(18)
    url = "git://127.0.0.1:50123/fixture"
    path.write_text(json.dumps({"source": url, "token": token + " # gitleaks:allow"}))
    with pytest.raises(DisclosureBlocked):
        evidence.check_disclosure(
            [path], tmp_path / "audit.json", allowed_source_urls=frozenset({url})
        )
    summary = (tmp_path / "audit.json").read_text()
    assert "credential" in json.loads(summary)["categories"]
    assert token not in summary


def successful_probe(tmp_path):
    import hashlib

    from tests.test_supply_chain_probe import synthetic_contract_predicate

    native = synthetic_contract_predicate()
    source = "git://127.0.0.1:50123/fixture"
    commit = "a" * 40
    native["buildDefinition"]["externalParameters"]["configSource"]["uri"] = (
        source + "#" + commit
    )
    native["buildDefinition"]["resolvedDependencies"][0]["uri"] = source + "#" + commit
    native["runDetails"]["metadata"]["buildkit_metadata"]["vcs"]["source"] = source
    raw = (json.dumps(native, indent=2) + "\n").encode()
    native_hash = hashlib.sha256(raw).hexdigest()
    manifest, config = "sha256:" + "b" * 64, "sha256:" + "c" * 64
    build_ref = "cg-probe-test-builder/cg-probe-test-builder0/" + "r" * 25
    metadata = {
        "buildx.build.ref": build_ref,
        "containerimage.digest": manifest,
        "containerimage.config.digest": config,
    }
    result = {
        "passed": True,
        "build_invocations": 1,
        "tools": {},
        "source_commit": commit,
        "validation_failures": [],
        "canonical": {"manifest": manifest, "config": config, "diff_ids": []},
        "copied_digest": manifest,
        "native_provenance_sha256": native_hash,
        "history": {
            "build_ref": build_ref,
            "invocation_id": "i" * 25,
            "predicate_type": "https://slsa.dev/provenance/v1",
            "predicate_digest": "sha256:" + native_hash,
            "output_manifest": manifest,
            "output_config": config,
        },
    }
    (tmp_path / "native-provenance.json").write_bytes(raw)
    (tmp_path / "metadata.json").write_text(json.dumps(metadata))
    (tmp_path / "result.json").write_text(json.dumps(result))
    return raw


def test_probe_audit_derives_only_exact_bound_fixture_allowance(tmp_path, scanner):
    from scripts.releases.supply_chain import evidence

    raw = successful_probe(tmp_path)
    summary = evidence.audit_probe(tmp_path)
    assert not summary["blocked"]
    assert len(summary["documents"]) == 3
    assert (tmp_path / "native-provenance.json").read_bytes() == raw
    assert "127.0.0.1" not in json.dumps(summary)


@pytest.mark.parametrize("kind", ["native", "metadata", "result", "source"])
def test_probe_audit_refuses_changed_or_unbound_bytes(tmp_path, scanner, kind):
    from scripts.releases.supply_chain import evidence

    successful_probe(tmp_path)
    if kind == "native":
        with (tmp_path / "native-provenance.json").open("ab") as stream:
            stream.write(b" ")
    elif kind == "metadata":
        path = tmp_path / "metadata.json"
        value = json.loads(path.read_text())
        value["buildx.build.ref"] += "wrong"
        path.write_text(json.dumps(value))
    elif kind == "result":
        path = tmp_path / "result.json"
        value = json.loads(path.read_text())
        value["passed"] = False
        path.write_text(json.dumps(value))
    else:
        path = tmp_path / "result.json"
        value = json.loads(path.read_text())
        value["source_commit"] = "c" * 40
        path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        evidence.audit_probe(tmp_path)
    assert not (tmp_path / "evidence-audit.json").exists()


def test_aggregate_evidence_limit_is_checked_before_parse(
    tmp_path, scanner, monkeypatch
):
    from scripts.releases.supply_chain import evidence

    monkeypatch.setattr(evidence, "COMBINED_LIMIT", 12)
    one, two = tmp_path / "one.json", tmp_path / "two.json"
    one.write_bytes(b"1234567")
    two.write_bytes(b"1234567")
    with pytest.raises(ValueError, match="size limit"):
        evidence.check_disclosure([one, two], tmp_path / "audit.json")


@pytest.mark.parametrize("kind", ["clean", "missing", "scanner", "blocked"])
def test_audit_cli_prints_only_safe_summary(tmp_path, scanner, kind):
    import subprocess
    import sys

    from scripts.releases.supply_chain import evidence

    successful_probe(tmp_path)
    environment = dict(os.environ)
    if kind == "missing":
        (tmp_path / "metadata.json").unlink()
    elif kind == "scanner":
        environment["FAKE_MODE"] = "invalid"
    elif kind == "blocked":
        environment["FAKE_MODE"] = "blocked"
    process = subprocess.run(
        [sys.executable, "-m", evidence.__name__, "--probe-dir", str(tmp_path)],
        capture_output=True,
        text=True,
        env=environment,
        timeout=20,
    )
    summary = json.loads(process.stdout)
    assert summary["passed"] is (kind == "clean")
    assert process.returncode == (0 if kind == "clean" else 1)
    assert process.stderr == ""
    assert all(
        marker not in process.stdout
        for marker in (str(tmp_path), "configSource", "127.0.0.1", "buildkit_metadata")
    )


def test_public_url_and_native_metadata_are_not_private_data(tmp_path, scanner):
    from scripts.releases.supply_chain import evidence

    value = {
        "buildType": "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
        "tool": "https://github.com/sigstore/cosign/releases/v3.1.3",
    }
    assert not evidence.check_disclosure(
        [document(tmp_path, value)], tmp_path / "audit.json"
    )["blocked"]


def test_audit_output_cannot_replace_raw_input(tmp_path, scanner):
    from scripts.releases.supply_chain import evidence

    path = document(tmp_path)
    raw = path.read_bytes()
    with pytest.raises(ValueError):
        evidence.check_disclosure([path], path)
    assert path.read_bytes() == raw


@pytest.mark.parametrize(
    "raw", [b"not-json", b'{"value": NaN}', b'{"value": Infinity}']
)
def test_non_json_evidence_fails_closed(tmp_path, scanner, raw):
    from scripts.releases.supply_chain import evidence

    with pytest.raises(ValueError):
        evidence.check_disclosure(
            [document(tmp_path, raw=raw)], tmp_path / "audit.json"
        )
    assert not (tmp_path / "audit.json").exists()


@pytest.mark.parametrize("field", ["configSource", "resolvedDependencies", "vcs"])
def test_unapproved_native_sources_block_without_inferring_acl(
    tmp_path, scanner, field
):
    from scripts.releases.disclosure import DisclosureBlocked
    from scripts.releases.supply_chain import evidence
    from tests.test_supply_chain_probe import synthetic_contract_predicate

    native = synthetic_contract_predicate()
    source = "https://github.com/containerguard-probe/fixture"
    approved = frozenset({source, source + "#" + "a" * 40})
    path = document(tmp_path, native)
    assert not evidence.check_disclosure(
        [path], tmp_path / "audit.json", allowed_source_urls=approved
    )["blocked"]
    other = "https://github.com/another-organization/unapproved-source"
    if field == "configSource":
        native["buildDefinition"]["externalParameters"]["configSource"]["uri"] = other
    elif field == "resolvedDependencies":
        native["buildDefinition"]["resolvedDependencies"].append(
            {"uri": other, "digest": {"sha1": "c" * 40}}
        )
    else:
        native["runDetails"]["metadata"]["buildkit_metadata"]["vcs"]["source"] = other
    path.write_text(json.dumps(native))
    with pytest.raises(DisclosureBlocked):
        evidence.check_disclosure(
            [path], tmp_path / "audit.json", allowed_source_urls=approved
        )
    summary = json.loads((tmp_path / "audit.json").read_text())
    assert "unapproved-source-url" in summary["categories"]
    assert other not in json.dumps(summary)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost./private",
        "https://build.internal./repo",
        "https://build.local./repo",
        "https://service.lan./repo",
        "https://service.localhost./repo",
        "https://LOCALHOST./repo",
    ],
)
def test_dns_root_dot_does_not_bypass_private_host_policy(tmp_path, scanner, url):
    from scripts.releases.disclosure import DisclosureBlocked
    from scripts.releases.supply_chain import evidence

    with pytest.raises(DisclosureBlocked):
        evidence.check_disclosure(
            [document(tmp_path, {"url": url})], tmp_path / "audit.json"
        )
    summary = json.loads((tmp_path / "audit.json").read_text())
    assert "private-source-url" in summary["categories"]
    assert url not in json.dumps(summary)


def test_host_classification_does_not_normalize_exact_fixture_allowance(
    tmp_path, scanner
):
    from scripts.releases.disclosure import DisclosureBlocked
    from scripts.releases.supply_chain import evidence

    original = "git://127.0.0.1:50123/fixture"
    rooted = "git://127.0.0.1.:50123/fixture"
    with pytest.raises(DisclosureBlocked):
        evidence.check_disclosure(
            [document(tmp_path, {"url": rooted})],
            tmp_path / "audit.json",
            allowed_source_urls=frozenset({original}),
        )


@pytest.mark.parametrize(
    "role,value,location,matcher,relation",
    [
        (
            "native",
            {
                "buildDefinition": {
                    "externalParameters": {
                        "configSource": {"uri": "git://127.0.0.1:123/fixture#extra"}
                    }
                }
            },
            "native-source",
            "url-private-host",
            "allowed-prefix",
        ),
        (
            "native",
            {"runDetails": {"marker": "http://private.internal/raw-marker"}},
            "native-run-details",
            "url-private-host",
            "other",
        ),
        (
            "native",
            {"buildDefinition": {"marker": "http://[broken/raw-marker"}},
            "native-build-config",
            "url-malformed",
            "other",
        ),
        (
            "metadata",
            {"raw-marker": "person@host:raw-marker"},
            "metadata",
            "scp",
            "other",
        ),
        (
            "result",
            {"tools": {"raw-marker": "golang:tag@sha256:raw-marker"}},
            "result-tools",
            "scp",
            "other",
        ),
        (
            "result",
            {"raw-marker": "http://localhost/raw-marker"},
            "result-other",
            "url-private-host",
            "other",
        ),
    ],
)
def test_private_diagnostics_preserve_policy_and_hide_values(
    role, value, location, matcher, relation
):
    from scripts.releases.supply_chain import evidence

    allowed = frozenset({"git://127.0.0.1:123/fixture"})
    before = evidence.privacy_categories(value, allowed_source_urls=allowed)
    diagnostics = {}
    after = evidence.privacy_categories(
        value, allowed_source_urls=allowed, diagnostics=diagnostics, role=role
    )
    assert after == before
    assert "private-source-url" in after
    assert diagnostics == {(location, matcher, relation): 1}
    assert "raw-marker" not in repr(diagnostics)
    assert "127.0.0.1" not in repr(diagnostics)


def test_private_diagnostics_are_bounded_and_exact_allowance_stays_exact():
    from scripts.releases.supply_chain import evidence

    allowed = frozenset({"git://127.0.0.1:123/fixture"})
    diagnostics = {}
    assert (
        evidence.privacy_categories(
            {"value": next(iter(allowed))},
            allowed_source_urls=allowed,
            diagnostics=diagnostics,
        )
        == set()
    )
    assert diagnostics == {}
    value = {"raw-marker": ["http://private.internal/raw-marker"] * 65540}
    assert evidence.privacy_categories(
        value, allowed_source_urls=allowed, diagnostics=diagnostics
    ) == {"private-source-url"}
    assert diagnostics == {("other", "url-private-host", "other"): 65535}


def test_private_diagnostics_reach_safe_summary(tmp_path, scanner):
    from scripts.releases.supply_chain import evidence

    output = tmp_path / "audit.json"
    with pytest.raises(evidence.EvidenceDisclosureBlocked) as blocked:
        evidence.check_disclosure(
            [document(tmp_path, {"raw-marker": "http://private.internal/raw-marker"})],
            output,
        )
    summary = blocked.value.summary
    assert summary["private_source_diagnostics"] == [
        {
            "location": "other",
            "matcher": "url-private-host",
            "relation": "other",
            "count": 1,
        }
    ]
    assert "raw-marker" not in json.dumps(summary)
    assert json.loads(output.read_text()) == summary


def test_native_nested_producer_diagnostic_buckets():
    from scripts.releases.supply_chain import evidence

    value = {
        "buildDefinition": {
            "internalParameters": {
                "buildConfig": {"raw-marker": "http://private.internal/raw-marker"}
            }
        },
        "runDetails": {
            "metadata": {
                "buildkit_metadata": {
                    "source": {"infos": ["http://private.internal/raw-marker"]}
                }
            }
        },
    }
    diagnostics = {}
    assert evidence.privacy_categories(
        value, allowed_source_urls=frozenset(), diagnostics=diagnostics, role="native"
    ) == {"private-source-url"}
    assert diagnostics == {
        ("native-build-config", "url-private-host", "other"): 1,
        ("native-source-map", "url-private-host", "other"): 1,
    }
