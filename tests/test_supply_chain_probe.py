import copy

import pytest


def synthetic_contract_predicate():
    """Source-faithful native history SLSA1 shape; synthetic, not real output."""
    return {
        "buildDefinition": {
            "buildType": "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
            "externalParameters": {
                "configSource": {
                    "uri": "https://github.com/containerguard-probe/fixture#"
                    + "a" * 40,
                    "digest": {"sha1": "a" * 40},
                    "path": "Dockerfile",
                },
                "request": {"frontend": "dockerfile.v0"},
            },
            "internalParameters": {
                "builderPlatform": "linux/amd64",
                "targetPlatform": "linux/amd64",
            },
            "resolvedDependencies": [
                {
                    "uri": "https://github.com/containerguard-probe/fixture",
                    "digest": {"sha1": "a" * 40},
                }
            ],
        },
        "runDetails": {
            "builder": {"id": ""},
            "metadata": {
                "invocationId": "i" * 25,
                "startedOn": "2026-10-12T00:00:00Z",
                "finishedOn": "2026-10-12T00:00:01Z",
                "buildkit_completeness": {
                    "request": True,
                    "resolvedDependencies": True,
                },
                "buildkit_metadata": {
                    "vcs": {
                        "source": "https://github.com/containerguard-probe/fixture",
                        "revision": "a" * 40,
                    }
                },
            },
        },
    }


def assess(probe, *args):
    return probe.assess(*args, expected_invocation="i" * 25)


@pytest.mark.parametrize(
    "mutation", ["source", "wrong-source", "manifest", "dirty", "platform"]
)
def test_probe_requires_native_source_and_equal_manifest(mutation):
    from scripts import probe_release_supply_chain as probe

    native = copy.deepcopy(synthetic_contract_predicate())
    copied = "sha256:" + "b" * 64
    if mutation == "source":
        native["buildDefinition"]["externalParameters"].pop("configSource")
    elif mutation == "wrong-source":
        native["buildDefinition"]["externalParameters"]["configSource"]["uri"] = (
            "https://example.invalid/wrong-source#" + "a" * 40
        )
    elif mutation == "manifest":
        copied = "sha256:" + "c" * 64
    elif mutation == "dirty":
        native["runDetails"]["metadata"]["buildkit_metadata"]["vcs"]["revision"] += (
            "-dirty"
        )
    else:
        native["buildDefinition"]["internalParameters"]["targetPlatform"] = (
            "linux/arm64"
        )
    assert assess(probe, native, "a" * 40, "sha256:" + "b" * 64, copied) is False


def test_synthetic_contract_source_and_manifest():
    from scripts import probe_release_supply_chain as probe

    assert assess(
        probe,
        synthetic_contract_predicate(),
        "a" * 40,
        "sha256:" + "b" * 64,
        "sha256:" + "b" * 64,
    )


def test_probe_builds_once_and_cleans_only_owned_resources(tmp_path, monkeypatch):
    from scripts import probe_release_supply_chain as probe

    commands = []
    monkeypatch.setattr(probe.tools, "verify_tools", lambda: {})
    monkeypatch.setattr(probe, "host_check", lambda: None)

    def command(args, **kwargs):
        commands.append(args)
        if args[:2] == ["git", "rev-parse"]:
            return "a" * 40
        if args[:3] == ["docker", "inspect", "--format"]:
            return "50123"
        if args[:2] == ["docker", "exec"]:
            return (
                "3.0.0"
                if args[-1] == "--version" and args[3] == "registry"
                else "0.34.0"
            )
        if "build" in args and args[0].endswith("buildx"):
            raise RuntimeError("injected build failure")
        return ""

    monkeypatch.setattr(probe, "command", command)
    result = probe.run_probe(tmp_path)
    assert result["passed"] is False
    assert result["failure_stage"] == "fixture-build"
    assert result["failure"] == "requirement-failed"
    builds = [c for c in commands if c[0].endswith("buildx") and "build" in c]
    assert len(builds) == 1
    cleanup = [c for c in commands if "rm" in c]
    assert cleanup
    assert all(any(str(a).startswith("cg-probe-") for a in c) for c in cleanup)
    assert not any("prune" in c or "compose" in c or "volume" in c for c in commands)


def test_builder_platform_cannot_replace_missing_target_platform():
    from scripts import probe_release_supply_chain as probe

    native = synthetic_contract_predicate()
    native["buildDefinition"]["internalParameters"].pop("targetPlatform")
    assert not assess(
        probe, native, "a" * 40, "sha256:" + "b" * 64, "sha256:" + "b" * 64
    )


def test_probe_archive_rejects_symlinks_without_extracting(tmp_path):
    import tarfile

    from scripts import probe_release_supply_chain as probe

    archive = tmp_path / "fixture.tar"
    with tarfile.open(archive, "w") as output:
        member = tarfile.TarInfo("link")
        member.type = tarfile.SYMTYPE
        member.linkname = "/etc/passwd"
        output.addfile(member)
    with pytest.raises(ValueError, match="unsafe"):
        probe.canonical(archive)
    assert not (tmp_path / "link").exists()


def test_conflicting_source_material_is_rejected():
    from scripts import probe_release_supply_chain as probe

    native = synthetic_contract_predicate()
    native["buildDefinition"]["resolvedDependencies"].append(
        {
            "uri": "https://github.com/containerguard-probe/fixture",
            "digest": {"sha1": "c" * 40},
        }
    )
    assert not assess(
        probe, native, "a" * 40, "sha256:" + "b" * 64, "sha256:" + "b" * 64
    )


def test_probe_failure_identifies_safe_host_checkpoint(tmp_path, monkeypatch):
    import json
    import subprocess

    from scripts import probe_release_supply_chain as probe

    def failed_host():
        raise subprocess.CalledProcessError(
            1, ["secret-command"], output="private-path", stderr="token=secret"
        )

    monkeypatch.setattr(probe, "host_check", failed_host)
    result = probe.run_probe(tmp_path)
    assert result["failure_stage"] == "host"
    assert result["failure"] == "process-failed"
    serialized = json.dumps(result)
    assert all(
        value not in serialized
        for value in ("secret-command", "private-path", "token=secret")
    )


def history_case(monkeypatch, mutation=None):
    import hashlib
    import json

    from scripts import probe_release_supply_chain as probe

    builder, ref = "cg-probe-test-builder", "r" * 25
    native = synthetic_contract_predicate()
    if mutation == "missing-invocation":
        native["runDetails"]["metadata"]["invocationId"] = ""
    raw = (json.dumps(native, indent=1) + "\n").encode()
    if mutation == "duplicate-json":
        raw = b'{"runDetails": {}, "runDetails": {}}'

    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + "b" * 64},
        }
    ).encode()
    manifest_digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    history = {
        "Ref": ref,
        "Status": "completed",
        "Attachments": [
            {
                "Digest": digest,
                "Platform": "",
                "Type": "https://slsa.dev/provenance/v1",
            },
            {
                "Digest": manifest_digest,
                "Platform": "linux/amd64",
                "Type": "application/vnd.oci.image.manifest.v1+json",
            },
        ],
    }
    if mutation == "wrong-schema":
        history["Attachments"][0]["Type"] = "https://slsa.dev/provenance/v0.2"
    if mutation == "wrong-ref":
        history["Ref"] = "s" * 25
    if mutation == "wrong-content-digest":
        raw += b" "
    if mutation == "duplicate":
        history["Attachments"].append(dict(history["Attachments"][0]))
    if mutation == "missing":
        history["Attachments"].pop(0)
    if mutation == "wrong-output":
        history["Attachments"][1]["Digest"] = "sha256:" + "c" * 64
    calls = []

    def bounded(args):
        calls.append(args)
        if "attachment" not in args:
            return json.dumps(history).encode()
        return raw if args[-1] == digest else manifest

    monkeypatch.setattr(probe, "bounded_command", bounded)
    metadata = {"buildx.build.ref": f"{builder}/{builder}0/{ref}"}
    identity = {"manifest": manifest_digest, "config": "sha256:" + "b" * 64}
    return probe, builder, metadata, identity, raw, digest, calls


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong-ref",
        "wrong-content-digest",
        "duplicate",
        "missing",
        "wrong-output",
        "missing-invocation",
        "duplicate-json",
        "wrong-schema",
    ],
)
def test_native_history_rejects_unbound_attachments(monkeypatch, mutation):
    probe, builder, metadata, identity, *_ = history_case(monkeypatch, mutation)
    with pytest.raises(ValueError):
        probe.capture_history("buildx", builder, metadata, identity)


def test_native_history_preserves_raw_bytes_and_exact_reference(monkeypatch):
    probe, builder, metadata, identity, raw, digest, calls = history_case(monkeypatch)
    captured, receipt = probe.capture_history("buildx", builder, metadata, identity)
    assert captured == raw
    assert receipt["predicate_digest"] == digest
    assert receipt["invocation_id"] == "i" * 25
    assert receipt["invocation_id"] != metadata["buildx.build.ref"].split("/")[-1]
    assert receipt["build_ref"] == metadata["buildx.build.ref"]
    assert all("r" * 25 in args for args in calls)
    assert all("^0" not in args for args in calls)
    assert calls[-1][-1] == identity["manifest"]


def test_native_invocation_must_match_exact_build():
    from scripts import probe_release_supply_chain as probe

    native = synthetic_contract_predicate()
    native["runDetails"]["metadata"]["invocationId"] = "s" * 25
    assert not assess(
        probe, native, "a" * 40, "sha256:" + "b" * 64, "sha256:" + "b" * 64
    )


def test_history_raw_response_is_bounded(monkeypatch):
    import sys

    from scripts import probe_release_supply_chain as probe

    monkeypatch.setattr(probe, "LIMIT", 128)
    with pytest.raises(ValueError, match="limit"):
        probe.bounded_command(
            [sys.executable, "-c", 'import sys;sys.stdout.write("x"*129)']
        )


@pytest.mark.parametrize(
    "build_ref",
    [
        "other/other0/" + "r" * 25,
        "cg-probe-test-builder/other0/" + "r" * 25,
        "^0",
        "",
        "cg-probe-test-builder/cg-probe-test-builder0/^0",
    ],
)
def test_native_history_ref_must_name_owned_builder_and_node(monkeypatch, build_ref):
    probe, builder, metadata, identity, *rest = history_case(monkeypatch)
    metadata["buildx.build.ref"] = build_ref
    with pytest.raises(ValueError, match="reference"):
        probe.capture_history("buildx", builder, metadata, identity)
    assert rest[-1] == []


def test_history_output_config_must_match_checked_archive(monkeypatch):
    probe, builder, metadata, identity, *_ = history_case(monkeypatch)
    identity["config"] = "sha256:" + "c" * 64
    with pytest.raises(ValueError, match="output identity"):
        probe.capture_history("buildx", builder, metadata, identity)


@pytest.mark.parametrize(
    "attachments",
    [
        [],
        [
            {
                "Digest": "sha256:" + "a" * 64,
                "Platform": "",
                "Type": "https://slsa.dev/provenance/v1",
            },
            {
                "Digest": "sha256:" + "b" * 64,
                "Platform": "linux/amd64",
                "Type": "application/vnd.oci.image.manifest.v1+json",
            },
        ],
    ],
)
def test_actual_history_template_renders_valid_json(tmp_path, attachments):
    import json
    import os
    import shutil
    import subprocess
    import uuid

    from scripts import probe_release_supply_chain as probe

    record = {"Ref": "r" * 25, "Status": "completed", "Attachments": attachments}
    (tmp_path / "fixture.json").write_text(
        json.dumps({"Template": probe.HISTORY_FORMAT, "Record": record})
    )
    (tmp_path / "render.go").write_text("""package main
import (
    "bytes"
    "encoding/json"
    "fmt"
    "os"
    "text/template"
)
func main() {
    raw, err := os.ReadFile("fixture.json")
    if err != nil { panic(err) }
    var input struct { Template string; Record map[string]any }
    if err := json.Unmarshal(raw, &input); err != nil { panic(err) }
    tmpl, err := template.New("inspect").Parse(input.Template)
    if err != nil { panic(err) }
    var output bytes.Buffer
    if err := tmpl.Execute(&output, input.Record); err != nil { panic(err) }
    fmt.Println(output.String())
}
""")
    if executable := shutil.which("go"):
        command = [executable, "run", "render.go"]
    elif os.environ.get("RELEASE_TEMPLATE_DOCKER") == "1":
        command = [
            "docker",
            "run",
            "--rm",
            "--name",
            "cg-template-" + uuid.uuid4().hex,
            "--network=none",
            "--read-only",
            "--tmpfs",
            "/tmp:exec",
            "-e",
            "GOTOOLCHAIN=local",
            "-e",
            "GOENV=off",
            "-e",
            "GOCACHE=/tmp/cache",
            "-v",
            f"{tmp_path}:/work:ro",
            "-w",
            "/work",
            probe.tools.pins()["skopeo"]["compiler_image"],
            "go",
            "run",
            "render.go",
        ]
    else:
        pytest.skip("Go required; RELEASE_TEMPLATE_DOCKER=1 enables pinned isolated Go")
    completed = subprocess.run(
        command, cwd=tmp_path, check=True, capture_output=True, text=True, timeout=180
    )
    assert json.loads(completed.stdout) == record


@pytest.mark.parametrize(
    "code,path,value",
    [
        ("native-build-type", ["buildDefinition", "buildType"], "private-native-value"),
        (
            "config-source-uri",
            ["buildDefinition", "externalParameters", "configSource", "uri"],
            "private-native-value",
        ),
        (
            "config-source-revision",
            ["buildDefinition", "externalParameters", "configSource", "digest"],
            {"sha1": "c" * 40},
        ),
        (
            "dockerfile-entrypoint",
            ["buildDefinition", "externalParameters", "configSource", "path"],
            "/private/Dockerfile",
        ),
        (
            "frontend",
            ["buildDefinition", "externalParameters", "request", "frontend"],
            "private-native-value",
        ),
        (
            "native-target-platform",
            ["buildDefinition", "internalParameters", "targetPlatform"],
            None,
        ),
        ("source-material-missing", ["buildDefinition", "resolvedDependencies"], []),
        (
            "conflicting-source-material",
            ["buildDefinition", "resolvedDependencies"],
            [
                {
                    "uri": "https://github.com/containerguard-probe/fixture",
                    "digest": {"sha1": "a" * 40},
                },
                {
                    "uri": "https://github.com/containerguard-probe/fixture",
                    "digest": {"sha1": "c" * 40},
                },
            ],
        ),
        (
            "material-digests-missing",
            ["buildDefinition", "resolvedDependencies"],
            [
                {
                    "uri": "https://github.com/containerguard-probe/fixture",
                    "digest": {"sha1": "a" * 40},
                },
                {"uri": "private-native-value", "digest": {}},
            ],
        ),
        (
            "invocation-id",
            ["runDetails", "metadata", "invocationId"],
            "private-native-value",
        ),
        (
            "vcs-revision",
            ["runDetails", "metadata", "buildkit_metadata", "vcs", "revision"],
            "private-native-value",
        ),
        (
            "vcs-source",
            ["runDetails", "metadata", "buildkit_metadata", "vcs", "source"],
            "private-native-value",
        ),
    ],
)
def test_assessment_reports_only_failed_check_codes(code, path, value):
    import json

    from scripts import probe_release_supply_chain as probe

    native = synthetic_contract_predicate()
    current = native
    for key in path[:-1]:
        current = current[key]
    current[path[-1]] = value
    failures = probe.assessment_failures(
        native,
        "a" * 40,
        "sha256:" + "b" * 64,
        "sha256:" + "b" * 64,
        expected_invocation="i" * 25,
    )
    assert failures == [code]
    assert not probe.assess(
        native,
        "a" * 40,
        "sha256:" + "b" * 64,
        "sha256:" + "b" * 64,
        expected_invocation="i" * 25,
    )
    assert "private" not in json.dumps(failures)


@pytest.mark.parametrize(
    "manifest,copied,invocation,expected",
    [
        ("secret-path", "secret-path", "i" * 25, ["manifest-format"]),
        (
            "sha256:" + "b" * 64,
            "sha256:" + "c" * 64,
            "i" * 25,
            ["manifest-copy-digest"],
        ),
        (
            "sha256:" + "b" * 64,
            "sha256:" + "b" * 64,
            "",
            ["invocation-id", "expected-invocation-empty"],
        ),
        ("sha256:" + "b" * 64, "sha256:" + "b" * 64, "i" * 25, []),
    ],
)
def test_assessment_reports_digest_and_invocation_checks(
    manifest, copied, invocation, expected
):
    from scripts import probe_release_supply_chain as probe

    assert (
        probe.assessment_failures(
            synthetic_contract_predicate(),
            "a" * 40,
            manifest,
            copied,
            expected_invocation=invocation,
        )
        == expected
    )


def test_assessment_malformed_structure_has_only_bounded_safe_codes():
    import json

    from scripts import probe_release_supply_chain as probe

    native = {"buildDefinition": "private-path/token=secret", "runDetails": None}
    failures = probe.assessment_failures(
        native,
        "a" * 40,
        "sha256:" + "b" * 64,
        "sha256:" + "b" * 64,
        expected_invocation="i" * 25,
    )
    assert failures == [
        "native-build-type",
        "config-source-uri",
        "config-source-revision",
        "dockerfile-entrypoint",
        "frontend",
        "native-target-platform",
        "source-material-missing",
        "conflicting-source-material",
        "material-digests-missing",
        "invocation-id",
        "vcs-revision",
        "vcs-source",
    ]
    assert len(failures) <= 15
    assert "private" not in json.dumps(failures)
    assert "secret" not in json.dumps(failures)
