import json

import pytest

from scripts.releases import publish
from scripts.releases.supply_chain import manifest, oci
from scripts.releases.supply_chain.oci import copy_preserving_digest as real_copy
from tests.test_release_artifacts import (
    COMMIT,
)
from tests.test_release_disclosure import scanner  # noqa: F401
from tests.test_supply_chain_manifest import sealed_case


@pytest.fixture
def candidate_dir(tmp_path, request):
    request.getfixturevalue("scanner")
    context, images = sealed_case(tmp_path)
    manifest.write_handoff(images, tmp_path, context=context)
    return tmp_path


def test_invalid_handoff_never_loads_images(candidate_dir, monkeypatch):
    calls = []
    monkeypatch.setattr(publish, "command", lambda *args, **kwargs: calls.append(args))
    (candidate_dir / "api.oci.tar").write_bytes(b"altered")
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


@pytest.fixture
def publication(candidate_dir, monkeypatch):
    document = json.loads((candidate_dir / "handoff.json").read_text())
    context = document["context"]
    for key, value in {
        "GITHUB_TOKEN": "nonfunctional-test-value",
        "GITHUB_ACTOR": "owner",
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REF": "refs/tags/v1.0.0",
        "GITHUB_SHA": COMMIT,
        "GITHUB_REPOSITORY": context["repository"],
        "GITHUB_RUN_ID": context["run_id"],
        "GITHUB_RUN_ATTEMPT": context["run_attempt"],
        "GITHUB_WORKFLOW_REF": (
            "christophervalle85/ContainerGuard/"
            ".github/workflows/release.yml@refs/tags/v1.0.0"
        ),
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(publish, "recheck_source", lambda *args: None)
    published, authfiles = {}, []

    class Registry:
        def manifest(self, service, tag, *, allow_missing=False):
            return published.get((service, tag))

    monkeypatch.setattr(publish, "Registry", Registry)

    def copy(path, destination, *, authfile, expected_identity):
        assert authfile.is_file()
        authfiles.append(authfile)
        service = path.name.split(".")[0]
        info = oci.inspect_canonical(path)
        assert all(info[key] == value for key, value in expected_identity.items())
        tag = destination.rsplit(":", 1)[1]
        published[(service, tag)] = {
            "digest": info["manifest_digest"],
            **{k: info[k] for k in ("image_id", "diff_ids", "platform", "labels")},
        }
        return info["manifest_digest"]

    monkeypatch.setattr(oci, "copy_preserving_digest", copy)
    return document, published, authfiles, copy


def test_publish_preserves_captured_manifest_for_both_tags(candidate_dir, publication):
    document, published, authfiles, _ = publication
    result = publish.publish_candidate(
        candidate_dir, version="v1.0.0", commit=COMMIT, dry_run=False
    )
    assert len(published) == 6
    for service in ("api", "worker", "frontend"):
        expected = document["images"][service]["identity"]["manifest_digest"]
        assert published[(service, "v1.0.0")]["digest"] == expected
        assert published[(service, "sha-" + COMMIT)]["digest"] == expected
        assert result["images"][service]["digest"] == expected
        assert set(result["images"][service]["evidence"]) == {
            "sbom",
            "provenance",
            "build-record",
        }
    assert result["schema_version"] == 2
    assert result["build_context"] == document["context"]
    assert all(not p.exists() for p in authfiles)
    assert manifest.validate_release(result, version="v1.0.0", commit=COMMIT) == result


def test_changed_digest_stops_remaining_writes(candidate_dir, publication, monkeypatch):
    _, published, authfiles, copy = publication

    def changed(path, destination, **kwargs):
        result = copy(path, destination, **kwargs)
        published[("api", "v1.0.0")]["digest"] = "sha256:" + "f" * 64
        return result

    monkeypatch.setattr(oci, "copy_preserving_digest", changed)
    with pytest.raises(ValueError):
        publish.publish_candidate(
            candidate_dir, version="v1.0.0", commit=COMMIT, dry_run=False
        )
    assert list(published) == [("api", "v1.0.0")]
    assert not (candidate_dir / "release.json").exists()
    assert all(not p.exists() for p in authfiles)


def test_previous_partial_publication_is_not_resumed(candidate_dir, publication):
    _, published, _, _ = publication
    partial = candidate_dir / "partial-publication.json"
    partial.write_text("previous attempt")
    with pytest.raises(ValueError, match="partial"):
        publish.publish_candidate(
            candidate_dir, version="v1.0.0", commit=COMMIT, dry_run=False
        )
    assert published == {}
    assert partial.read_text() == "previous attempt"


@pytest.mark.parametrize("fail_at", range(6))
def test_partial_failure_records_only_safe_operations(
    candidate_dir, publication, monkeypatch, fail_at
):
    _, published, authfiles, copy = publication
    attempts = []

    def failed(path, destination, **kwargs):
        attempts.append(destination)
        if len(attempts) == fail_at + 1:
            raise ValueError("secret failure details")
        return copy(path, destination, **kwargs)

    monkeypatch.setattr(oci, "copy_preserving_digest", failed)
    with pytest.raises(ValueError):
        publish.publish_candidate(
            candidate_dir, version="v1.0.0", commit=COMMIT, dry_run=False
        )
    partial = json.loads((candidate_dir / "partial-publication.json").read_text())
    assert partial["attempted"] == attempts
    assert partial["uploaded"] == attempts[:-1]
    assert partial["complete"] is False
    assert len(published) == fail_at
    assert "secret failure" not in json.dumps(partial)
    assert not (candidate_dir / "release.json").exists()
    assert all(not p.exists() for p in authfiles)


@pytest.mark.parametrize(
    "field", ["GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_WORKFLOW_REF"]
)
def test_guarded_publication_context_cannot_be_supplied_by_handoff(
    candidate_dir, publication, monkeypatch, field
):
    _, published, _, _ = publication
    monkeypatch.setenv(field, "999")
    with pytest.raises(ValueError):
        publish.publish_candidate(
            candidate_dir, version="v1.0.0", commit=COMMIT, dry_run=False
        )
    assert published == {}


@pytest.mark.parametrize(
    "mutation",
    [
        "schema",
        "unknown",
        "version",
        "commit",
        "context",
        "predicate",
        "path",
        "size",
        "hash",
        "evidence",
    ],
)
def test_schema2_release_rejects_conflicting_or_unsafe_descriptors(
    candidate_dir, publication, mutation
):
    result = publish.publish_candidate(
        candidate_dir, version="v1.0.0", commit=COMMIT, dry_run=False
    )
    if mutation == "schema":
        result["schema_version"] = 1
    elif mutation == "unknown":
        result["unknown"] = True
    elif mutation == "version":
        result["version"] = "v9.0.0"
    elif mutation == "commit":
        result["commit"] = "f" * 40
    elif mutation == "context":
        result["build_context"]["run_id"] = "999"
    elif mutation == "evidence":
        del result["images"]["api"]["evidence"]["sbom"]
    else:
        descriptor = result["images"]["api"]["evidence"]["sbom"]
        descriptor[
            {
                "predicate": "predicate_type",
                "path": "path",
                "size": "size_bytes",
                "hash": "sha256",
            }[mutation]
        ] = {
            "predicate": "https://wrong.invalid",
            "path": "../secret",
            "size": 16 * 1024**2 + 1,
            "hash": "z" * 64,
        }[mutation]
    with pytest.raises(ValueError):
        manifest.validate_release(result, version="v1.0.0", commit=COMMIT)


def test_archive_changed_after_preflight_never_publishes(
    candidate_dir, publication, monkeypatch
):
    _, published, _, _ = publication
    calls = []
    original = publish.preflight_tags

    def mutate(*args, **kwargs):
        original(*args, **kwargs)
        calls.append(True)
        if len(calls) == 2:
            from tests.test_supply_chain_manifest import canonical_archive

            # A valid but different service archive must not replace the sealed API.
            canonical_archive(candidate_dir / "api.oci.tar", "worker")

    monkeypatch.setattr(publish, "preflight_tags", mutate)
    with pytest.raises(ValueError):
        publish.publish_candidate(
            candidate_dir, version="v1.0.0", commit=COMMIT, dry_run=False
        )
    assert published == {}


def test_substitution_between_inspection_and_copy_never_reaches_transport(
    candidate_dir, publication, monkeypatch
):
    writes = []
    # Restore real transport validation; intercept only its external command.
    monkeypatch.setattr(oci, "_command", lambda args: writes.append(args))

    def substituted(path, destination, **kwargs):
        with path.open("ab") as stream:
            stream.write(b"\0" * 512)
        return real_copy(path, destination, **kwargs)

    monkeypatch.setattr(oci, "copy_preserving_digest", substituted)
    with pytest.raises(ValueError, match="Sealed"):
        publish.publish_candidate(
            candidate_dir, version="v1.0.0", commit=COMMIT, dry_run=False
        )
    assert writes == []


def test_summary_replaced_during_transport_cannot_change_release_findings(
    candidate_dir, publication, monkeypatch
):
    _, _, _, copy = publication
    summary_path = candidate_dir / "checks-summary.json"
    original = json.loads(summary_path.read_text())
    expected = {
        service: original["images"][service]["vulnerability"]["counts"]
        for service in ("api", "worker", "frontend")
    }

    def replaced(path, destination, **kwargs):
        altered = json.loads(summary_path.read_text())
        altered["images"]["api"]["vulnerability"]["counts"] = {"LOW": 999}
        summary_path.write_text(json.dumps(altered))
        return copy(path, destination, **kwargs)

    monkeypatch.setattr(oci, "copy_preserving_digest", replaced)
    result = publish.publish_candidate(
        candidate_dir, version="v1.0.0", commit=COMMIT, dry_run=False
    )
    assert result["remaining_findings"] == expected
    saved = json.loads((candidate_dir / "release.json").read_text())
    assert saved["remaining_findings"] == expected


def test_summary_replaced_during_final_preflight_blocks_transport(
    candidate_dir, publication, monkeypatch
):
    _, published, _, _ = publication
    original = publish.preflight_tags
    preflights = []

    def replaced(*args, **kwargs):
        original(*args, **kwargs)
        preflights.append(True)
        if len(preflights) == 2:
            path = candidate_dir / "checks-summary.json"
            altered = json.loads(path.read_text())
            altered["images"]["api"]["vulnerability"]["counts"] = {"LOW": 999}
            path.write_text(json.dumps(altered))

    monkeypatch.setattr(publish, "preflight_tags", replaced)
    with pytest.raises(ValueError):
        publish.publish_candidate(
            candidate_dir, version="v1.0.0", commit=COMMIT, dry_run=False
        )
    assert published == {}
    assert not (candidate_dir / "release.json").exists()
