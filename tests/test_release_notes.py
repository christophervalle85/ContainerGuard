import json

import pytest

from scripts.releases import notes
from tests import test_supply_chain_verification as verification_fixtures
from tests.test_release_compose import release_manifest


@pytest.fixture
def verified_assets(verified_inputs, tmp_path):
    from scripts.releases.compose import render_verified_compose
    from scripts.releases.supply_chain import verification

    path, evidence_dir, context, _, document = verified_inputs
    directory = tmp_path / "verified-assets"
    result = verification.verify_release(
        path,
        evidence_dir,
        version=context["version"],
        commit=context["commit"],
        output=directory,
    )
    (directory / "compose.release.yaml").write_text(
        render_verified_compose(document, result)
    )
    return document, directory, context


def test_existing_release_is_never_replaced(verified_assets, monkeypatch):
    document, directory, context = verified_assets
    monkeypatch.setattr(notes, "verify_publication_context", lambda *args: None)
    monkeypatch.setattr(notes, "recheck_source", lambda *args: None)
    calls = []

    def request(url, **kwargs):
        calls.append((url, kwargs))
        return 200, {"id": 1}

    monkeypatch.setattr(notes, "request", request)
    with pytest.raises(ValueError):
        notes.create_draft(
            document, directory, version=context["version"], commit=context["commit"]
        )
    assert len(calls) == 1 and calls[0][1] == {}


def test_new_release_is_draft_and_assets_uploaded_once(verified_assets, monkeypatch):
    document, directory, context = verified_assets
    monkeypatch.setattr(notes, "verify_publication_context", lambda *args: None)
    monkeypatch.setattr(notes, "recheck_source", lambda *args: None)
    calls = []

    def request(url, **kwargs):
        calls.append((url, kwargs))
        if "/tags/" in url:
            return 404, {}
        if url == notes.API:
            payload = json.loads(kwargs["body"])
            assert payload["draft"] is True
            assert payload["target_commitish"] == "a" * 40
            return 201, {"id": 123, "draft": True}
        return 201, {"name": url.split("name=")[1], "state": "uploaded"}

    monkeypatch.setattr(notes, "request", request)
    assert notes.create_draft(
        document, directory, version=context["version"], commit=context["commit"]
    ).endswith("/v1.0.0")
    assert len(calls) == 26
    assert (directory / "compose.release.yaml").is_file()


def test_untrusted_notes_endpoint_cannot_receive_credentials():
    with pytest.raises(ValueError):
        notes.request("https://evil.invalid/upload")


def test_draft_requires_successful_verification(tmp_path, monkeypatch):
    """Even a structurally valid legacy manifest cannot bypass verification."""
    calls = []
    monkeypatch.setattr(notes, "verify_publication_context", lambda *args: None)
    monkeypatch.setattr(notes, "recheck_source", lambda *args: None)

    def request(*args, **kwargs):
        calls.append(args)
        return 200, {}

    monkeypatch.setattr(notes, "request", request)
    with pytest.raises(ValueError):
        notes.create_draft(
            release_manifest(), tmp_path, version="v1.0.0", commit="a" * 40
        )
    assert calls == []


def test_verified_assets_are_uploaded_and_bound_to_receipt(
    verified_inputs, tmp_path, monkeypatch
):
    from scripts.releases.compose import render_verified_compose
    from scripts.releases.supply_chain import verification

    path, evidence_dir, context, _, document = verified_inputs
    directory = tmp_path / "verified-assets"
    result = verification.verify_release(
        path,
        evidence_dir,
        version=context["version"],
        commit=context["commit"],
        output=directory,
    )
    (directory / "compose.release.yaml").write_text(
        render_verified_compose(document, result)
    )
    monkeypatch.setattr(notes, "recheck_source", lambda *args: None)
    calls = []

    def request(url, **kwargs):
        calls.append((url, kwargs))
        if "/tags/" in url:
            return 404, {}
        if url == notes.API:
            return 201, {"id": 123, "draft": True}
        return 201, {"name": url.split("name=")[1], "state": "uploaded"}

    monkeypatch.setattr(notes, "request", request)
    notes.create_draft(
        document, directory, version=context["version"], commit=context["commit"]
    )
    assert len(calls) == 26
    assert len([url for url, _ in calls if "/assets?" in url]) == 24


verified_inputs = verification_fixtures.verified_inputs
candidate_dir = verification_fixtures.candidate_dir
publication = verification_fixtures.publication
signing_case = verification_fixtures.signing_case
scanner = verification_fixtures.scanner


def test_changed_bundle_cannot_be_uploaded(verified_inputs, tmp_path, monkeypatch):
    from scripts.releases.compose import render_verified_compose
    from scripts.releases.supply_chain import verification

    path, evidence_dir, context, _, document = verified_inputs
    directory = tmp_path / "verified-assets"
    result = verification.verify_release(
        path,
        evidence_dir,
        version=context["version"],
        commit=context["commit"],
        output=directory,
    )
    (directory / "compose.release.yaml").write_text(
        render_verified_compose(document, result)
    )
    (directory / "api.signature.bundle.json").write_text("{}")
    calls = []
    monkeypatch.setattr(notes, "recheck_source", lambda *args: None)
    monkeypatch.setattr(notes, "request", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError):
        notes.create_draft(
            document, directory, version=context["version"], commit=context["commit"]
        )
    assert calls == []


def test_check_assets_cli_runs_without_release_credentials(
    verified_assets, monkeypatch
):
    import sys

    from scripts.releases import __main__

    document, directory, context = verified_assets
    calls = []
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(
        notes, "validate_assets", lambda *args, **kwargs: calls.append((args, kwargs))
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "releases",
            "check-assets",
            "--manifest",
            str(directory / "release.json"),
            "--output-dir",
            str(directory),
            "--version",
            context["version"],
            "--commit",
            context["commit"],
        ],
    )
    assert __main__.main() == 0
    assert calls == [
        (
            (document, directory),
            {"version": context["version"], "commit": context["commit"]},
        )
    ]


@pytest.mark.parametrize(
    "mutation",
    [
        "receipt_type",
        "schema_boolean",
        "missing_log",
        "unknown",
        "missing_asset",
        "compose",
        "older_attempt",
    ],
)
def test_invalid_verified_assets_never_reach_release_api(
    verified_assets, monkeypatch, mutation
):
    document, directory, context = verified_assets
    receipt_path = directory / "verification.json"
    receipt = json.loads(receipt_path.read_text())
    if mutation == "receipt_type":
        receipt = []
    elif mutation == "schema_boolean":
        receipt["schema_version"] = True
    elif mutation == "missing_log":
        receipt["trust_checks"].remove("transparency_log")
    elif mutation == "unknown":
        receipt["unexpected"] = "value"
    elif mutation == "missing_asset":
        (directory / "worker.sbom.json").unlink()
    elif mutation == "compose":
        (directory / "compose.release.yaml").write_text("{}")
    else:
        monkeypatch.setenv("GITHUB_RUN_ATTEMPT", str(int(context["run_attempt"]) + 1))
    receipt_path.write_text(json.dumps(receipt))
    calls = []
    monkeypatch.setattr(notes, "recheck_source", lambda *args: None)
    monkeypatch.setattr(notes, "request", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError):
        notes.create_draft(
            document, directory, version=context["version"], commit=context["commit"]
        )
    assert not calls
