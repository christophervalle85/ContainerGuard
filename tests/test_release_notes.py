import json

import pytest

from scripts.releases import notes
from tests.test_release_compose import release_manifest


def test_existing_release_is_never_replaced(tmp_path, monkeypatch):
    monkeypatch.setattr(notes, "verify_publication_context", lambda *args: None)
    monkeypatch.setattr(notes, "recheck_source", lambda *args: None)
    calls = []

    def request(url, **kwargs):
        calls.append((url, kwargs))
        return 200, {"id": 1}

    monkeypatch.setattr(notes, "request", request)
    with pytest.raises(ValueError):
        notes.create_draft(release_manifest(), tmp_path)
    assert len(calls) == 1 and calls[0][1] == {}


def test_new_release_is_draft_and_assets_uploaded_once(tmp_path, monkeypatch):
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
    assert notes.create_draft(release_manifest(), tmp_path).endswith("/v1.0.0")
    assert len(calls) == 4
    assert (tmp_path / "compose.release.yaml").is_file()


def test_untrusted_notes_endpoint_cannot_receive_credentials():
    with pytest.raises(ValueError):
        notes.request("https://evil.invalid/upload")
