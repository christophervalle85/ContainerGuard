import json
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.main import app
from app.persistence.database import get_session
from app.persistence.models import Scan
from tests.database_support import isolated_repository_engine


@pytest.mark.parametrize(
    "reference",
    [
        "ghcr.io/org/image:tag",
        "example.com/org/image:tag",
        "https://docker.io/library/alpine:tag",
        "docker.io/user:sentinel_password@host:tag",
        "docker.io/library/alpine@sha256:" + "a" * 64,
        "docker.io/library/alpine",
        "docker.io/library/../alpine:tag",
        "docker.io/library/alpine:bad\ntag",
        "docker.io/library/alpine:" + "a" * 513,
    ],
)
def test_invalid_reference_rejected_before_any_work(reference, caplog):
    # Returning a session without an engine makes accidental DB access fail visibly.
    def empty_session() -> Iterator[Session]:
        with Session() as session:
            yield session

    previous = app.dependency_overrides.copy()
    app.dependency_overrides[get_session] = empty_session
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.post("/api/v1/scans", json={"image_reference": reference})
        assert response.status_code == 422
        assert "sentinel_password" not in response.text
        assert "sentinel_password" not in caplog.text
        assert "input" not in json.dumps(response.json())
        assert "ctx" not in json.dumps(response.json())
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


@pytest.mark.parametrize(
    "reference",
    [
        "docker.io/library/alpine:3.20",
        "docker.io/alpine:tag",
        "  docker.io/org/image:TAG_1  ",
    ],
)
def test_supported_reference_preserves_trimmed_spelling(reference):
    assert (
        ScanSubmission(image_reference=reference).image_reference == reference.strip()
    )


def test_invalid_reference_creates_no_record():
    with isolated_repository_engine() as engine:

        def test_session() -> Iterator[Session]:
            with Session(engine) as session:
                yield session

        previous = app.dependency_overrides.copy()
        app.dependency_overrides[get_session] = test_session
        try:
            with TestClient(app) as client:
                response = client.post(
                    "/api/v1/scans", json={"image_reference": "ghcr.io/x/y:z"}
                )
            assert response.status_code == 422
            with Session(engine) as session:
                assert session.scalar(select(func.count()).select_from(Scan)) == 0
        finally:
            app.dependency_overrides.clear()
            app.dependency_overrides.update(previous)
