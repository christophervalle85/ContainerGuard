from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.main import app
from app.persistence import repository
from app.persistence.database import get_session
from app.persistence.models import Image, Scan
from tests.database_support import isolated_repository_engine

CREATED = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
STARTED = datetime(2026, 10, 9, 12, 1, tzinfo=UTC)
COMPLETED = datetime(2026, 10, 9, 12, 2, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64
REFERENCE = "docker.io/library/alpine:3.20.0"


@pytest.fixture
def api_database():
    with isolated_repository_engine() as engine:

        def test_session():
            with Session(engine) as session:
                yield session

        previous = app.dependency_overrides.copy()
        app.dependency_overrides[get_session] = test_session
        try:
            yield engine
        finally:
            app.dependency_overrides.clear()
            app.dependency_overrides.update(previous)


def seed(engine, *, status="completed", mock=False, metadata=None):
    scan_id = uuid4()
    with Session(engine) as session, session.begin():
        image = None
        if status == "completed" and not mock:
            image = Image(
                registry_host="docker.io",
                repository="library/alpine",
                digest=DIGEST,
                platform="linux/amd64",
            )
            session.add(image)
            session.flush()
        session.add(
            Scan(
                id=scan_id,
                submitted_reference=REFERENCE,
                status=status,
                image_id=image.id if image else None,
                created_at=CREATED,
                started_at=STARTED if status != "queued" and not mock else None,
                completed_at=COMPLETED if status in {"completed", "failed"} else None,
                scanner_name=None if mock else "trivy",
                scanner_version="0.75.0" if image else None,
                scanner_database_metadata=metadata,
                error_details="resolution_failed: Image reference could not be resolved"
                if status == "failed"
                else None,
            )
        )
    return scan_id


def fetch(scan_id):
    with TestClient(app) as client:
        response = client.get(f"/api/v1/scans/{scan_id}")
    assert response.status_code == 200
    return response.json()


def timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@pytest.mark.parametrize("status", ["queued", "running"])
def test_unfinished_real_scans_expose_saved_times_without_invented_results(
    api_database, status
):
    scan_id = seed(api_database, status=status)
    body = fetch(scan_id)
    assert body["scan_id"] == str(scan_id)
    assert body["image_reference"] == REFERENCE
    assert body["status"] == status
    assert timestamp(body["created_at"]) == CREATED
    if status == "queued":
        assert body["started_at"] is None
    else:
        assert timestamp(body["started_at"]) == STARTED
    assert body["completed_at"] is None
    assert body["digest"] is None and body["platform"] is None
    assert body["scanner_name"] == "trivy" and body["scanner_version"] is None
    assert body["scanner_database_metadata"] is None
    assert body["error_details"] is None and body["mock"] is False


@pytest.mark.parametrize(
    "metadata", [None, {"Version": 2, "UpdatedAt": "2026-10-09T11:00:00Z"}]
)
def test_completed_scan_exposes_durable_identity_tool_and_optional_database_metadata(
    api_database, metadata
):
    scan_id = seed(api_database, metadata=metadata)
    body = fetch(scan_id)
    assert body["digest"] == DIGEST
    assert body["platform"] == "linux/amd64"
    assert body["scanner_name"] == "trivy" and body["scanner_version"] == "0.75.0"
    assert body["scanner_database_metadata"] == metadata
    assert timestamp(body["created_at"]) == CREATED
    assert timestamp(body["started_at"]) == STARTED
    assert timestamp(body["completed_at"]) == COMPLETED
    assert body["status"] == "completed" and body["mock"] is False
    assert body["error_details"] is None


def test_unresolved_failure_exposes_safe_details_without_image_identity(api_database):
    body = fetch(seed(api_database, status="failed"))
    assert body["status"] == "failed" and body["mock"] is False
    assert body["digest"] is None and body["platform"] is None
    assert (
        body["error_details"]
        == "resolution_failed: Image reference could not be resolved"
    )
    assert timestamp(body["completed_at"]) == COMPLETED


def test_legacy_mock_record_is_identified_without_fabricated_scanner_metadata(
    api_database,
):
    body = fetch(seed(api_database, mock=True))
    assert body["status"] == "completed" and body["mock"] is True
    assert body["digest"] is None and body["platform"] is None
    assert body["scanner_name"] is None and body["scanner_version"] is None
    assert body["started_at"] is None
    assert timestamp(body["completed_at"]) == COMPLETED


def test_repository_returns_details_visible_from_a_new_session(api_database):
    scan_id = seed(api_database)
    with Session(api_database) as session:
        result = repository.get_scan(session, scan_id)
    assert result.digest == DIGEST
    assert result.created_at == CREATED
    assert result.platform == "linux/amd64"
    assert result.mock is False
    with Session(api_database) as session:
        assert repository.get_scan(session, uuid4()) is None


def test_history_stays_compact_and_details_do_not_load_findings_or_artifacts(
    api_database,
):
    scan_id = seed(api_database)
    statements = []

    def capture(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement.lower())

    event.listen(api_database, "before_cursor_execute", capture)
    try:
        body = fetch(scan_id)
    finally:
        event.remove(api_database, "before_cursor_execute", capture)
    assert body["digest"] == DIGEST
    assert 1 <= len(statements) <= 2
    assert not any("findings" in sql or "sbom_artifacts" in sql for sql in statements)
    with TestClient(app) as client:
        history = client.get("/api/v1/scans").json()
    assert history["items"] == [
        {
            "scan_id": str(scan_id),
            "image_reference": REFERENCE,
            "status": "completed",
        }
    ]
    assert history["total"] == 1
