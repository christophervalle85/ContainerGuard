import hashlib
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, text, update
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.main import app
from app.persistence import repository
from app.persistence.artifacts import add_sbom_outcome
from app.persistence.database import get_session
from app.persistence.models import Image, SbomArtifact, Scan
from app.scanning.trivy.parser import ParsedScanMetadata
from app.scanning.trivy.sbom import SbomOutcome, parse_sbom
from tests.database_support import isolated_repository_engine
from tests.test_database_errors import unavailable_database  # noqa: F401

PINNED = (
    "docker.io/library/alpine@sha256:"
    "216266c86fc4dcef5619930bd394245824c2af52fd21ba7c6fa0e618657d4c3b"
)
SUBMISSION = ScanSubmission(image_reference="docker.io/library/alpine:3.20.0")


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


def parsed():
    payload = b" \n" + Path("tests/fixtures/trivy/cyclonedx.json").read_bytes()
    return parse_sbom(
        payload,
        pinned_reference=PINNED,
        platform="linux/amd64",
        scanner_version="0.75.0",
    )


def seed(engine, status="completed", outcome=None):
    with Session(engine) as session:
        scan_id = repository.start_trivy_scan(session, SUBMISSION)
        if status == "completed":
            repository.complete_trivy_scan(
                session,
                scan_id,
                PINNED,
                ParsedScanMetadata(
                    PINNED, PINNED.split("@")[1], "linux/amd64", "0.75.0"
                ),
                [],
                sbom_outcome=outcome,
            )
        else:
            with session.begin():
                session.get(Scan, scan_id).status = status
    return scan_id


def path(scan_id):
    return f"/api/v1/scans/{scan_id}/sbom"


@pytest.mark.parametrize("suffix", ["", "/metadata"])
def test_unknown_scan_is_404(api_database, suffix):
    with TestClient(app) as client:
        response = client.get(path(uuid4()) + suffix)
    assert response.status_code == 404
    assert response.json() == {"detail": "Scan not found"}


@pytest.mark.parametrize(
    "status, expected, code",
    [
        ("queued", "pending", 409),
        ("running", "pending", 409),
        ("failed", "not_generated", 404),
        ("completed", "not_generated", 404),
    ],
)
def test_scan_without_artifact_distinguishes_pending_from_not_generated(
    api_database, status, expected, code
):
    scan_id = seed(api_database, status)
    with TestClient(app) as client:
        metadata = client.get(path(scan_id) + "/metadata")
        download = client.get(path(scan_id))
    assert metadata.status_code == 200
    assert metadata.json()["scan_id"] == str(scan_id)
    assert metadata.json()["status"] == expected
    assert metadata.json()["sha256"] is None
    assert download.status_code == code


@pytest.mark.parametrize("error_code", ["sbom_timeout", "sbom_invalid_report"])
def test_failed_artifact_returns_safe_metadata_and_no_download(
    api_database, error_code
):
    scan_id = seed(api_database, outcome=SbomOutcome(None, error_code))
    with api_database.begin() as connection:
        connection.execute(
            update(SbomArtifact).values(error_details="private raw diagnostics")
        )
    with TestClient(app) as client:
        metadata = client.get(path(scan_id) + "/metadata")
        download = client.get(path(scan_id))
    assert metadata.status_code == 200
    body = metadata.json()
    assert body["status"] == "failed" and body["error_code"] == error_code
    assert body["error_details"] and "private" not in metadata.text
    assert body["size_bytes"] is None and body["sha256"] is None
    assert download.status_code == 404


def test_download_is_original_json_with_integrity_headers(api_database):
    artifact = parsed()
    scan_id = seed(api_database, outcome=SbomOutcome(artifact, None))
    with TestClient(app) as client:
        metadata = client.get(path(scan_id) + "/metadata")
        response = client.get(path(scan_id))
    assert metadata.status_code == 200
    body = metadata.json()
    assert body["status"] == "available"
    assert body["format"] == "CycloneDX" and body["format_version"] == "1.7"
    assert body["scanner_version"] == "0.75.0" and body["platform"] == "linux/amd64"
    assert body["pinned_reference"] == PINNED and body["digest"] == PINNED.split("@")[1]
    assert body["size_bytes"] == len(artifact.payload)
    assert body["sha256"] == hashlib.sha256(artifact.payload).hexdigest()
    assert body["created_at"] and body["error_code"] is None
    assert "payload" not in body
    assert response.status_code == 200
    assert response.content == artifact.payload
    assert response.headers["content-type"] == "application/json"
    assert response.headers["etag"] == '"' + artifact.sha256 + '"'
    assert (
        response.headers["content-disposition"]
        == f'attachment; filename="{scan_id}.cdx.json"'
    )


@pytest.mark.parametrize(
    "change",
    [
        "checksum",
        "size",
        "artifact-reference",
        "artifact-platform",
        "image-digest",
        "image-repository",
        "image-platform",
        "scanner-version",
        "format-version",
        "missing-image",
        "malformed-payload",
        "oversized-payload",
    ],
)
def test_corrupted_evidence_returns_safe_error_without_payload(api_database, change):
    artifact = parsed()
    scan_id = seed(api_database, outcome=SbomOutcome(artifact, None))
    with api_database.begin() as connection:
        updates = {}
        if change == "checksum":
            updates["sha256"] = "0" * 64
        elif change == "size":
            schema = connection.get_execution_options()["schema_translate_map"][None]
            connection.execute(
                text(
                    f'ALTER TABLE "{schema}".sbom_artifacts '
                    "DROP CONSTRAINT ck_sbom_artifacts_size"
                )
            )
            updates["size_bytes"] = 1
        elif change == "artifact-reference":
            updates["pinned_reference"] = PINNED.replace("216266c8", "ffffffff")
        elif change == "artifact-platform":
            updates["platform"] = "linux/arm64"
        elif change == "image-digest":
            connection.execute(update(Image).values(digest="sha256:" + "a" * 64))
        elif change == "image-repository":
            connection.execute(update(Image).values(repository="library/other"))
        elif change == "image-platform":
            connection.execute(update(Image).values(platform="linux/arm64"))
        elif change == "scanner-version":
            connection.execute(update(Scan).values(scanner_version="0.74.0"))
        elif change == "format-version":
            updates["format_version"] = "1.6"
        elif change == "missing-image":
            connection.execute(update(Scan).values(image_id=None))
        elif change == "malformed-payload":
            payload = b"private malformed report"
            updates.update(
                payload=payload,
                size_bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        elif change == "oversized-payload":
            schema = connection.get_execution_options()["schema_translate_map"][None]
            connection.execute(
                text(
                    f'ALTER TABLE "{schema}".sbom_artifacts '
                    "DROP CONSTRAINT ck_sbom_artifacts_size"
                )
            )
            payload = b" " * 10485761
            updates.update(
                payload=payload,
                size_bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        if updates:
            connection.execute(update(SbomArtifact).values(**updates))
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get(path(scan_id))
    assert response.status_code == 500
    assert response.json() == {"detail": "Stored SBOM failed integrity verification"}
    assert "private" not in response.text and "CycloneDX" not in response.text
    assert "etag" not in response.headers


def test_unfinished_scan_cannot_download_even_if_artifact_exists(api_database):
    scan_id = seed(api_database, status="running")
    with Session(api_database) as session, session.begin():
        add_sbom_outcome(session, scan_id, SbomOutcome(parsed(), None))
    with TestClient(app) as client:
        assert client.get(path(scan_id)).status_code == 409


def test_metadata_and_history_queries_never_select_payload(api_database):
    scan_id = seed(api_database, outcome=SbomOutcome(parsed(), None))
    statements = []

    def capture(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement.lower())

    event.listen(api_database, "before_cursor_execute", capture)
    try:
        with TestClient(app) as client:
            for endpoint in [
                path(scan_id) + "/metadata",
                "/api/v1/scans",
                f"/api/v1/scans/{scan_id}",
            ]:
                assert client.get(endpoint).status_code == 200
    finally:
        event.remove(api_database, "before_cursor_execute", capture)
    assert any("sbom_artifacts" in sql for sql in statements)
    assert all("payload" not in sql for sql in statements)


@pytest.mark.usefixtures("unavailable_database")
@pytest.mark.parametrize("suffix", ["", "/metadata"])
def test_database_failure_is_safe_503(suffix):
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get(path(uuid4()) + suffix)
    assert response.status_code == 503
    assert response.json() == {"detail": "Database temporarily unavailable"}


@pytest.mark.parametrize(
    "suffix, codes", [("", {"404", "409", "500", "503"}), ("/metadata", {"404", "503"})]
)
def test_openapi_documents_artifact_errors(suffix, codes):
    with TestClient(app) as client:
        contract = client.get("/openapi.json").json()
    responses = contract["paths"]["/api/v1/scans/{scan_id}/sbom" + suffix]["get"][
        "responses"
    ]
    assert codes <= responses.keys()
