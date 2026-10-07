from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.main import app
from app.persistence.database import get_session

SCAN_PATH = "/api/v1/scans/00000000-0000-0000-0000-000000000000"


@pytest.fixture
def unavailable_database() -> Iterator[None]:
    # A real connection attempt to a closed local port, with no production data.
    engine = create_engine(
        "postgresql+psycopg://offline:private_test_password@127.0.0.1:1/containerguard_test",
        connect_args={"connect_timeout": 1},
    )

    def unavailable_session() -> Iterator[Session]:
        with Session(engine) as session:
            yield session

    previous_overrides = app.dependency_overrides.copy()
    app.dependency_overrides[get_session] = unavailable_session
    try:
        yield
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous_overrides)
        engine.dispose()


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/v1/scans"),
        ("GET", "/api/v1/scans"),
        ("GET", SCAN_PATH),
        ("GET", f"{SCAN_PATH}/findings"),
    ],
)
def test_database_failure_returns_safe_service_unavailable(
    unavailable_database: None, method: str, path: str
) -> None:
    with TestClient(app, raise_server_exceptions=False) as client:
        kwargs = (
            {"json": {"image_reference": "demo/image:offline"}}
            if method == "POST"
            else {}
        )
        response = client.request(method, path, **kwargs)
    assert response.status_code == 503
    assert response.json() == {"detail": "Database temporarily unavailable"}
    assert "private_test_password" not in response.text
    assert "psycopg" not in response.text


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("post", "/api/v1/scans"),
        ("get", "/api/v1/scans"),
        ("get", "/api/v1/scans/{scan_id}"),
        ("get", "/api/v1/scans/{scan_id}/findings"),
    ],
)
def test_scan_contract_documents_database_failure(method: str, path: str) -> None:
    with TestClient(app) as client:
        contract = client.get("/openapi.json").json()
    responses = contract["paths"][path][method]["responses"]
    assert "503" in responses
    assert responses["503"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ErrorResponse"
    }


def test_health_remains_available_without_database(unavailable_database: None) -> None:
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
