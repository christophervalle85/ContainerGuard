from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, func, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.main import app
from app.persistence.models import Evaluation, SbomArtifact, Scan
from app.scanning.trivy.sbom import SbomOutcome
from tests.test_policy_evaluations import add_high_occurrences, policy
from tests.test_sbom_api import (  # noqa: F401
    api_database,
    parsed,
    seed,
    unavailable_database,
)


def path(scan_id):
    return f"/api/v1/scans/{scan_id}/evaluations"


def test_post_duplicate_and_list_saved_result(api_database):  # noqa: F811
    version = policy(api_database, require_sbom=False)
    scan_id = seed(api_database)
    add_high_occurrences(api_database, scan_id)
    with TestClient(app) as client:
        first = client.post(
            path(scan_id), json={"policy_version_id": str(version.policy_version_id)}
        )
        second = client.post(
            path(scan_id), json={"policy_version_id": str(version.policy_version_id)}
        )
        assert first.status_code == second.status_code == 200
        assert first.json() == second.json()
        body = first.json()
        assert body["scan_id"] == str(scan_id) and body["policy_id"] == str(
            version.policy_id
        )
        assert (
            body["policy_version_id"] == str(version.policy_version_id)
            and body["version_number"] == 1
        )
        assert body["outcome"] == "passed" and body["counts"]["HIGH"] == 2
        assert body["rule_snapshot"] == version.rules.model_dump()
        assert len(body["rules"]) == 4 and body["created_at"]
        assert body["evaluator_version"] == 1 and body["error_code"] is None
        page = client.get(path(scan_id), params={"limit": 1}).json()
        assert page == {"items": [body], "total": 1, "limit": 1, "offset": 0}
        assert client.get(path(scan_id), params={"offset": 1}).json()["items"] == []


@pytest.mark.parametrize(
    "status", ["queued", "running", "failed", "mock", "missing-image"]
)
def test_ineligible_scan_is_409(api_database, status):  # noqa: F811
    version = policy(api_database)
    scan_id = seed(
        api_database,
        status=status if status in {"queued", "running", "failed"} else "completed",
    )
    if status in {"mock", "missing-image"}:
        with api_database.begin() as connection:
            connection.execute(
                update(Scan).values(
                    **(
                        {"scanner_name": None}
                        if status == "mock"
                        else {"image_id": None}
                    )
                )
            )
    with TestClient(app) as client:
        assert (
            client.post(
                path(scan_id),
                json={"policy_version_id": str(version.policy_version_id)},
            ).status_code
            == 409
        )
        assert client.get(path(scan_id)).json()["total"] == 0


@pytest.mark.parametrize("missing", ["scan", "version"])
def test_missing_evaluation_input_is_404(api_database, missing):  # noqa: F811
    version = policy(api_database)
    scan_id = seed(api_database)
    with TestClient(app) as client:
        response = client.post(
            path(uuid4() if missing == "scan" else scan_id),
            json={
                "policy_version_id": str(
                    uuid4() if missing == "version" else version.policy_version_id
                )
            },
        )
        assert response.status_code == 404
        assert client.get(path(uuid4())).status_code == 404


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"policy_version_id": "not-uuid"},
        {"policy_version_id": None},
        {"policy_version_id": str(uuid4()), "latest": True},
    ],
)
def test_explicit_valid_version_is_required(api_database, body):  # noqa: F811
    scan_id = seed(api_database)
    with TestClient(app) as client:
        assert client.post(path(scan_id), json=body).status_code == 422


def test_corrupt_artifact_returns_persisted_safe_error(api_database):  # noqa: F811
    version = policy(api_database)
    scan_id = seed(api_database, outcome=SbomOutcome(parsed(), None))
    with api_database.begin() as connection:
        connection.execute(update(SbomArtifact).values(sha256="0" * 64))
    with TestClient(app) as client:
        response = client.post(
            path(scan_id), json={"policy_version_id": str(version.policy_version_id)}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["outcome"] == "error" and body["error_code"] == "invalid_evidence"
        assert body["rules"] == [] and body["error_details"]
        assert (
            client.post(
                path(scan_id),
                json={"policy_version_id": str(version.policy_version_id)},
            ).json()
            == body
        )
        assert client.get(path(scan_id)).json()["items"] == [body]


def test_list_pagination_is_stable_and_never_loads_artifact_payload(api_database):  # noqa: F811
    from app.persistence import policies
    from app.policies.schemas import PolicyRules
    from tests.test_policy_schemas import RULES

    version = policy(api_database, require_sbom=False)
    scan_id = seed(api_database)
    ids = []
    with TestClient(app) as client:
        for index in range(3):
            if index:
                with Session(api_database) as session:
                    version = policies.create_policy_version(
                        session,
                        version.policy_id,
                        PolicyRules(**(RULES | {"require_sbom": False})),
                    )
            response = client.post(
                path(scan_id),
                json={"policy_version_id": str(version.policy_version_id)},
            )
            ids.append(response.json()["evaluation_id"])
        with api_database.begin() as connection:
            connection.execute(
                update(Evaluation).values(created_at=datetime(2026, 1, 1, tzinfo=UTC))
            )
        statements = []

        def capture(connection, cursor, statement, parameters, context, executemany):
            statements.append(statement.lower())

        event.listen(api_database, "before_cursor_execute", capture)
        try:
            items = [
                client.get(path(scan_id), params={"limit": 1, "offset": index}).json()[
                    "items"
                ][0]
                for index in range(3)
            ]
        finally:
            event.remove(api_database, "before_cursor_execute", capture)
        assert [item["evaluation_id"] for item in items] == sorted(ids, reverse=True)
        assert all("payload" not in sql and "findings" not in sql for sql in statements)
        for params in ({"limit": 0}, {"limit": 101}, {"offset": -1}):
            assert client.get(path(scan_id), params=params).status_code == 422


@pytest.mark.usefixtures("unavailable_database")
@pytest.mark.parametrize("method", ["post", "get"])
def test_database_outage_returns_safe_503(method):
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.request(
            method,
            path(uuid4()),
            **(
                {"json": {"policy_version_id": str(uuid4())}}
                if method == "post"
                else {}
            ),
        )
    assert response.status_code == 503
    assert response.json() == {"detail": "Database temporarily unavailable"}


def test_insert_outage_returns_503_and_leaves_no_result(api_database):  # noqa: F811
    version = policy(api_database, require_sbom=False)
    scan_id = seed(api_database)

    def reject(connection, cursor, statement, parameters, context, executemany):
        if "insert into" in statement.lower() and "evaluations" in statement.lower():
            raise SQLAlchemyError("private SQL diagnostics")

    event.listen(api_database, "before_cursor_execute", reject)
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.post(
                path(scan_id),
                json={"policy_version_id": str(version.policy_version_id)},
            )
    finally:
        event.remove(api_database, "before_cursor_execute", reject)
    assert response.status_code == 503
    assert response.json() == {"detail": "Database temporarily unavailable"}
    with Session(api_database) as session:
        assert session.scalar(select(func.count()).select_from(Evaluation)) == 0
