from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.main import app
from tests.test_policy_schemas import RULES
from tests.test_sbom_api import api_database, unavailable_database  # noqa: F401


def create(client, name="release", rules=None):
    return client.post("/api/v1/policies", json={"name": name, "rules": rules or RULES})


@pytest.mark.usefixtures("api_database")
def test_create_and_list_immutable_versions():
    with TestClient(app) as client:
        response = create(client, "  release  ")
        assert response.status_code == 201
        first = response.json()
        assert first["version_number"] == 1 and first["rules"] == RULES
        endpoint = f"/api/v1/policies/{first['policy_id']}/versions"
        response = client.post(endpoint, json={"rules": RULES | {"max_high": 0}})
        assert response.status_code == 201
        second = response.json()
        assert second["version_number"] == 2
        assert second["policy_version_id"] != first["policy_version_id"]
        listed = client.get(endpoint, params={"limit": 1, "offset": 0}).json()
        assert listed["total"] == 2 and listed["items"] == [second]
        assert listed["limit"] == 1 and listed["offset"] == 0
        assert client.get(endpoint, params={"limit": 1, "offset": 1}).json()[
            "items"
        ] == [first]
        assert client.get(endpoint, params={"offset": 2}).json()["items"] == []
        for method in ("put", "patch", "delete"):
            assert client.request(method, endpoint).status_code == 405


@pytest.mark.usefixtures("api_database")
def test_name_conflict_and_case_sensitive_names():
    with TestClient(app) as client:
        assert create(client, "Release").status_code == 201
        assert create(client, "release").status_code == 201
        assert create(client, " Release ").status_code == 409
        assert client.get("/api/v1/policies").json()["total"] == 2


def test_policy_pagination_has_stable_timestamp_tiebreaker(api_database):  # noqa: F811
    from app.persistence.models import Policy

    with TestClient(app) as client:
        ids = [create(client, name).json()["policy_id"] for name in ("a", "b", "c")]
        with Session(api_database) as session, session.begin():
            from datetime import UTC, datetime

            session.execute(
                update(Policy).values(created_at=datetime(2026, 1, 1, tzinfo=UTC))
            )
        expected = sorted(ids, reverse=True)
        actual = [
            client.get(
                "/api/v1/policies", params={"limit": 1, "offset": offset}
            ).json()["items"][0]["policy_id"]
            for offset in range(3)
        ]
        assert actual == expected
        page = client.get("/api/v1/policies", params={"offset": 3}).json()
        assert page["total"] == 3 and page["items"] == []


@pytest.mark.usefixtures("api_database")
@pytest.mark.parametrize("method", ["get", "post"])
def test_missing_parent_is_404(method):
    with TestClient(app) as client:
        response = client.request(
            method,
            f"/api/v1/policies/{uuid4()}/versions",
            **({"json": {"rules": RULES}} if method == "post" else {}),
        )
    assert response.status_code == 404


@pytest.mark.usefixtures("api_database")
@pytest.mark.parametrize(
    "payload",
    [
        {"name": "", "rules": RULES},
        {"name": "release", "rules": RULES | {"max_high": True}},
        {"name": "release", "rules": RULES | {"max_high": "5"}},
        {"name": "release", "rules": RULES | {"extra": 0}},
        {"name": "release", "rules": RULES, "extra": 0},
        {"name": "release"},
    ],
)
def test_invalid_create_is_422_without_policy(payload):
    with TestClient(app) as client:
        assert client.post("/api/v1/policies", json=payload).status_code == 422
        assert client.get("/api/v1/policies").json()["total"] == 0


@pytest.mark.usefixtures("api_database")
def test_invalid_version_does_not_change_history():
    with TestClient(app) as client:
        first = create(client).json()
        endpoint = f"/api/v1/policies/{first['policy_id']}/versions"
        assert (
            client.post(
                endpoint, json={"rules": RULES | {"require_sbom": "true"}}
            ).status_code
            == 422
        )
        assert client.get(endpoint).json()["items"] == [first]
        for params in ({"limit": 0}, {"limit": 101}, {"offset": -1}):
            assert client.get(endpoint, params=params).status_code == 422
            assert client.get("/api/v1/policies", params=params).status_code == 422


@pytest.mark.usefixtures("unavailable_database")
@pytest.mark.parametrize(
    "method, endpoint, body",
    [
        ("post", "/api/v1/policies", {"name": "release", "rules": RULES}),
        ("get", "/api/v1/policies", None),
        (
            "post",
            "/api/v1/policies/00000000-0000-0000-0000-000000000000/versions",
            {"rules": RULES},
        ),
        ("get", "/api/v1/policies/00000000-0000-0000-0000-000000000000/versions", None),
    ],
)
def test_policy_outage_is_safe_503(method, endpoint, body):
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.request(method, endpoint, **({"json": body} if body else {}))
    assert response.status_code == 503
    assert response.json() == {"detail": "Database temporarily unavailable"}
