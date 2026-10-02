from collections.abc import Iterator
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.store import findings, scans

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_scan_store() -> Iterator[None]:
    scans.clear()
    findings.clear()
    try:
        yield
    finally:
        scans.clear()
        findings.clear()


def test_submit_scan_returns_accepted_response() -> None:
    response = client.post(
        "/api/v1/scans",
        json={"image_reference": "docker.io/library/alpine:3.20"},
    )

    assert response.status_code == 202
    body = response.json()
    scan_id = UUID(body["scan_id"])
    assert body["status"] == "completed"
    assert body["status_url"] == f"/api/v1/scans/{scan_id}"


def test_submitted_scan_can_be_retrieved() -> None:
    submitted = client.post(
        "/api/v1/scans",
        json={"image_reference": "docker.io/library/alpine:3.20"},
    )
    assert submitted.status_code == 202
    accepted = submitted.json()

    response = client.get(accepted["status_url"])

    assert response.status_code == 200
    assert response.json() == {
        "scan_id": accepted["scan_id"],
        "image_reference": "docker.io/library/alpine:3.20",
        "status": "completed",
    }


def test_unknown_scan_returns_not_found() -> None:
    response = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000")

    assert response.status_code == 404
    assert response.json() == {"detail": "Scan not found"}


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"image_reference": ""},
        {"image_reference": "   "},
        {"image_reference": 123},
        {"image_reference": "a" * 513},
    ],
    ids=["missing", "empty", "whitespace", "number", "too-long"],
)
def test_invalid_submission_does_not_create_scan(payload: dict) -> None:
    existing_ids = set(scans)

    response = client.post("/api/v1/scans", json=payload)

    assert response.status_code == 422
    assert set(scans) == existing_ids


def test_scan_history_is_empty_initially() -> None:
    response = client.get("/api/v1/scans")

    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0, "limit": 20, "offset": 0}


def test_scan_history_paginates_newest_first() -> None:
    first = client.post(
        "/api/v1/scans",
        json={"image_reference": "docker.io/library/alpine:3.20"},
    )
    second = client.post(
        "/api/v1/scans",
        json={"image_reference": "docker.io/library/nginx:1.27"},
    )
    assert first.status_code == second.status_code == 202

    page_one = client.get("/api/v1/scans", params={"limit": 1, "offset": 0})
    page_two = client.get("/api/v1/scans", params={"limit": 1, "offset": 1})
    past_end = client.get("/api/v1/scans", params={"limit": 1, "offset": 2})

    for page in [page_one, page_two, past_end]:
        assert page.status_code == 200
        assert page.json()["total"] == 2
        assert page.json()["limit"] == 1

    assert page_one.json()["items"] == [
        {
            "scan_id": second.json()["scan_id"],
            "image_reference": "docker.io/library/nginx:1.27",
            "status": "completed",
        }
    ]
    assert page_two.json()["items"] == [
        {
            "scan_id": first.json()["scan_id"],
            "image_reference": "docker.io/library/alpine:3.20",
            "status": "completed",
        }
    ]
    assert page_one.json()["offset"] == 0
    assert page_two.json()["offset"] == 1
    assert past_end.json()["offset"] == 2
    assert past_end.json()["items"] == []


@pytest.mark.parametrize(
    "params",
    [{"limit": 0}, {"limit": 101}, {"offset": -1}, {"limit": "abc"}],
    ids=["zero-limit", "over-limit", "negative-offset", "noninteger-limit"],
)
def test_scan_history_rejects_invalid_pagination(params: dict) -> None:
    response = client.get("/api/v1/scans", params=params)

    assert response.status_code == 422


@pytest.fixture
def findings_url() -> str:
    response = client.post(
        "/api/v1/scans",
        json={"image_reference": "docker.io/library/alpine:3.20"},
    )
    assert response.status_code == 202
    return f"{response.json()['status_url']}/findings"


def test_findings_returns_fictional_records(findings_url: str) -> None:
    response = client.get(findings_url)

    assert response.status_code == 200
    body = response.json()
    assert body["mock"] is True
    assert body["total"] == 3
    assert body["limit"] == 20
    assert body["offset"] == 0
    assert [item["vulnerability_id"] for item in body["items"]] == [
        "MOCK-001",
        "MOCK-002",
        "MOCK-003",
    ]
    assert body["items"][2]["fixed_version"] is None


def test_findings_paginates(findings_url: str) -> None:
    response = client.get(findings_url, params={"limit": 1, "offset": 1})
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert body["limit"] == 1
    assert body["offset"] == 1
    assert [item["vulnerability_id"] for item in body["items"]] == ["MOCK-002"]

    past_end = client.get(findings_url, params={"offset": 3})
    assert past_end.status_code == 200
    assert past_end.json()["items"] == []
    assert past_end.json()["total"] == 3


@pytest.mark.parametrize(
    ("severity", "expected_ids"),
    [("HIGH", ["MOCK-002"]), ("UNKNOWN", ["MOCK-003"]), ("LOW", [])],
)
def test_findings_filters_before_pagination(
    findings_url: str, severity: str, expected_ids: list[str]
) -> None:
    response = client.get(
        findings_url, params={"severity": severity, "limit": 1, "offset": 0}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == len(expected_ids)
    assert [item["vulnerability_id"] for item in body["items"]] == expected_ids
    assert all(item["severity"] == severity for item in body["items"])


def test_findings_for_unknown_scan_returns_not_found() -> None:
    response = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000/findings")
    assert response.status_code == 404
    assert response.json() == {"detail": "Scan not found"}


@pytest.mark.parametrize(
    "params",
    [{"severity": "INVALID"}, {"limit": 0}, {"limit": 101}, {"offset": -1}],
)
def test_findings_rejects_invalid_query(findings_url: str, params: dict) -> None:
    response = client.get(findings_url, params=params)
    assert response.status_code == 422


def test_scan_status_contract_defines_all_lifecycle_states() -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schemas = response.json()["components"]["schemas"]

    assert "ScanStatus" in schemas
    assert set(schemas["ScanStatus"]["enum"]) == {
        "queued",
        "running",
        "completed",
        "failed",
    }
    for name in ["ScanRecord", "ScanAccepted"]:
        assert schemas[name]["properties"]["status"]["$ref"] == (
            "#/components/schemas/ScanStatus"
        )


def test_separate_submissions_keep_distinct_records() -> None:
    first = client.post(
        "/api/v1/scans", json={"image_reference": "docker.io/library/alpine:3.20"}
    )
    second = client.post(
        "/api/v1/scans", json={"image_reference": "docker.io/library/nginx:1.27"}
    )
    assert first.status_code == second.status_code == 202
    assert first.json()["scan_id"] != second.json()["scan_id"]
    for submitted, expected_image in [
        (first, "docker.io/library/alpine:3.20"),
        (second, "docker.io/library/nginx:1.27"),
    ]:
        retrieved = client.get(submitted.json()["status_url"])
        assert retrieved.status_code == 200
        assert retrieved.json()["image_reference"] == expected_image


@pytest.mark.parametrize(
    "path", ["/api/v1/scans/{scan_id}", "/api/v1/scans/{scan_id}/findings"]
)
def test_retrieval_contract_documents_not_found(path: str) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    contract = response.json()
    responses = contract["paths"][path]["get"]["responses"]
    assert "404" in responses
    schema = responses["404"]["content"]["application/json"]["schema"]
    assert schema["$ref"] == "#/components/schemas/ErrorResponse"
    error = contract["components"]["schemas"]["ErrorResponse"]
    assert error["properties"]["detail"]["type"] == "string"
    assert "detail" in error["required"]
