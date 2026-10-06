from datetime import UTC, datetime
from importlib import import_module
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Finding, Image, Scan
from app.schemas import ScanSubmission, Severity
from tests.database_support import isolated_repository_engine


def test_submission_commits_scan_and_findings_for_another_connection() -> None:
    repository = import_module("app.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            accepted = repository.create_scan(
                session,
                ScanSubmission(image_reference="docker.io/library/alpine:3.20"),
            )
        with Session(engine) as session:
            stored = session.get(Scan, accepted.scan_id)
            assert stored is not None
            assert stored.submitted_reference == "docker.io/library/alpine:3.20"
            assert stored.status == "completed"
            assert stored.image_id is None
            assert stored.completed_at is not None
            assert stored.scanner_name is None
            assert session.scalar(select(func.count()).select_from(Image)) == 0
            rows = session.scalars(
                select(Finding)
                .where(Finding.scan_id == accepted.scan_id)
                .order_by(Finding.occurrence_order)
            ).all()
            assert [row.vulnerability_id for row in rows] == [
                "MOCK-001",
                "MOCK-002",
                "MOCK-003",
            ]
            assert rows[2].severity == "UNKNOWN"
            assert rows[2].fixed_version is None
            assert accepted.status_url == f"/api/v1/scans/{accepted.scan_id}"


def test_finding_write_failure_rolls_back_entire_submission(monkeypatch) -> None:
    repository = import_module("app.repository")
    original = repository.build_mock_findings
    sample = original()[0]
    monkeypatch.setattr(repository, "build_mock_findings", lambda: [sample, sample])
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            with pytest.raises(IntegrityError):
                repository.create_scan(
                    session,
                    ScanSubmission(image_reference="docker.io/library/alpine:3.20"),
                )
            assert not session.in_transaction()
        with Session(engine) as session:
            assert session.scalar(select(func.count()).select_from(Scan)) == 0
            assert session.scalar(select(func.count()).select_from(Finding)) == 0


def test_get_scan_returns_requested_record_from_a_new_session() -> None:
    repository = import_module("app.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            accepted = repository.create_scan(
                session,
                ScanSubmission(image_reference="docker.io/library/alpine:3.20"),
            )
            repository.create_scan(
                session,
                ScanSubmission(image_reference="docker.io/library/nginx:1.27"),
            )
        with Session(engine) as session:
            record = repository.get_scan(session, accepted.scan_id)
        assert record is not None
        assert record.scan_id == accepted.scan_id
        assert record.image_reference == "docker.io/library/alpine:3.20"
        assert record.status == "completed"


def test_get_scan_returns_none_for_an_unknown_id() -> None:
    repository = import_module("app.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            repository.create_scan(
                session,
                ScanSubmission(image_reference="docker.io/library/alpine:3.20"),
            )
        with Session(engine) as session:
            assert repository.get_scan(session, uuid4()) is None


@pytest.mark.parametrize(
    ("limit", "offset", "expected_ids"),
    [
        (20, 0, [2, 1, 3]),
        (1, 1, [1]),
        (2, 10, []),
    ],
)
def test_scan_history_orders_and_paginates_saved_records(
    limit: int, offset: int, expected_ids: list[int]
) -> None:
    repository = import_module("app.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as session, session.begin():
            session.add_all(
                [
                    Scan(
                        id=UUID(int=number),
                        submitted_reference=f"demo/image:{number}",
                        status="completed",
                        created_at=datetime(2026, 1, day, tzinfo=UTC),
                    )
                    for number, day in [(3, 1), (2, 2), (1, 2)]
                ]
            )
        with Session(engine) as session:
            page = repository.get_scan_history(session, limit=limit, offset=offset)
        assert [item.scan_id for item in page.items] == [
            UUID(int=number) for number in expected_ids
        ]
        assert [item.image_reference for item in page.items] == [
            f"demo/image:{number}" for number in expected_ids
        ]
        assert all(item.status == "completed" for item in page.items)
        assert page.total == 3
        assert page.limit == limit
        assert page.offset == offset


def test_scan_history_returns_an_empty_page_when_no_scans_exist() -> None:
    repository = import_module("app.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            page = repository.get_scan_history(session, limit=20, offset=0)
        assert page.items == []
        assert page.total == 0
        assert page.limit == 20
        assert page.offset == 0


@pytest.mark.parametrize(
    ("severity", "limit", "offset", "expected_ids", "expected_total"),
    [
        (None, 20, 0, ["MOCK-001", "MOCK-002", "MOCK-003"], 3),
        (Severity.HIGH, 1, 0, ["MOCK-002"], 1),
        (Severity.HIGH, 1, 1, [], 1),
        (Severity.UNKNOWN, 20, 0, ["MOCK-003"], 1),
        (Severity.LOW, 20, 0, [], 0),
        (None, 1, 1, ["MOCK-002"], 3),
        (None, 20, 10, [], 3),
    ],
)
def test_scan_findings_filter_before_pagination_and_stay_with_their_scan(
    severity: Severity | None,
    limit: int,
    offset: int,
    expected_ids: list[str],
    expected_total: int,
) -> None:
    repository = import_module("app.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            accepted = repository.create_scan(
                session, ScanSubmission(image_reference="demo/image:first")
            )
            repository.create_scan(
                session, ScanSubmission(image_reference="demo/image:second")
            )
        with Session(engine) as session:
            page = repository.get_scan_findings(
                session, accepted.scan_id, limit=limit, offset=offset, severity=severity
            )
        assert page is not None
        assert [item.vulnerability_id for item in page.items] == expected_ids
        assert page.total == expected_total
        assert page.limit == limit
        assert page.offset == offset
        assert page.mock is True
        if "MOCK-003" in expected_ids:
            unknown = next(
                item for item in page.items if item.vulnerability_id == "MOCK-003"
            )
            assert unknown.severity == Severity.UNKNOWN
            assert unknown.fixed_version is None
        if "MOCK-002" in expected_ids:
            high = next(
                item for item in page.items if item.vulnerability_id == "MOCK-002"
            )
            assert high.package_name == "demo-library-b"
            assert high.installed_version == "2.0"
            assert high.fixed_version == "2.1"
            assert high.severity == Severity.HIGH
            assert high.title == "Fictional high finding for API demonstration"


def test_scan_findings_returns_none_for_an_unknown_scan() -> None:
    repository = import_module("app.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            assert (
                repository.get_scan_findings(
                    session, uuid4(), limit=20, offset=0, severity=None
                )
                is None
            )


def test_scan_findings_returns_empty_page_for_a_saved_scan_without_findings() -> None:
    repository = import_module("app.repository")
    scan_id = uuid4()
    with isolated_repository_engine() as engine:
        with Session(engine) as session, session.begin():
            session.add(
                Scan(
                    id=scan_id, submitted_reference="demo/image:failed", status="failed"
                )
            )
        with Session(engine) as session:
            page = repository.get_scan_findings(
                session, scan_id, limit=20, offset=0, severity=None
            )
        assert page is not None
        assert page.items == []
        assert page.total == 0
        assert page.limit == 20
        assert page.offset == 0
