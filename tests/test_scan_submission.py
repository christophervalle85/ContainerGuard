from importlib import import_module

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import ScanSubmission
from app.persistence.models import Finding, Image, Scan
from tests.database_support import isolated_repository_engine

SUBMISSION = ScanSubmission(image_reference="docker.io/library/alpine:3.20")


def test_queued_real_scan_is_committed_without_starting_or_creating_results():
    repository = import_module("app.persistence.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as creator:
            scan_id = repository.create_queued_trivy_scan(creator, SUBMISSION)
            assert not creator.in_transaction()
            with Session(engine) as observer:
                stored = observer.get(Scan, scan_id)
                assert stored is not None
                assert stored.submitted_reference == "docker.io/library/alpine:3.20"
                assert stored.status == "queued"
                assert stored.scanner_name == "trivy"
                assert stored.created_at.tzinfo is not None
                assert stored.started_at is None
                assert stored.completed_at is None
                assert stored.image_id is None
                assert stored.scanner_version is None
                assert stored.scanner_database_metadata is None
                assert stored.error_details is None
                assert observer.scalar(select(func.count()).select_from(Image)) == 0
                assert observer.scalar(select(func.count()).select_from(Finding)) == 0
                record = repository.get_scan(observer, scan_id)
                assert record.status == "queued"
                page = repository.get_scan_findings(observer, scan_id, 20, 0)
                assert page.items == []
                assert page.total == 0
                assert page.mock is False


def test_repeated_submissions_have_independent_durable_queue_records():
    repository = import_module("app.persistence.repository")
    with isolated_repository_engine() as engine:
        with Session(engine) as creator:
            first = repository.create_queued_trivy_scan(creator, SUBMISSION)
            second = repository.create_queued_trivy_scan(creator, SUBMISSION)
        assert first != second
        with Session(engine) as observer:
            history = repository.get_scan_history(observer, limit=20, offset=0)
            assert history.total == 2
            assert {record.scan_id for record in history.items} == {first, second}
            assert all(record.status == "queued" for record in history.items)
