import hashlib
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.persistence.artifacts import add_sbom_outcome
from app.persistence.models import SbomArtifact, Scan
from app.scanning.trivy.sbom import SbomOutcome, parse_sbom
from tests.database_support import isolated_repository_engine

PINNED = (
    "docker.io/library/alpine@sha256:"
    "216266c86fc4dcef5619930bd394245824c2af52fd21ba7c6fa0e618657d4c3b"
)


def artifact(payload=None):
    if payload is None:
        payload = Path("tests/fixtures/trivy/cyclonedx.json").read_bytes()
    return parse_sbom(
        payload,
        pinned_reference=PINNED,
        platform="linux/amd64",
        scanner_version="0.75.0",
    )


def scan(session):
    row = Scan(submitted_reference="docker.io/library/alpine:3.20.0")
    session.add(row)
    session.flush()
    return row.id


def test_available_bytes_survive_new_session_without_loading_in_metadata():
    Model, add = SbomArtifact, add_sbom_outcome
    parsed = artifact()
    with isolated_repository_engine() as engine:
        with Session(engine) as session, session.begin():
            scan_id = scan(session)
            add(session, scan_id, SbomOutcome(parsed, None))
        with Session(engine) as session:
            row = session.scalar(select(Model).where(Model.scan_id == scan_id))
            assert "payload" in inspect(row).unloaded
            assert row.status == "available"
            assert row.payload == parsed.payload
            assert row.sha256 == hashlib.sha256(parsed.payload).hexdigest()
            assert row.size_bytes == len(parsed.payload)
            assert row.pinned_reference == PINNED
            assert row.platform == "linux/amd64"
            assert row.format == "CycloneDX"
            assert row.format_version == "1.7"
            assert row.scanner_version == "0.75.0"
            assert row.created_at.utcoffset().total_seconds() == 0
            assert row.error_code is None and row.error_details is None


@pytest.mark.parametrize(
    "code",
    [
        "sbom_timeout",
        "sbom_unavailable",
        "sbom_execution_failed",
        "sbom_output_limit",
        "sbom_invalid_report",
    ],
)
def test_failed_outcome_has_safe_message_and_no_usable_payload(code):
    Model, add = SbomArtifact, add_sbom_outcome
    with isolated_repository_engine() as engine:
        with Session(engine) as session, session.begin():
            scan_id = scan(session)
            add(session, scan_id, SbomOutcome(None, code))
        with Session(engine) as session:
            row = session.scalar(select(Model).where(Model.scan_id == scan_id))
            assert row.status == "failed" and row.error_code == code
            assert row.error_details and "Traceback" not in row.error_details
            assert row.payload is None and row.sha256 is None and row.size_bytes is None


def test_unknown_failure_code_is_rejected_without_writing():
    Model, add = SbomArtifact, add_sbom_outcome
    with isolated_repository_engine() as engine, Session(engine) as session:
        scan_id = scan(session)
        with pytest.raises(ValueError, match="Unknown SBOM failure"):
            add(session, scan_id, SbomOutcome(None, "secret diagnostic"))
        assert session.scalar(select(Model)) is None


def test_caller_rollback_removes_artifact():
    Model, add = SbomArtifact, add_sbom_outcome
    with isolated_repository_engine() as engine:
        with Session(engine) as session, session.begin():
            scan_id = scan(session)
        with Session(engine) as session:
            add(session, scan_id, SbomOutcome(artifact(), None))
            session.rollback()
        with Session(engine) as session:
            assert session.get(Scan, scan_id) is not None
            assert session.scalar(select(Model)) is None


def test_scan_can_only_have_one_outcome():
    add = add_sbom_outcome
    with isolated_repository_engine() as engine, Session(engine) as session:
        scan_id = scan(session)
        add(session, scan_id, SbomOutcome(artifact(), None))
        with pytest.raises(IntegrityError):
            add(session, scan_id, SbomOutcome(None, "sbom_timeout"))


def test_artifact_requires_existing_scan():
    add = add_sbom_outcome
    with isolated_repository_engine() as engine, Session(engine) as session:
        with pytest.raises(IntegrityError):
            add(session, uuid4(), SbomOutcome(artifact(), None))


def values(scan_id):
    parsed = artifact()
    return dict(
        scan_id=scan_id,
        status="available",
        payload=parsed.payload,
        size_bytes=parsed.size_bytes,
        sha256=parsed.sha256,
        format=parsed.format,
        format_version=parsed.format_version,
        scanner_version=parsed.scanner_version,
        pinned_reference=parsed.pinned_reference,
        platform=parsed.platform,
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"status": "pending"},
        {"payload": None},
        {"size_bytes": None},
        {"sha256": None},
        {"sha256": "bad"},
        {"sha256": "A" * 64},
        {"size_bytes": -1},
        {"size_bytes": 1},
        {"format": None},
        {"format_version": None},
        {"scanner_version": None},
        {"pinned_reference": None},
        {"platform": None},
        {"error_code": "sbom_timeout"},
        {"error_details": "unexpected"},
        {"status": "failed"},
        {"status": "failed", "payload": None, "size_bytes": None, "sha256": None},
        {
            "status": "failed",
            "payload": None,
            "size_bytes": None,
            "sha256": None,
            "error_code": "unknown",
            "error_details": "bad",
        },
    ],
)
def test_database_rejects_inconsistent_outcome(changes):
    Model = SbomArtifact
    with isolated_repository_engine() as engine, Session(engine) as session:
        data = values(scan(session))
        data.update(changes)
        session.add(Model(**data))
        with pytest.raises(IntegrityError):
            session.flush()


@pytest.mark.parametrize("extra", [0, 1])
def test_database_enforces_byte_limit(extra):
    Model = SbomArtifact
    payload = artifact().payload
    payload += b" " * (10485760 + extra - len(payload))
    with isolated_repository_engine() as engine, Session(engine) as session:
        data = values(scan(session))
        data.update(
            payload=payload,
            size_bytes=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
        )
        session.add(Model(**data))
        if extra:
            with pytest.raises(IntegrityError):
                session.flush()
        else:
            session.commit()
            assert session.scalar(select(Model)).payload == payload
