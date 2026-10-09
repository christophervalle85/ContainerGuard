from concurrent.futures import ThreadPoolExecutor
from importlib import import_module
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import event, func, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.persistence import policies
from app.persistence.models import Evaluation, Finding, Image, SbomArtifact, Scan
from app.policies.schemas import PolicyRules
from app.scanning.trivy.sbom import SbomOutcome
from tests.database_support import isolated_repository_engine
from tests.test_policy_schemas import RULES
from tests.test_sbom_api import parsed, seed


def service():
    return import_module("app.persistence.evaluations")


def policy(engine, **overrides):
    with Session(engine) as session:
        return policies.create_policy(
            session, "release", PolicyRules(**(RULES | overrides))
        )


def add_high_occurrences(engine, scan_id):
    with Session(engine) as session, session.begin():
        session.add_all(
            [
                Finding(
                    scan_id=scan_id,
                    vulnerability_id="CVE-same",
                    package_name=name,
                    package_type="apk",
                    target="alpine",
                    installed_version="1.0",
                    fixed_version=None,
                    severity="HIGH",
                    title="Fixture finding",
                    occurrence_order=number,
                )
                for number, name in enumerate(("library-a", "library-b"))
            ]
        )


@pytest.mark.parametrize(
    "artifact, required, expected",
    [
        ("available", True, "passed"),
        ("missing", True, "failed"),
        ("failed", True, "failed"),
        ("missing", False, "passed"),
        ("failed", False, "passed"),
    ],
)
def test_real_completed_scan_uses_verified_sbom_requirement(
    artifact, required, expected
):
    evaluator = service()
    with isolated_repository_engine() as engine:
        version = policy(engine, require_sbom=required)
        outcome = (
            SbomOutcome(parsed(), None)
            if artifact == "available"
            else SbomOutcome(None, "sbom_timeout")
            if artifact == "failed"
            else None
        )
        scan_id = seed(engine, outcome=outcome)
        with Session(engine) as session:
            result = evaluator.evaluate_scan(
                session, scan_id, version.policy_version_id
            )
            assert not session.in_transaction()
        assert result.outcome == expected and len(result.rules) == 4
        assert result.counts == {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0,
        }
        assert result.rule_snapshot == version.rules
        assert result.error_code is None


def test_repeated_cve_occurrences_are_counted_individually_in_sql():
    evaluator = service()
    with isolated_repository_engine() as engine:
        version = policy(engine, max_high=1, require_sbom=False)
        scan_id = seed(engine)
        add_high_occurrences(engine, scan_id)
        statements = []

        def capture(connection, cursor, statement, parameters, context, executemany):
            statements.append(statement.lower())

        event.listen(engine, "before_cursor_execute", capture)
        try:
            with Session(engine) as session:
                result = evaluator.evaluate_scan(
                    session, scan_id, version.policy_version_id
                )
        finally:
            event.remove(engine, "before_cursor_execute", capture)
        assert result.outcome == "failed" and result.counts["HIGH"] == 2
        assert any(
            "group by" in sql and "findings.severity" in sql and "count(" in sql
            for sql in statements
        )
        assert not any("findings.package_name" in sql for sql in statements)


@pytest.mark.parametrize(
    "state", ["queued", "running", "failed", "mock", "missing-image"]
)
def test_ineligible_scans_leave_no_evaluation(state):
    evaluator = service()
    with isolated_repository_engine() as engine:
        version = policy(engine)
        scan_id = seed(
            engine,
            status=state if state in {"queued", "running", "failed"} else "completed",
        )
        if state in {"mock", "missing-image"}:
            with engine.begin() as connection:
                connection.execute(
                    update(Scan).values(
                        **(
                            {"scanner_name": None}
                            if state == "mock"
                            else {"image_id": None}
                        )
                    )
                )
        with Session(engine) as session:
            with pytest.raises(evaluator.IneligibleScan):
                evaluator.evaluate_scan(session, scan_id, version.policy_version_id)
            assert not session.in_transaction()
            assert session.scalar(select(func.count()).select_from(Evaluation)) == 0


@pytest.mark.parametrize("missing", ["scan", "version"])
def test_missing_scan_or_version_leaves_no_evaluation(missing):
    evaluator = service()
    with isolated_repository_engine() as engine:
        version = policy(engine)
        scan_id = seed(engine)
        with Session(engine) as session:
            with pytest.raises(
                evaluator.ScanNotFound
                if missing == "scan"
                else evaluator.PolicyVersionNotFound
            ):
                evaluator.evaluate_scan(
                    session,
                    uuid4() if missing == "scan" else scan_id,
                    uuid4() if missing == "version" else version.policy_version_id,
                )
            assert session.scalar(select(func.count()).select_from(Evaluation)) == 0


@pytest.mark.parametrize("corruption", ["checksum", "reference", "platform"])
@pytest.mark.parametrize("required", [True, False])
def test_corrupt_available_evidence_is_saved_error_even_for_optional_sbom(
    corruption, required
):
    evaluator = service()
    with isolated_repository_engine() as engine:
        version = policy(engine, require_sbom=required)
        scan_id = seed(engine, outcome=SbomOutcome(parsed(), None))
        changes = {
            "checksum": {"sha256": "0" * 64},
            "reference": {"pinned_reference": "private corrupted reference"},
            "platform": {"platform": "linux/arm64"},
        }
        with engine.begin() as connection:
            connection.execute(update(SbomArtifact).values(**changes[corruption]))
        with Session(engine) as session:
            first = evaluator.evaluate_scan(session, scan_id, version.policy_version_id)
            second = evaluator.evaluate_scan(
                session, scan_id, version.policy_version_id
            )
        assert first == second and first.outcome == "error"
        assert first.error_code == "invalid_evidence" and first.error_details
        assert "private" not in first.model_dump_json()
        assert first.rules == []


def test_duplicate_and_new_policy_version_preserve_original_result():
    evaluator = service()
    with isolated_repository_engine() as engine:
        first_version = policy(engine, require_sbom=False)
        scan_id = seed(engine)
        add_high_occurrences(engine, scan_id)
        with Session(engine) as session:
            original = evaluator.evaluate_scan(
                session, scan_id, first_version.policy_version_id
            )
            original_bytes = original.model_dump_json()
            assert (
                evaluator.evaluate_scan(
                    session, scan_id, first_version.policy_version_id
                ).model_dump_json()
                == original_bytes
            )
            second_version = policies.create_policy_version(
                session,
                first_version.policy_id,
                PolicyRules(**(RULES | {"max_high": 0, "require_sbom": False})),
            )
            stricter = evaluator.evaluate_scan(
                session, scan_id, second_version.policy_version_id
            )
            assert stricter.outcome == "failed" and original.outcome == "passed"
            assert stricter.evaluation_id != original.evaluation_id
            assert (
                evaluator.evaluate_scan(
                    session, scan_id, first_version.policy_version_id
                ).model_dump_json()
                == original_bytes
            )


def test_simultaneous_evaluations_return_one_persisted_winner(monkeypatch):
    evaluator = service()
    with isolated_repository_engine() as engine:
        version = policy(engine, require_sbom=False)
        scan_id = seed(engine)
        gate = Barrier(2)
        actual = evaluator.evaluate_policy

        def simultaneous(*args, **kwargs):
            gate.wait(timeout=10)
            return actual(*args, **kwargs)

        monkeypatch.setattr(evaluator, "evaluate_policy", simultaneous)

        def run():
            with Session(engine) as session:
                return evaluator.evaluate_scan(
                    session, scan_id, version.policy_version_id
                )

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(run) for _ in range(2)]
            results = [future.result(timeout=15) for future in futures]
        assert results[0] == results[1]
        with Session(engine) as session:
            assert session.scalar(select(func.count()).select_from(Evaluation)) == 1


def test_failed_insert_rolls_back_without_fabricated_saved_result():
    evaluator = service()
    with isolated_repository_engine() as engine:
        version = policy(engine, require_sbom=False)
        scan_id = seed(engine)

        def reject(connection, cursor, statement, parameters, context, executemany):
            if (
                "insert into" in statement.lower()
                and "evaluations" in statement.lower()
            ):
                raise SQLAlchemyError("private failure")

        event.listen(engine, "before_cursor_execute", reject)
        try:
            with Session(engine) as session:
                with pytest.raises(SQLAlchemyError):
                    evaluator.evaluate_scan(session, scan_id, version.policy_version_id)
                assert not session.in_transaction()
                assert session.scalar(select(func.count()).select_from(Evaluation)) == 0
        finally:
            event.remove(engine, "before_cursor_execute", reject)


@pytest.mark.parametrize("artifact", ["missing", "failed"])
@pytest.mark.parametrize("corruption", ["digest", "platform", "scanner_version"])
def test_invalid_scan_identity_is_an_error_without_an_available_sbom(
    artifact, corruption
):
    with isolated_repository_engine() as engine:
        version = policy(engine, require_sbom=False)
        scan_id = seed(
            engine,
            outcome=SbomOutcome(None, "sbom_timeout") if artifact == "failed" else None,
        )
        with Session(engine) as session, session.begin():
            scan = session.get(Scan, scan_id)
            image = session.get(Image, scan.image_id)
            if corruption == "digest":
                image.digest = "not-a-digest"
            elif corruption == "platform":
                image.platform = "linux/arm64"
            else:
                scan.scanner_version = None
        with Session(engine) as session:
            result = service().evaluate_scan(
                session, scan_id, version.policy_version_id
            )
        assert result.outcome == "error"
        assert result.error_code == "invalid_evidence"
        assert result.error_details == "Saved scan evidence could not be verified"
        with Session(engine) as session:
            duplicate = service().evaluate_scan(
                session, scan_id, version.policy_version_id
            )
        assert duplicate == result


def test_legacy_real_scanner_version_without_sbom_remains_eligible():
    with isolated_repository_engine() as engine:
        version = policy(engine, require_sbom=False)
        scan_id = seed(engine)
        with Session(engine) as session, session.begin():
            session.get(Scan, scan_id).scanner_version = "0.74.0"
        with Session(engine) as session:
            result = service().evaluate_scan(
                session, scan_id, version.policy_version_id
            )
        assert result.outcome == "passed"
