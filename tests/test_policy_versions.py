from concurrent.futures import ThreadPoolExecutor
from importlib import import_module
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import event, func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from tests.database_support import isolated_repository_engine
from tests.test_policy_schemas import RULES


def interfaces():
    return (
        import_module("app.persistence.policies"),
        import_module("app.persistence.models"),
        import_module("app.policies.schemas"),
    )


def test_policy_and_first_version_commit_atomically():
    service, models, schemas = interfaces()
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            created = service.create_policy(
                session, "  release  ", schemas.PolicyRules(**RULES)
            )
            assert not session.in_transaction()
        with Session(engine) as session:
            assert session.get(models.Policy, created.policy_id).name == "release"
            version = session.get(models.PolicyVersion, created.policy_version_id)
            assert version.version_number == 1
            assert version.max_high == 5 and version.max_critical == 0
            assert (
                version.require_sbom is True
                and version.unknown_severity_action == "fail"
            )
            assert version.created_at.utcoffset().total_seconds() == 0


def test_duplicate_names_are_case_sensitive_and_leave_no_orphans():
    service, models, schemas = interfaces()
    with isolated_repository_engine() as engine, Session(engine) as session:
        rules = schemas.PolicyRules(**RULES)
        service.create_policy(session, "Release", rules)
        service.create_policy(session, "release", rules)
        with pytest.raises(service.PolicyNameConflict):
            service.create_policy(session, " Release ", rules)
        assert not session.in_transaction()
        assert session.scalar(select(func.count()).select_from(models.Policy)) == 2
        assert (
            session.scalar(select(func.count()).select_from(models.PolicyVersion)) == 2
        )


def test_new_version_preserves_old_rules_and_lists_newest_first():
    service, models, schemas = interfaces()
    with isolated_repository_engine() as engine, Session(engine) as session:
        first = service.create_policy(session, "release", schemas.PolicyRules(**RULES))
        second = service.create_policy_version(
            session, first.policy_id, schemas.PolicyRules(**(RULES | {"max_high": 0}))
        )
        assert (
            second.version_number == 2
            and second.policy_version_id != first.policy_version_id
        )
        page = service.list_policy_versions(session, first.policy_id, limit=1, offset=0)
        assert page.total == 2 and page.items[0] == second
        old = session.get(models.PolicyVersion, first.policy_version_id)
        assert old.max_high == 5


@pytest.mark.parametrize("operation", ["create", "list"])
def test_versions_require_existing_policy(operation):
    service, _, schemas = interfaces()
    with isolated_repository_engine() as engine, Session(engine) as session:
        with pytest.raises(service.PolicyNotFound):
            if operation == "create":
                service.create_policy_version(
                    session, uuid4(), schemas.PolicyRules(**RULES)
                )
            else:
                service.list_policy_versions(session, uuid4(), limit=20, offset=0)


def test_failed_first_version_rolls_back_policy_too():
    service, models, schemas = interfaces()

    def fail(mapper, connection, target):
        raise SQLAlchemyError("test insert failure")

    with isolated_repository_engine() as engine, Session(engine) as session:
        event.listen(models.PolicyVersion, "before_insert", fail)
        try:
            with pytest.raises(SQLAlchemyError):
                service.create_policy(session, "release", schemas.PolicyRules(**RULES))
        finally:
            event.remove(models.PolicyVersion, "before_insert", fail)
        assert not session.in_transaction()
        assert session.scalar(select(func.count()).select_from(models.Policy)) == 0
        assert (
            session.scalar(select(func.count()).select_from(models.PolicyVersion)) == 0
        )


def test_simultaneous_allocations_produce_consecutive_distinct_versions():
    service, models, schemas = interfaces()
    with isolated_repository_engine() as engine:
        with Session(engine) as session:
            first = service.create_policy(
                session, "release", schemas.PolicyRules(**RULES)
            )
        gate = Barrier(2)

        def create(threshold):
            with Session(engine) as session:
                gate.wait(timeout=10)
                return service.create_policy_version(
                    session,
                    first.policy_id,
                    schemas.PolicyRules(**(RULES | {"max_high": threshold})),
                )

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(create, threshold) for threshold in (1, 2)]
            versions = [future.result(timeout=15) for future in futures]
        assert {version.version_number for version in versions} == {2, 3}
        assert len({version.policy_version_id for version in versions}) == 2
        with Session(engine) as session:
            assert (
                session.scalar(select(func.count()).select_from(models.PolicyVersion))
                == 3
            )
            assert (
                session.get(models.PolicyVersion, first.policy_version_id).max_high == 5
            )


@pytest.mark.parametrize(
    "changes",
    [
        {"version_number": 0},
        {"version_number": 1},
        {"max_critical": -1},
        {"max_high": -1},
        {"unknown_severity_action": "allow"},
        {"policy_id": "missing"},
    ],
)
def test_database_rejects_invalid_version(changes):
    service, models, schemas = interfaces()
    with isolated_repository_engine() as engine, Session(engine) as session:
        first = service.create_policy(session, "release", schemas.PolicyRules(**RULES))
        values = dict(policy_id=first.policy_id, version_number=2, **RULES)
        if changes.get("policy_id") == "missing":
            changes = {"policy_id": uuid4()}
        values.update(changes)
        session.add(models.PolicyVersion(**values))
        with pytest.raises(IntegrityError):
            session.commit()


def evaluation_values(scan_id, version_id):
    return dict(
        scan_id=scan_id,
        policy_version_id=version_id,
        evaluator_version=1,
        outcome="passed",
        counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        rules=[],
        rule_snapshot=RULES,
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"outcome": "pending"},
        {"evaluator_version": 0},
        {"error_code": "invalid_evidence"},
        {"outcome": "error"},
        {"outcome": "error", "error_code": "private", "error_details": "bad"},
        {"counts": []},
        {"rule_snapshot": []},
        {"rules": {}},
        {"rules": [{}] * 5},
        {"scan_id": "missing"},
        {"policy_version_id": "missing"},
    ],
)
def test_evaluation_storage_rejects_invalid_states(changes):
    service, models, schemas = interfaces()
    with isolated_repository_engine() as engine, Session(engine) as session:
        first = service.create_policy(session, "release", schemas.PolicyRules(**RULES))
        row = models.Scan(submitted_reference="alpine", status="completed")
        session.add(row)
        session.flush()
        values = evaluation_values(row.id, first.policy_version_id)
        values.update(
            {
                key: uuid4() if value == "missing" else value
                for key, value in changes.items()
            }
        )
        session.add(models.Evaluation(**values))
        with pytest.raises(SQLAlchemyError):
            session.commit()


@pytest.mark.parametrize("operation", ["duplicate", "delete-scan", "delete-version"])
def test_evaluation_association_is_unique_and_protects_history(operation):
    service, models, schemas = interfaces()
    with isolated_repository_engine() as engine, Session(engine) as session:
        first = service.create_policy(session, "release", schemas.PolicyRules(**RULES))
        row = models.Scan(submitted_reference="alpine", status="completed")
        session.add(row)
        session.flush()
        scan_id = row.id
        session.add(
            models.Evaluation(**evaluation_values(scan_id, first.policy_version_id))
        )
        session.commit()
        if operation == "duplicate":
            session.add(
                models.Evaluation(**evaluation_values(scan_id, first.policy_version_id))
            )
        elif operation == "delete-scan":
            session.delete(session.get(models.Scan, scan_id))
        else:
            session.delete(session.get(models.PolicyVersion, first.policy_version_id))
        with pytest.raises(IntegrityError):
            session.commit()
