from pathlib import Path

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import inspect

from app.persistence.models import Base
from tests.database_support import isolated_model_connection


def test_initial_migration_matches_models_and_can_be_reapplied() -> None:
    assert Path("alembic.ini").is_file(), "Alembic configuration is not implemented"
    with isolated_model_connection() as connection:
        schema = connection.get_execution_options()["schema_translate_map"][None]
        connection.exec_driver_sql(f'SET LOCAL search_path TO "{schema}"')
        previous_default = connection.dialect.default_schema_name
        connection.dialect.default_schema_name = schema
        try:
            config = Config("alembic.ini")
            config.attributes["connection"] = connection
            assert inspect(connection).get_table_names(schema=schema) == []

            command.upgrade(config, "head")
            assert set(inspect(connection).get_table_names(schema=schema)) == {
                "images",
                "scans",
                "findings",
                "alembic_version",
                "sbom_artifacts",
                "policies",
                "policy_versions",
                "evaluations",
            }
            context = MigrationContext.configure(connection)
            assert context.get_current_revision() == "0003"
            assert compare_metadata(context, Base.metadata) == []

            checks = inspect(connection).get_check_constraints("scans", schema=schema)
            assert "ck_scans_status" in {check["name"] for check in checks}
            checks = inspect(connection).get_check_constraints(
                "findings", schema=schema
            )
            assert "ck_findings_severity" in {check["name"] for check in checks}
            finding_fk = inspect(connection).get_foreign_keys("findings", schema=schema)
            assert finding_fk[0]["options"]["ondelete"] == "CASCADE"
            scan_fk = inspect(connection).get_foreign_keys("scans", schema=schema)
            assert scan_fk[0]["options"]["ondelete"] == "RESTRICT"

            command.upgrade(config, "head")
            command.downgrade(config, "base")
            assert inspect(connection).get_table_names(schema=schema) == [
                "alembic_version"
            ]
            command.upgrade(config, "head")
            assert compare_metadata(context, Base.metadata) == []
        finally:
            connection.dialect.default_schema_name = previous_default


def test_artifact_upgrade_preserves_old_scan_and_findings():
    from uuid import uuid4

    from sqlalchemy import text

    with isolated_model_connection() as connection:
        schema = connection.get_execution_options()["schema_translate_map"][None]
        connection.exec_driver_sql(f'SET LOCAL search_path TO "{schema}"')
        config = Config("alembic.ini")
        config.attributes["connection"] = connection
        command.upgrade(config, "0001")
        scan_id, finding_id = uuid4(), uuid4()
        connection.execute(
            text(
                "INSERT INTO scans (id, submitted_reference, status, created_at) "
                "VALUES (:id, 'docker.io/library/alpine:3.20.0', 'completed', now())"
            ),
            {"id": scan_id},
        )
        connection.execute(
            text(
                "INSERT INTO findings (id, scan_id, vulnerability_id, package_name, "
                "package_type, target, installed_version, severity, title, "
                "occurrence_order) VALUES (:id, :scan, 'CVE-example', 'busybox', "
                "'apk', 'alpine', '1.0', 'HIGH', 'Retained finding', 0)"
            ),
            {"id": finding_id, "scan": scan_id},
        )
        command.upgrade(config, "head")
        assert (
            connection.scalar(
                text("SELECT status FROM scans WHERE id=:id"), {"id": scan_id}
            )
            == "completed"
        )
        assert (
            connection.scalar(
                text("SELECT title FROM findings WHERE id=:id"), {"id": finding_id}
            )
            == "Retained finding"
        )
        assert connection.scalar(text("SELECT count(*) FROM sbom_artifacts")) == 0
        command.downgrade(config, "0001")
        assert connection.scalar(text("SELECT count(*) FROM findings")) == 1


def test_policy_upgrade_preserves_saved_artifact_and_scan():
    from uuid import uuid4

    from sqlalchemy import text

    with isolated_model_connection() as connection:
        schema = connection.get_execution_options()["schema_translate_map"][None]
        connection.exec_driver_sql(f'SET LOCAL search_path TO "{schema}"')
        config = Config("alembic.ini")
        config.attributes["connection"] = connection
        command.upgrade(config, "0002")
        scan_id, artifact_id = uuid4(), uuid4()
        connection.execute(
            text(
                "INSERT INTO scans (id, submitted_reference, status, created_at) "
                "VALUES (:id, 'alpine', 'completed', now())"
            ),
            {"id": scan_id},
        )
        connection.execute(
            text(
                "INSERT INTO sbom_artifacts (id, scan_id, status, created_at, "
                "error_code, error_details) VALUES (:id, :scan, 'failed', now(), "
                "'sbom_timeout', 'Retained outcome')"
            ),
            {"id": artifact_id, "scan": scan_id},
        )
        command.upgrade(config, "head")
        assert (
            connection.scalar(
                text("SELECT status FROM scans WHERE id=:id"), {"id": scan_id}
            )
            == "completed"
        )
        assert (
            connection.scalar(
                text("SELECT error_details FROM sbom_artifacts WHERE id=:id"),
                {"id": artifact_id},
            )
            == "Retained outcome"
        )
        for table in ("policies", "policy_versions", "evaluations"):
            assert connection.scalar(text(f"SELECT count(*) FROM {table}")) == 0
        command.downgrade(config, "0002")
        assert connection.scalar(text("SELECT count(*) FROM sbom_artifacts")) == 1
