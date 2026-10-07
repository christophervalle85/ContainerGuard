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
            }
            context = MigrationContext.configure(connection)
            assert context.get_current_revision() == "0001"
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
