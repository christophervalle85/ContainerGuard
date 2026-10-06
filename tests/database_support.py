import os
from collections.abc import Iterator
from contextlib import contextmanager
from uuid import uuid4

from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.schema import CreateSchema, DropSchema


def validate_test_database_url(
    test_url: str | None, development_url: str | None
) -> str:
    """Check test targets before any database connection or cleanup."""
    if not test_url or not development_url:
        raise ValueError("Both test and development database settings are required")

    try:
        test = make_url(test_url)
        development = make_url(development_url)
    except Exception:
        raise ValueError("Invalid database configuration") from None

    if test.query or development.query:
        raise ValueError("Database query parameters are not supported by test cleanup")

    if test.drivername != "postgresql+psycopg":
        raise ValueError("Tests require the PostgreSQL Psycopg driver")
    if test.database != "containerguard_test":
        raise ValueError("Tests require the dedicated containerguard_test database")

    def target(url: URL) -> tuple[str | None, int, str | None]:
        host = url.host
        if host in {"localhost", "127.0.0.1", "::1"}:
            host = "loopback"
        return host, url.port or 5432, url.database

    if target(test) == target(development):
        raise ValueError("Test and development database targets must differ")
    return test_url


def verify_connected_test_database(connection: Connection) -> None:
    if connection.scalar(text("SELECT current_database()")) != "containerguard_test":
        raise ValueError("Connected database is not the dedicated test database")


@contextmanager
def isolated_model_connection() -> Iterator[Connection]:
    """Create a transactional test schema; rollback removes it and its records."""
    url = validate_test_database_url(
        os.environ.get("TEST_DATABASE_URL"), os.environ.get("DATABASE_URL")
    )
    engine = create_engine(url, connect_args={"connect_timeout": 5})
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                schema = f"test_{uuid4().hex}"
                verify_connected_test_database(connection)
                connection.execute(CreateSchema(schema))
                connection = connection.execution_options(
                    schema_translate_map={None: schema}
                )
                yield connection
            finally:
                transaction.rollback()
    finally:
        engine.dispose()


@contextmanager
def isolated_repository_engine() -> Iterator[Engine]:
    """Use a migrated disposable schema with real commits and separate connections."""
    url = validate_test_database_url(
        os.environ.get("TEST_DATABASE_URL"), os.environ.get("DATABASE_URL")
    )
    schema = f"test_{uuid4().hex}"
    engine = create_engine(
        url,
        connect_args={"connect_timeout": 5},
        execution_options={"schema_translate_map": {None: schema}},
    )
    try:
        with engine.begin() as connection:
            verify_connected_test_database(connection)
            connection.execute(CreateSchema(schema))
            config = Config("alembic.ini")
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        yield engine
    finally:
        try:
            with engine.begin() as connection:
                verify_connected_test_database(connection)
                connection.execute(DropSchema(schema, cascade=True, if_exists=True))
        finally:
            engine.dispose()
