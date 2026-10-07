import os
from importlib import import_module

import pytest
from sqlalchemy import text

from tests.database_support import validate_test_database_url


def test_session_connects_to_test_database_and_releases_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_url = validate_test_database_url(
        os.environ.get("TEST_DATABASE_URL"), os.environ.get("DATABASE_URL")
    )
    monkeypatch.setenv("DATABASE_URL", test_url)
    database = import_module("app.persistence.database")
    database.get_engine.cache_clear()
    engine = database.get_engine()
    sessions = database.get_session()
    try:
        session = next(sessions)
        connection = session.connection()
        assert session.execute(text("SELECT 1")).scalar_one() == 1
        assert session.execute(text("SELECT current_database()")).scalar_one() == (
            "containerguard_test"
        )
        sessions.close()
        assert connection.closed
    finally:
        sessions.close()
        engine.dispose()
        database.get_engine.cache_clear()
