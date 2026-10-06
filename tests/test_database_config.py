from importlib import import_module

import pytest

DEV_URL = "postgresql+psycopg://dev:local@127.0.0.1:5433/containerguard"
TEST_URL = "postgresql+psycopg://test:local@127.0.0.1:5434/containerguard_test"


@pytest.mark.parametrize(
    ("test_url", "development_url"),
    [
        (None, DEV_URL),
        (TEST_URL, None),
        (DEV_URL, DEV_URL),
        ("sqlite:///containerguard_test", DEV_URL),
        (TEST_URL, TEST_URL.replace("test:local", "other:password")),
    ],
    ids=[
        "missing-test-url",
        "missing-dev-url",
        "dev-database",
        "wrong-driver",
        "same-target",
    ],
)
def test_unsafe_test_database_configuration_is_rejected(
    test_url: str | None, development_url: str | None
) -> None:
    support = import_module("tests.database_support")
    with pytest.raises(ValueError) as error:
        support.validate_test_database_url(test_url, development_url)
    assert "password" not in str(error.value)
    assert "postgresql+psycopg://" not in str(error.value)


def test_separate_postgresql_test_database_is_accepted() -> None:
    support = import_module("tests.database_support")
    assert support.validate_test_database_url(TEST_URL, DEV_URL) == TEST_URL


@pytest.mark.parametrize(
    "query", ["dbname=containerguard", "host=localhost", "port=5433", "service=local"]
)
@pytest.mark.parametrize("override_target", ["test", "development"])
def test_database_query_options_are_rejected_before_cleanup(
    query: str, override_target: str
) -> None:
    support = import_module("tests.database_support")
    test_url = f"{TEST_URL}?{query}" if override_target == "test" else TEST_URL
    development_url = (
        f"{DEV_URL}?{query}" if override_target == "development" else DEV_URL
    )
    with pytest.raises(ValueError, match="query parameters"):
        support.validate_test_database_url(test_url, development_url)
