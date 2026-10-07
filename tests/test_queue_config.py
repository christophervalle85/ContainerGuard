import pytest

from app.jobs.connection import get_redis_connection


@pytest.mark.parametrize("url", [None, "", "   "], ids=["missing", "empty", "blank"])
def test_missing_redis_configuration_does_not_fall_back_to_another_server(
    monkeypatch: pytest.MonkeyPatch, url: str | None
) -> None:
    if url is None:
        monkeypatch.delenv("REDIS_URL", raising=False)
    else:
        monkeypatch.setenv("REDIS_URL", url)

    with pytest.raises(ValueError, match="REDIS_URL must be configured"):
        get_redis_connection()
