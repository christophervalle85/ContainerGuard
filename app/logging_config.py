"""Structured, correlated logs for ContainerGuard application events."""

import json
import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime

_scan_context: ContextVar[dict[str, str] | None] = ContextVar(
    "scan_context", default=None
)
_HANDLER_NAME = "containerguard-json"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        item = {
            "time": datetime.fromtimestamp(record.created, UTC).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            **(_scan_context.get() or {}),
        }
        for field in ("scan_id", "job_id", "error_code"):
            value = getattr(record, field, None)
            if value is not None:
                item[field] = str(value)
        # Application callers use fixed event messages and safe error codes.
        # Do not append arbitrary extras, exception text, or stack traces.
        return json.dumps(item)


def configure_logging() -> None:
    logger = logging.getLogger("app")
    for handler in logger.handlers[:]:
        if handler.get_name() == _HANDLER_NAME:
            logger.removeHandler(handler)
            handler.close()
    handler = logging.StreamHandler(sys.stdout)
    handler.set_name(_HANDLER_NAME)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


@contextmanager
def bind_scan_context(scan_id: str, job_id: str | None) -> Iterator[None]:
    context = {"scan_id": str(scan_id)}
    if job_id is not None:
        context["job_id"] = str(job_id)
    token = _scan_context.set(context)
    try:
        yield
    finally:
        _scan_context.reset(token)
