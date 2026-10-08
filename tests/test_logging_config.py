import io
import json
import logging
from datetime import datetime

import pytest

from app.logging_config import JsonFormatter, bind_scan_context, configure_logging


@pytest.fixture
def app_logger():
    logger = logging.getLogger("app")
    previous = logger.handlers[:], logger.level, logger.propagate
    logger.handlers = []
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        yield logger
    finally:
        for handler in logger.handlers:
            if handler not in previous[0]:
                handler.close()
        logger.handlers, logger.level, logger.propagate = previous


def test_formatter_produces_json_with_time_level_logger_and_message():
    record = logging.LogRecord(
        "app.jobs.tasks", logging.INFO, "file", 1, "job_started", (), None
    )
    item = json.loads(JsonFormatter().format(record))
    assert item["level"] == "INFO"
    assert item["logger"] == "app.jobs.tasks"
    assert item["message"] == "job_started"
    assert datetime.fromisoformat(item["time"]).utcoffset().total_seconds() == 0


def test_formatter_keeps_only_selected_extra_fields():
    record = logging.makeLogRecord(
        {
            "name": "app.test",
            "msg": "scan_failed",
            "levelname": "WARNING",
            "scan_id": "scan-123",
            "job_id": "job-456",
            "error_code": "invalid_report",
            "password": "private-password",
            "request_body": "private-body",
        }
    )
    item = json.loads(JsonFormatter().format(record))
    assert item["scan_id"] == "scan-123"
    assert item["job_id"] == "job-456"
    assert item["error_code"] == "invalid_report"
    assert "private-password" not in json.dumps(item)
    assert "private-body" not in json.dumps(item)


def test_exception_details_are_not_appended_to_safe_application_logs(app_logger):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    app_logger.addHandler(handler)
    try:
        raise RuntimeError("private-password and scanner diagnostics")
    except RuntimeError:
        app_logger.exception("operation_failed")
    output = stream.getvalue()
    assert json.loads(output)["message"] == "operation_failed"
    assert "private-password" not in output
    assert "Traceback" not in output


def test_repeated_configuration_emits_one_json_record(app_logger, capsys):
    configure_logging()
    configure_logging()
    logging.getLogger("app.jobs.tasks").info("job_started")
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["message"] == "job_started"


def test_configuration_does_not_replace_other_library_handlers(app_logger):
    root = logging.getLogger()
    before = root.handlers[:]
    configure_logging()
    assert root.handlers == before


def test_scan_context_is_nested_and_cleared_after_errors(app_logger):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    app_logger.addHandler(handler)
    with bind_scan_context("outer-scan", "outer-job"):
        app_logger.info("outer_before")
        with pytest.raises(ValueError):
            with bind_scan_context("inner-scan", "inner-job"):
                app_logger.info("inner")
                raise ValueError("test")
        app_logger.info("outer_after")
    app_logger.info("unrelated")
    items = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert [item.get("scan_id") for item in items] == [
        "outer-scan",
        "inner-scan",
        "outer-scan",
        None,
    ]
    assert [item.get("job_id") for item in items] == [
        "outer-job",
        "inner-job",
        "outer-job",
        None,
    ]


def test_direct_scan_context_does_not_invent_a_job_id(app_logger):
    with bind_scan_context("direct-scan", None):
        record = logging.makeLogRecord({"msg": "scan_completed"})
        item = json.loads(JsonFormatter().format(record))
    assert item["scan_id"] == "direct-scan"
    assert "job_id" not in item
