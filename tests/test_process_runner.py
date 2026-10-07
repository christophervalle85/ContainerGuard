import os
import sys
from importlib import import_module

import pytest


def run_script(script, **kwargs):
    runner = import_module("app.scanning.trivy.process_runner")
    return runner.run_bounded_command(
        [sys.executable, "-c", script], **{"timeout_seconds": 5, **kwargs}
    )


def test_stdout_is_separate_from_scanner_logs():
    output = run_script(
        'import sys; print(\'{"Results": []}\'); print("warning", file=sys.stderr)'
    )
    assert output.strip() == '{"Results": []}'


def test_failed_process_does_not_expose_stderr():
    runner = import_module("app.scanning.trivy.process_runner")
    with pytest.raises(runner.ProcessExecutionError) as error:
        run_script('import sys; print("secret-token", file=sys.stderr); sys.exit(2)')
    assert error.value.code == "execution_failed"
    assert "secret-token" not in str(error.value)


def test_timeout_reaps_the_process(tmp_path):
    runner = import_module("app.scanning.trivy.process_runner")
    pid_path = tmp_path / "pid"
    script = (
        f'import os, time; open({str(pid_path)!r}, "w").write(str(os.getpid())); '
        "time.sleep(10)"
    )
    with pytest.raises(runner.ProcessExecutionError) as error:
        run_script(script, timeout_seconds=0.5)
    assert error.value.code == "timeout"
    with pytest.raises(ProcessLookupError):
        os.kill(int(pid_path.read_text()), 0)


@pytest.mark.parametrize(
    "stream,limit", [("stdout", "max_output_bytes"), ("stderr", "max_error_bytes")]
)
def test_output_limits_apply_to_both_streams(stream, limit):
    runner = import_module("app.scanning.trivy.process_runner")
    with pytest.raises(runner.ProcessExecutionError) as error:
        run_script(f'import sys; sys.{stream}.write("x" * 4096)', **{limit: 128})
    assert error.value.code == "output_limit"


def test_missing_executable_is_reported_safely(tmp_path):
    runner = import_module("app.scanning.trivy.process_runner")
    with pytest.raises(runner.ProcessExecutionError) as error:
        runner.run_bounded_command([str(tmp_path / "missing")], timeout_seconds=1)
    assert error.value.code == "unavailable"


def test_invalid_utf8_is_rejected():
    runner = import_module("app.scanning.trivy.process_runner")
    with pytest.raises(runner.ProcessExecutionError) as error:
        run_script("import sys; sys.stdout.buffer.write(bytes([255]))")
    assert error.value.code == "invalid_output"


def test_timeout_still_applies_after_process_closes_its_output():
    runner = import_module("app.scanning.trivy.process_runner")
    with pytest.raises(runner.ProcessExecutionError) as error:
        run_script(
            "import os, time; os.close(1); os.close(2); time.sleep(10)",
            timeout_seconds=0.2,
        )
    assert error.value.code == "timeout"


@pytest.mark.parametrize(
    "options", [{"timeout_seconds": 0}, {"max_output_bytes": 0}, {"max_error_bytes": 0}]
)
def test_invalid_execution_limits_are_rejected(options):
    with pytest.raises(ValueError):
        run_script('print("ok")', **options)
