"""Run scanner commands with bounded output and a wall-clock deadline."""

import math
import os
import selectors
import signal
import subprocess
import time


class ProcessExecutionError(RuntimeError):
    _messages = {
        "timeout": "Scanner exceeded its execution deadline",
        "output_limit": "Scanner exceeded its output limit",
        "execution_failed": "Scanner command failed",
        "unavailable": "Scanner executable could not be started",
        "invalid_output": "Scanner output was not valid UTF-8",
    }

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(self._messages[code])


def run_bounded_command(
    command: list[str],
    timeout_seconds: float,
    max_output_bytes: int = 10 * 1024 * 1024,
    max_error_bytes: int = 64 * 1024,
) -> str:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError("Timeout must be finite and positive")
    if any(
        type(limit) is not int or limit <= 0
        for limit in (max_output_bytes, max_error_bytes)
    ):
        raise ValueError("Output limits must be positive integers")

    deadline = time.monotonic() + timeout_seconds
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
    except OSError:
        raise ProcessExecutionError("unavailable") from None

    completed = False
    output = bytearray()
    error_size = 0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProcessExecutionError("timeout")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stdout":
                        if len(output) + len(chunk) > max_output_bytes:
                            raise ProcessExecutionError("output_limit")
                        output.extend(chunk)
                    else:
                        error_size += len(chunk)
                        if error_size > max_error_bytes:
                            raise ProcessExecutionError("output_limit")

        try:
            return_code = process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise ProcessExecutionError("timeout") from None
        if return_code != 0:
            raise ProcessExecutionError("execution_failed")
        try:
            result = output.decode("utf-8")
            completed = True
            return result
        except UnicodeDecodeError:
            raise ProcessExecutionError("invalid_output") from None
    finally:
        if not completed:
            # Stop the process group, including children holding output pipes.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                # Some environments restrict group signals; still reap our child.
                if process.poll() is None:
                    process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()
