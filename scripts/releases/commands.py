"""Fixed argument-list commands with deadlines and safe diagnostics."""

import subprocess
import tempfile


def command(
    args: list[str], *, timeout: int = 180, capture: bool = False, **kwargs
) -> str:
    with tempfile.TemporaryFile() as output:
        try:
            subprocess.run(
                args,
                stdout=output if capture else subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=True,
                **kwargs,
            )
            if capture:
                if output.tell() > 4 * 1024**2:
                    raise ValueError("Command output exceeded bounds")
                output.seek(0)
                return output.read().decode()
            return ""
        except (OSError, UnicodeError, subprocess.TimeoutExpired):
            raise ValueError("Release command could not complete") from None
