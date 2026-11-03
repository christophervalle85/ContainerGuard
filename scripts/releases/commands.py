"""Fixed argument-list commands with deadlines and safe diagnostics."""

import os
import resource
import selectors
import stat
import subprocess
import tempfile
import time
from pathlib import Path


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


def command_file(
    args: list[str],
    output: Path,
    *,
    limit: int,
    timeout: int = 600,
    generated: list[Path] | None = None,
    **kwargs,
) -> Path:
    """Bound stdout while the child runs; never surface child diagnostics."""
    if limit < 1 or timeout < 1 or output.is_symlink():
        raise ValueError("Release command invalid bounds")
    if any(parent.is_symlink() for parent in output.parents):
        raise ValueError("Release command unsafe output")
    generated = generated or []
    for path in generated:
        if (
            path.exists()
            or path.is_symlink()
            or any(p.is_symlink() for p in path.parents)
        ):
            raise ValueError("Release command unsafe generated output")
    if generated:
        if "preexec_fn" in kwargs:
            raise ValueError("Release command invalid process policy")

        def file_bound():
            _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
            bound = limit if hard == resource.RLIM_INFINITY else min(limit, hard)
            resource.setrlimit(resource.RLIMIT_FSIZE, (bound, bound))

        kwargs["preexec_fn"] = file_bound
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as target:
            temporary = Path(target.name)
            process = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, **kwargs
            )
            try:
                deadline, total = time.monotonic() + timeout, 0
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while selector.get_map() or process.poll() is None:
                        for path in generated:
                            if path.is_symlink() or (
                                path.exists()
                                and (
                                    not stat.S_ISREG(path.stat().st_mode)
                                    or path.stat().st_size > limit
                                )
                            ):
                                raise ValueError("Release command exceeded bounds")
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise ValueError("Release command exceeded bounds")
                        for key, _ in selector.select(min(remaining, 0.1)):
                            chunk = os.read(
                                key.fileobj.fileno(), min(65536, limit + 1 - total)
                            )
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            total += len(chunk)
                            if total > limit:
                                raise ValueError("Release command exceeded bounds")
                            target.write(chunk)
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
                for path in generated:
                    if (
                        path.is_symlink()
                        or not path.is_file()
                        or path.stat().st_size > limit
                    ):
                        raise ValueError("Release command exceeded bounds")
                if process.returncode:
                    if any(path.stat().st_size >= limit for path in generated):
                        raise ValueError("Release command exceeded bounds")
                    raise ValueError("Release command failed")
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                process.stdout.close()
        os.replace(temporary, output)
        return output
    except (OSError, subprocess.SubprocessError):
        raise ValueError("Release command could not complete") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
