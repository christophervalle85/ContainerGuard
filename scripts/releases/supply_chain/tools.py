"""Install reviewed Linux/amd64 tools without executing unchecked downloads."""

import hashlib
import json
import os
import platform
import re
import subprocess
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "security/release-tools.json"


def pins() -> dict:
    return json.loads(MANIFEST.read_text())


def host_check() -> None:
    if platform.system() != "Linux" or platform.machine() not in {"amd64", "x86_64"}:
        raise RuntimeError("release tools require a Linux/amd64 host")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def checked_version(
    binary: Path, expected: str, args: list[str], *, runner=subprocess.run
) -> str:
    if binary.is_symlink() or not binary.is_file() or sha256(binary) != expected:
        raise ValueError("tool checksum mismatch")
    return runner(
        [str(binary), *args], check=True, capture_output=True, text=True, timeout=30
    ).stdout.strip()


def version_matches(output: str, expected: str) -> bool:
    return (
        re.search(r"(?<![0-9.])v?" + re.escape(expected) + r"(?![0-9.])", output)
        is not None
    )


def _run(args: list[str], **kwargs) -> str:
    return subprocess.run(
        args, check=True, capture_output=True, text=True, timeout=900, **kwargs
    ).stdout.strip()


def install_tools(destination: Path) -> dict:
    host_check()
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    manifest = pins()
    for name in ("cosign", "buildx"):
        pin = manifest[name]
        with tempfile.TemporaryDirectory(prefix="cg-tool-") as temporary:
            downloaded = Path(temporary) / name
            with urllib.request.urlopen(pin["url"], timeout=60) as response:
                with downloaded.open("wb") as output:
                    total = 0
                    while chunk := response.read(1024 * 1024):
                        total += len(chunk)
                        if total > 256 * 1024 * 1024:
                            raise ValueError("tool download exceeds limit")
                        output.write(chunk)
            if sha256(downloaded) != pin["sha256"]:
                raise ValueError("tool checksum mismatch")
            target = destination / name
            if target.is_symlink():
                raise ValueError("symlink tool destination")
            target.write_bytes(downloaded.read_bytes())
            target.chmod(0o755)
    pin = manifest["skopeo"]
    with tempfile.TemporaryDirectory(prefix="cg-skopeo-") as temporary:
        context = Path(temporary)
        # A separate Docker build exports a host executable. No Docker socket mount.
        (context / "Dockerfile").write_text(f'''FROM {pin["compiler_image"]} AS build
ENV GOTOOLCHAIN=local CGO_ENABLED=0
RUN apk add --no-cache git
WORKDIR /source
RUN git init && git remote add origin {pin["source"]} && \\
    git fetch --depth=1 origin {pin["commit"]} && \\
    test "$(git rev-parse FETCH_HEAD)" = "{pin["commit"]}" && \\
    test "$(git cat-file -t FETCH_HEAD)" = commit && \\
    git checkout --detach FETCH_HEAD
RUN test "$(go env GOVERSION)" = "go{pin["compiler_version"]}" && \\
    go mod download && go mod verify && \\
    go build -mod=readonly \\
      -tags=containers_image_openpgp,exclude_graphdriver_btrfs -trimpath \\
      -o /out/skopeo ./cmd/skopeo
FROM scratch
COPY --from=build /out/skopeo /skopeo
''')
        exported = context / "out"
        _run(
            [
                "docker",
                "build",
                "--platform=linux/amd64",
                "--output",
                f"type=local,dest={exported}",
                str(context),
            ]
        )
        target = destination / "skopeo"
        if target.is_symlink():
            raise ValueError("symlink tool destination")
        target.write_bytes((exported / "skopeo").read_bytes())
        target.chmod(0o755)
    record = {
        "skopeo": {
            "sha256": sha256(destination / "skopeo"),
            "source_commit": pin["commit"],
            "integrity": "locally-built; not an upstream signature",
        }
    }
    (destination / "installed.json").write_text(json.dumps(record, indent=2) + "\n")
    return _verify(destination)


def _verify(destination: Path) -> dict:
    manifest = pins()
    local = json.loads((destination / "installed.json").read_text())
    record = {}
    for name, args in [
        ("cosign", ["version"]),
        ("buildx", ["version"]),
        ("skopeo", ["--version"]),
    ]:
        pin = manifest[name]
        expected = pin.get("sha256", local.get(name, {}).get("sha256"))
        version = checked_version(destination / name, expected, args)
        if not version_matches(version, pin["version"]):
            raise ValueError("tool version mismatch")
        if name == "skopeo" and local[name]["source_commit"] != pin["commit"]:
            raise ValueError("tool source mismatch")
        record[name] = {
            "version": pin["version"],
            "sha256": sha256(destination / name),
            "integrity": (
                "upstream-checksum" if name != "skopeo" else local[name]["integrity"]
            ),
        }
    for name in ("buildkit", "registry"):
        record[name] = manifest[name]
    record["inventory"] = json.loads(
        (ROOT / manifest["inventory_manifest"]).read_text()
    )
    return record


def verify_tools() -> dict:
    host_check()
    return _verify(Path(os.environ.get("CG_RELEASE_TOOLS", ROOT / ".release-tools")))
