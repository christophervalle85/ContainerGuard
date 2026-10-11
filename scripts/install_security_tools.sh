#!/usr/bin/env bash
# CI installs reviewed Linux amd64 binaries; no moving latest downloads.
set -euo pipefail
python3 - "$@" <<'PYTHON'
import hashlib
import json
import os
import platform
import sys
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
    raise SystemExit("Security CLI installation supports Linux amd64 only")
if len(sys.argv) != 2:
    raise SystemExit("Usage: bash scripts/install_security_tools.sh OUTPUT_DIRECTORY")
destination = Path(sys.argv[1]).resolve()
destination.mkdir(parents=True, exist_ok=True)
tools = json.loads(Path("security/tools.json").read_text())
for name, tool in tools.items():
    with tempfile.TemporaryDirectory() as directory:
        if "build_target" in tool:
            exported = Path(directory) / "export"
            subprocess.run([
                "docker", "build", "--platform", "linux/amd64",
                "--target", tool["build_target"], "-f", tool["dockerfile"],
                "--output", f"type=local,dest={exported}", ".",
            ], check=True, timeout=900)
            binary = destination / name
            binary.write_bytes((exported / "usr/local/bin/trivy").read_bytes())
            binary.chmod(0o755)
            print(f"Installed {name} {tool['version']} from verified source")
            continue
        archive = Path(directory) / "download.tar.gz"
        with urllib.request.urlopen(tool["url"], timeout=30) as response:
            with archive.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    output.write(chunk)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != tool["sha256"]:
            raise SystemExit("Security tool checksum mismatch")
        with tarfile.open(archive) as bundle:
            member = bundle.getmember(name)
            if not member.isfile():
                raise SystemExit("Security tool archive lacks expected binary")
            with bundle.extractfile(member) as source:
                binary = destination / name
                binary.write_bytes(source.read())
                binary.chmod(0o755)
    print(f"Installed {name} {tool['version']}")
PYTHON
