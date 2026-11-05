#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - "$@" <<'PY'
import json
import sys
from pathlib import Path
from scripts.releases.supply_chain.tools import install_tools

if len(sys.argv) != 2:
    raise SystemExit('Usage: bash scripts/install_release_tools.sh OUTPUT_DIRECTORY')
print(json.dumps(install_tools(Path(sys.argv[1])), indent=2))
PY
