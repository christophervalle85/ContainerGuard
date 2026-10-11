import json
import os
import subprocess
import sys

import pytest

from tests.test_security_gate import ROOT, report


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("clean", 0),
        ("patched", 0),
        ("wrong_version", 2),
        ("blocked", 1),
        ("failed", 2),
        ("absent", 2),
        ("missing_target", 2),
        ("timeout", 2),
    ],
)
def test_runner_never_passes_unusable_scan(tmp_path, mode, expected):
    source = tmp_path / "source"
    (source / "frontend").mkdir(parents=True)
    (source / "uv.lock").write_text("version = 1")
    (source / "frontend/package-lock.json").write_text("{}")
    output = tmp_path / "output"
    output.mkdir()
    # A previous passing report cannot hide a failed invocation.
    (output / "report.json").write_text(json.dumps(report()))
    (output / "summary.json").write_text('{"blocked": false}')
    document = report("HIGH" if mode == "blocked" else None)
    if mode != "missing_target":
        document["Results"].append(
            {
                "Target": "frontend/package-lock.json",
                "Class": "lang-pkgs",
                "Type": "npm",
            }
        )
    version = (
        "0.75.0+cg.1"
        if mode == "patched"
        else ("0.74.0" if mode == "wrong_version" else "0.75.0")
    )
    scanner = tmp_path / "trivy"
    scanner.write_text(
        "#!/usr/bin/env python3\n"
        + "import json,sys,time\n"
        + "if '--version' in sys.argv:\n"
        + f" print(json.dumps({{'Version':{version!r}}}));sys.exit(0)\n"
        + ("time.sleep(3)\n" if mode == "timeout" else "")
        + ("sys.exit(0)\n" if mode == "absent" else "")
        + "from pathlib import Path\n"
        + "Path(sys.argv[sys.argv.index('--output')+1]).write_text("
        + repr(json.dumps(document))
        + ")\n"
        + ("sys.exit(3)\n" if mode == "failed" else "")
    )
    scanner.chmod(0o700)
    environment = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"])
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.scan_security",
            "--kind",
            "filesystem",
            "--input",
            str(source),
            "--target",
            ".",
            "--output-dir",
            str(output),
            "--expected-target",
            "uv.lock",
            "--expected-target",
            "frontend/package-lock.json",
            "--timeout",
            "1",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == expected, result.stderr
    if expected < 2:
        assert json.loads((output / "summary.json").read_text())["blocked"] is (
            expected == 1
        )
        assert json.loads((output / "scanner.json").read_text())["Version"] == version
    else:
        assert not (output / "summary.json").exists()
        assert not (output / "report.json").exists()


def test_standalone_security_scripts_parse_on_ci_system_python():
    import ast

    for path in (ROOT / "scripts").glob("*.py"):
        ast.parse(path.read_text(), filename=str(path), feature_version=(3, 12))
