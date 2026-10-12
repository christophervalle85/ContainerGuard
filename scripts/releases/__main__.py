"""Command line interface for checked image releases."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

from scripts.releases.artifacts import read_json_file
from scripts.releases.candidate import CandidateBlocked, build_candidate
from scripts.releases.compose import release_notes, render_compose
from scripts.releases.disclosure import DisclosureBlocked
from scripts.releases.identity import validate_source
from scripts.releases.notes import create_draft
from scripts.releases.publish import publish_candidate
from scripts.releases.verify import verify_published


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    candidate = commands.add_parser("candidate")
    candidate.add_argument("--version", required=True)
    candidate.add_argument("--commit", required=True)
    candidate.add_argument("--output-dir", type=Path, required=True)
    guard = commands.add_parser("guard")
    guard.add_argument("--version", required=True)
    guard.add_argument("--commit", required=True)
    publish = commands.add_parser("publish")
    publish.add_argument("--version", required=True)
    publish.add_argument("--commit", required=True)
    publish.add_argument("--handoff-dir", type=Path, required=True)
    publish.add_argument("--dry-run", action="store_true")
    for name in ("render", "draft", "verify-published"):
        sub = commands.add_parser(name)
        sub.add_argument("--manifest", type=Path, required=True)
        sub.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "guard":
            validate_source(args.version, args.commit, repository=Path.cwd())
        elif args.command == "publish":
            publish_candidate(
                args.handoff_dir,
                version=args.version,
                commit=args.commit,
                dry_run=args.dry_run,
            )
        elif args.command in ("render", "draft", "verify-published"):
            manifest = read_json_file(args.manifest)
            args.output_dir.mkdir(parents=True, exist_ok=True)
            if args.command == "draft":
                create_draft(manifest, args.output_dir)
            elif args.command == "verify-published":
                result = verify_published(manifest, args.output_dir)
                (args.output_dir / "published-verification.json").write_text(
                    json.dumps(result, indent=2) + "\n"
                )
            else:
                (args.output_dir / "compose.release.yaml").write_text(
                    render_compose(manifest)
                )
                (args.output_dir / "release-notes.md").write_text(
                    release_notes(manifest)
                )
        else:
            build_candidate(args.version, args.commit, args.output_dir)
    except (CandidateBlocked, DisclosureBlocked):
        print("Release blocked by a completed security check.", file=sys.stderr)
        return 1
    except (ValueError, OSError, subprocess.SubprocessError):
        print(
            "Release validation or execution failed; publication refused.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
