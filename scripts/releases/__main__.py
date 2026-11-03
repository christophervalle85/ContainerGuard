"""Command line interface for checked image releases."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from scripts.releases.artifacts import read_json_file
from scripts.releases.candidate import CandidateBlocked, build_candidate
from scripts.releases.compose import (
    release_notes,
    render_compose,
    render_verified_compose,
)
from scripts.releases.disclosure import DisclosureBlocked
from scripts.releases.identity import validate_source
from scripts.releases.notes import create_draft
from scripts.releases.publish import publish_candidate
from scripts.releases.supply_chain.verification import (
    VerificationIndeterminate,
    VerificationUnavailable,
)
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
    for name in ("render", "draft", "check-assets", "verify-published"):
        sub = commands.add_parser(name)
        sub.add_argument("--manifest", type=Path, required=True)
        sub.add_argument("--output-dir", type=Path, required=True)
        if name in ("draft", "check-assets"):
            sub.add_argument("--version", required=True)
            sub.add_argument("--commit", required=True)
    signer = commands.add_parser("sign")
    signer.add_argument("--manifest", type=Path, required=True)
    signer.add_argument("--evidence-dir", type=Path, required=True)
    signer.add_argument("--output-dir", type=Path, required=True)
    signer.add_argument("--version", required=True)
    signer.add_argument("--commit", required=True)
    signed = commands.add_parser("verify-release")
    signed.add_argument("--manifest", type=Path, required=True)
    signed.add_argument("--version", required=True)
    signed.add_argument("--commit", required=True)
    signed.add_argument("--evidence-dir", type=Path, required=True)
    signed.add_argument("--output-dir", type=Path, required=True)
    signed.add_argument("--exercise", action="store_true")
    transfer = commands.add_parser("validate-transfer")
    transfer.add_argument("--artifact-id", required=True)
    transfer.add_argument("--producer", required=True)
    transfer.add_argument("--version", required=True)
    transfer.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        if args.command == "validate-transfer":
            from scripts.releases.candidate import release_context
            from scripts.releases.publish import verify_publication_context
            from scripts.releases.transfer import validate_transfer

            verify_publication_context(args.version, args.commit)
            context = release_context(args.version, args.commit)
            validate_transfer(
                args.artifact_id,
                producer=args.producer,
                commit=args.commit,
                run_id=context["run_id"],
                attempt=context["run_attempt"],
            )
        elif args.command == "sign":
            from scripts.releases.candidate import release_context
            from scripts.releases.supply_chain.signing import sign_release

            context = release_context(args.version, args.commit)
            sign_release(
                read_json_file(args.manifest),
                args.evidence_dir,
                context=context,
                output=args.output_dir,
            )
        elif args.command == "verify-release":
            from scripts.releases.smoke import exercise_stack
            from scripts.releases.supply_chain.verification import verify_release

            if os.environ.get("GITHUB_ACTIONS") == "true":
                from scripts.releases.candidate import release_context
                from scripts.releases.publish import verify_publication_context
                from scripts.releases.supply_chain.manifest import validate_release

                verify_publication_context(args.version, args.commit)
                document = read_json_file(args.manifest)
                validate_release(document, version=args.version, commit=args.commit)
                if document["build_context"] != release_context(
                    args.version, args.commit
                ):
                    raise ValueError("Verification run context mismatch")
            result = verify_release(
                args.manifest,
                args.evidence_dir,
                version=args.version,
                commit=args.commit,
                output=args.output_dir,
            )
            document = result._document
            (args.output_dir / "compose.release.yaml").write_text(
                render_verified_compose(document, result)
            )
            if args.exercise:
                images = {
                    service: document["images"][service]["reference"]
                    for service in document["images"]
                }
                with tempfile.TemporaryDirectory(prefix="cg-exercise-auth-") as auth:
                    (Path(auth) / "config.json").write_text('{"auths":{}}\n')
                    environment = {
                        k: os.environ[k]
                        for k in (
                            "PATH",
                            "HOME",
                            "DOCKER_HOST",
                            "DOCKER_CONTEXT",
                            "DOCKER_TLS_VERIFY",
                            "DOCKER_CERT_PATH",
                            "XDG_RUNTIME_DIR",
                            "SSL_CERT_FILE",
                            "SSL_CERT_DIR",
                        )
                        if k in os.environ
                    }
                    environment["DOCKER_CONFIG"] = auth
                    exercise_stack(
                        images, workspace=args.output_dir, environment=environment
                    )
        elif args.command == "guard":
            validate_source(args.version, args.commit, repository=Path.cwd())
        elif args.command == "publish":
            publish_candidate(
                args.handoff_dir,
                version=args.version,
                commit=args.commit,
                dry_run=args.dry_run,
            )
        elif args.command in ("render", "draft", "check-assets", "verify-published"):
            manifest = read_json_file(args.manifest)
            args.output_dir.mkdir(parents=True, exist_ok=True)
            if args.command == "draft":
                create_draft(
                    manifest, args.output_dir, version=args.version, commit=args.commit
                )
            elif args.command == "check-assets":
                from scripts.releases.notes import validate_assets

                validate_assets(
                    manifest, args.output_dir, version=args.version, commit=args.commit
                )
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
    except VerificationIndeterminate:
        print(
            "Release verifier result indeterminate; trust was not established.",
            file=sys.stderr,
        )
        return 3
    except VerificationUnavailable:
        print(
            "Release verification infrastructure unavailable or response invalid.",
            file=sys.stderr,
        )
        return 2
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError):
        print(
            "Release validation or execution failed; publication refused.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
