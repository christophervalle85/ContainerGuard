# Versioned releases implementation plan

**Goal:** Publish three checked, traceable public ContainerGuard images and prove that another installation can run them without rebuilding source.

**Architecture:** A trusted tag invokes reusable read-only CI. A single candidate job builds and checks all three images and exercises them together before exporting archives. A separate publisher validates those same archives and pushes them; a narrowly privileged notes job creates a draft GitHub Release.

**Tech stack:** GitHub Actions, GHCR, Docker/Compose, existing pinned Trivy and Gitleaks, Python 3.12-compatible standard-library release scripts, pytest, existing backend/frontend checks.

**Spec:** `docs/architecture/releases.md`.

## Global constraints

- Work in the existing VSCode checkout on `feat/versioned-releases`; no worktrees. Preserve approved uncommitted documentation and all development containers/data/volumes.
- No automatic commits, pushes, PRs, version-tag creation, registry publication, package visibility changes, or GitHub Release publication. Obtain the maintainer's instruction for those actions after preparing concrete reviewable results.
- Public GHCR packages: `ghcr.io/christophervalle85/containerguard-{api,worker,frontend}`. First platform: `linux/amd64`; document amd64 emulation on Apple Silicon.
- Stable `vMAJOR.MINOR.PATCH` tags only, no leading zeroes except zero. Full 40-character source SHA tags use `sha-`. No latest or moving major/minor aliases.
- Release source must resolve to the event commit and be reachable from origin/main. PRs never receive package-write credentials.
- Preserve HIGH/CRITICAL blocking including unfixed findings; no new exceptions or weaker thresholds merely to release. Scanner errors and unusable reports fail closed.
- Build/scan/smoke the exact images that will be pushed; no rebuilds or label changes in the publisher. Registry manifest digests, image/config IDs, and archive checksums are distinct identities.
- No embedded runtime configuration, credentials, public build-cache export, or application Docker socket. Repository docs stay separate and linked; version-tag links go in release notes.
- All archive/disclosure checks precede image-artifact upload. Images retain for one day; validated safe vulnerability summaries retain for seven days. Never upload rejected archives or raw secret reports.
- First upload may create private packages. Verify anonymous pulls and the published-image workflow after intentional public visibility, before publishing the GitHub Release.
- Signing/provenance/release SBOM distribution remain later work. No zero-vulnerability or exhaustive secret-detection claim.

## Review focus

1. A tag moved between validation and publication: recheck its peeled commit before any registry write; a changed ref fails (Tasks 1, 6).
2. A secret removed by a later Docker layer, or present only in image metadata: still blocks, without printing the sentinel (Task 3).
3. A clean report paired with a different image archive: handoff identity/digest/source checks reject it before load/push (Tasks 2, 4, 6).
4. Registry 401/403/429/5xx or a partial previous publication: never means an unused version; do not overwrite or announce success (Task 6).
5. Failure during verification cleanup: never deletes development volumes or masks the original failure (Tasks 4, 7).

## File responsibilities

- `scripts/releases/identity.py`: version/source validation and canonical package/tag names.
- `scripts/releases/artifacts.py`: bounded archive inspection, identity/handoff validation and hashing.
- `scripts/releases/disclosure.py`: redacted layer/config/history secret detection, isolated scanner execution.
- `scripts/releases/candidate.py`: build/check/export orchestration; no registry-write operations.
- `scripts/releases/smoke.py`: isolated Compose full-workflow checks and owned-resource cleanup.
- `scripts/releases/registry.py`: authenticated registry responses, manifest/config validation; safe fixed errors.
- `scripts/releases/publish.py`: preflight all six tags, publish exact checked archives, write digest manifest; explicit dry-run mode.
- `scripts/releases/compose.py`: generate standalone release Compose configuration from validated digests.
- `scripts/releases/__main__.py`, `__init__.py`: a small command-line entry point and package boundary.
- `.github/workflows/ci.yml`: reusable read-only quality checks with optional candidate mode, preserving ordinary CI behavior.
- `.github/workflows/release.yml`: trusted tag guard, quality call, isolated publisher, draft notes.
- `docs/releases.md`: installation/release/recovery instructions; existing verification notes carry observed evidence.

## Task 1: Release identity and restricted build inputs

**Files:** create `scripts/releases/{__init__,identity}.py`, `tests/test_release_identity.py`, `tests/test_release_contexts.py`; modify `.dockerignore`, `frontend/.dockerignore`, `docs/architecture/releases.md` only for an evidence-backed clarification.

**Interfaces:** `validate_version(value: str) -> str`; `release_image(service: str) -> str`; `release_tags(version: str, commit: str) -> tuple[str, str]`; `validate_source(tag: str, event_commit: str, *, repository: Path) -> str`. Fixed service set: api, worker, frontend. Invalid values raise a safe `ValueError` without echoing raw input.

- [ ] Write tests: accept v0.1.0/v1.0.0; reject whitespace, newline, leading zeroes, prerelease strings and shell metacharacters. Assert full SHA tags and fixed lower-case packages. Use disposable Git repositories to reject non-main commits, mismatched event commits and a moved tag; accept annotated and lightweight tags after peeling.
- [ ] Run `uv run pytest tests/test_release_identity.py -q`; expect missing implementation failures. Implement the interfaces with bounded Git argument-list subprocesses, explicit refs, and `merge-base --is-ancestor` against fetched origin/main; run again for pass.
- [ ] Write Docker-backed context tests using temporary copied contexts, synthetic nonfunctional markers, and an inspection-only target. Assert excluded .env/key/log/cache files do not enter either context, including beneath app/src directories; assert all required build inputs still enter. Never put markers into the actual tracked source or print contents.
- [ ] Change allowlists only enough to meet those tests. Preserve required frontend TS test/config inputs because `tsc --noEmit` covers them; do not silently weaken compilation. Deny .git, local keys/credential filenames, environments, logs, caches and generated output even beneath allowed directories. A filename denylist supplements disclosure scanning; it cannot recognize arbitrary sensitive content by name.
- [ ] Run focused tests and real frontend build. Expected: both contexts exclude sentinels, normal build passes, no source/runtime behavior change. Review diff; leave uncommitted until instructed.

## Task 2: Bounded image archives and handoff identity

**Files:** create `scripts/releases/artifacts.py`, `tests/test_release_artifacts.py`; modify `pyproject.toml` and the existing Python-3.12 grammar regression in `tests/test_security_scan.py` to cover nested release scripts.

**Interfaces:** `inspect_image_archive(path: Path) -> dict`; `validate_handoff(document: dict, directory: Path, *, version: str, commit: str) -> dict`; `write_handoff(images: dict[str, dict], output: Path, *, version: str, commit: str) -> Path`. JSON schema version 1; exactly api/worker/frontend, fixed `service.tar` basenames, linux/amd64, full source SHA, version, byte size, archive SHA-256, image/config ID, rootfs diff IDs, required OCI labels. Missing or extra services/fields fail.

- [ ] Characterize the current Docker save/export layout in an isolated image. Write generated-tar tests for Docker archives and OCI layouts supported by the selected exporter. Reject unknown formats, duplicate JSON keys/archive paths, wrong config hashes, missing layer blobs, multiple ambiguous images, wrong platform/source/version and unexpected image labels/tags. Include clean-report/different-archive mismatch coverage.
- [ ] Run `uv run pytest tests/test_release_artifacts.py -q`; expect failures before implementation. Implement streaming SHA-256 and strict schema/identity validation. Bound each archive to 2 GiB, aggregate handoff archives to 4 GiB, config/manifest JSON to 4 MiB, a regular file to 1 GiB, expanded scanned bytes to 8 GiB per image, and members to 200,000. Reject out-of-bound data before unbounded allocation.
- [ ] Read tar/gzip members without `extractall`; never follow symlinks/hardlinks on the host. Support legitimate image absolute symlink targets without following them. Reject unsafe member names, sparse/device payloads or unsupported compression/structure. Check all referenced config/layer content digests; compare uncompressed layer hashes to config diff IDs where applicable. Stream each layer's regular-file data in stored order, retaining deleted-file coverage.
- [ ] Add oversized/compression-bomb, malformed/truncated archive, symlink traversal and duplicate-entry tests. Assert no file outside the temporary inspection directory is created and safe errors omit payloads. Test exact boundaries with small configurable limits in unit fixtures while production defaults remain fixed.
- [ ] Run focused tests and Python-3.12 grammar checks; inspect real candidate archives. Expected: valid images accepted, all malformed identities/bounds rejected, no image execution or registry access.

## Task 3: Disclosure checks for every runtime layer and metadata

**Files:** create `scripts/releases/disclosure.py`, `tests/test_release_disclosure.py`; reuse `security/gitleaks.toml` and pinned installer/tool versions.

**Interfaces:** `check_disclosure(archive: Path, output: Path) -> dict` returns only schema version, archive hash, covered layer/file counts, safe rule-ID counts and blocked status. Failure exits/raises safely; a sanitized summary is not equivalent to scanner success if any stage fails. Task 2 provides archive validation/regular-file streams and configuration/history.

- [ ] Write fake-scanner tests for clean data, detection, unavailable executable, timeout, nonzero infrastructure exit, malformed/oversized output, hostile GITLEAKS_* environment settings, inline allow comments and stale clean summaries. Assert none of the failure modes can become a clean result.
- [ ] Run focused tests for RED. Implement explicit pinned Gitleaks 8.30.1 invocation, default rules through the reviewed config, 100% redaction, ignore-allow-comment protection, empty ignore/baseline context and sanitized environment. Use bounded streamed stdin for layer regular-file data and metadata; preserve file boundaries and enough chunk overlap to detect a secret crossing a stream boundary. Set 60-second subprocess deadlines and a 600-second per-image total; cap captured diagnostic/report data at 1 MiB. Never echo raw scanner output.
- [ ] Validate the pinned CLI's flags/help before freezing the invocation. Enable one decoding level where supported and test its behavior; document nested archive/binary/encoding detection limits rather than claiming exhaustive inspection. Do not use a file-size skip as a clean result; Task 2 bounds or a scanner failure must block unsupported input.
- [ ] Generate ephemeral synthetic secrets at runtime, never as literal tracked tokens. With real Gitleaks, assert detection in a copied source file, a binary-adjacent token, a file deleted by a later layer, metadata/history, and supported encoded data. Assert captured logs and retained summaries contain no sentinel. Confirm excluded environment markers from Task 1 never enter built images.
- [ ] Run `uv run pytest tests/test_release_disclosure.py -q` and the real sentinel probe; expected clean/detection/error distinctions and no raw disclosure. Store only safe results in ignored task scratch; clean fixture resources owned by this task.

## Task 4: Exact-image candidate build and isolated smoke test

**Files:** create `scripts/releases/{candidate,smoke,__main__}.py`, `tests/test_release_candidate.py`, `tests/test_release_smoke.py`; reuse existing Dockerfiles and security runner.

**Interfaces:** `build_candidate(version: str, commit: str, output: Path) -> Path`; `exercise_stack(images: dict[str, str], *, workspace: Path, platform: str = "linux/amd64") -> dict`. CLI: `python3 -m scripts.releases candidate --version VERSION --commit SHA --output-dir DIRECTORY`.

- [ ] Write orchestration tests spying on command calls: exact source/labels/platform; each image built once; image ID captured before checking; failed build/vulnerability/disclosure/smoke yields no exportable handoff; changed image identity after checking rejects export; no push/login command. Run for RED.
- [ ] Build all three images on one fresh runner with release labels present from the start. Use shared pinned scanner installation/build cache on that runner only. Run the existing `scripts.scan_security` image gate on those exact images, export each to a local bounded archive and apply Task 3. Recheck IDs/archive hashes before forming Task 2's handoff. No archive upload happens here.
- [ ] Implement the smoke helper with fresh project names starting `containerguard-release-verify-`, alternate/free localhost ports, generated runtime configuration, and verification-owned volumes/cache. Use fixed accepted project-name syntax and ownership validation before cleanup. Never read or mutate the development .env or development project.
- [ ] Exercise health/readiness, migration success, a public real scan, bounded status polling, non-mock findings retrieval, SBOM metadata/download/hash, permissive and strict policy-version evaluation, and duplicate evaluation identity. Vulnerability counts are observations, not fixed assertions. Timeout/failure retains safe correlation and returns nonzero.
- [ ] Test failed startup, polling timeout, SBOM mismatch and cleanup failure: only owned resources are touched, original failure preserved, cleanup failure prevents declaring success. Run the candidate stack using built images without rebuilding during smoke, then recreate application services and recheck stored artifact bytes.
- [ ] Run focused tests and one real isolated candidate verification on linux/amd64. Expected handoff written only after full success; preserve development data, record disk/resource use and deadlines, remove only owned resources. Candidate CLI errors use exit 2, blocking vulnerability/disclosure findings use exit 1, success uses 0.

## Task 5: Reusable CI and release guard without publication

**Files:** modify `.github/workflows/ci.yml`; create `.github/workflows/release.yml`, `tests/test_release_workflow.py`; wire identity/candidate CLI commands; pin any new action by verified upstream SHA.

**Interfaces:** CI adds `workflow_call` inputs `release_candidate` (boolean, false), `release_version` (string, empty), `release_commit` (string, empty), and output `candidate_artifact_id`. Normal push-main/PR behavior retains the existing six jobs. Candidate mode replaces only the runtime matrix with Task 4's combined candidate job, dependent on backend/frontend/dependency jobs. It returns one immutable artifact ID, not a free-form foreign artifact name.

- [ ] Validate workflow syntax with a checksum-pinned actionlint release from its official repository; record version/checksum before use. For structural workflow tests, add `PyYAML>=6,<7` to the dev dependency group and lock it, keeping application scripts standard-library-only and including the lock update in dependency scans. Tests must parse workflow structure, not merely search strings.
- [ ] Write tests for trusted tag guard order, no publishing from PRs, inherited-secrets absence, exact source input consistency, candidate job's prerequisites, artifact upload only after candidate success, empty artifact IDs on failure, pinned actions, read-only defaults and no always()/continue-on-error bypass. Run for RED.
- [ ] Add tag-push trigger `v*` with Task 1 strict guard and fetched main ancestry. Keep every build/check job contents-read only. Call CI at the same commit using local reusable-workflow syntax. Candidate job timeout: 50 minutes; normal jobs keep existing bounds. Upload only the checked handoff directory, at most 4 GiB, with one-day retention and error on missing files.
- [ ] Restrict candidate exports to validated same-repository tag calls. Ordinary PRs keep tests/history/dependency/runtime checks but produce no release archives. Reusable inputs alone are not authority: candidate code verifies source/tag/event context again. No publisher job is enabled until Task 6 tests pass.
- [ ] Run actionlint and parsed graph tests. Verify the read-only workflow and candidate helper locally before requesting any commit/push. Expected: existing PR behavior preserved; no registry writes or real release tags.

## Task 6: Isolated publisher, registry identities, and overwrite prevention

**Files:** create `scripts/releases/{registry,publish}.py`, `tests/test_release_registry.py`, `tests/test_release_publish.py`; extend CLI and release workflow.

**Interfaces:** `preflight_tags(version: str, commit: str) -> None`; `publish_candidate(directory: Path, *, version: str, commit: str, dry_run: bool) -> dict`; CLI `publish --handoff-dir DIRECTORY --version VERSION --commit SHA [--dry-run]`. Output `release.json` schema 1 with all three fixed service references/digests/config IDs/platform, source/version, safe check links and remaining-findings summary.

- [ ] Write bounded local HTTP fixture tests for registry challenge/auth, valid/malformed manifests/configs, config identity mismatch, redirects to unexpected hosts, TLS/network errors, 401/403/429/5xx, ambiguous absence and existing version/commit tags. Only a confirmed authorized not-found response qualifies as absent. Assert tokens never appear in returned errors/logs.
- [ ] Write publisher tests: validate exact-run artifact ID/source/checksums/config IDs; recheck current tag commit; check all six destination tags before the first push; refuse any existing tag; verify post-push registry manifest/config identity; preserve image bytes/labels; dry-run never logs in for writing or pushes; failed handoff never loads/executes payloads. Include changed-tag and clean-report/different-image cases from Review Focus.
- [ ] Implement pinned-registry HTTPS interactions with argument-list tools/standard library, fixed allowed GHCR/auth hosts and bounded JSON/timeouts. Load validated archives only after all handoff checks; registry login uses temporary Docker config and GITHUB_TOKEN through stdin. No application dependency installation, rebuild, Dockerfile invocation or image execution in publisher.
- [ ] Add separate publisher job after successful reusable CI, using exact candidate artifact ID from the same run. Grant packages:write and only necessary read permissions there; check out reviewed scripts with credentials persistence disabled. Use release-wide concurrency without cancelling an active publisher. No cross-workflow artifacts or PR execution.
- [ ] Push both fixed tags for each exact image, verify registry manifest digest/config/platform/source and write the full digest manifest. If any push/verification fails, report safe partial state and stop; do not delete or overwrite partial tags and do not create a public GitHub Release. Test failures after each upload and ensure next attempt refuses occupied tags.
- [ ] Run focused tests, actionlint and a dry-run with validated local handoff plus mock registry. Expected zero registry mutations in dry-run and all negative cases blocked. Actual GHCR writes remain a later maintainer-approved tag checkpoint.

## Task 7: Digest-pinned installation and draft release notes

**Files:** create `scripts/releases/compose.py`, `tests/test_release_compose.py`, `docs/releases.md`; update README, release workflow and architecture links.

**Interfaces:** `render_compose(manifest: dict) -> str` produces standalone `compose.release.yaml` with no build directives. Validate all three digest references before rendering. `release.json` and that Compose file are attached to the draft GitHub Release by a contents-write notes job after publisher success.

- [ ] Write render tests for missing/extra services, malformed digests, mismatched source/platform, injected strings and localhost defaults. Assert API/worker/frontend/migrate use exact published digests; migrate reuses API; no build section, Docker socket, DB/Redis host ports or browser secret configuration. Preserve health/migration ordering, stop grace, limits and persistent volumes.
- [ ] Implement generator with fixed Compose structure and JSON-safe values (JSON is valid Compose input) or a small reviewed YAML renderer. Reuse documented supported service settings. Pin database/Redis images for the release manifest where verified, documenting they remain outside the current runtime vulnerability gate. Keep secret/runtime values in separately generated ignored configuration, not release assets.
- [ ] Generate release notes with tagged docs links, source/platform, exact digests and tags, required-check links, safe findings summary and limitations. Notes job gets contents:write, no packages:write or application execution, and creates only a draft. Refuse to overwrite an existing GitHub Release's assets silently.
- [ ] Document public-package visibility, temporary empty Docker auth configuration for anonymous pulls, `pull` plus `up --no-build`, startup/download expectations, migration/persistence, manual recovery and partial-publication handling. Installation docs must exist at the tag; retain separate docs and README navigation rather than combining files.
- [ ] Add published-image verification mode using Task 4's owned stack helper. Pull only manifest digests; recheck identities and exercise real workflow/recreation with no source build. Test cleanup failure with development-name refusal. Run local renderer/smoke tests; mark actual public pull evidence pending until Task 8.

## Task 8: Review, negative demonstrations, and first release evidence

**Files:** update `docs/development/verification.md`, `docs/releases.md`, README and the task ledger with observed results. No fabricated release IDs/digests.

- [ ] Run full backend lint/format/tests, frontend lint/format/types/unit/build/browser checks, actionlint, all focused release tests, real disclosure sentinels and candidate smoke. Expected all assertions pass, scanner errors blocked, no sentinel in logs/artifacts, no development data changes. Review the complete branch against the documented scope; fix important issues with RED/GREEN verification.
- [ ] Present reviewed diff and local results before requesting commit/push/PR instructions. Run ordinary GitHub PR checks. Exercise controlled negative release validation/handoff/gate cases without registry writes and record results before merging; distinguish local orchestration proof from actual event/permission proof. Do not expose sentinels in source history.
- [ ] After maintainer-approved merge and green main CI, prepare an unused first version, exact reviewed commit and release commands for explicit tag-push approval. Inspect tag/package protections and explain actual enforcement boundaries; do not assume repository rules were configured.
- [ ] Only after authorized tag push, observe release CI, validated archive transfer and all three GHCR uploads. Record actual config IDs/manifest digests and draft Release URL. A red job or partial upload blocks the completion claim.
- [ ] With maintainer-approved public visibility, perform anonymous pulls using empty auth, run the full isolated published-image workflow and recreation without rebuilding, and clean only owned resources. The owner publishes the GitHub Release only after these checks pass. Record actual evidence, source/tag links and remaining findings.
- [ ] Mark milestone complete only when the public Release, three digest-traceable images, anonymous pull and no-build demo exist. State whether a second developer independently tried setup. Leave signing/provenance and cloud hosting unclaimed.

## Self-review and execution

The eight tasks cover identity/trust, context disclosure, archives, runtime smoke,
CI, publishing, installation, documentation and real first-release evidence.
Review Focus maps to tests in Tasks 1/3/4/6/7. Task 4 keeps the three images on one
runner so full-stack smoke can finish before any archive is uploaded; only the
trusted release mode changes the runtime-matrix arrangement. Artifacts/config IDs
and registry digests have separate checks. Safe archive transfer does not provide
signing or provenance. No first publication is authorized by plan approval.

Implement each task with its focused verification, then review the complete
branch against the design and review-focus cases. Release tags and publication
require explicit maintainer approval after the reviewed checks pass.

## References used while planning

- [GitHub reusable workflows](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows)
- [GitHub workflow artifacts](https://docs.github.com/en/actions/concepts/workflows-and-actions/workflow-artifacts)
- [GitHub container registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
- [Gitleaks commands and flags](https://github.com/gitleaks/gitleaks)
- [Docker image exporters](https://docs.docker.com/build/exporters/image-registry/)
