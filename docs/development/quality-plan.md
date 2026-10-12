# Security and quality implementation plan

**Goal:** Finish the local product with blocking security checks, bounded scan admission, and reproducible portfolio evidence.

**Architecture:** PostgreSQL remains the source of truth for outstanding scans. CI scans committed dependencies and locally built runtime images, then evaluates validated reports with a small shared gate. Existing RQ processing and browser workflows remain intact.

**Tech stack:** Python 3.14, PostgreSQL 17, SQLAlchemy, Redis/RQ, Trivy 0.75.0, Gitleaks 8.30.1, React/TypeScript, Docker Compose, GitHub Actions.

**Spec:** `docs/architecture/security.md`.

## Global constraints

- Work in the existing VSCode checkout; no worktrees. Use `feat/security-quality` for implementation after plan approval. Preserve uncommitted approved documentation when switching branches.
- Do not commit, push, open a PR, or merge without the maintainer's instruction. Each task ends with a reviewable diff, not an automatic commit.
- Localhost-only; no authentication, deployment, publishing, signing, or automatic interrupted-job reconciliation.
- Block HIGH and CRITICAL, including unfixed findings. No exceptions initially; any exception expires within 30 days and matches vulnerability, package, and target.
- MAX_ACTIVE_SCANS defaults to 20, accepts integers 1 through 1000, and counts queued/running real Trivy scans, including retry delays.
- Invalid references: 422 before persistence/queue access. Capacity: 429 and Retry-After: 30 without creating a row/job. Contention or service failure: safe 503.
- One scan per worker in the supported Compose deployment; no distributed execution semaphore or exactly-once claim.
- Keep existing development data and volumes intact. Tests use dedicated PostgreSQL/Redis services and disposable schemas.
- Use neutral documentation names, truthful completion status, and actual UI screenshots.

## Review focus

1. Simultaneous admissions for the last slot: separate transactions must admit exactly one (Task 4).
2. Interrupted/retrying work: retains one capacity slot across restart/recovery (Task 4).
3. Successful scanner exit with an empty or wrong-target report: fails closed (Tasks 1–2).
4. Credentials in rejected inputs or third-party tracebacks: never reflected in public errors or captured logs (Tasks 3 and 6).
5. Explicit queue rejection versus uncertain network outcome: browser must explain rejection accurately and never retry a POST automatically (Task 5).

## File responsibilities

- `scripts/security_gate.py`: validate vulnerability reports/exceptions and determine the gate result; standard library only, usable without application services.
- `scripts/scan_security.py`: run pinned Trivy with explicit settings and invoke the gate only on successful scan execution.
- `scripts/install_security_tools.sh`, `security/tools.json`: checksum-verified pinned Linux CLI installation and tool metadata.
- `security/exceptions.json`: initially empty, scoped vulnerability exceptions.
- `security/gitleaks.toml`: default detection rules plus only proven narrow example exceptions, if necessary.
- `app/persistence/admission.py`: capacity configuration and transaction-scoped admission serialization.
- `frontend/src/features/scans/reference.ts`: browser supported-reference validation.
- Existing API/repository/job modules: integrate validation, capacity, and safe failures without changing scan execution semantics.
- `docs/development/verification.md`, `docs/demo.md`, `docs/images/`: verification evidence, demo instructions, real screenshots.

## Task 1: A vulnerability gate with deterministic negative tests

**Files:** create `scripts/__init__.py`, `scripts/security_gate.py`, `security/exceptions.json`, `tests/test_security_gate.py`, and `tests/fixtures/security/README.md`; use explicitly fictional report builders in the gate tests.

**Interfaces:** `evaluate_report(report: dict, exceptions: list[dict], *, target: str, expected_targets: set[str], now: datetime) -> dict` returns a summary with `blocked`, `findings`, and `exceptions_used`. Invalid input raises `ValueError` with a fixed safe message. CLI accepts `--report`, `--exceptions`, `--target`, repeatable `--expected-target`, and `--summary`; exits 0 for pass, 1 for threshold failure, 2 for invalid input.

- [x] Write failing tests: `test_critical_and_high_block_even_without_fix`, `test_lower_and_unknown_are_reported`, `test_clean_expected_target_passes`, `test_missing_or_wrong_target_fails`, and `test_malformed_vulnerability_fails`. Assertions: both blocked severities fail; LOW/MEDIUM/UNKNOWN remain visible; malformed input never becomes zero findings.
- [x] Run `uv run pytest tests/test_security_gate.py -q`; confirm failures identify missing gate behavior.
- [x] Implement schema validation for the pinned Trivy JSON version, including report kind, target identity, expected dependency targets, and vulnerability field types. Keep runtime-image identity checks separate from filesystem lockfile checks. Validate even lower-severity entries before evaluating thresholds.
- [x] Add exception tests for exact ID/package/target match, mismatched target, missing rationale/owner/reference, duplicate entries, expiration today, expiration in the past, and a duration exceeding 30 days. Use UTC `created_at` and `expires_at`; require `created_at <= now < expires_at <= created_at + 30 days`.
- [x] Implement exception validation. CLI subprocess tests assert actual exit codes and summary contents for clean, blocked, malformed, and absent reports. Keep fixtures explicitly fictional.
- [x] Run the focused tests and Ruff. Inspect the diff against the approved severity and exception policy.

## Task 2: Pinned security tools and blocking CI

**Files:** create `scripts/install_security_tools.sh`, `scripts/scan_security.py`, `security/tools.json`, `security/gitleaks.toml`, `tests/test_security_scan.py`; modify `.github/workflows/ci.yml`; update `tests/test_security_gate.py` with observed report shapes.

**Interfaces:** `scan_security.py` accepts `--kind filesystem|image`, `--input`, `--target`, `--output-dir`, and repeatable `--expected-target`. It runs a successful scan before calling Task 1's gate. Exit 2 denotes execution/report failure; exit 1 denotes a valid blocked report. `tools.json` records versions, Linux amd64 release URLs/checksums or checksum-pinned source-build metadata.

- [x] Fetch official Trivy 0.75.0 and Gitleaks 8.30.1 release metadata; verify downloadable artifacts/checksums and the pinned CLI help. Record the verified checksums before enabling CI installation. Installer must reject checksum mismatch and unsupported platforms; it must not fall back to latest.
- [x] Write failing runner tests using a fake executable: scanner exits nonzero while writing a clean report; scanner times out; scanner produces no report; filesystem report omits one lockfile; valid report blocks. Assert no failure becomes exit 0 and stale report files cannot be reused.
- [x] Implement explicit Trivy vulnerability-only JSON scans, all severities, no ignore-unfixed filtering, bounded execution, and fresh output paths. Pass an explicit empty native ignore file/config from a temporary directory; gate exceptions come only from `security/exceptions.json`. Include development dependencies using the pinned CLI's verified flags. Validate both `uv.lock` and `frontend/package-lock.json` target coverage.
- [x] Build and scan the current linux/amd64 API, worker, and frontend images. Record actual package/OS report targets, scanner version, database metadata, and HIGH/CRITICAL baseline. Update fixtures only with sanitized shapes, not changing live findings.
- [x] Resolve baseline findings through targeted supported dependency/base-image updates and relevant existing tests. If an unfixed finding requires an exception, present the exact evidence and proposed exception to the maintainer before adding it; do not weaken the threshold.
- [x] Run Gitleaks with default rules, full redaction, and reachable history. Create an ephemeral synthetic-secret repository outside the source tree and assert detection exits nonzero with no sentinel printed. Do not commit the synthetic credential fixture. If demo credentials cause a proven false positive, scope an exception to the exact documented example and path.
- [x] Add dependency/secret CI jobs and a runtime-image matrix (`api`, `worker`, `frontend`), linux/amd64 Docker builds, bounded 20-minute job deadlines, and 7-day vulnerability-report retention. Pin any newly used actions by verified SHA, retain contents: read and persist-credentials: false; checkout history for secrets uses fetch-depth: 0.
- [x] Upload only validated vulnerability reports/summaries on success or gate failure, never raw secret output. Scanner/install failures remain failing jobs. Reports identify target and tool version; no `continue-on-error` or unconditional success fallback.
- [x] Run focused gate/runner tests and inspect workflow permissions, PR triggers, credentials, shell exit handling, and upload conditions. Preserve backend/frontend jobs.

## Task 3: Validate supported references at submission

**Files:** modify `app/api/schemas.py`, `app/main.py`, `tests/test_scans.py`, `tests/test_database_errors.py`; add `tests/test_scan_reference_validation.py`. Keep resolver tests where worker-side behavior is being tested.

**Interfaces:** `ScanSubmission.image_reference` retains its trimmed string contract and 512-character maximum, with a field validator reusing `parse_docker_tag(image_reference: str) -> tuple[str, str]`. The public error response must not include the raw value or exception context.

- [x] Write parameterized failing API tests for GHCR/other hosts, URLs, embedded credentials, digest inputs, missing tags, control characters, malformed paths, and overlong input. Spy on repository/enqueue calls: invalid requests produce 422 with neither call made.
- [x] Assert accepted references include explicit library namespace and Docker Hub shorthand supported by the parser. Preserve submitted spelling after whitespace trimming rather than silently rewriting stored references.
- [x] Implement schema validation and a safe validation-error response that preserves field locations/types needed by the browser while omitting input and exception context. Preserve unrelated query/path validation semantics.
- [x] Assert sentinel credentials do not appear in serialized responses or captured application/access logs. Adapt existing tests whose invalid image requests should now fail before worker invocation; do not remove worker validation tests.
- [x] Run focused API/schema/resolver tests, then backend checks.

## Task 4: Atomic outstanding-scan capacity

**Files:** create `app/persistence/admission.py`, `tests/test_scan_admission.py`; modify `app/persistence/repository.py`, `app/jobs/submission.py`, `app/main.py`, `.env.example`, `compose.yaml`, `tests/test_enqueue_failure.py`, and `tests/test_scan_recovery.py`.

**Interfaces:** `get_max_active_scans() -> int`; `ScanCapacityExceeded` and `ScanAdmissionUnavailable` safe exception types; `reserve_scan_capacity(session: Session, *, limit: int) -> None` called inside the creation transaction. Existing `create_queued_trivy_scan` and `start_trivy_scan` signatures stay unchanged.

- [x] Write failing configuration tests: absent value yields 20; 1 and 1000 accepted; 0, 1001, booleans-as-text, decimals, blank, and nonnumeric values rejected safely.
- [x] Write real PostgreSQL tests with separate sessions and a synchronized start barrier for two requests competing at limit 1. Assert exactly one new scan, one capacity exception, and no orphan job for the rejected submission. Join threads with bounded timeouts and fail rather than hang.
- [x] Implement one transaction advisory lock key (`1128746545`) shared by both real-scan creation paths. Use a transaction-local 2-second lock timeout, then a fresh count query under PostgreSQL READ COMMITTED. Count scanner_name=trivy and status in queued/running; insert before releasing the transaction lock. Handle lock timeout with a safe typed exception and rollback.
- [x] Add tests for running/queued/mock/completed/failed rows; completion/failure frees capacity; retries/recovery retain a single slot; direct synchronous creation cannot bypass admission; lock contention rolls back without inserts; Redis failure marks an admitted queued record failed. A record left by a simulated commit-before-enqueue interruption continues counting.
- [x] Wire 429 with Retry-After: 30 and a fixed message; map admission contention to 503. Update OpenAPI descriptions. Wire identical capacity configuration to API/worker/migration environments where applicable; keep tests isolated from development state.
- [x] Run admission, enqueue, retry, recovery, and workflow tests, then all backend tests. Inspect transaction boundaries and lock ordering for deadlocks.

## Task 5: Browser validation and capacity feedback

**Files:** create `frontend/src/features/scans/reference.ts`, `reference.test.ts`; modify `frontend/src/features/scans/ScanForm.tsx`, `ScansPage.test.tsx`, `frontend/src/api/client.ts`, `client.test.ts`, and `frontend/tests/browser/scans.spec.ts`.

**Interfaces:** `isSupportedImageReference(value: string): boolean` mirrors the server's supported grammar. Client 429 copy: "The scan queue is full. Try again shortly." ScanForm treats a confirmed 429 as rejection, while network/timeout/invalid-response outcomes retain the history-check guidance.

- [x] Write failing validator tests from the same accepted/rejected cases as Task 3, including shorthand, trimming, 512-character maximum, and tag boundaries.
- [x] Add component tests: invalid input sends zero POST requests; 429 sends exactly one POST, displays queue-full copy, and does not imply the scan may have been saved; network uncertainty still offers history inspection.
- [x] Implement validation/help and explicit 429 handling without automatic retry, extra controls, or broad UI redesign. Keep keyboard focus and existing busy-submit protection.
- [x] Add one browser fixture case for queue rejection and run frontend lint, format, types, unit tests, build, and browser tests. Confirm backend remains authoritative if browser validation is bypassed.

## Task 6: Runtime limits and disclosure checks

**Files:** modify `compose.yaml`, `app/jobs/worker.py`, `app/jobs/tasks.py`, `app/logging_config.py` only where disclosure tests reveal a gap; extend `tests/test_logging_config.py`, `tests/test_scan_logging.py`, `tests/test_scan_job.py`; update `docs/architecture/jobs.md` and `containers.md`.

**Interfaces:** Compose service CPU/memory/PID limits; Redis `maxmemory` with existing noeviction/AOF. Preserve public error codes, RQ retries, and graceful-stop behavior.

- [x] Measure idle and real-scan CPU/memory, including a database download in a disposable cold-cache worker. Candidate starting bounds: frontend 0.5 CPU/128 MiB/64 PIDs; API 1 CPU/512 MiB/128 PIDs; worker 2 CPUs/2 GiB/256 PIDs; Redis 0.5 CPU/256 MiB/64 PIDs with maxmemory 128 MiB. Record measured peaks/headroom; revise bounds with evidence before finalizing. Migration uses API limits.
- [x] Write failing sentinel tests for database/Redis URLs, registry auth, subprocess stderr, and an unexpected job exception. Inspect worker/RQ captured output, not only the application formatter. Require generic diagnostics plus scan/job correlation, preserving failure classification and retry behavior.
- [x] Implement only required safe-error/logging fixes. Avoid replacing exceptions with success or suppressing operational failure state.
- [x] Configure supported Compose resource fields and Redis maxmemory. Inspect Docker HostConfig for applied CPU/memory/PID settings, and Redis CONFIG GET for maxmemory/noeviction.
- [x] Submit a real scan under limits; verify completion/findings/SBOM and worker health. Exercise Redis refusal with a disposable service and verify safe failure rather than job loss reported as success.
- [x] Run focused logging/worker tests and full backend checks. Document one-job-per-worker scope, retained stale slots, cache sharing, disk-growth limits, and measured sizing without production-capacity claims.

## Task 7: Fresh-checkout and portfolio evidence

**Files:** create `docs/development/verification.md`, `docs/demo.md`, and actual screenshot files under `docs/images/`; update `README.md`, `docs/architecture/security.md`, and related architecture links.

**Interfaces:** A reproducible local setup and demo using current API/browser routes; no new product API.

- [x] Prepare an isolated source snapshot including the pending branch changes but excluding local environments, ignored files, credentials, and caches. Record that an uncommitted snapshot is provisional; repeat against the committed branch before declaring fresh-checkout verification complete.
- [x] Use a unique Compose project and alternate ports with fresh named volumes/cache. Run documented setup/migrations, scan a public Docker Hub image, inspect findings, verify downloaded SBOM hash, version a policy, and retrieve its evaluation. Confirm restart persistence. Never reuse or remove development volumes.
- [x] Capture real browser screenshots of scan findings, SBOM metadata/download, and evaluation rules. Inspect screenshots for accidental personal information or credentials. Record live versions/date and counts as observations, not permanent expected values.
- [x] Add a concise Mermaid system diagram and short demo walkthrough. Update README with security-check commands and links, threat boundaries, exact scan/gate scope, capacity semantics, and recovery instructions. Change security.md status only for controls actually verified.
- [x] After maintainer-approved push, demonstrate deliberately red test and gate runs on a disposable demonstration branch, restore correct code, and record run links. No automatic push under this plan. Scanner-failure fixtures must exercise the same runner CI uses.
- [x] Run complete backend/frontend checks and all runtime builds/security scans. Record any unresolved findings or exceptions clearly. Review the complete branch against the design and verification evidence.
- [x] Repeat setup from a committed checkout and record final CI results after the maintainer commits/pushes. State explicitly if no second developer has exercised setup; do not claim external validation. Clean only verification-owned resources.

## Verification commands

Backend (existing dedicated test services must be ready):

```sh
uv run ruff check .
uv run ruff format --check .
uv run --env-file .env.example pytest
```

Frontend, using Node 24 from `frontend/`:

```sh
npm ci
npm run lint
npm run format:check
npm run typecheck
npm test
npm run build
npm run test:e2e
```

For security, use the Task 2 installer/runner with the same arguments as CI;
validate command parity during implementation rather than maintaining a second
manual policy. A successful result requires all expected scan targets, no
unexcepted HIGH/CRITICAL finding, and no scanner infrastructure error.

## Execution and review

The implementation and full-branch review are complete. Subsequent committed-
checkout and controlled red/green CI results are recorded in
[verification](verification.md).

Plan self-review: all spec sections map to Tasks 1–7. The five review-focus cases
have explicit tests. Gate and runner interfaces remain distinct; repository
creation signatures remain stable. Runtime sizing and tool checksums are measured
verification outputs, not fabricated constants. Baseline findings requiring an
exception or an incompatible base update must return for a specific decision.
