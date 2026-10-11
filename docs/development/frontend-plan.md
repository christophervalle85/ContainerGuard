# Frontend Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for the established guided inline workflow. Steps use checkbox syntax. Preserve learner checkpoints and learner control of commits; do not implement the whole milestone in one turn.

**Goal:** Let a browser user submit scans, inspect their evidence, download SBOMs, and manage/evaluate immutable security policies.

**Architecture:** A React/TypeScript application under `frontend/` uses the existing FastAPI backend through relative `/api/v1` requests. Vite proxies requests in development; an unprivileged static server does so in Compose. PostgreSQL remains authoritative, with one additive scan-details response and no schema migration.

**Tech Stack:** React, TypeScript, Vite, React Router, native fetch, npm, Node 24 LTS, Vitest, React Testing Library, Playwright, unprivileged Nginx; existing Python/FastAPI/PostgreSQL/Redis/Trivy unchanged.

**Spec:** [Frontend architecture](../architecture/frontend.md).

## Global Constraints

- Use the existing `feat/frontend-dashboard` checkout; no new worktree and no implementation on main.
- Work one task/checkpoint at a time. The learner reruns checks and tries the delivered behavior before the next task. Commits/pushes remain learner-led.
- Preserve compact history and existing response fields; add metadata only to the single-scan response. No database migration or scanner/retry change.
- All browser API requests use relative `/api/v1/...` paths. Preserve the `/api/` prefix through both proxies.
- Request deadline: 15 seconds. Poll three seconds after the last successful response, with no overlap. Stop after ten minutes elapsed, on terminal status, or on an API error; pause while hidden. Reloading the page restarts observation.
- Never automatically retry a POST. Server-side pagination; reset findings offset on severity change. No unbounded lists or per-history-row details requests.
- Distinguish scan execution failure, SBOM failure, policy rejection, and evaluation error. Do not interpret HTTP 200 or zero findings as evidence that an image is secure.
- Keep saved policy versions/evaluations immutable and require explicit version selection.
- Localhost-only frontend port 8080 by default, API 8000, Vite 5173. No credentials in browser assets, permissive CORS, submitted-image execution, or Docker socket mount.
- Light neutral workspace, blue action accent, text with semantic status colors, system fonts, no marketing hero/decorative charts. Visible labels/focus, keyboard workflow, reduced motion, narrow-screen support.
- Commit package-lock.json; ignore dependencies, build/test output, and real environment files. Root Python Docker context stays narrow.
- Routine tests use fixtures and isolated local services. Real scans are a separate recorded smoke test; do not hardcode live vulnerability counts.

## Review Focus

1. Late responses after navigation/filter changes must not overwrite current state; cover in Tasks 3/4/5.
2. Lost POST responses must not cause a duplicate scan, version, or automatic evaluation; cover in Tasks 3/6/7.
3. Hidden tabs, React development remounts, and slow responses must not multiply polling or evade the observation bound; cover in Task 4.
4. API/static failures must remain errors rather than HTML masquerading as JSON or an empty success; cover in Tasks 2/8/9.
5. Policies beyond page one, failed SBOMs, and fictional scans must not yield an implicit version choice or misleading real policy pass; cover in Tasks 5/6/7/9.

## File responsibilities and common checks

Backend: modify `app/api/schemas.py`, `app/persistence/repository.py`, and the GET response annotation in `app/main.py`. New backend tests live in `tests/test_scan_details.py`; update exact GET-response assertions in existing tests only when the intentional additive contract requires it.

Frontend: `src/app/` owns layout/routes; `src/api/` owns contracts, requests, and endpoint functions; `src/features/scans/` and `src/features/policies/` own their screens and hooks; `src/components/` owns reusable pagination/status controls; `src/styles/` owns visual tokens/base/layout. Fixtures and browser tests use `frontend/tests/`. Keep feature-specific files with their feature.

Backend shared checks, from repository root:

```bash
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked --env-file .env.example pytest
```

Expected: clean lint/format and the full suite passing against dedicated test-db/test-redis. Start only those test services if needed; never clear development data.

Frontend scripts introduced in Task 2:

```bash
npm --prefix frontend run lint
npm --prefix frontend run format:check
npm --prefix frontend run typecheck
npm --prefix frontend test
npm --prefix frontend run build
```

Expected: all commands exit zero. `test` runs Vitest once, with optional filename arguments. Browser tests added in Task 9 use `npm --prefix frontend run test:e2e`. Do not rerun unrelated live scans for routine frontend changes.

## Task 1: Expose saved scan details

**Files:** Modify `app/api/schemas.py`, `app/persistence/repository.py`, `app/main.py`; create `tests/test_scan_details.py`; adjust `tests/test_scans.py` exact single-scan assertions if required.

**Interfaces:** Produce `ScanDetails(ScanRecord)` with `created_at: datetime`, `started_at/completed_at: datetime | None`, `digest/platform/scanner_name/scanner_version/error_details: str | None`, `scanner_database_metadata: dict | None`, `mock: bool`. `repository.get_scan(session: Session, scan_id: UUID) -> ScanDetails | None`; GET `/api/v1/scans/{scan_id}` returns ScanDetails. History stays `ScanHistory[ScanRecord]` in behavior and field shape.

- [x] Write API/repository tests using real isolated PostgreSQL: queued and running Trivy scans have creation time and appropriate null fields; completed scans return saved digest/platform/tool/timestamps/database metadata; unresolved failures return safe details without invented identity; legacy mock scans have `mock: true`; missing UUID404 and database503 remain intact.
- [x] Add a compact-history assertion and SQL capture showing details reads do not fetch findings or SBOM payloads. Existing ID/reference/status values must be preserved. Use a new session to prove values come from durable storage.
- [x] Run `uv run --locked --env-file .env.example pytest tests/test_scan_details.py -q`. Expected RED: absent detail fields/type before implementation.
- [x] Add the response model and bounded scan/image retrieval. Set `mock` using the same scanner-name convention as findings; keep history construction unchanged. Expose only already-safe persisted error details.
- [x] Update intentional exact single-scan assertions, run the focused tests and backend shared checks. Expected GREEN; no new migration.
- [x] Learner checkpoint: rebuild/recreate the API if using Compose, retrieve an existing real scan in Swagger, verify identity/timestamps/tool/mockfalse. Suggested commit: `Expose saved scan metadata for the dashboard`.

## Task 2: Create the frontend shell and API boundary

**Files:** Create `frontend/package.json`, lockfile, `.npmrc`, `.nvmrc`, `index.html`, TypeScript/Vite/ESLint/Prettier/Vitest configuration, `src/main.tsx`, `src/app/{App,AppLayout}.tsx`, `src/styles/{tokens,base}.css`, `src/api/{types,client,scans,policies,evaluations,sboms}.ts`, test setup/fixtures. Modify root `.gitignore` only for frontend-local artifacts. Add focused client/layout tests alongside these files.

**Interfaces:** `ApiError` contains an HTTP status when available, a safe message, and field-validation information when present. `requestJson<T>(path: string, options?: RequestInit): Promise<T>` supports caller cancellation and a 15000ms deadline. Endpoint functions accept an optional AbortSignal; use explicit input/output types matching Python contracts. `App` accepts browser routing normally and supports a memory router in tests. Routes `/scans`, `/scans/:scanId`, `/policies`; `/` redirects to `/scans`; unknown UI route shows not-found.

- [x] Verify/install a Node24 LTS runtime for this project's commands; record the observed patch and installation method without replacing unrelated system software. Current host Node23 is not the chosen runtime. Pin Node major24 in `.nvmrc`, package engines, later Docker and CI; install compatible stable packages with exact direct versions and commit the lockfile. No global product package installation.
- [x] Create only the tooling needed to run tests/build, then write failing layout/client tests: accessible Scans/Policies navigation, root redirect, safe404/409/422/503 messages, malformed JSON/unknown status rejected, timeout and caller cancellation, relative URLs, and exactly one call for a failed POST.
- [x] Run `npm --prefix frontend test -- src/api/client.test.ts src/app/App.test.tsx`. Expected RED for absent client/layout behavior; tooling itself may be installed to enable the test runner.
- [x] Implement the shell and API boundary. Validate response fields needed by each endpoint rather than casting arbitrary JSON and silently substituting defaults. Add a separate binary-download helper; never send downloads through JSON parsing. Use no automatic request retry. Native fetch stays behind this boundary.
- [x] Configure Vite localhost5173 strictPort and server-only `API_PROXY_TARGET`, defaulting to `http://127.0.0.1:8000`, with `/api/` preserved. Run all frontend shared checks. Expected GREEN and a production asset build.
- [x] Learner checkpoint: open the shell and navigate with the keyboard. Explain components/props, TypeScript contracts, and why the dev proxy differs from the backend. Suggested commit: `Add the typed React dashboard foundation`.

## Task 3: Submit scans and browse history

**Files:** Create `src/features/scans/{ScansPage,ScanForm,ScanHistory}.tsx`, `src/components/{Pagination,StatusLabel}.tsx`, feature tests; extend `src/api/scans.ts` and routes from Task2.

**Interfaces:** `ScansPage` uses `submitScan({image_reference}, signal?) -> Promise<ScanAccepted>` and `listScans({limit,offset}, signal?) -> Promise<ScanHistory>`. `Pagination` receives limit/offset/total plus `onPageChange(offset)`. `StatusLabel` renders text plus semantic styling, not color alone.

- [x] Write tests for labeled submission, 202 navigation using returned UUID, in-flight disabling, input preserved on validation/network failure, and a lost response causing no second POST. Server status_url cannot redirect to an arbitrary origin.
- [x] Test empty/loading/error history, server-side pages, direct links, stable current page after a late old response, and no per-row metadata/findings calls. Keep limit/offset in validated URL parameters; invalid values normalize to defaults20/0 before requests.
- [x] Run `npm --prefix frontend test -- src/features/scans/ScansPage.test.tsx`. Expected RED for missing workflow.
- [x] Implement form/history with cancellation and current-request protection. Use no history polling loop. Show supported public DockerHub/linuxamd64 scope and an explicit refresh. On ambiguous submission failure suggest checking history before resubmitting.
- [x] Run frontend shared checks. Expected GREEN. Learner submits a real scan through the UI and sees its saved ID/history; the details route can still be a shell at this checkpoint. Suggested commit: `Submit scans and browse durable history in the dashboard`.

## Task 4: Follow scan details with bounded polling

**Files:** Create `src/features/scans/{ScanDetailsPage,ScanIdentity}.tsx`, `useScanDetails.ts`, corresponding tests; extend detail route.

**Interfaces:** `useScanDetails(scanId: string)` exposes detail/loading/error/observation-paused state. Reloading the page begins a new observation window. Uses `getScan(scanId, signal?) -> Promise<ScanDetails>`. Internally shared constants are request15000ms, delay3000ms, observation600000ms. Child sections in later tasks consume the loaded ScanDetails, never start duplicate status polling.

- [x] Write timer-driven tests for queued->running->completed and failed transitions; next request starts3000ms after successful completion, never during a slow request. Stop on terminal/error/deadline; page reload begins a new bounded window without changing server status.
- [x] Cover hidden-tab pauses with elapsed deadline retained, navigation/ID changes cancelling work and ignoring late responses, and React StrictMode setup/cleanup leaving one active loop. Preserve current content while refreshing and focus during updates.
- [x] Test visible digest/platform/timestamps/tool/safe errors, null metadata, missing UUID, fictional labels, and failed execution distinct from a completed zero-findings state.
- [x] Run `npm --prefix frontend test -- src/features/scans/useScanDetails.test.tsx src/features/scans/ScanDetailsPage.test.tsx`. Expected RED.
- [x] Implement status/identity and hook, with no POST in an effect. Format timezone explicitly and preserve full identifiers with copy actions. Run frontend shared checks. Expected GREEN.
- [ ] Learner checkpoint: follow a real scan and verify completion stops refreshing. Explain effects, cleanup, cancellation, and why UI observation timeout does not cancel a job. Suggested commit: `Follow scan progress with bounded dashboard polling`.

## Task 5: Browse findings and download SBOMs

**Files:** Create `src/features/scans/{FindingsSection,SbomSection}.tsx`, tests; complete `src/api/{scans,sboms}.ts` binary retrieval.

**Interfaces:** `FindingsSection({scan})` uses `getFindings(scanId,{severity?,limit,offset},signal?) -> Promise<FindingPage>`. `SbomSection({scan})` uses `getSbomMetadata(scanId,signal?) -> Promise<SbomMetadata>` and `downloadSbom(scanId,signal?) -> Promise<Blob>`. Both respond to terminal transition without their own scan-status loop.

- [x] Write tests for server severity filtering and matching totals, resetoffset0 on filter change, URL page restoration, late filter-response rejection, past-end/zero results, repeated CVE occurrences, nullable fix, and visible legacy mock status. Failed/pending scan must not look like zero vulnerable packages.
- [x] Write SBOM tests for all four statuses, metadata-only rendering, explicit binary download with UUID filename, object URL cleanup, and409/404/500/network failures. A section failure leaves loaded identity/findings intact; a failed SBOM does not become a scan execution failure.
- [x] Run `npm --prefix frontend test -- src/features/scans/FindingsSection.test.tsx src/features/scans/SbomSection.test.tsx`. Expected RED.
- [x] Implement independently loading sections with cancellation, labeled severity filter, accessible table/pagination, and bounded binary helper. Do not parse/reserialize downloaded JSON or download it during polling.
- [x] Run frontend shared checks. Expected GREEN. Learner filters real findings, downloads an SBOM, and compares its checksum with metadata. Suggested commit: `Inspect findings and download saved SBOMs in the dashboard`.

## Task 6: Manage policies and immutable versions

**Files:** Create `src/features/policies/{PoliciesPage,PolicyList,VersionHistory,PolicyForm,RuleFields,RuleSummary}.tsx`, focused tests; complete `src/api/policies.ts`.

**Interfaces:** API functions `listPolicies({limit,offset},signal?)`, `listPolicyVersions(policyId,{limit,offset},signal?)`, `createPolicy({name,rules},signal?)`, `createPolicyVersion(policyId,{rules},signal?)`. RuleFields uses controlled `PolicyRuleFormValues` with threshold strings until validation produces PolicyRules; RuleSummary accepts a saved PolicyRules. Selected policy comes from a validated `policy` URL parameter.

- [x] Write tests for policy and version pagination beyond page1, selected-policy changes cancelling old requests, stable immutable version display, and creation selecting the returned identity/version.
- [x] Test thresholds0/2147483647 accepted; empty/negative/fractional/out-of-range rejected without coercion. Test name trimming/length, explicitUNKNOWN action, requiredSBOMboolean, duplicate409, field422, pending disable, preserved values, and no repeated POST after a lost response.
- [x] Run `npm --prefix frontend test -- src/features/policies/PoliciesPage.test.tsx src/features/policies/PolicyForm.test.tsx`. Expected RED.
- [x] Implement the view and reusable rule form/summary. Use create-new-version wording and do not expose nonexistent edit/delete behavior. Refresh only affected lists. Run frontend shared checks. Expected GREEN.
- [x] Learner creates a policy and a second version and confirms the first rules remain unchanged. Explain controlled inputs and converting form strings into validated API values. Suggested commit: `Manage immutable security policies in the dashboard`.

## Task 7: Evaluate explicit versions and show saved decisions

**Files:** Create `src/features/scans/{EvaluationSection,EvaluationResult,PolicyVersionPicker}.tsx`, tests; complete `src/api/evaluations.ts`; reuse Task6 rule display and policy functions.

**Interfaces:** `EvaluationSection({scan})` uses `evaluateScan(scanId,{policy_version_id},signal?) -> Promise<EvaluationRecord>` and `listEvaluations(scanId,{limit,offset},signal?) -> Promise<EvaluationPage>`. Picker returns an explicit selected PolicyVersionRecord; selection alone never calls evaluateScan.

- [x] Write tests proving no implicit latest selection, independent paginated policy/version access beyond page1, selected rule preview, and no evaluation until a version is explicitly chosen and the user submits.
- [x] Cover passed/failed/error HTTP200 outcomes, all5counts, all explanations, saved rule snapshot rather than current policy rules, duplicate ID/timestamp retention, and saved evaluation pagination. New versions cannot change already displayed saved results.
- [x] Test pending/failed/fictional/no-image scans disabled with explanation, backend409 authoritative, missing resource404, corruptionerror distinct from rejection, and lost response with no automatic POST. Selection changes during an in-flight request must not mislabel the resulting version.
- [x] Run `npm --prefix frontend test -- src/features/scans/EvaluationSection.test.tsx`. Expected RED.
- [x] Implement picker, submission, and results. Keep saved result rendering keyed to returned scan/version identity; refresh list after mutation without overwriting historical decisions. Run frontend shared checks. Expected GREEN.
- [x] Learner evaluates a real scan, checks the determining rule, then repeats the request and verifies saved identity. Suggested commit: `Explain saved policy evaluations in the dashboard`.

## Task 8: Serve the complete UI through Compose

**Files:** Create root `Dockerfile.frontend`, `frontend/{nginx.conf,.dockerignore}`; modify `compose.yaml`, `.env.example`; add focused operational notes to `docs/architecture/frontend.md` after verification.

**Interfaces:** frontend build context `./frontend`, Dockerfile `../Dockerfile.frontend`; Node24 builds assets with npmci; unprivileged Nginx serves on container8080. Host binding `127.0.0.1:${FRONTEND_PORT:-8080}:8080`, static `/healthz`, same-path `/api/` proxy, client route fallback, API hostname re-resolution after recreation.

- [x] Before server configuration, capture failing smoke checks for `/scans/<uuid>` reload, missingstatic404, unknownAPI404 notHTML200, backend outage visible502/504, healthz200, and API reconnection after recreation. Use only an isolated disposable Compose project for fault/recreation tests.
- [x] Build locked static assets, choose and record the supported unprivileged Nginx tag/digest used, configure proxy/DNS/fallback without broadening the Python Docker context, and add frontend service after API health. No runtimeNode/devtools/secrets or socket mount.
- [x] Run `docker compose --env-file .env.example config --quiet` and `docker compose --env-file .env.example build frontend`. Expected valid configuration/build. Inspect runtime nonroot and test health/direct reload/proxy/error checks; expected GREEN.
- [x] Confirm frontend health only establishes static-server liveness, existing migration dependency still blocks API/worker as before, and named data volumes are retained. Run frontend shared checks after configuration changes.
- [x] Learner starts the Compose UI at8080, completes a real workflow, recreates application services, and retrieves the same scan/artifact/evaluations. Suggested commit: `Run the dashboard and API proxy through Compose`.

## Task 9: Browser workflows and CI checks

**Files:** Create `frontend/playwright.config.ts`, `frontend/tests/browser/{scans,policies,evaluations,accessibility}.spec.ts`, shared deterministic fixture routing; modify frontend scripts and `.github/workflows/ci.yml`.

**Interfaces:** `npm run test:e2e` launches a localhost frontend server through Playwright webServer with an explicit port. Tests intercept API routes using deterministic responses; never need a live public scan. CIfrontend job uses Node24, npmci, lint/format/typecheck/tests/build, then pinned Playwright dependency's Chromium installation and browser tests. Existing backend job/services remain intact.

- [x] Write failing browser scenarios: submit/follow scan, filter/page findings, download exact fixturebytes, createpolicy/version, explicit evaluation rejection and saved snapshot, directroute refresh, keyboard labels/focus, and narrow viewport without page-wide overflow.
- [x] Add fixture failures for malformed API, unavailable proxy, missing scan, failedSBOM, evaluationerror, and off-first-page policy/version selection. Fixture intercepts must not hide real static routing failures; Task8 covers the actual static server separately.
- [x] Run `npm --prefix frontend run test:e2e`. Expected RED for any missing behavior; distinguish a missing browser/tooling failure from the behavior regression before fixing product code.
- [x] Implement only demonstrated behavior fixes with focused RED/GREEN tests, then add the frontend CI job using least permissions. Frontend build artifacts and test reports stay ignored; upload only useful failure reports if configured.
- [x] Run backend and frontend shared checks plus browser suite. Expected GREEN; CI YAML parses and keeps backend isolation/official ECR service-image references. Learner reruns checks before commit. Suggested commit: `Check dashboard browser workflows in CI`.

## Task 10: Integrated verification, documentation, and review

**Files:** Refine frontend components/styles for the requested UI/UX pass; update README, `docs/architecture/{frontend,containers}.md`, and this checklist. Keep screenshots/demo evidence limited to features actually verified.

- [x] Complete the learner-requested UI/UX polish pass using a frontend design plugin. Figma is installed and is the current candidate; confirm its connection/capabilities when starting the pass. Apply the deferred decisions in UI/UX notes below. Review screen hierarchy, spacing, typography, scan progress, forms, empty/error states, keyboard access, and narrow-screen layouts with the learner, then implement the agreed design in this React app. Preserve API behavior and rerun affected tests plus the full frontend checks.
- [x] Run all backend/frontend/browser checks, build all three application images, and exercise the complete real browser workflow in Compose. Record actual image digest/platform/Trivyversion/date/outcomes; no fixed live finding count assertions.
- [x] Verify checksum-preserving download, explicit-version pass/rejection, historical snapshots after policy evolution, retained history after recreation, and visible scan/SBOM/API/evaluation failure states. Exercise API reconnection after recreation. Use disposable resources for destructive cases and remove only owned resources.
- [x] Update README startup, Node24 hostdev, UI/APIports, tests, polling deadline/page reload, unknownPOSToutcome, limits, and troubleshooting. Mark architecture implemented only after verification. Explain the backend addition and why TypeScript contracts are not runtime validation.
- [x] Dispatch one fresh independent whole-branch reviewer through requesting-code-review, passing plan/spec and Review Focus. Resolve Important/Critical findings with regression RED/GREEN and full checks; record minor limitations honestly. No per-checkpoint implementer agents.
- [ ] Learner reviews scope and evidence, commits/pushes; open PR only when requested. Confirm all relevant CI jobs green before merge. Suggested final commit: `Document and verify the complete dashboard workflow`.

## UI/UX decisions

- **Scan status refresh:** Removed the separate **Refresh status** button and
  its manual-refresh-only logic as requested. Unfinished scans still update
  automatically. Reloading the page resumes observation after a connection error
  or the ten-minute limit; it reads the existing scan without submitting another
  job or cancelling the worker. Tests and recovery copy cover this behavior.
- **Decision presentation:** Show the outcome, severity counts, and rule
  explanations first. Expand **Saved rules and evaluation record** for immutable
  identifiers, timestamps, and the original rules. A newly submitted decision
  appears once; its history page explains that it is included in the total.
- **Layout:** Keep the light workspace and blue action color. Use flat form
  surfaces, compact label/value rows with inline copy controls, and sticky scan
  section navigation. Wide screens keep policies beside their version history;
  narrow screens stack controls and wrap long identifiers. Hover feedback and
  disclosure motion respect reduced-motion preferences. The earlier editable
  Figma reference is https://www.figma.com/design/ous2k82nmWfoxqdwy5USIH; the React
  interface includes the subsequent compact-layout refinements.


## Execution status

Implementation and local integrated verification are complete in the existing
feature branch. The learner accepted the UI refinement. A fresh independent
whole-branch review and focused follow-up are complete; its minor findings have
been addressed. The architecture document records the live verification results
and the boundary between browser fixtures and real Compose evidence. Final
learner sign-off, commit/push, PR creation, and GitHub CI remain pending.

Task4's original learner polling checkbox is retained for final sign-off. The
final verification submitted a real scan through the dashboard and reached
Completed automatically; the browser suite separately observes queued/running/
completed transitions and the unit suite verifies terminal polling cleanup.
