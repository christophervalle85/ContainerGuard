# Frontend architecture

Status: implemented and locally verified. Independent branch review is complete. The learner controls commit, push, PR creation, and the GitHub CI checkpoint.

## Purpose and scope

ContainerGuard's browser interface should let someone submit a real image scan,
follow its progress, inspect findings, download its SBOM, and understand a saved
policy decision without using Swagger. The intended audience is a local operator
or someone reviewing the project demonstration. The existing backend remains the
source of truth for history, image identity, findings, artifacts, and evaluations.

The agreed scope is three views: scans and recent history; scan details; policies.
Evaluation controls and results belong to the selected scan's details. This keeps
the relationship between the decision and its evidence visible. The user has
JavaScript/React experience and wants focused refreshers as concepts arise.
Implementation proceeds through learner checkpoints, not a full milestone dump.

Success means a keyboard user can complete the browser workflow, saved history
survives service recreation, and Compose starts the complete local application.
There is no authentication, public deployment, analytics suite, image execution,
or change to scanner/retry/recovery semantics in this work.

## Architecture and tool choices

Use a React and TypeScript application built with Vite under `frontend/`, with
React Router in declarative mode for client-side routes. Use npm and commit its
lockfile; lock compatible package versions during implementation. Select a
supported Node LTS release that satisfies the selected toolchain, and record it
for host development, Docker builds, and CI.

Use native fetch behind one small typed API client, plus focused hooks for
loading and polling. Do not introduce a global state store or query library for
these three views. URL parameters hold shareable filters/page offsets, local
state holds form input and temporary UI state, and the backend holds saved data.
TypeScript contracts describe API responses; they do not replace server-side
validation. Handle malformed responses as errors instead of fabricating results.

```text
Browser
  -> Vite development server OR static frontend server
       -> /api/v1/* proxy -> FastAPI -> PostgreSQL / Redis
                                               -> worker -> Trivy
```

Requests use relative `/api/v1/...` URLs. Vite proxies `/api/` to the configured
host API during development. In Compose, the static frontend server proxies the
same prefix to `api:8000`, preserving the path. The browser never calls the
Docker service name directly. This keeps UI requests on the UI's origin without
adding permissive CORS to FastAPI. Direct API access and Swagger remain available
on their existing port.

The alternative is Python-rendered templates, which reduce frontend tooling.
React fits the user's experience and interactive status/filtering workflow, so
it is the selected approach. Server rendering and another application server
framework would add responsibilities this local dashboard does not need.

## Views and interactions

### Scans: `/scans`

The root route redirects to `/scans`. Show a labeled image-reference field,
submit button, supported registry/platform note, and paginated recent history.
Submission calls POST once, then navigates to the returned scan ID after 202.
Disable repeat submission while that request is in flight. Preserve input after
failure. A lost response may have followed a successful enqueue, so explain that
uncertainty and offer history rather than automatically repeating POST.

History uses the existing paginated list endpoint, newest first, with image
reference, scan ID, and a text status. Each row has an ordinary accessible link
to its details. Show a useful empty state and explicit refresh. Do not fetch
findings or artifact metadata for every history row. History does not need a
second polling loop; progress is followed on the selected scan's detail view.

### Scan details: `/scans/:scanId`

Show submitted reference, scan ID, status, saved digest/platform when known,
creation/start/completion timestamps, scanner name/version, and safe error
details. Use copy actions for full identifiers. Display timestamps in UTC with an explicit timezone label and retain each
original value in the time element. This keeps saved records comparable across
machines and screenshots; browser-locale formatting is intentionally deferred.
Missing values display as unavailable or not yet recorded, never invented.

Show findings only as scan evidence when completion permits interpreting them.
A queued/running scan displays progress; a failed scan displays its execution
failure, not a reassuring zero-findings result. Completed zero-findings scans
have their own empty state. Fictional legacy records are clearly marked.

Findings use server-side severity filtering and pagination. Show vulnerability
ID, package, installed version, nullable fixed version, severity, and title.
The page total means matching finding occurrences, not unique CVEs. Reset offset
to zero on severity changes. Put severity, limit, and offset in URL parameters;
validate them before requests. Label an absent fix as "No known fix". Do not add
search/sorting that the API cannot support accurately.

The SBOM section shows metadata and all four availability states. Enable download
only for an available artifact. Fetch the download through the same origin,
handle HTTP failures visibly, preserve the bytes, and use a UUID-based filename.
Release temporary browser object URLs. Show format/version, tool, size, and
checksum without loading the payload merely to render the page. Download is an
explicit user action, never a polling request. Explain SBOM failure separately
from completed vulnerability collection.

The evaluation section lets the user choose a policy, then an explicit version.
Show that version's rules before evaluation; never silently choose the latest
version. Paginate policy/version choices rather than truncating them or loading
unbounded lists. A completed real scan with saved image identity can be submitted
for evaluation; backend validation remains authoritative.

POST evaluation only on an explicit action. Show all severity counts, the rule
snapshot/version, and each rule's actual/expected values and explanation. Browse
saved evaluations with pagination. Read their saved snapshots rather than
recomputing decisions in the browser. Use distinct labels for "Policy passed",
"Policy rejected", and "Evaluation error"; HTTP 200 is not itself a policy pass.
Changing a selection does not automatically evaluate or rewrite history.

### Policies: `/policies`

List policies with pagination. Selecting one shows paginated immutable versions
and their four rules. Allow creating a policy and adding a new version using
labeled forms. Explain that new versions leave past versions and evaluations
unchanged. Do not label version creation as editing an existing record.

Use integer inputs for CRITICAL/HIGH maximums, a required-SBOM checkbox, and an
explicit UNKNOWN fail/ignore choice. Validate nonnegative integer thresholds
through 2147483647; reject empty/fractional values rather than coercing them to
zero. Trim policy names and enforce the server's length rules. Surface duplicate
names and field validation errors beside the relevant form. Disable a form while
its POST is pending; do not automatically retry a policy/version creation.

After a successful creation, select the returned identity/version and refresh
only the affected lists. A failed request preserves form values.

## Backend API addition

Introduce a `ScanDetails` response extending the existing compact `ScanRecord`.
Return it from GET `/api/v1/scans/{scan_id}`. Keep existing ID/reference/status
fields and their meanings; add:

- `created_at`, nullable `started_at`, nullable `completed_at`.
- Nullable `digest` and `platform` from the saved Image association.
- Nullable `scanner_name`, `scanner_version`, and `scanner_database_metadata`.
- Nullable safe `error_details` and an explicit `mock` indicator consistent with
  the findings response and scanner identity.

Do not expose database URLs, raw scanner stderr, or artifact payloads. Optional
scanner-database metadata remains an observation of the cache, not proof of a
fixed vulnerability database identity. Keep history's compact response unchanged
and use a bounded query for the details/image association. No new database
columns or migrations are needed; these values are already stored.

Add API/repository tests for pending, successful, unresolved failure, legacy
mock, and missing scans, including null metadata and preservation of old fields.
Update assertions intentionally affected by the additive detail response.
All other endpoints and persistence behavior remain unchanged.

## Requests, polling, and error states

Use AbortController for cancellation and a 15-second deadline per API request.
Do not overlap requests in one polling loop: schedule the next status request
three seconds after the previous successful response. Cancel on navigation,
unmount, and scan-ID changes. Ignore late results for a superseded request,
including rapid severity/page changes. React development checks must not cause
POSTs or leave duplicate timers alive.

Poll only the selected queued/running scan. Stop on completed/failed, on an API
error, or after ten minutes of elapsed automatic observation. Pause requests
while the document is hidden; keep the elapsed-time bound. On visibility return,
refresh only if still eligible. When the bound is reached, preserve the last
status and say automatic updates paused. Reloading the page starts another bounded observation window without submitting
a scan. This UI deadline does not cancel the backend job or
mark it failed; backend retries can outlast it.

On terminal transition, load the relevant findings, artifact metadata, and saved
evaluations. Ordinary filter/page changes fetch only the selected page. Keep
independent sections independent: a failed SBOM/evaluation request must not
replace a successfully loaded scan or findings panel with a whole-page error.

Map 404 to missing resource, 409 to a state/conflict explanation, 422 to validation
feedback, and 503/network/timeout to an availability message with recovery guidance.
Proxy 502/504 errors also produce an availability message. Render server text as
text through React, never injected HTML. Treat unknown/malformed errors safely.
Do not automatically repeat mutations after any response or connection failure.
A status_url from submission is metadata, not an arbitrary navigation target;
construct the UI route from the returned scan ID.

## Visual design and accessibility

Visual thesis: a calm security workspace with a light neutral canvas, dark ink,
one blue action accent, and restrained semantic status colors.
Content plan: compact product navigation, the current view's primary action or
identity, the main table/result, and supporting metadata. Use aligned rows,
whitespace, and thin dividers instead of a dashboard of decorative cards.
Interaction thesis: clear hover/focus feedback, short disclosure transitions,
and subtle status/loading changes that preserve layout. Honor reduced-motion
preferences. No marketing hero, decorative charts, or animation dependency.

Use two top-level navigation items, Scans and Policies, with clear active state
and a route back from scan details. Use system typography, monospace identifiers,
readable contrast, visible focus, native controls, and real table headers.
Every form input has a visible label; errors are associated with fields. Status
changes use restrained live announcements without repeatedly interrupting a
screen reader. Status text accompanies color. Keep focus stable during polling,
and provide feedback when navigation or an action completes.

At narrow widths, stack forms/metadata and allow findings tables to scroll within
their own region. Long digests wrap or truncate with an accessible full value;
they must not force the whole page wider than the viewport. No theme switcher or
external font/image request is required for this operational interface.

## Files and responsibility boundaries

```text
frontend/
  src/
    app/            routing and shared application layout
    api/            response types, request/error handling, endpoint functions
    features/
      scans/        submission, history, detail sections, bounded polling
      policies/     policy list, version history, rule forms
    components/     genuinely shared controls, status labels, pagination
    styles/         tokens and base/layout styles
  tests/            shared fixtures and browser workflow tests
  public/           static assets, if needed
  package.json and package-lock.json
  vite.config.ts and TypeScript/lint/test configuration
  nginx.conf
Dockerfile.frontend
```

Keep feature-specific components alongside their feature. Split files when they
acquire separate responsibilities; avoid a generic components dumping ground.
Evaluation UI belongs to scan details; shared rule display/form types can be
reused by policy views. Existing Python package organization stays intact.

## Containers and configuration

Build static assets with a Node build stage and `npm ci`, then serve them from
an unprivileged Nginx runtime image. The shipped frontend runtime contains no
Node development server, Python scanner, credentials, or Docker socket.

Add a `frontend` Compose service publishing `127.0.0.1:${FRONTEND_PORT:-8080}`.
The server listens on an unprivileged container port, proxies `/api/` to the API,
and serves client routes on direct navigation/reload. Missing static assets and
unknown API paths must not silently return the SPA HTML with HTTP 200. Configure
API hostname resolution so recreating the API does not require restarting the
frontend just to discover its new container address.

A static `/healthz` verifies the frontend server itself. Compose initially waits
for a healthy API; a later API outage remains visible in the UI. A healthy static
frontend is not proof that scanning dependencies are healthy. Document the UI's
8080 port separately from API 8000 and Vite development 5173; use strict dev-port
binding and a configurable server-side development proxy target for changed API
ports. Only public values belong in browser assets; no service secret is needed.

Use `frontend/` as the frontend build context so the Python root build allowlist
stays narrow. Extend ignore rules for node_modules, build output, test artifacts,
and frontend-local credentials. Preserve the existing migration prerequisite and
API/worker runtime configuration. Recreating services retains the existing named
volumes; frontend changes do not create a new persistence mechanism.

## Verification and delivery

Use Vitest and React Testing Library for meaningful component/request behavior,
including loading/empty/errors, submission once, filter pagination, cancellation,
poll stop/deadline/visibility, explicit version choice, rejection versus error,
and SBOM download failures. Use controlled timers and API fixtures; routine tests
must not launch Trivy or query a public registry.

Use Playwright for a small browser workflow suite with deterministic API responses:
submission and progress, filtered findings, an SBOM download, version creation,
and explicit-version evaluation with a saved rejection. Verify direct route
reloads and keyboard operation. These fixture browser tests do not establish real
backend integration, so record them separately from the live Compose exercise.

Add frontend locked installation, lint, format, TypeScript checks, unit tests,
build, and the focused browser suite to CI. Keep the existing backend checks and
dedicated PostgreSQL/Redis test isolation. No new release/security-gate project
is part of this milestone; later roadmap work expands those checks.

Before completion, build the frontend image and exercise the real Compose browser
workflow: new scan -> completed findings -> matching SBOM download -> explicit
policy evaluation -> persisted history after recreation. Record image digest,
platform, scanner version, date, and observed outcome without hardcoding live
vulnerability counts into tests. Also verify visible failures and API reconnection
after recreation. Use disposable resources for destructive verification.

Update README with frontend startup, host development, checks, request/polling
limits, and troubleshooting. Keep this document under a neutral filename as the
architecture evolves. Create a separate implementation checkpoint plan only
after this written design is reviewed. Commits and final checkpoint verification
remain learner-led; do not implement later checkpoints ahead of the learner.

## References

- [Vite guide](https://vite.dev/guide/) and [proxy configuration](https://vite.dev/config/server-options.html#server-proxy).
- [React Router declarative installation](https://reactrouter.com/start/declarative/installation).
- [Node release support](https://nodejs.org/en/about/previous-releases).
- [Unprivileged Nginx image](https://github.com/nginx/docker-nginx-unprivileged).
- [Vitest](https://vitest.dev/guide/) and [Playwright](https://playwright.dev/docs/intro).
- Existing [container](containers.md), [SBOM](sboms.md), and [policy](policies.md) contracts.


## Container serving

`Dockerfile.frontend` builds with Node 24 and `npm ci`, then copies only the
compiled assets into an unprivileged Nginx runtime. Its build context is
`frontend/`; the Python image allowlist stays unchanged. Neither Node nor source
files, environment files, or the Docker socket are part of the serving container.
The runtime uses UID/GID 101 and listens on 8080. The pinned stable-alpine image
was verified as Nginx 1.30.5. Its multi-platform index is
`sha256:15c994d10d6d78658721c3bcafff14cb281fba2a4bdf9d5ba92c416a472516e3`.
The Node 24 Alpine build index is
`sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1`.
See the [upstream image documentation](https://github.com/nginx/docker-nginx-unprivileged).

Compose binds the dashboard to `127.0.0.1:${FRONTEND_PORT:-8080}` and waits for
API health initially. API/worker migration dependencies and named data volumes
remain unchanged. `/healthz` checks only the static server, so it can stay healthy
while the API is unavailable. It does not imply database or worker readiness.

Nginx preserves `/api/` paths and query strings, forwarding them to `api:8000`.
Docker DNS is re-resolved with a five-second cache so API recreation does not
require restarting the frontend. Proxy errors stay HTTP errors, never the SPA
HTML document. Proxy connection/read limits are 3/10 seconds. Browser requests
retain their own 15-second bound. Application routes fall back to `index.html`;
missing assets return 404. HTML is revalidated, while hashed assets may be cached.

Routing, non-root execution, missing assets, API 404s, outage 502s and reconnection
after an actual API address change were verified in a separate disposable Compose
project. That project used a tiny HTTP fixture rather than the real database or
queue. Live saved scan retrieval was verified separately through port 8080. This
is serving/reconnection evidence, not an automatic job recovery guarantee.


## Integrated verification record

Verified on October 11, 2026 through the Compose dashboard at localhost:8080.
A real submission of `docker.io/library/alpine:3.20.0` completed as scan
`c1b723f3-c679-4ecd-b44f-c18354b0f823`, with Trivy 0.75.0 on linux/amd64 and
saved digest `sha256:216266c86fc4dcef5619930bd394245824c2af52fd21ba7c6fa0e618657d4c3b`.
The observed 70 occurrences were 2 CRITICAL, 21 HIGH, 20 MEDIUM, 27 LOW, and 0 UNKNOWN.
Those counts describe this saved result, not a fixed expectation for future scans.

The browser-downloaded SBOM matched its saved SHA-256:
`e2a6f69b07024f48a8fe567d9f7727e9f60ed0f562262465fdd16b2bba1e60df`.
The `dashboard-verification` policy was created through the UI. Its first version
allowed up to 2,147,483,647 CRITICAL/HIGH occurrences, required an SBOM, and ignored
UNKNOWN severity. It passed. A second version with zero CRITICAL/HIGH allowance
and UNKNOWN set to fail rejected the same scan. Re-evaluating version 1 returned
the original evaluation `72adc3c8-a1e0-4029-a2d4-76a1d536197a`, timestamp
`2026-10-11T06:07:05.534498Z`, and unchanged saved rules. These deliberately
permissive first-version rules demonstrate evaluation behavior; they are not a
recommended security policy.

Recreating only API/frontend containers preserved the full scan details, both
policy versions, both evaluations, original first-version identity/timestamp,
and byte-identical SBOM. PostgreSQL, Redis, the worker, and their volumes were
not replaced. A previously saved resolution failure displayed its execution
error and disabled evaluation in the real dashboard.

A separate temporary HTTP-fixture Compose project checked deep links, missing
assets returning 404, API 404 JSON responses, API outage errors, static health during outages, and proxy
reconnection after the API address changed from 172.20.0.3 to 172.20.0.4 without
restarting the frontend. An initial outage assertion expected 502 but received 504
during a cached-address timeout; the probe was corrected to accept both valid
proxy failures and rerun successfully. Only owned temporary containers/network
were removed. Deterministic browser fixtures separately verify unavailable and
malformed APIs, failed SBOM generation, and evaluation errors without damaging
live records or interrupting real jobs.

Final local checks passed 737 backend tests, 166 frontend unit tests, 13 Chromium
browser tests, Ruff, ESLint, Prettier, TypeScript, production build, Compose
validation, and all three application image builds. Independent whole-branch
review found no Critical or Important defect. Its minor findings were resolved:
safe 502/504 availability messages, current setup docs, and explicit UTC timestamp
conventions. The focused review follow-up found no remaining issues. GitHub CI
has not yet run for these uncommitted changes. Focused layout/keyboard checks are
not a complete accessibility audit; public deployment and authentication remain
outside this scope.
