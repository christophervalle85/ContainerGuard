# ContainerGuard dashboard

The browser interface lives here. The Scans view submits real image scans and
shows paginated saved history, with explicit refresh and links to each scan.
The detail view follows scan progress, shows saved image identity and scanner
metadata, and lets you inspect findings and download the saved SBOM. The
Policies view manages policies and their immutable versions. The scan view also evaluates explicit policy versions and explains saved decisions.

## Run locally

Use Node 24. The repository keeps its frontend packages local, so there is no
need to install Vite or React globally. If you use nvm, run `nvm use` from this
folder; `.nvmrc` selects Node 24.

For the runtime installed during development on this Mac, select it in the
current terminal:

```bash
export PATH="$HOME/.local/share/containerguard/node-v24.21.0-darwin-arm64/bin:$PATH"
node --version
```

From the repository root:

```bash
npm --prefix frontend ci
npm --prefix frontend run dev
```

Open <http://127.0.0.1:5173>. The development server uses that exact port and
fails if another process already occupies it.

Keep the API running on port 8000 when trying features that load data. Requests
to `/api/` pass through Vite to `http://127.0.0.1:8000`, keeping the path intact.
The browser talks to one origin; Vite forwards API traffic to FastAPI. Set
`API_PROXY_TARGET` in the server's environment if your local API uses another
address. This setting is not included in browser assets.

`npm run build` creates static files in `dist/`. Those files do not contain a
server: Vite's development proxy is only active during development. The Compose frontend server uses Nginx to serve these files and proxy API
requests; see the Compose instructions below.

## Checks

Run these from the repository root:

```bash
npm --prefix frontend run lint
npm --prefix frontend run format:check
npm --prefix frontend run typecheck
npm --prefix frontend test
npm --prefix frontend run build
```

Tests use fixture responses rather than submitting real image scans. Commit
`package-lock.json` alongside `package.json`; leave `node_modules` and `dist`
local. Direct dependency versions are exact and the lockfile records the full
installed dependency tree.

## Where things live

- `src/app/`: shared layout and routes. `main.tsx` supplies the browser router;
  component tests supply a memory router.
- `src/api/`: endpoint functions, response contracts, validation, request
  deadlines, cancellation, and safe errors. Unvalidated JSON stays `unknown`;
  Zod validates it before a screen receives a typed value. Downloads use a
  separate helper that preserves the saved bytes.
- `src/features/scans/`: image submission, saved history, and scan details.
  `useScanDetails` owns status observation; `ScanIdentity` displays the saved
  identifiers, timestamps, and scanner metadata. `FindingsSection` and
  `SbomSection` load their own evidence without extra scan-status polling. Requests are cancelled when
  you leave a view; late responses cannot replace the current page.
- `src/features/policies/`: paginated policies and version history, creation
  forms, reusable rule fields, and saved rule summaries.
- `src/components/`: shared pagination and text status labels.
- `src/styles/`: shared colors, spacing, typography, and keyboard focus styles.
- `tests/`: test setup and reusable fixture data.

A component describes one part of the interface. Props are the values passed
into a component by its parent. TypeScript checks those values during
development; runtime response validation checks what actually arrives from
FastAPI. Both checks matter because TypeScript cannot control a network response.

## Try a scan

Make sure the API and worker containers are running. In the Scans view, enter
`docker.io/library/alpine:3.20.0` and choose **Submit scan**. The API saves the
submission and queues its work; the browser opens the returned scan ID and
follows its status automatically. A completed scan means processing finished,
not that the image has no vulnerabilities. The detail view shows the saved
digest, platform, scanner version, and timestamps in UTC. Copy actions preserve
the entire ID or digest, and the expandable database metadata shows what was
recorded for that scan.

History loads one page at a time. Its `limit` and `offset` are stored in the URL,
so a refresh or shared local link opens the same page. Changing the page size
returns to the beginning. History does not poll automatically.

If a submission's response is lost, the server might still have saved it. The
form keeps your input and offers a history refresh; it never retries the POST
automatically. Check history before submitting the same request again.

## Status observation

Only the detail view checks status automatically. It waits three seconds after
an unfinished scan response before making the next request, so slow requests do
not overlap. Checking stops on completion, execution failure, a request error,
or ten minutes of elapsed observation. Individual requests have a fifteen-second
timeout. Hiding the tab pauses its requests but does not reset the ten-minute
limit.

Reload the page to start a fresh observation window after a connection error or
the ten-minute limit. The view preserves its last loaded status when automatic
checks stop. An API outage does not mean the scan itself failed. Legacy sample
records are explicitly marked as fictional.

Leaving the page cancels its requests and timers. This cancels browser
observation only: it does not cancel the worker's job or change the saved scan
status. Refreshing this view never submits another scan.

## Review findings and the SBOM

On a completed scan, use **Severity** to filter the saved findings. Filtering
and pagination happen in the API, so the total reflects all matching records,
not just the rows visible on the page. The total counts finding occurrences:
the same CVE may affect several packages. An absent fixed version is shown as
**No known fix**.

The detail URL keeps the findings severity, limit, and offset. Changing severity
or page size returns to the first page. An unfinished or failed scan gets an
explanation instead of an empty result that could suggest it has no findings.

The SBOM section loads only metadata until you choose **Download SBOM**. It
shows whether the artifact is pending, available, failed, or was not generated.
An SBOM failure is separate from scan execution and does not hide vulnerability
findings. Likewise, a request error in either section leaves the other sections
available.

Downloads use `<scan-id>.cdx.json` and preserve the original saved bytes. After
downloading, compare the file's checksum with **SHA-256 checksum** in the view:

```bash
shasum -a 256 "$HOME/Downloads/<scan-id>.cdx.json"
```

Replace `<scan-id>` with the saved UUID and use your browser's actual download
location if it differs. Temporary browser download URLs are released afterward.
Neither changing a filter nor downloading an artifact submits another scan.

## Create a policy and version

Open **Policies**, choose **Create policy**, and enter a unique name. Policy
names are trimmed and must contain 1–100 characters. Set the CRITICAL and HIGH
limits, choose whether to require an SBOM, and explicitly choose **Fail** or
**Ignore** for findings whose severity is UNKNOWN. Saving creates version 1.

Select a saved policy to see its version history. The **Create new version**
form saves another set of rules; it never edits the earlier version. Its fields
start with defaults for the new version, so review every value before saving.
Each saved version shows its own ID, creation time in UTC, and recorded rules.
After a save, the view opens the returned policy and highlights its new version.

The policy and version lists have independent pagination, with their page state
and selected policy in the URL. Neither list starts automatic polling. Adding
a version refreshes version history without reloading the unrelated policy
list. Creating a policy refreshes the policy list and opens its first version.

The form uses controlled inputs: React state holds each value, and changing an
input updates that state. Thresholds stay as strings while typing so a blank
field remains blank. On submission, validation first checks for decimal whole
numbers between 0 and 2,147,483,647, then converts accepted values into JSON
numbers. The checkbox supplies a boolean directly. A blank UNKNOWN action is
rejected rather than silently choosing a policy behavior.

Failed requests preserve the input. Duplicate-name and validation responses
identify the affected fields. If the save response is lost, check saved
policies or versions before submitting again: the server may already have
saved the request. The browser never automatically retries a creation POST.

### Policy evaluations

Open a completed real scan and choose a policy, then a specific version. The
preview shows that version's rules; nothing is submitted until you press
**Evaluate scan**. Policies and versions have separate pagination.

A policy failure means the evidence exceeded the selected rules. An evaluation
error means the saved evidence could not be evaluated. Both differ from a failed
HTTP request. Results include the saved rule snapshot, all severity counts, rule
explanations, and full identities. Later policy versions do not rewrite them.
Repeated submissions for the same scan/version return the original decision.
If a response is lost, check saved evaluations before submitting again; the
server may already have saved it. Evaluation history is paginated separately.

### Run the built dashboard with Compose

From the repository root:

```sh
docker compose --env-file .env.example up -d --build frontend
```

Open http://127.0.0.1:8080. This uses the built assets and proxies API requests
through Nginx. The Vite development server at 5173 is separate; changes to source
require rebuilding the frontend image here. Use `.env` in that command if it is
your customized configuration. `FRONTEND_PORT` changes the host dashboard port.

```sh
docker compose --env-file .env.example ps frontend api worker
```

Frontend health checks the static server only. If the API is down, dashboard API
requests show an error even while the frontend container is healthy. Reload a
direct scan link to verify that client routes work through the static server.

### Browser workflow tests

From the repository root, install the browser once and run the suite:

```sh
npm --prefix frontend exec -- playwright install chromium
npm --prefix frontend run test:e2e
```

Playwright starts its own server on **4173**, leaving your development server on
5173 and Compose dashboard on 8080 alone. Port 4173 must be free. The tests use
fixed API responses and reject unexpected API requests; they never submit work
to your real database, Redis queue, or public registries. API interception covers
only `/api/v1/`, so the browser still loads the actual React app and assets.

The suite checks scan submission/progress, filtering/paging, exact SBOM download
bytes, policy creation/version history, explicit evaluation and saved snapshots,
direct-route reload, keyboard focus, and narrow-screen overflow. It also checks
malformed/missing/unavailable API responses, failed SBOM generation, and evaluation
errors. These are browser tests against fixtures; live persistence and Nginx
routing remain separate Compose checks. The keyboard/layout checks are focused
checks, not a complete accessibility audit.

GitHub Actions has a separate frontend job using Node 24, locked packages,
lint/format/types, component tests, build, and Chromium browser workflows. It
installs the [browser and Linux dependencies](https://playwright.dev/docs/ci)
for the locked Playwright version. Both jobs use read-only repository permissions.
Tests do not retry automatically. Local failure screenshots and traces are in
`frontend/test-results/`, which stays out of Git and the Docker build context.
