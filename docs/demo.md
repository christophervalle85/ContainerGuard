# A short ContainerGuard demo

Start the local stack using the [README](../README.md#run-it-locally), then open
<http://127.0.0.1:8080>. Use a public Docker Hub image with an explicit tag.
The older `docker.io/library/alpine:3.20.0` makes a useful findings demonstration;
its age also illustrates why completed scanning is not a security verdict.

1. In **Scans**, submit that reference. Watch queued become running and then
   completed. The API remains available while the worker scans. A fresh scanner
   cache needs an initial database download.
2. Review the scan's digest, platform, scanner version, and timestamp. Open
   **Findings**, filter a severity, and page through the saved occurrences.
   Counts can change as vulnerability data changes.
3. Open **SBOM** and download the original CycloneDX JSON. Compare its checksum
   with `shasum -a 256 /path/to/download.json` (or `sha256sum` on Linux).
   The checksum verifies saved bytes, not inventory completeness or authenticity.
4. In **Policies**, create a named policy with max critical 0, max high 5, required
   SBOM, and unknown severity set to fail. Create a second version with max high
   0. Both versions remain visible; editing does not overwrite the first.
5. Return to the completed scan's **Evaluations** section. Explicitly select the
   policy and a version, inspect its rules, then choose **Evaluate scan**.
   A failed policy is an explained decision about the saved evidence, not a failed
   scanner job. Compare the outcomes for the two versions.
6. Evaluate the same version again and inspect its saved record: ID, timestamp,
   rule snapshot, and result remain unchanged. Refreshing retrieves saved evidence.
7. Recreate the application containers using the README's update sequence.
   The scan, findings, artifact, policy versions, and evaluations remain in
   PostgreSQL. Download the same SBOM and compare its checksum again.

For a quick explanation: FastAPI saves and queues a request, Redis/RQ delivers
it to a worker, and the worker pins a Docker Hub digest before running Trivy.
PostgreSQL stores the evidence. Policies evaluate explicit saved versions, so
later rule changes do not rewrite earlier decisions.

The separate CI release gate scans ContainerGuard's own dependencies and runtime
images. Its HIGH/CRITICAL threshold is independent of a user's scan policy.
There is no authentication or public deployment in this local demo, and
interrupted work may need manual recovery. See the
[verification record](development/verification.md) for real screenshots, observed
results, and checks still awaiting a committed branch and GitHub execution.
