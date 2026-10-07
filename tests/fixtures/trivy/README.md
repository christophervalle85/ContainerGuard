# Trivy report fixtures

`no_findings.json` is a trimmed Trivy 0.75.0 report for
`docker.io/library/alpine:3.20`, scanned remotely for `linux/amd64` on October 6,
2026. The scan reported no vulnerabilities and marked the Alpine release as
end of support. This is a parser example, not a claim that the image is secure.

Only the fields needed for parsing and two package inventory entries remain.
An absent `Vulnerabilities` key is preserved as it appeared in the report.
These fixtures keep routine tests independent of live registries and changing
vulnerability databases.

`findings.json` is a synthetic report with explicitly fictional FIXTURE IDs and
packages. It exercises repeated vulnerability IDs across packages and targets,
missing optional fields, an empty fixed version, and lowercase severity. These
are parser test inputs, not vulnerabilities reported by a live scan.


`version_info.json` records the local output of `trivy --version --format json`
from Trivy 0.75.0, read on October 7, 2026. Its cached database timestamps are
sample data for parser tests, not the current database state. The nested
`Version` is the database format version. It is separate from the executable
version in the top-level `Version` field.
