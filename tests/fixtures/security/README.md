# Security gate fixtures

Fictional reports are built inline in `tests/test_security_gate.py` and reused by
runner tests. Package names and vulnerability identifiers are synthetic; they
test CI policy decisions, not actual package vulnerability status. The report
envelope follows Trivy JSON SchemaVersion 2. No synthetic credential is committed.
