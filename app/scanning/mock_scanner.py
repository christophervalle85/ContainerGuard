from app.api.schemas import Finding, Severity


def build_mock_findings() -> list[Finding]:
    """Return fictional sample data, unrelated to any submitted image."""
    return [
        Finding(
            vulnerability_id="MOCK-001",
            package_name="demo-library-a",
            installed_version="1.0",
            fixed_version="1.1",
            severity=Severity.CRITICAL,
            title="Fictional critical finding for API demonstration",
        ),
        Finding(
            vulnerability_id="MOCK-002",
            package_name="demo-library-b",
            installed_version="2.0",
            fixed_version="2.1",
            severity=Severity.HIGH,
            title="Fictional high finding for API demonstration",
        ),
        Finding(
            vulnerability_id="MOCK-003",
            package_name="demo-library-c",
            installed_version="3.0",
            fixed_version=None,
            severity=Severity.UNKNOWN,
            title="Fictional finding with unknown severity and no known fix",
        ),
    ]
