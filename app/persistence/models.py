from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Image(Base):
    __tablename__ = "images"
    __table_args__ = (
        UniqueConstraint(
            "registry",
            "repository",
            "digest",
            "platform",
            name="uq_images_identity",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    registry_host: Mapped[str] = mapped_column("registry", Text)
    repository: Mapped[str] = mapped_column(Text)
    digest: Mapped[str] = mapped_column(Text)
    platform: Mapped[str] = mapped_column(Text)


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed')",
            name="ck_scans_status",
        ),
        Index("ix_scans_history", "created_at", "id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    submitted_reference: Mapped[str] = mapped_column(Text)
    image_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("images.id", ondelete="RESTRICT"),
        index=True,
    )
    status: Mapped[str] = mapped_column(Text, default="queued")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scanner_name: Mapped[str | None] = mapped_column(Text)
    scanner_version: Mapped[str | None] = mapped_column(Text)
    scanner_database_metadata: Mapped[dict | None] = mapped_column(JSON)
    error_details: Mapped[str | None] = mapped_column(Text)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "vulnerability_id",
            "package_name",
            "package_type",
            "target",
            "installed_version",
            name="uq_findings_occurrence",
        ),
        CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')",
            name="ck_findings_severity",
        ),
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_scan_order", "scan_id", "occurrence_order"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"),
    )
    vulnerability_id: Mapped[str] = mapped_column(Text)
    package_name: Mapped[str] = mapped_column(Text)
    package_type: Mapped[str] = mapped_column(Text)
    target: Mapped[str] = mapped_column(Text)
    installed_version: Mapped[str] = mapped_column(Text)
    fixed_version: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    occurrence_order: Mapped[int] = mapped_column()


class SbomArtifact(Base):
    __tablename__ = "sbom_artifacts"
    __table_args__ = (
        UniqueConstraint("scan_id", name="uq_sbom_artifacts_scan"),
        CheckConstraint(
            "status IN ('available', 'failed')", name="ck_sbom_artifacts_status"
        ),
        CheckConstraint(
            "(status = 'available' AND payload IS NOT NULL AND size_bytes IS NOT NULL "
            "AND sha256 IS NOT NULL AND format IS NOT NULL "
            "AND format_version IS NOT NULL "
            "AND scanner_version IS NOT NULL AND pinned_reference IS NOT NULL "
            "AND platform IS NOT NULL AND error_code IS NULL "
            "AND error_details IS NULL) OR "
            "(status = 'failed' AND payload IS NULL "
            "AND size_bytes IS NULL AND sha256 IS NULL "
            "AND error_code IS NOT NULL AND error_details IS NOT NULL)",
            name="ck_sbom_artifacts_outcome",
        ),
        CheckConstraint(
            "size_bytes BETWEEN 1 AND 10485760 AND octet_length(payload) = size_bytes",
            name="ck_sbom_artifacts_size",
        ),
        CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="ck_sbom_artifacts_sha256"),
        CheckConstraint(
            "error_code IN ('sbom_timeout', 'sbom_unavailable', "
            "'sbom_execution_failed', "
            "'sbom_output_limit', 'sbom_invalid_report')",
            name="ck_sbom_artifacts_error_code",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    format: Mapped[str | None] = mapped_column(Text)
    format_version: Mapped[str | None] = mapped_column(Text)
    scanner_version: Mapped[str | None] = mapped_column(Text)
    pinned_reference: Mapped[str | None] = mapped_column(Text)
    platform: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[bytes | None] = mapped_column(LargeBinary, deferred=True)
    size_bytes: Mapped[int | None] = mapped_column()
    sha256: Mapped[str | None] = mapped_column(Text)
    error_code: Mapped[str | None] = mapped_column(Text)
    error_details: Mapped[str | None] = mapped_column(Text)


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (
        UniqueConstraint("name", name="uq_policies_name"),
        CheckConstraint(
            "char_length(name) BETWEEN 1 AND 100 AND name = btrim(name)",
            name="ck_policies_name",
        ),
        Index("ix_policies_history", "created_at", "id"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class PolicyVersion(Base):
    __tablename__ = "policy_versions"
    __table_args__ = (
        UniqueConstraint(
            "policy_id", "version_number", name="uq_policy_versions_number"
        ),
        CheckConstraint("version_number > 0", name="ck_policy_versions_number"),
        CheckConstraint(
            "max_critical BETWEEN 0 AND 2147483647", name="ck_policy_versions_critical"
        ),
        CheckConstraint(
            "max_high BETWEEN 0 AND 2147483647", name="ck_policy_versions_high"
        ),
        CheckConstraint(
            "unknown_severity_action IN ('fail', 'ignore')",
            name="ck_policy_versions_unknown",
        ),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    policy_id: Mapped[UUID] = mapped_column(
        ForeignKey("policies.id", ondelete="RESTRICT")
    )
    version_number: Mapped[int] = mapped_column()
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    max_critical: Mapped[int] = mapped_column()
    max_high: Mapped[int] = mapped_column()
    require_sbom: Mapped[bool] = mapped_column()
    unknown_severity_action: Mapped[str] = mapped_column(Text)


class Evaluation(Base):
    __tablename__ = "evaluations"
    __table_args__ = (
        UniqueConstraint(
            "scan_id", "policy_version_id", name="uq_evaluations_scan_version"
        ),
        CheckConstraint(
            "outcome IN ('passed', 'failed', 'error')", name="ck_evaluations_outcome"
        ),
        CheckConstraint("evaluator_version > 0", name="ck_evaluations_version"),
        CheckConstraint(
            "(outcome IN ('passed', 'failed') AND error_code IS NULL "
            "AND error_details IS NULL) OR (outcome = 'error' "
            "AND error_code IS NOT NULL AND error_code = 'invalid_evidence' "
            "AND error_details IS NOT NULL)",
            name="ck_evaluations_error",
        ),
        CheckConstraint(
            "json_typeof(counts) = 'object' AND json_typeof(rule_snapshot) = 'object'",
            name="ck_evaluations_objects",
        ),
        CheckConstraint(
            "json_typeof(rules) = 'array' AND json_array_length(rules) <= 4",
            name="ck_evaluations_rules",
        ),
        Index("ix_evaluations_policy_version_id", "policy_version_id"),
        Index("ix_evaluations_scan_history", "scan_id", "created_at", "id"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(ForeignKey("scans.id", ondelete="RESTRICT"))
    policy_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("policy_versions.id", ondelete="RESTRICT")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    evaluator_version: Mapped[int] = mapped_column()
    outcome: Mapped[str] = mapped_column(Text)
    counts: Mapped[dict] = mapped_column(JSON)
    rules: Mapped[list] = mapped_column(JSON)
    rule_snapshot: Mapped[dict] = mapped_column(JSON)
    error_code: Mapped[str | None] = mapped_column(Text)
    error_details: Mapped[str | None] = mapped_column(Text)
