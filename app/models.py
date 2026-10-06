from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
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
