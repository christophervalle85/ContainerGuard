"""Create image, scan, and finding storage."""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "images",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("registry", sa.Text(), nullable=False),
        sa.Column("repository", sa.Text(), nullable=False),
        sa.Column("digest", sa.Text(), nullable=False),
        sa.Column("platform", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "registry", "repository", "digest", "platform", name="uq_images_identity"
        ),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("submitted_reference", sa.Text(), nullable=False),
        sa.Column("image_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scanner_name", sa.Text(), nullable=True),
        sa.Column("scanner_version", sa.Text(), nullable=True),
        sa.Column("scanner_database_metadata", sa.JSON(), nullable=True),
        sa.Column("error_details", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'failed')",
            name="ck_scans_status",
        ),
        sa.ForeignKeyConstraint(["image_id"], ["images.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scans_history", "scans", ["created_at", "id"], unique=False)
    op.create_index(op.f("ix_scans_image_id"), "scans", ["image_id"], unique=False)
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("vulnerability_id", sa.Text(), nullable=False),
        sa.Column("package_name", sa.Text(), nullable=False),
        sa.Column("package_type", sa.Text(), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("installed_version", sa.Text(), nullable=False),
        sa.Column("fixed_version", sa.Text(), nullable=True),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("occurrence_order", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')",
            name="ck_findings_severity",
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_id",
            "vulnerability_id",
            "package_name",
            "package_type",
            "target",
            "installed_version",
            name="uq_findings_occurrence",
        ),
    )
    op.create_index(
        "ix_findings_scan_order",
        "findings",
        ["scan_id", "occurrence_order"],
        unique=False,
    )
    op.create_index(
        "ix_findings_scan_severity", "findings", ["scan_id", "severity"], unique=False
    )


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("images")
