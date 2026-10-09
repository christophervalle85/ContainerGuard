"""Store scan-associated SBOM outcomes without changing existing history."""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sbom_artifacts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("format", sa.Text(), nullable=True),
        sa.Column("format_version", sa.Text(), nullable=True),
        sa.Column("scanner_version", sa.Text(), nullable=True),
        sa.Column("pinned_reference", sa.Text(), nullable=True),
        sa.Column("platform", sa.Text(), nullable=True),
        sa.Column("payload", sa.LargeBinary(), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("sha256", sa.Text(), nullable=True),
        sa.Column("error_code", sa.Text(), nullable=True),
        sa.Column("error_details", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("scan_id", name="uq_sbom_artifacts_scan"),
        sa.CheckConstraint(
            "status IN ('available', 'failed')", name="ck_sbom_artifacts_status"
        ),
        sa.CheckConstraint(
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
        sa.CheckConstraint(
            "size_bytes BETWEEN 1 AND 10485760 AND octet_length(payload) = size_bytes",
            name="ck_sbom_artifacts_size",
        ),
        sa.CheckConstraint(
            "sha256 ~ '^[0-9a-f]{64}$'", name="ck_sbom_artifacts_sha256"
        ),
        sa.CheckConstraint(
            "error_code IN ('sbom_timeout', 'sbom_unavailable', "
            "'sbom_execution_failed', "
            "'sbom_output_limit', 'sbom_invalid_report')",
            name="ck_sbom_artifacts_error_code",
        ),
    )


def downgrade() -> None:
    op.drop_table("sbom_artifacts")
