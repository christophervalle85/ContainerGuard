"""Create versioned policies and storage for immutable evaluations."""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "policies",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="uq_policies_name"),
        sa.CheckConstraint(
            "char_length(name) BETWEEN 1 AND 100 AND name = btrim(name)",
            name="ck_policies_name",
        ),
    )
    op.create_index(
        "ix_policies_history", "policies", ["created_at", "id"], unique=False
    )
    op.create_table(
        "policy_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("policy_id", sa.Uuid(), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("max_critical", sa.Integer(), nullable=False),
        sa.Column("max_high", sa.Integer(), nullable=False),
        sa.Column("require_sbom", sa.Boolean(), nullable=False),
        sa.Column("unknown_severity_action", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["policy_id"], ["policies.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint(
            "policy_id", "version_number", name="uq_policy_versions_number"
        ),
        sa.CheckConstraint("version_number > 0", name="ck_policy_versions_number"),
        sa.CheckConstraint(
            "max_critical BETWEEN 0 AND 2147483647", name="ck_policy_versions_critical"
        ),
        sa.CheckConstraint(
            "max_high BETWEEN 0 AND 2147483647", name="ck_policy_versions_high"
        ),
        sa.CheckConstraint(
            "unknown_severity_action IN ('fail', 'ignore')",
            name="ck_policy_versions_unknown",
        ),
    )
    op.create_table(
        "evaluations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("policy_version_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evaluator_version", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("counts", sa.JSON(), nullable=False),
        sa.Column("rules", sa.JSON(), nullable=False),
        sa.Column("rule_snapshot", sa.JSON(), nullable=False),
        sa.Column("error_code", sa.Text(), nullable=True),
        sa.Column("error_details", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["policy_version_id"], ["policy_versions.id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint(
            "scan_id", "policy_version_id", name="uq_evaluations_scan_version"
        ),
        sa.CheckConstraint(
            "outcome IN ('passed', 'failed', 'error')", name="ck_evaluations_outcome"
        ),
        sa.CheckConstraint("evaluator_version > 0", name="ck_evaluations_version"),
        sa.CheckConstraint(
            "(outcome IN ('passed', 'failed') AND error_code IS NULL "
            "AND error_details IS NULL) OR (outcome = 'error' "
            "AND error_code IS NOT NULL AND error_code = 'invalid_evidence' "
            "AND error_details IS NOT NULL)",
            name="ck_evaluations_error",
        ),
        sa.CheckConstraint(
            "json_typeof(counts) = 'object' AND json_typeof(rule_snapshot) = 'object'",
            name="ck_evaluations_objects",
        ),
        sa.CheckConstraint(
            "json_typeof(rules) = 'array' AND json_array_length(rules) <= 4",
            name="ck_evaluations_rules",
        ),
    )
    op.create_index(
        "ix_evaluations_policy_version_id",
        "evaluations",
        ["policy_version_id"],
        unique=False,
    )
    op.create_index(
        "ix_evaluations_scan_history",
        "evaluations",
        ["scan_id", "created_at", "id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("evaluations")
    op.drop_table("policy_versions")
    op.drop_table("policies")
