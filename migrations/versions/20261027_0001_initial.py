"""Create scan history table.

Revision ID: 20261027_0001
Revises:
Create Date: 2026-10-27
"""
from alembic import op
import sqlalchemy as sa

revision = "20261027_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_name", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("uploaded_bytes", sa.Integer(), nullable=False),
        sa.Column("files_examined", sa.Integer(), nullable=False),
        sa.Column("findings_json", sa.Text(), nullable=False),
        sa.Column("tools_json", sa.Text(), nullable=False),
        sa.Column("warnings_json", sa.Text(), nullable=False),
        sa.Column("config_json", sa.Text(), nullable=False),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scans_created_at", "scans", ["created_at"])
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_scans_project_created", "scans", ["project_name", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_scans_project_created", table_name="scans")
    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_index("ix_scans_created_at", table_name="scans")
    op.drop_table("scans")
