from __future__ import annotations

from typing import Any
from pydantic import BaseModel, ConfigDict


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    project_name: str
    status: str
    created_at: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None
    uploaded_bytes: int
    files_examined: int
    finding_count: int
    severity_counts: dict[str, int]
    findings: list[dict[str, Any]]
    tools: list[dict[str, Any]]
    warnings: list[str]
    config: dict[str, Any]

