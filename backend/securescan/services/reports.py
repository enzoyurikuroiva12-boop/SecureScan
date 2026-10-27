from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from ..models import Scan


def scan_payload(scan: Scan) -> dict[str, Any]:
    findings = json.loads(scan.findings_json or "[]")
    tools = json.loads(scan.tools_json or "[]")
    warnings = json.loads(scan.warnings_json or "[]")
    return {
        "id": scan.id,
        "project_name": scan.project_name,
        "status": scan.status,
        "created_at": _iso(scan.created_at),
        "started_at": _iso(scan.started_at),
        "completed_at": _iso(scan.completed_at),
        "duration_seconds": scan.duration_seconds,
        "uploaded_bytes": scan.uploaded_bytes,
        "files_examined": scan.files_examined,
        "finding_count": len(findings),
        "severity_counts": dict(Counter(item["severity"] for item in findings)),
        "findings": findings,
        "tools": tools,
        "warnings": warnings,
        "config": json.loads(scan.config_json or "{}"),
    }


def json_report(scan: Scan) -> dict[str, Any]:
    payload = scan_payload(scan)
    tool_statuses = {tool["name"]: tool["status"] for tool in payload["tools"]}
    return {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analysis": {key: payload[key] for key in ("id", "project_name", "status", "created_at", "started_at", "completed_at", "duration_seconds")},
        "summary": {
            "files_examined": payload["files_examined"],
            "finding_count": payload["finding_count"],
            "severity_counts": payload["severity_counts"],
            "interpretation": "Resultados estáticos ajudam a priorizar revisão; ausência de achados não comprova que o projeto esteja livre de vulnerabilidades.",
        },
        "tools": payload["tools"],
        "findings": payload["findings"],
        "limitations": payload["warnings"] + [
            "A análise não executa o projeto nem instala dependências enviadas.",
            "Histórico Git, binários e diretórios ignorados não são examinados.",
            "A autenticação multiusuário e relatórios PDF não fazem parte desta versão MVP.",
        ],
        "configuration": payload["config"],
        "tool_statuses": tool_statuses,
    }


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None

