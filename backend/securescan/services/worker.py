from __future__ import annotations

import json
import logging
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from ..config import DATA_DIR
from ..database import SessionLocal
from ..models import Scan
from .archive import extract_archive
from .scanners import run_bandit, run_dependency_audit, scan_configuration, scan_secrets, deduplicate_findings, SEVERITY_ORDER

logger = logging.getLogger("securescan.worker")


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _cancelled(scan_id: str) -> bool:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        return scan is None or scan.cancel_requested or scan.status == "cancelled"


def run_scan(scan_id: str, archive_path: Path) -> None:
    started_clock = time.monotonic()
    workdir: Path | None = None
    try:
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            if scan is None or scan.cancel_requested:
                if scan:
                    scan.status = "cancelled"
                    scan.completed_at = datetime.now(timezone.utc)
                    db.commit()
                return
            scan.status = "analyzing"
            scan.started_at = datetime.now(timezone.utc)
            config = json.loads(scan.config_json or "{}")
            db.commit()

        workdir = Path(tempfile.mkdtemp(prefix=f"scan-{scan_id[:8]}-", dir=DATA_DIR))
        project_dir = workdir / "project"
        file_count, _total_bytes = extract_archive(archive_path, project_dir)
        if _cancelled(scan_id):
            _finish_cancelled(scan_id, started_clock, file_count)
            return

        findings = []
        tools: list[dict] = []
        warnings: list[str] = []
        if config.get("secrets", True):
            findings.extend(scan_secrets(project_dir))
        if config.get("configuration", True):
            findings.extend(scan_configuration(project_dir))
        if config.get("secrets", True) or config.get("configuration", True):
            tools.append({"name": "SecureScan Rules", "status": "completed", "version": "1.0", "details": "Verificações locais selecionadas concluídas."})

        if config.get("dependencies", True) and not _cancelled(scan_id):
            dep_findings, dep_tool, dep_warning = run_dependency_audit(project_dir, lambda: _cancelled(scan_id))
            findings.extend(dep_findings)
            tools.append(dep_tool)
            if dep_warning:
                warnings.append(dep_warning)
            elif dep_tool["status"] == "skipped":
                warnings.append("Verificação de dependências ignorada: nenhum requirements*.txt suportado foi encontrado.")
        elif not config.get("dependencies", True):
            tools.append({"name": "pip-audit", "status": "not_selected", "version": None})
        if config.get("static", True) and not _cancelled(scan_id):
            bandit_findings, bandit_tool, bandit_warning = run_bandit(project_dir, lambda: _cancelled(scan_id))
            findings.extend(bandit_findings)
            tools.append(bandit_tool)
            if bandit_warning:
                warnings.append(bandit_warning)
        elif not config.get("static", True):
            tools.append({"name": "Bandit", "status": "not_selected", "version": None})

        ordered = sorted(deduplicate_findings(findings), key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item.get("file") or "", item.get("line") or 0))
        if _cancelled(scan_id):
            _finish_cancelled(scan_id, started_clock, file_count)
            return
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            if scan is None:
                return
            scan.status = "completed_with_warnings" if warnings else "completed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.duration_seconds = round(time.monotonic() - started_clock, 2)
            scan.files_examined = file_count
            scan.findings_json = _json(ordered)
            scan.tools_json = _json(tools)
            scan.warnings_json = _json(warnings)
            db.commit()
    except Exception as exc:
        # Never persist exception details: they may contain project paths or scanner output.
        logger.error("scan_failed id=%s error_type=%s", scan_id, type(exc).__name__)
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            if scan and scan.status != "cancelled":
                scan.status = "failed"
                scan.completed_at = datetime.now(timezone.utc)
                scan.duration_seconds = round(time.monotonic() - started_clock, 2)
                scan.warnings_json = _json(["A análise falhou. Consulte os logs locais do servidor para diagnóstico sem registrar conteúdo do projeto."])
                db.commit()
    finally:
        try:
            archive_path.unlink(missing_ok=True)
        except OSError:
            pass
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)


def _finish_cancelled(scan_id: str, started_clock: float, file_count: int = 0) -> None:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "cancelled"
            scan.completed_at = datetime.now(timezone.utc)
            scan.duration_seconds = round(time.monotonic() - started_clock, 2)
            scan.files_examined = file_count
            db.commit()

