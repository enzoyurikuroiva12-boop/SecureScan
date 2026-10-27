from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
import uuid
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import desc

from .config import DATA_DIR, MAX_UPLOAD_BYTES
from .database import SessionLocal, engine, init_db
from .models import Scan
from .schemas import ScanOut
from .services.archive import ArchiveError, validate_archive
from .services.reports import json_report, scan_payload
from .services.worker import run_scan

executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="securescan-worker")
_requests: dict[str, deque[float]] = defaultdict(deque)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    upload_dir = DATA_DIR / "uploads"
    temp_dir = DATA_DIR / "tmp"
    upload_dir.mkdir(parents=True, exist_ok=True)
    temp_dir.mkdir(parents=True, exist_ok=True)
    tempfile.tempdir = str(temp_dir)
    with SessionLocal() as db:
        interrupted = db.query(Scan).filter(Scan.status.in_(("queued", "analyzing"))).all()
        for scan in interrupted:
            scan.status = "failed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.warnings_json = json.dumps(["A análise foi interrompida por reinicialização do serviço."])
        db.commit()
    for orphan in upload_dir.glob("incoming-*.zip"):
        orphan.unlink(missing_ok=True)
    for orphan in DATA_DIR.glob("scan-*"):
        if orphan.is_dir() and not orphan.is_symlink():
            shutil.rmtree(orphan, ignore_errors=True)
    for orphan in temp_dir.glob("securescan-audit-*.txt"):
        orphan.unlink(missing_ok=True)
    yield


app = FastAPI(title="SecureScan API", version="1.0.0", description="Análise defensiva de projetos autorizados.", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_credentials=False, allow_methods=["GET", "POST"], allow_headers=["*"])


class UploadBodyLimitMiddleware:
    """Cap multipart bytes before Starlette spools an uploaded body to disk."""
    def __init__(self, application):
        self.application = application

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") != "POST" or scope.get("path") != "/api/v1/scans":
            await self.application(scope, receive, send)
            return
        limit = MAX_UPLOAD_BYTES + 1024 * 1024
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        try:
            if int(headers.get(b"content-length", b"0")) > limit:
                response = JSONResponse(status_code=413, content={"detail": {"code": "upload_too_large", "message": "O corpo enviado excede o limite permitido."}})
                await response(scope, receive, send)
                return
        except ValueError:
            pass
        received = 0
        rejected = False

        async def capped_receive():
            nonlocal received, rejected
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    rejected = True
                    response = JSONResponse(status_code=413, content={"detail": {"code": "upload_too_large", "message": "O corpo enviado excede o limite permitido."}})
                    await response(scope, receive, send)
                    return {"type": "http.disconnect"}
            return message

        async def capped_send(message):
            if not rejected:
                await send(message)

        await self.application(scope, capped_receive, capped_send)


app.add_middleware(UploadBodyLimitMiddleware)


def _rate_limit(request: Request) -> None:
    now = time.monotonic()
    client = request.client.host if request.client else "unknown"
    bucket = _requests[client]
    while bucket and now - bucket[0] > 60:
        bucket.popleft()
    if len(bucket) >= 5:
        raise HTTPException(status_code=429, detail={"code": "rate_limited", "message": "Limite de 5 análises por minuto atingido."})
    bucket.append(now)


@app.middleware("http")
async def scan_rate_limit(request: Request, call_next):
    if request.url.path == "/api/v1/scans" and request.method == "POST":
        try:
            _rate_limit(request)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return await call_next(request)


def _get_scan(scan_id: str) -> Scan:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail={"code": "not_found", "message": "Análise não encontrada."})
        db.expunge(scan)
        return scan


@app.exception_handler(Exception)
async def safe_unhandled_error(_request: Request, _exc: Exception):
    return JSONResponse(status_code=500, content={"detail": {"code": "internal_error", "message": "Ocorreu um erro interno ao processar a solicitação."}})


@app.get("/api/v1/health")
def health():
    from sqlalchemy import text
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        return JSONResponse(status_code=503, content={"status": "unavailable", "database": "unavailable", "version": app.version})
    return {"status": "ok", "database": "ok", "version": app.version}


@app.post("/api/v1/scans", response_model=ScanOut, status_code=202)
async def create_scan(request: Request, file: UploadFile = File(...), project_name: str | None = Form(None),
                      check_dependencies: bool = Form(True), check_secrets: bool = Form(True),
                      check_static: bool = Form(True), check_configuration: bool = Form(True)):
    filename = (file.filename or "projeto.zip").replace("\\", "/").split("/")[-1]
    if not filename.lower().endswith(".zip"):
        raise HTTPException(415, detail={"code": "unsupported_file", "message": "Envie um arquivo .zip."})
    name = (project_name or filename[:-4]).strip()
    name = re.sub(r"[\x00-\x1f\x7f]", "", name)[:120].strip()
    if not name:
        name = "Projeto sem nome"
    upload_dir = DATA_DIR / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    fd, raw_path = tempfile.mkstemp(prefix="incoming-", suffix=".zip", dir=upload_dir)
    upload_path = Path(raw_path)
    size = 0
    try:
        with os.fdopen(fd, "wb") as target:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, detail={"code": "upload_too_large", "message": "O ZIP excede o limite de envio configurado."})
                target.write(chunk)
        if not size:
            raise HTTPException(400, detail={"code": "empty_upload", "message": "O arquivo enviado está vazio."})
        try:
            validate_archive(upload_path)
        except ArchiveError as exc:
            raise HTTPException(422, detail={"code": "invalid_archive", "message": str(exc)}) from exc
        scan_id = str(uuid.uuid4())
        config = {"dependencies": check_dependencies, "secrets": check_secrets, "static": check_static,
                  "configuration": check_configuration, "git_history": False}
        scan = Scan(id=scan_id, project_name=name, status="queued", uploaded_bytes=size,
                    findings_json="[]", tools_json="[]", warnings_json="[]", config_json=json.dumps(config))
        with SessionLocal() as db:
            db.add(scan)
            db.commit()
            db.refresh(scan)
            payload = scan_payload(scan)
        executor.submit(run_scan, scan_id, upload_path)
        return payload
    except Exception:
        upload_path.unlink(missing_ok=True)
        raise
    finally:
        await file.close()


@app.get("/api/v1/scans")
def list_scans(limit: int = 50, offset: int = 0):
    if not 1 <= limit <= 100 or offset < 0:
        raise HTTPException(422, detail={"code": "invalid_pagination", "message": "Use limit entre 1 e 100 e offset não negativo."})
    with SessionLocal() as db:
        scans = db.query(Scan).order_by(desc(Scan.created_at)).offset(offset).limit(limit).all()
        return {"items": [scan_payload(scan) for scan in scans], "limit": limit, "offset": offset}


@app.get("/api/v1/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str):
    return scan_payload(_get_scan(scan_id))


@app.get("/api/v1/scans/{scan_id}/findings")
def get_findings(scan_id: str, severity: str | None = None, category: str | None = None,
                 file: str | None = None, tool: str | None = None):
    payload = scan_payload(_get_scan(scan_id))
    findings = payload["findings"]
    if severity:
        findings = [item for item in findings if item["severity"].casefold() == severity.casefold()]
    if category:
        findings = [item for item in findings if item["category"].casefold() == category.casefold()]
    if file:
        findings = [item for item in findings if file.casefold() in (item.get("file") or "").casefold() or any(file.casefold() in path.casefold() for path in item.get("files", []))]
    if tool:
        findings = [item for item in findings if tool.casefold() in (item.get("tool") or "").casefold()]
    return {"items": findings, "total": len(findings)}


@app.get("/api/v1/scans/{scan_id}/report")
def get_report(scan_id: str):
    scan = _get_scan(scan_id)
    if scan.status not in {"completed", "completed_with_warnings", "failed", "cancelled"}:
        raise HTTPException(409, detail={"code": "report_not_ready", "message": "O relatório estará disponível quando a análise terminar."})
    return json_report(scan)


@app.post("/api/v1/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str):
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if not scan:
            raise HTTPException(404, detail={"code": "not_found", "message": "Análise não encontrada."})
        if scan.status in {"completed", "completed_with_warnings", "failed", "cancelled"}:
            raise HTTPException(409, detail={"code": "cannot_cancel", "message": "A análise já terminou."})
        scan.cancel_requested = True
        if scan.status == "queued":
            scan.status = "cancelled"
            from datetime import datetime, timezone
            scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        return {"id": scan_id, "status": "cancelled" if scan.status == "cancelled" else "cancelling"}

