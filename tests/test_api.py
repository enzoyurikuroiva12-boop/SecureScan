import io
import time
import zipfile
import pytest

from fastapi.testclient import TestClient

from securescan import main
from securescan.main import app
from securescan.config import DATA_DIR


@pytest.fixture(autouse=True)
def reset_local_rate_bucket():
    main._requests.clear()
    yield
    main._requests.clear()


def make_zip(*entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return stream.getvalue()


def test_upload_rejects_non_zip_and_malformed_archive():
    with TestClient(app) as client:
        wrong_type = client.post("/api/v1/scans", files={"file": ("project.txt", b"x")})
        malformed = client.post("/api/v1/scans", files={"file": ("project.zip", b"not a zip")})
        unsafe = client.post("/api/v1/scans", files={"file": ("unsafe.zip", make_zip(("../escape.txt", "x")))})
    assert wrong_type.status_code == 415
    assert malformed.status_code == 422
    assert unsafe.status_code == 422


def test_upload_size_limit(monkeypatch):
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 8)
    with TestClient(app) as client:
        response = client.post("/api/v1/scans", files={"file": ("too-big.zip", make_zip(("a.txt", "payload")))})
    assert response.status_code == 413


def test_upload_persists_history_and_exports_json_report():
    with TestClient(app) as client:
        response = client.post("/api/v1/scans", files={"file": ("project.zip", make_zip(("README.md", "demo")))})
        assert response.status_code == 202
        scan_id = response.json()["id"]
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            scan = client.get(f"/api/v1/scans/{scan_id}").json()
            if scan["status"] in {"completed", "completed_with_warnings", "failed", "cancelled"}:
                break
            time.sleep(0.05)
        assert scan["status"] in {"completed", "completed_with_warnings"}
        assert client.get("/api/v1/scans").json()["items"][0]["id"] == scan_id
        report = client.get(f"/api/v1/scans/{scan_id}/report")
        assert report.status_code == 200
        assert report.json()["schema_version"] == "1.0.0"


def test_queued_scan_can_be_cancelled(monkeypatch):
    monkeypatch.setattr(main.executor, "submit", lambda *_args: None)
    with TestClient(app) as client:
        response = client.post("/api/v1/scans", files={"file": ("queued.zip", make_zip(("README.md", "demo")))})
        scan_id = response.json()["id"]
        cancelled = client.post(f"/api/v1/scans/{scan_id}/cancel")
        assert cancelled.status_code == 200
        assert cancelled.json()["status"] == "cancelled"
        assert client.get(f"/api/v1/scans/{scan_id}").json()["status"] == "cancelled"
        upload_path = max((DATA_DIR / "uploads").glob("incoming-*.zip"), key=lambda path: path.stat().st_mtime)
        main.run_scan(scan_id, upload_path)
        assert not upload_path.exists()

