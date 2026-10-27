import json

from securescan.services import scanners
from securescan.services.reports import json_report
from securescan.models import Scan


def test_secret_detection_masks_value(tmp_path):
    (tmp_path / "settings.py").write_text('API_KEY = "sk_live_dont_store_this_real_token"\n', encoding="utf-8")
    findings = scanners.scan_secrets(tmp_path)
    assert len(findings) == 1
    assert "dont_store_this_real_token" not in json.dumps(findings)
    assert "[REDACTED]" not in findings[0]["evidence"]
    assert findings[0]["category"] == "secrets"


def test_environment_file_flagged_without_values(tmp_path):
    (tmp_path / ".env").write_text("PASSWORD=example\n", encoding="utf-8")
    findings = scanners.scan_secrets(tmp_path)
    assert any(item["rule"] == "SEC-SECRET-ENV" for item in findings)
    assert all("example" not in json.dumps(item) for item in findings)


def test_normalization_has_stable_identifier_and_preserves_source_severity():
    first = scanners.normalize_finding(tool="Bandit", category="static", severity="Alta", title="Unsafe call", description="Check", rule="B307", original_severity="HIGH")
    again = scanners.normalize_finding(tool="Bandit", category="static", severity="Alta", title="Unsafe call", description="Different prose", rule="B307", original_severity="HIGH")
    assert first["id"] == again["id"]
    assert first["original_severity"] == "HIGH"


def test_timeout_and_missing_external_tool_are_reported(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("demo==1.2.3\n", encoding="utf-8")
    monkeypatch.setattr(scanners.shutil, "which", lambda _: "pip-audit")
    monkeypatch.setattr(scanners, "_run_command", lambda *a, **k: (None, "", "", "timeout"))
    _findings, result, warning = scanners.run_dependency_audit(tmp_path, lambda: False)
    assert result["status"] == "timeout"
    assert "tempo limite" in warning


def test_json_report_has_limitations_and_no_secret_values():
    scan = Scan(id="scan-1", project_name="demo", status="completed", config_json="{}", findings_json="[]", tools_json="[]", warnings_json="[]", uploaded_bytes=0, files_examined=0)
    report = json_report(scan)
    assert report["schema_version"] == "1.0.0"
    assert "não comprova" in report["summary"]["interpretation"]
    assert any("não executa" in item for item in report["limitations"])

