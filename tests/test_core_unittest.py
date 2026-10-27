"""Dependency-free smoke tests for the archive and built-in scanner core."""
import json
import sys
import shutil
import uuid
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
TEST_TEMP = Path(__file__).resolve().parents[1] / ".test-tmp"
TEST_TEMP.mkdir(parents=True, exist_ok=True)


class WorkspaceTemp:
    def __enter__(self):
        self.path = TEST_TEMP / uuid.uuid4().hex
        self.path.mkdir()
        return str(self.path)

    def __exit__(self, *_exc):
        shutil.rmtree(self.path)

from securescan.services.archive import ArchiveError, extract_archive, safe_member_name, validate_archive
from securescan.services import scanners


class ArchiveTests(unittest.TestCase):
    def test_rejects_posix_and_windows_traversal(self):
        for path in ("../outside", "C:/Windows/win.ini", "\\\\server\\share\\x", "src\\..\\secret", "app.py:stream", "NUL.txt"):
            with self.subTest(path=path), self.assertRaises(ArchiveError):
                safe_member_name(path)

    def test_extracts_zip_without_running_contents(self):
        with WorkspaceTemp() as temp:
            root = Path(temp)
            source = root / "project.zip"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("src/app.py", "print('only data')")
                archive.writestr("node_modules/a.txt", "ignored")
            self.assertGreater(validate_archive(source), 0)
            count, _ = extract_archive(source, root / "out")
            self.assertEqual(count, 1)
            self.assertTrue((root / "out/src/app.py").exists())
            self.assertFalse((root / "out/node_modules").exists())

    def test_rejects_zip_traversal_before_extracting(self):
        with WorkspaceTemp() as temp:
            source = Path(temp) / "unsafe.zip"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("../../outside.txt", "no")
            with self.assertRaisesRegex(ArchiveError, "traversal"):
                validate_archive(source)


class ScannerTests(unittest.TestCase):
    def test_secret_value_is_masked_in_finding(self):
        with WorkspaceTemp() as temp:
            root = Path(temp)
            (root / "settings.py").write_text('API_KEY = "sk_live_not_for_reports_6789"\n', encoding="utf-8")
            findings = scanners.scan_secrets(root)
            serialized = json.dumps(findings)
            self.assertEqual(len(findings), 1)
            self.assertNotIn("sk_live_not_for_reports_6789", serialized)
            self.assertEqual(findings[0]["category"], "secrets")

    def test_docker_configuration_masks_evidence_and_checks_root(self):
        with WorkspaceTemp() as temp:
            root = Path(temp)
            (root / "Dockerfile").write_text("FROM ubuntu # PASSWORD=secret_docker_value\nUSER root\n", encoding="utf-8")
            findings = scanners.scan_configuration(root)
            serialized = json.dumps(findings)
            self.assertNotIn("secret_docker_value", serialized)
            self.assertTrue(any(item["rule"] == "SEC-DOCKER-001" for item in findings))
            self.assertTrue(any(item["rule"] == "SEC-DOCKER-ROOT" for item in findings))

    def test_docker_multistage_alias_and_scratch_do_not_raise_unpinned_image(self):
        with WorkspaceTemp() as temp:
            root = Path(temp)
            (root / "Dockerfile").write_text("FROM scratch\nFROM alpine:3.20 AS builder\nFROM builder AS app\n", encoding="utf-8")
            findings = scanners.scan_configuration(root)
            self.assertFalse(any(item["rule"] == "SEC-DOCKER-001" for item in findings))

    def test_ignores_placeholder_but_flags_env_file(self):
        with WorkspaceTemp() as temp:
            root = Path(temp)
            (root / ".env").write_text("PASSWORD=example\n", encoding="utf-8")
            findings = scanners.scan_secrets(root)
            self.assertTrue(any(item["rule"] == "SEC-SECRET-ENV" for item in findings))
            self.assertFalse(any(item["rule"] == "SEC-SECRET-001" for item in findings))

    def test_secret_with_spaces_is_fully_masked(self):
        with WorkspaceTemp() as temp:
            root = Path(temp)
            (root / "config.py").write_text("SECRET = 'multi word credential that must stay private'\n", encoding="utf-8")
            findings = scanners.scan_secrets(root)
            self.assertEqual(len(findings), 1)
            self.assertNotIn("multi word credential that must stay private", json.dumps(findings))
            self.assertNotIn("private", findings[0]["evidence"])

    def test_severity_mapping_keeps_original_and_does_not_guess_cvss_vector(self):
        mapped, original = scanners._normalize_source_severity([{"type": "CVSS_V3", "score": "8.1"}])
        self.assertEqual(mapped, "Alta")
        self.assertIn("8.1", original)
        mapped, _ = scanners._normalize_source_severity([{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}])
        self.assertEqual(mapped, "Informativa")

    def test_dependency_advisories_from_two_manifests_are_grouped(self):
        common = {"tool": "pip-audit / OSV", "category": "dependency", "severity": "Alta",
                  "title": "demo-package vulnerável", "description": "Aviso", "package": "demo-package",
                  "version": "1.2.3", "vulnerability_id": "CVE-2026-1234"}
        first = scanners.normalize_finding(**common, file="requirements.txt")
        second = scanners.normalize_finding(**common, file="pylock.toml")
        grouped = scanners.deduplicate_findings([first, second])
        self.assertEqual(len(grouped), 1)
        self.assertEqual(set(grouped[0]["files"]), {"requirements.txt", "pylock.toml"})

    def test_requirements_audit_disables_pip_and_reports_timeout(self):
        with WorkspaceTemp() as temp:
            root = Path(temp)
            (root / "requirements.txt").write_text("demo-package==1.2.3\n", encoding="utf-8")
            calls = []

            def fake_run(args, **_kwargs):
                calls.extend(args)
                return None, "", "", "timeout"

            with patch.object(scanners.shutil, "which", return_value="pip-audit"), patch.object(scanners, "_run_command", side_effect=fake_run):
                _findings, tool, warning = scanners.run_dependency_audit(root, lambda: False)
            self.assertEqual(tool["status"], "timeout")
            self.assertIn("--no-deps", calls)
            self.assertIn("--disable-pip", calls)
            self.assertIn("--vulnerability-service=osv", calls)
            self.assertIn("tempo limite", warning)

    def test_pylock_is_reduced_to_exact_pins_before_osv_audit(self):
        with WorkspaceTemp() as temp:
            root = Path(temp)
            (root / "pylock.toml").write_text('lock-version = "1.0"\n[[packages]]\nname = "demo-package"\nversion = "1.2.3"\n', encoding="utf-8")
            audited = []

            def fake_run(args, **_kwargs):
                clean_file = Path(args[args.index("-r") + 1])
                audited.append(clean_file.read_text(encoding="utf-8"))
                return 0, json.dumps({"dependencies": []}), "", None

            with patch.object(scanners.shutil, "which", return_value="pip-audit"), patch.object(scanners, "_run_command", side_effect=fake_run), patch.object(scanners, "_tool_version", return_value="pip-audit 2.x"):
                _findings, tool, warning = scanners.run_dependency_audit(root, lambda: False)
            self.assertEqual(tool["status"], "completed")
            self.assertEqual(audited, ["demo-package==1.2.3\n"])
            self.assertIsNone(warning)

    def test_bandit_finding_is_normalized_and_evidence_redacted(self):
        with WorkspaceTemp() as temp:
            root = Path(temp)
            (root / "app.py").write_text("SECRET_KEY = 'sensitive_value_abc123'\n", encoding="utf-8")
            report = {"errors": [], "results": [{"filename": str(root / "app.py"), "line_number": 1,
                "test_id": "B303", "test_name": "Unsafe crypto", "issue_severity": "HIGH",
                "issue_confidence": "HIGH", "issue_text": "Review cryptography choice.",
                "code": "SECRET_KEY = 'sensitive_value_abc123'", "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b303.html"}]}
            with patch.object(scanners.shutil, "which", return_value="bandit"), patch.object(scanners, "_run_command", return_value=(1, json.dumps(report), "", None)), patch.object(scanners, "_tool_version", return_value="1.8.0"):
                findings, tool, warning = scanners.run_bandit(root, lambda: False)
            self.assertEqual(tool["status"], "completed")
            self.assertIsNone(warning)
            self.assertEqual(findings[0]["severity"], "Alta")
            self.assertEqual(findings[0]["original_severity"], "HIGH")
            self.assertNotIn("sensitive_value_abc123", json.dumps(findings))


if __name__ == "__main__":
    unittest.main()
