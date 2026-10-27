from __future__ import annotations

import hashlib
import json
import os
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Any
from urllib.parse import quote

from ..config import DATA_DIR, SCANNER_TIMEOUT_SECONDS

SEVERITY_ORDER = {"Crítica": 0, "Alta": 1, "Média": 2, "Baixa": 3, "Informativa": 4}


def normalize_finding(*, tool: str, category: str, severity: str, title: str, description: str,
                      file: str | None = None, line: int | None = None, rule: str | None = None,
                      remediation: str | None = None, references: list[str] | None = None,
                      package: str | None = None, version: str | None = None,
                      fixed_version: str | None = None, vulnerability_id: str | None = None,
                      original_severity: str | None = None, evidence: str | None = None,
                      confidence: str | None = None, source: str | None = None,
                      source_consulted_at: str | None = None) -> dict[str, Any]:
    identity_file = None if category == "dependency" else file
    signature = "|".join(str(x or "") for x in (tool, category, identity_file, line, rule, package, version, vulnerability_id, title))
    return {
        "id": hashlib.sha256(signature.encode("utf-8")).hexdigest()[:16],
        "tool": tool, "category": category, "severity": severity, "title": title[:240],
        "description": description[:2_000], "file": file, "line": line, "rule": rule,
        "remediation": (remediation or "")[0:2_000], "references": (references or [])[:10],
        "package": package, "version": version, "fixed_version": fixed_version,
        "vulnerability_id": vulnerability_id, "original_severity": original_severity,
        "evidence": evidence[:500] if evidence else None, "confidence": confidence,
        "source": source or tool,
        "source_consulted_at": source_consulted_at or datetime.now(timezone.utc).isoformat(),
        "files": [file] if file else [],
    }


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group repeat dependency advisories from multiple supported manifests."""
    grouped: dict[str, dict[str, Any]] = {}
    for finding in findings:
        existing = grouped.get(finding["id"])
        if existing is None:
            grouped[finding["id"]] = finding
            continue
        for path in finding.get("files", []):
            if path not in existing.setdefault("files", []):
                existing["files"].append(path)
    for finding in grouped.values():
        if finding.get("files"):
            finding["file"] = finding["files"][0]
    return list(grouped.values())


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > 2_000_000:
            return None
        raw = path.read_bytes()
        if b"\x00" in raw[:8192]:
            return None
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return None


_ASSIGNMENT_SECRET = re.compile(
    r"(?i)\b(api[_-]?key|client[_-]?secret|secret[_-]?key|private[_-]?key|secret|access[_-]?token|auth[_-]?token|password|passwd|pwd|token|credential)"
    r"(\s*[:=]\s*)(?:\"((?:\\.|[^\"\\]){4,})\"|'((?:\\.|[^'\\]){4,})'|([^\s,;#]{4,}))"
)
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
_PRIVATE_KEY_BLOCK = re.compile(r"-----BEGIN [^\r\n]+PRIVATE KEY-----[\s\S]*?-----END [^\r\n]+PRIVATE KEY-----")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_URL_CREDENTIAL = re.compile(r"(?i)(https?://)([^\s/:@]+):([^\s/@]+)@")
_DOCKER_CREDENTIAL = re.compile(r"(?i)(\bFROM\s+)([^\s/:@]+):([^\s/@]+)@([^\s]+)")
_KNOWN_TOKENS = [
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b")),
    ("Stripe-like key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
]


def _masked(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * min(12, len(value) - 3) + value[-3:]


def scan_secrets(root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        content = _read_text(path)
        if content is None:
            continue
        rel = path.relative_to(root).as_posix()
        for line_no, line in enumerate(content.splitlines(), 1):
            candidates: list[tuple[str, str, str]] = []
            for match in _ASSIGNMENT_SECRET.finditer(line):
                key = match.group(1)
                value = match.group(3) or match.group(4) or match.group(5)
                if value.lower() in {"changeme", "change-me", "example", "your_token", "your-secret", "placeholder", "null", "none"}:
                    continue
                quote_char = '"' if match.group(3) else "'" if match.group(4) else ""
                evidence = f"{key}{match.group(2)}{quote_char}{_masked(value)}{quote_char}"
                candidates.append((key, value, evidence))
            for match in _AWS_KEY.finditer(line):
                candidates.append(("AWS access key", match.group(), _masked(match.group())))
            for match in _JWT.finditer(line):
                candidates.append(("JWT-like token", match.group(), _masked(match.group())))
            for rule, pattern in _KNOWN_TOKENS:
                for match in pattern.finditer(line):
                    candidates.append((rule, match.group(), _masked(match.group())))
            for match in _URL_CREDENTIAL.finditer(line):
                raw = match.group(0)
                candidates.append(("URL credential", raw, f"{match.group(1)}{_masked(match.group(2))}:{_masked(match.group(3))}@"))
            if _PRIVATE_KEY.search(line):
                candidates.append(("Private key material", "private key", "-----BEGIN [REDACTED] PRIVATE KEY-----"))
            for rule, _secret, masked in candidates:
                findings.append(normalize_finding(
                    tool="SecureScan Rules", category="secrets", severity="Alta",
                    title=f"Possível segredo exposto: {rule}",
                    description="Um padrão com aparência de credencial foi encontrado. Pode haver falso positivo; valide o contexto sem compartilhar o valor.",
                    file=rel, line=line_no, rule="SEC-SECRET-001",
                    remediation="Se a credencial for real, revogue-a e gere outra. Remova o valor do código e use um gerenciador de segredos ou variável de ambiente.",
                    references=["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"],
                    evidence=masked,
                ))
        if path.name == ".env":
            findings.append(normalize_finding(
                tool="SecureScan Rules", category="secrets", severity="Média",
                title="Arquivo .env incluído no projeto", description="Arquivos .env frequentemente contêm credenciais. Confirme que o arquivo não será versionado ou distribuído.",
                file=rel, rule="SEC-SECRET-ENV", remediation="Adicione .env ao .gitignore e mantenha apenas um .env.example sem valores reais.",
                references=["https://git-scm.com/docs/gitignore"],
            ))
    return findings


def scan_configuration(root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(root).as_posix()
        name = path.name.lower()
        text = _read_text(path)
        if text is None:
            continue
        if name == "dockerfile":
            stage_aliases: set[str] = set()
            lines = text.splitlines()
            for line_no, line in enumerate(lines, 1):
                match = re.match(r"\s*FROM\s+(\S+)", line, re.I)
                image = match.group(1) if match else ""
                is_stage_alias = image.lower() in stage_aliases
                image_name = image.split("@", 1)[0]
                has_tag = ":" in image_name.rsplit("/", 1)[-1]
                if match and image.lower() != "scratch" and not is_stage_alias and not has_tag and "@" not in image:
                    findings.append(normalize_finding(tool="SecureScan Rules", category="configuration", severity="Baixa",
                        title="Imagem de contêiner sem versão fixa", description="A imagem não fixa uma tag ou digest e pode mudar entre builds.",
                        file=rel, line=line_no, rule="SEC-DOCKER-001", evidence=_redact_evidence(line.strip())[:300],
                        remediation="Fixe uma tag revisada ou, para maior reprodutibilidade, um digest de imagem.",
                        references=["https://docs.docker.com/build/building/best-practices/"]))
                alias = re.match(r"\s*FROM\s+\S+\s+AS\s+(\S+)", line, re.I)
                if alias:
                    stage_aliases.add(alias.group(1).lower())
            user = re.search(r"(?im)^\s*USER\s+(\S+)", text)
            if user and user.group(1).lower().split(":")[0] in {"root", "0"}:
                line_no = text[:user.start()].count("\n") + 1
                findings.append(normalize_finding(tool="SecureScan Rules", category="configuration", severity="Baixa",
                    title="Contêiner configurado para executar como root", description="A instrução USER seleciona root. Avalie se a aplicação precisa desses privilégios.",
                    file=rel, line=line_no, rule="SEC-DOCKER-ROOT", evidence=_redact_evidence(user.group(0).strip()),
                    remediation="Quando compatível, use uma conta sem privilégios para executar a aplicação.",
                    references=["https://docs.docker.com/build/building/best-practices/#user"]))
            elif not user:
                findings.append(normalize_finding(tool="SecureScan Rules", category="configuration", severity="Informativa",
                    title="Dockerfile não declara usuário de execução", description="Sem uma instrução USER, o contêiner normalmente inicia como root. A necessidade depende da imagem e da aplicação.",
                    file=rel, rule="SEC-DOCKER-002", remediation="Quando compatível, crie e use um usuário sem privilégios.",
                    references=["https://docs.docker.com/build/building/best-practices/#user"]))
        if name in {"settings.py", "config.py", "configuration.py"} and re.search(r"(?i)\bdebug\s*=\s*true\b", text):
            findings.append(normalize_finding(tool="SecureScan Rules", category="configuration", severity="Média",
                title="Modo de depuração habilitado na configuração", description="A configuração contém DEBUG=True; confirme que ela não será usada em produção.",
                file=rel, rule="SEC-CONFIG-DEBUG", remediation="Desative o modo de depuração em ambientes de produção e configure o valor por ambiente.",
                references=["https://docs.djangoproject.com/en/stable/howto/deployment/checklist/#debug"]))
        if name == ".env":
            ignore = root / ".gitignore"
            ignored = _read_text(ignore) if ignore.exists() else ""
            if not ignored or not re.search(r"(?m)^\s*(?:\.env|\.env\*)\s*$", ignored):
                findings.append(normalize_finding(tool="SecureScan Rules", category="configuration", severity="Baixa",
                    title=".env pode não estar excluído pelo Git", description="Não foi encontrada uma regra simples de exclusão para .env no .gitignore. Padrões mais complexos podem não ser reconhecidos.",
                    file=".gitignore" if ignore.exists() else ".gitignore (ausente)", rule="SEC-GITIGNORE-ENV",
                    remediation="Inclua .env no .gitignore e mantenha um .env.example sem credenciais.", references=["https://git-scm.com/docs/gitignore"]))
    return findings


def _run_command(args: list[str], *, cwd: Path, timeout: int, cancelled: Callable[[], bool]) -> tuple[int, str, str, str | None]:
    """Run a known scanner with argv, no shell, bounded time, and cancellation polling."""
    try:
        process = subprocess.Popen(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   encoding="utf-8", errors="replace", shell=False)
    except OSError:
        return -1, "", "", "Não foi possível iniciar a ferramenta externa."
    deadline = time.monotonic() + timeout
    while True:
        if cancelled():
            process.kill()
            out, err = process.communicate()
            return process.returncode or -9, out, err, "cancelled"
        if time.monotonic() >= deadline:
            process.kill()
            out, err = process.communicate()
            return process.returncode or -9, out, err, "timeout"
        try:
            out, err = process.communicate(timeout=0.2)
            return process.returncode or 0, out, err, None
        except subprocess.TimeoutExpired:
            continue


def run_dependency_audit(root: Path, cancelled: Callable[[], bool]) -> tuple[list[dict[str, Any]], dict[str, Any], str | None]:
    manifests = sorted(p for p in root.rglob("*") if p.is_file() and
                       (p.name.startswith("requirements") and p.suffix.lower() == ".txt" or
                        p.name.startswith("pylock") and p.suffix.lower() == ".toml"))
    if not manifests:
        return [], {"name": "pip-audit", "status": "skipped", "version": None, "details": "Nenhum requirements*.txt ou pylock*.toml encontrado."}, None
    executable = shutil.which("pip-audit")
    base = [executable] if executable else ([sys.executable, "-m", "pip_audit"] if _module_available("pip_audit") else None)
    if not base:
        return [], {"name": "pip-audit", "status": "unavailable", "version": None, "details": "Instale pip-audit para consultar o banco OSV."}, "pip-audit não está instalado; dependências não foram verificadas."
    findings: list[dict[str, Any]] = []
    skipped_lines = 0
    scanned_manifests = 0
    for manifest in manifests[:30]:
        # Requirements files can contain index URLs, editable Git sources and other
        # directives. Only pass exact package pins to the external resolver.
        pins: list[str] = []
        if manifest.name.startswith("pylock"):
            try:
                lock_data = tomllib.loads(manifest.read_text(encoding="utf-8", errors="replace"))
                packages = lock_data.get("packages", [])
                for package in packages:
                    package_name, package_version = package.get("name"), package.get("version")
                    if package_name and package_version and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", package_name) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!+_-]*", package_version):
                        pins.append(f"{package_name}=={package_version}")
                    else:
                        skipped_lines += 1
            except (OSError, tomllib.TOMLDecodeError):
                skipped_lines += 1
        else:
            try:
                lines = manifest.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                skipped_lines += 1
                continue
            for line in lines:
                item = line.strip()
                if not item or item.startswith("#"):
                    continue
                match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,.-]+\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)(?:\s+#.*)?", item)
                if match:
                    pins.append(f"{match.group(1)}=={match.group(2)}")
                else:
                    skipped_lines += 1
        pins = list(dict.fromkeys(pins))
        if not pins:
            continue
        scanned_manifests += 1
        temp_root = DATA_DIR / "tmp"
        temp_root.mkdir(parents=True, exist_ok=True)
        fd, clean_manifest_raw = tempfile.mkstemp(prefix="securescan-audit-", suffix=".txt", dir=temp_root)
        clean_manifest = Path(clean_manifest_raw)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                output.write("\n".join(pins) + "\n")
            _code, stdout, _stderr, issue = _run_command(base + ["-r", str(clean_manifest), "--format=json", "--progress-spinner=off",
                                                                  "--vulnerability-service=osv", "--no-deps", "--disable-pip"],
                                                          cwd=root, timeout=SCANNER_TIMEOUT_SECONDS, cancelled=cancelled)
        finally:
            clean_manifest.unlink(missing_ok=True)
        if issue == "cancelled":
            return findings, {"name": "pip-audit", "status": "cancelled", "version": None}, None
        if issue:
            return findings, {"name": "pip-audit", "status": "timeout" if issue == "timeout" else "failed", "version": None}, f"pip-audit {('excedeu o tempo limite' if issue == 'timeout' else 'falhou ao iniciar')} ."
        if _code not in (0, 1):
            return findings, {"name": "pip-audit", "status": "failed", "version": None}, "pip-audit terminou com erro antes de concluir a consulta de vulnerabilidades."
        try:
            report = json.loads(stdout)
        except json.JSONDecodeError:
            return findings, {"name": "pip-audit", "status": "failed", "version": None}, "pip-audit retornou uma resposta inválida."
        for dep in report.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                aliases = vuln.get("aliases") or []
                vuln_id = (aliases[0] if aliases else vuln.get("id"))
                fix = (vuln.get("fix_versions") or [None])[0]
                raw_severity = vuln.get("severity")
                normalized_severity, preserved_severity = _normalize_source_severity(raw_severity)
                findings.append(normalize_finding(tool="pip-audit / OSV", category="dependency", severity=normalized_severity,
                    title=f"{dep.get('name', 'Pacote')} possui vulnerabilidade conhecida",
                    description=(vuln.get("description") or "O banco consultado identificou uma vulnerabilidade para esta versão.")[:2_000],
                    file=manifest.relative_to(root).as_posix(), rule=vuln.get("id"), package=dep.get("name"), version=dep.get("version"),
                    fixed_version=fix, vulnerability_id=vuln_id,
                    original_severity=preserved_severity, source="OSV", source_consulted_at=datetime.now(timezone.utc).isoformat(),
                    remediation=f"Atualize {dep.get('name')} para {fix}." if fix else f"Revise os avisos oficiais para {dep.get('name')} e atualize para uma versão corrigida.",
                    references=[f"https://osv.dev/vulnerability/{quote(str(vuln_id), safe='')}"] if vuln_id else ["https://osv.dev/"]))
    if not scanned_manifests:
        return [], {"name": "pip-audit", "status": "skipped", "version": None, "details": "Nenhuma dependência com versão exata pôde ser auditada."}, "Dependências não verificadas: use pins exatos (pacote==versão); linhas com índices, URLs ou intervalos são ignoradas por segurança."
    version = _tool_version(base, root)
    details = "Consulta OSV realizada para pins exatos; pip desativado e sem resolver dependências transitivas."
    warning = None
    if skipped_lines:
        details += f" {skipped_lines} linha(s) não analisadas por segurança."
        warning = f"{skipped_lines} linha(s) de requirements não puderam ser auditadas; foram ignorados intervalos, URLs e diretivas." 
    return findings, {"name": "pip-audit", "status": "completed", "version": version, "details": details}, warning


def run_bandit(root: Path, cancelled: Callable[[], bool]) -> tuple[list[dict[str, Any]], dict[str, Any], str | None]:
    python_files = [p for p in root.rglob("*.py") if p.is_file()]
    if not python_files:
        return [], {"name": "Bandit", "status": "skipped", "version": None, "details": "Nenhum arquivo Python encontrado."}, None
    executable = shutil.which("bandit")
    base = [executable] if executable else ([sys.executable, "-m", "bandit"] if _module_available("bandit") else None)
    if not base:
        return [], {"name": "Bandit", "status": "unavailable", "version": None, "details": "Instale Bandit para análise estática Python."}, "Bandit não está instalado; análise estática Python não foi executada."
    code, stdout, _stderr, issue = _run_command(base + ["-r", str(root), "-f", "json", "-q"], cwd=root,
                                                 timeout=SCANNER_TIMEOUT_SECONDS, cancelled=cancelled)
    if issue == "cancelled":
        return [], {"name": "Bandit", "status": "cancelled", "version": None}, None
    if issue:
        return [], {"name": "Bandit", "status": "timeout" if issue == "timeout" else "failed", "version": None}, f"Bandit {('excedeu o tempo limite' if issue == 'timeout' else 'falhou ao iniciar')} ."
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError:
        return [], {"name": "Bandit", "status": "failed", "version": None}, "Bandit retornou uma resposta inválida."
    if report.get("errors"):
        return [], {"name": "Bandit", "status": "failed", "version": _tool_version(base, root), "details": "Bandit encontrou erros ao analisar arquivos."}, "Bandit não conseguiu analisar todos os arquivos; veja o estado da ferramenta."
    severity = {"HIGH": "Alta", "MEDIUM": "Média", "LOW": "Baixa"}
    findings = []
    for item in report.get("results", []):
        path = Path(item.get("filename", ""))
        try:
            rel = path.resolve().relative_to(root.resolve()).as_posix()
        except (ValueError, OSError):
            rel = path.name
        evidence = item.get("code") or ""
        evidence = _redact_evidence(evidence)
        test_id = item.get("test_id", "BANDIT")
        findings.append(normalize_finding(tool="Bandit", category="static", severity=severity.get(item.get("issue_severity"), "Informativa"),
            title=item.get("test_name", "Padrão de código suspeito"), description=item.get("issue_text", "Verifique este padrão no contexto."),
            file=rel, line=item.get("line_number"), rule=test_id,
            remediation="Revise o contexto e aplique a recomendação da documentação da regra.",
            references=[item.get("more_info") if str(item.get("more_info", "")).startswith("https://bandit.readthedocs.io/") else "https://bandit.readthedocs.io/en/latest/"],
            evidence=evidence, confidence=item.get("issue_confidence"), original_severity=item.get("issue_severity")))
    version = report.get("metrics", {}).get("_totals", {}).get("loc")
    return findings, {"name": "Bandit", "status": "completed", "version": _tool_version(base, root), "details": f"Analisados {version or 0} linhas."}, None


def _redact_evidence(code: str) -> str:
    code = _PRIVATE_KEY_BLOCK.sub("[REDACTED PRIVATE KEY]", code)
    def mask_assignment(match: re.Match[str]) -> str:
        value = match.group(3) or match.group(4) or match.group(5)
        quote_char = '"' if match.group(3) else "'" if match.group(4) else ""
        return f"{match.group(1)}{match.group(2)}{quote_char}[REDACTED]{quote_char}"

    code = _ASSIGNMENT_SECRET.sub(mask_assignment, code)
    code = _AWS_KEY.sub("[REDACTED]", code)
    code = _JWT.sub("[REDACTED]", code)
    code = _URL_CREDENTIAL.sub(r"\1[REDACTED]@", code)
    code = _DOCKER_CREDENTIAL.sub(r"\1[REDACTED]@\4", code)
    return code[:500]


def _normalize_source_severity(raw: Any) -> tuple[str, str | None]:
    if raw is None:
        return "Informativa", None
    if isinstance(raw, list):
        original = json.dumps(raw, ensure_ascii=False, separators=(",", ":"))[:240]
        candidate = " ".join(str(item.get("score", "")) if isinstance(item, dict) else str(item) for item in raw)
    elif isinstance(raw, dict):
        original = json.dumps(raw, ensure_ascii=False, separators=(",", ":"))[:240]
        candidate = " ".join(str(value) for value in raw.values())
    else:
        original = str(raw)[:240]
        candidate = original
    upper = candidate.upper()
    if "CVSS:" in upper:
        # A CVSS vector is not itself a score; without a CVSS calculator do not
        # guess a severity from the vector text.
        return "Informativa", original
    match = re.search(r"\b(\d{1,2}(?:\.\d+)?)\b", candidate)
    if match:
        score = float(match.group(1))
        if 0 <= score <= 10:
            return ("Crítica" if score >= 9 else "Alta" if score >= 7 else "Média" if score >= 4 else "Baixa"), original
    for source, normalized in (("CRITICAL", "Crítica"), ("HIGH", "Alta"), ("MODERATE", "Média"), ("MEDIUM", "Média"), ("LOW", "Baixa")):
        if source in upper:
            return normalized, original
    return "Informativa", original


def _module_available(name: str) -> bool:
    try:
        return subprocess.run([sys.executable, "-c", f"import {name}"], capture_output=True, timeout=3, shell=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _tool_version(args: list[str], cwd: Path) -> str | None:
    try:
        result = subprocess.run(args + ["--version"], cwd=cwd, capture_output=True, text=True, timeout=5, shell=False)
        text = (result.stdout or result.stderr).strip().splitlines()
        return text[0][:120] if text else None
    except (OSError, subprocess.TimeoutExpired):
        return None

