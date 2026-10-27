from __future__ import annotations

import os
import re
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath

from ..config import MAX_ARCHIVE_FILES, MAX_EXTRACTED_BYTES, MAX_SINGLE_FILE_BYTES

IGNORED_PARTS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".next", "dist", "build"}


class ArchiveError(ValueError):
    pass


def safe_member_name(name: str) -> str:
    """Return a normalized relative path, rejecting POSIX and Windows traversal."""
    if not name or "\x00" in name or "\\" in name:
        raise ArchiveError("O ZIP contém um caminho inválido.")
    win = PureWindowsPath(name)
    posix = PurePosixPath(name)
    if win.is_absolute() or win.drive or posix.is_absolute() or re.match(r"^[A-Za-z]:", name):
        raise ArchiveError("O ZIP contém um caminho absoluto.")
    parts = name.split("/")
    if any(part in ("..", ".") for part in parts):
        raise ArchiveError("O ZIP contém tentativa de path traversal.")
    normalized = "/".join(part for part in parts if part)
    if not normalized:
        raise ArchiveError("O ZIP contém um caminho inválido.")
    if len(normalized) > 240 or any(len(part) > 120 for part in normalized.split("/")):
        raise ArchiveError("O ZIP contém um caminho longo demais para extração segura.")
    for part in normalized.split("/"):
        if part.endswith((".", " ")) or ":" in part:
            raise ArchiveError("O ZIP contém um nome de arquivo incompatível com Windows.")
        device = part.split(".", 1)[0].upper()
        if device in {"CON", "PRN", "AUX", "NUL"} or re.fullmatch(r"(?:COM|LPT)[1-9]", device):
            raise ArchiveError("O ZIP contém um nome de dispositivo reservado.")
    return normalized


def validate_archive(path: Path) -> int:
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if not entries:
                raise ArchiveError("O ZIP está vazio.")
            if len(entries) > MAX_ARCHIVE_FILES:
                raise ArchiveError("O ZIP excede o limite de arquivos.")
            total = 0
            seen_paths: set[str] = set()
            for info in entries:
                normalized = safe_member_name(info.filename.rstrip("/"))
                windows_key = normalized.casefold()
                if windows_key in seen_paths:
                    raise ArchiveError("O ZIP contém caminhos duplicados ou ambíguos.")
                seen_paths.add(windows_key)
                if info.is_dir() and info.file_size:
                    raise ArchiveError("O ZIP contém uma entrada de diretório inválida.")
                if info.flag_bits & 0x1:
                    raise ArchiveError("ZIPs protegidos por senha não são aceitos.")
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ArchiveError("O ZIP contém links simbólicos, que não são aceitos.")
                file_type = stat.S_IFMT(mode)
                if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ArchiveError("O ZIP contém um tipo de arquivo especial, que não é aceito.")
                if info.file_size > MAX_SINGLE_FILE_BYTES:
                    raise ArchiveError("O ZIP contém um arquivo acima do limite permitido.")
                total += info.file_size
                if total > MAX_EXTRACTED_BYTES:
                    raise ArchiveError("O conteúdo descompactado excede o limite permitido.")
                if info.file_size and info.compress_size == 0:
                    raise ArchiveError("O ZIP contém uma entrada compactada inválida.")
                if info.compress_size and info.file_size / info.compress_size > 250:
                    raise ArchiveError("O ZIP excede o limite de compressão permitido.")
            return total
    except zipfile.BadZipFile as exc:
        raise ArchiveError("O arquivo enviado não é um ZIP válido.") from exc


def extract_archive(path: Path, destination: Path) -> tuple[int, int]:
    """Extract regular files only; never follows archive paths or symlinks."""
    destination.mkdir(parents=True, exist_ok=True)
    total = 0
    count = 0
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                rel = safe_member_name(info.filename.rstrip("/"))
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ArchiveError("O ZIP contém links simbólicos, que não são aceitos.")
                parts = PurePosixPath(rel).parts
                if any(part in IGNORED_PARTS for part in parts):
                    continue
                target = destination.joinpath(*parts).resolve()
                if os.path.commonpath((str(destination.resolve()), str(target))) != str(destination.resolve()):
                    raise ArchiveError("O ZIP contém um caminho fora da área temporária.")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with archive.open(info) as src, target.open("xb") as dst:
                    while chunk := src.read(1024 * 1024):
                        written += len(chunk)
                        total += len(chunk)
                        if written > MAX_SINGLE_FILE_BYTES or total > MAX_EXTRACTED_BYTES:
                            raise ArchiveError("O conteúdo descompactado excede o limite permitido.")
                        dst.write(chunk)
                count += 1
        return count, total
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise

