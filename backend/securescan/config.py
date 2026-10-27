from __future__ import annotations

import os
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.getenv("SECURESCAN_DATA_DIR", ROOT_DIR / "data")).resolve()
DATABASE_URL = os.getenv("SECURESCAN_DATABASE_URL", f"sqlite:///{(DATA_DIR / 'securescan.db').as_posix()}")
MAX_UPLOAD_BYTES = int(os.getenv("SECURESCAN_MAX_UPLOAD_BYTES", 50 * 1024 * 1024))
MAX_ARCHIVE_FILES = int(os.getenv("SECURESCAN_MAX_ARCHIVE_FILES", 8_000))
MAX_EXTRACTED_BYTES = int(os.getenv("SECURESCAN_MAX_EXTRACTED_BYTES", 200 * 1024 * 1024))
MAX_SINGLE_FILE_BYTES = int(os.getenv("SECURESCAN_MAX_SINGLE_FILE_BYTES", 25 * 1024 * 1024))
SCANNER_TIMEOUT_SECONDS = int(os.getenv("SECURESCAN_SCANNER_TIMEOUT_SECONDS", 90))

