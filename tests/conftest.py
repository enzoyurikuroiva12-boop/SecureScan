import os
from pathlib import Path

# Keep test state isolated from a developer's local SecureScan database.
os.environ["SECURESCAN_DATA_DIR"] = str(Path(__file__).parent / ".test-data")
os.environ["SECURESCAN_DATABASE_URL"] = f"sqlite:///{(Path(__file__).parent / '.test-data' / 'test.db').as_posix()}"
