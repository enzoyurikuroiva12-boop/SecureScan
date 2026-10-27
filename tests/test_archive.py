import zipfile

import pytest

from securescan.services.archive import ArchiveError, extract_archive, safe_member_name, validate_archive


@pytest.mark.parametrize("name", ["../escape.txt", "a/../../escape.txt", "C:/Windows/win.ini", "\\\\server\\share\\x", "/etc/passwd", "a\\..\\b"])
def test_rejects_malicious_paths(name):
    with pytest.raises(ArchiveError):
        safe_member_name(name)


def test_extracts_regular_files_to_destination(tmp_path):
    archive_path = tmp_path / "project.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("src/app.py", "print('data only')")
        archive.writestr("node_modules/ignored.txt", "ignored")
    destination = tmp_path / "out"
    count, _size = extract_archive(archive_path, destination)
    assert count == 1
    assert (destination / "src/app.py").read_text() == "print('data only')"
    assert not (destination / "node_modules").exists()


def test_archive_validation_rejects_path_traversal(tmp_path):
    archive_path = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../../outside.txt", "no")
    with pytest.raises(ArchiveError, match="traversal"):
        validate_archive(archive_path)

