"""Exercise the real PowerShell source packager in disposable Git checkouts.

Windows/Linux CI supplies PowerShell 7. The slim application container does not
include this release-maintainer tool, so packaging tests are skipped there.
"""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
PWSH = shutil.which("pwsh")
GIT = shutil.which("git")
pytestmark = pytest.mark.skipif(not PWSH or not GIT, reason="Packaging requires PowerShell 7 and Git")


def git(root, *arguments):
    subprocess.run([GIT, "-C", str(root), *arguments], check=True, capture_output=True, text=True)


def commit(root):
    git(root, "add", "--all")
    git(root, "-c", "user.name=NorthFlux Test", "-c", "user.email=test@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-m", "Test fixture")


@pytest.fixture
def package_project(tmp_path):
    root = tmp_path / "NorthFlux release with spaces"
    (root / "scripts").mkdir(parents=True)
    shutil.copyfile(ROOT / "scripts/create_submission_zip.ps1", root / "scripts/create_submission_zip.ps1")
    (root / "README.md").write_text("# Test release\n", encoding="utf-8")
    (root / ".gitignore").write_text("dist/\n", encoding="utf-8")
    git(root, "init")
    return root


def package(root, *arguments):
    return subprocess.run(
        [PWSH, "-NoProfile", "-File", str(root / "scripts/create_submission_zip.ps1"), *arguments],
        cwd=root, capture_output=True, text=True, encoding="utf-8", timeout=30,
    )


def test_package_preserves_unicode_names_and_excludes_runtime_files(package_project):
    root = package_project
    (root / "café & review.md").write_text("Preserve this source document.", encoding="utf-8")
    for name in (".env", ".ENV.LOCAL", "operator.sqlite3", "backup.db", "backup.db-wal",
                 "backup.sqlite-wal", "backup.sqlite-shm", "backup.sqlite3-wal", "backup.sqlite3-shm", "session.log"):
        (root / name).write_text("private test placeholder", encoding="utf-8")
    (root / ".venv-backup").mkdir()
    (root / ".venv-backup/local.txt").write_text("local environment", encoding="utf-8")
    commit(root)
    result = package(root)
    assert result.returncode == 0, result.stdout + result.stderr
    archive = root / "dist/NorthFlux_Security.zip"
    with zipfile.ZipFile(archive) as source:
        names = source.namelist()
        assert "NorthFlux_Security/café & review.md" in names
        assert not any("private test placeholder" in source.read(name).decode("utf-8") for name in names)
        assert not any(".venv-backup" in name for name in names)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert archive.with_suffix(".zip.sha256").read_text(encoding="utf-8").split()[0] == digest


@pytest.mark.skipif(os.name == "nt", reason="Windows does not allow newline filenames")
def test_package_preserves_newline_filename(package_project):
    root = package_project
    filename = "review\nnotes.md"
    (root / filename).write_text("A valid Linux filename.", encoding="utf-8")
    commit(root)
    result = package(root)
    assert result.returncode == 0, result.stdout + result.stderr
    with zipfile.ZipFile(root / "dist/NorthFlux_Security.zip") as source:
        assert "NorthFlux_Security/" + filename in source.namelist()


def test_package_rejects_linked_input_instead_of_reading_outside_checkout(package_project, tmp_path):
    root = package_project
    private = tmp_path / "outside-private.txt"
    private.write_text("DO NOT PACKAGE: harmless test content", encoding="utf-8")
    try:
        (root / "ordinary-looking.txt").symlink_to(private)
    except OSError:
        pytest.skip("This Windows host does not permit creating test symlinks")
    commit(root)
    result = package(root)
    assert result.returncode != 0
    assert "must not follow filesystem links" in result.stderr
    assert not (root / "dist/NorthFlux_Security.zip").exists()


def test_dirty_checkout_preserves_last_good_archive(package_project):
    root = package_project
    commit(root)
    result = package(root)
    assert result.returncode == 0, result.stdout + result.stderr
    archive = root / "dist/NorthFlux_Security.zip"
    original = archive.read_bytes()
    checksum = archive.with_suffix(".zip.sha256").read_bytes()
    (root / "README.md").write_text("uncommitted change", encoding="utf-8")
    result = package(root)
    assert result.returncode != 0
    assert "dirty working tree" in result.stderr
    assert archive.read_bytes() == original
    assert archive.with_suffix(".zip.sha256").read_bytes() == checksum


def test_directory_checksum_target_cannot_replace_last_good_archive(package_project):
    root = package_project
    commit(root)
    dist = root / "dist"
    dist.mkdir()
    archive = dist / "NorthFlux_Security.zip"
    archive.write_bytes(b"previous release")
    archive.with_suffix(".zip.sha256").mkdir()
    result = package(root)
    assert result.returncode != 0
    assert "regular file" in result.stderr
    assert archive.read_bytes() == b"previous release"


@pytest.mark.skipif(os.name == "nt", reason="Backslashes are path separators on Windows")
def test_linux_backslash_filename_cannot_become_zip_traversal(package_project):
    root = package_project
    (root / r"..\..\outside.txt").write_text("Must never escape the package root", encoding="utf-8")
    commit(root)
    result = package(root)
    assert result.returncode != 0
    assert "unsafe on Windows" in result.stderr
    assert not (root / "dist/NorthFlux_Security.zip").exists()
