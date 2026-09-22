"""Keep current and archived Markdown navigation usable after repository changes."""

import re
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
ROOT_DOCUMENTS = ("README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md")


def test_documentation_local_link_targets_exist():
    """Check inline links and images, including the preserved academic archive."""
    documents = [ROOT / name for name in ROOT_DOCUMENTS]
    assert (ROOT / "docs" / "INDEX.md").is_file(), "The test requires the documentation tree"
    documents.extend(sorted((ROOT / "docs").rglob("*.md")))
    broken = []
    for document in documents:
        assert document.is_file(), f"Missing root document: {document.name}"
        content = document.read_text(encoding="utf-8")
        # Code examples are not live Markdown navigation.
        content = re.sub(r"^```[^\n]*\n.*?^```[^\n]*$", "", content, flags=re.M | re.S)
        for match in re.finditer(r"!?\[[^\]\n]*\]\(([^)\n]+)\)", content):
            target = match.group(1).strip()
            if target.startswith("<"):
                target = target[1:].split(">", 1)[0]
            else:
                target = target.split(maxsplit=1)[0]
            parts = urlsplit(target)
            if parts.scheme or parts.netloc or not parts.path:
                continue
            path = unquote(parts.path)
            resolved = (ROOT / path.lstrip("/") if path.startswith("/") else document.parent / path)
            if not resolved.exists():
                broken.append(f"{document.relative_to(ROOT).as_posix()} -> {target}")
    assert not broken, "Broken local Markdown links:\n" + "\n".join(broken)
