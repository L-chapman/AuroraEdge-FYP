"""Prevent duplicate push and pull-request runs for the same feature change."""

from pathlib import Path
import re


def test_feature_branches_use_pull_request_checks_not_duplicate_push_checks():
    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    triggers = workflow.split('"on":', 1)[1].split("permissions:", 1)[0]
    pushes = triggers.split("  push:", 1)[1].split("  pull_request:", 1)[0]
    pull_requests = triggers.split("  pull_request:", 1)[1].split("  workflow_dispatch:", 1)[0]
    assert re.search(r"branches:\s*\[main,\s*master\]", pushes)
    assert re.search(r"branches:\s*\[main,\s*master\]", pull_requests)
    assert "codex/**" not in pushes
    assert "workflow_dispatch:" in triggers
