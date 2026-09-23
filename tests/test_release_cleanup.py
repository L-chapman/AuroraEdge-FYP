"""Retired academic demo tools must stay out of the current product tree."""

from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("name", ["demo.ps1", "demo_prep.py", "lab_experiment.py"])
def test_retired_demo_script_is_not_shipped(name):
    assert not (ROOT / "scripts" / name).exists(), (
        f"Retired demo script scripts/{name} must remain in project history, "
        "not the current product release."
    )
