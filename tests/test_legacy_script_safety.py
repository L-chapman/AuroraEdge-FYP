"""Legacy educational scripts must not bypass the validated operator workflow."""

import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest


ROOT = Path(__file__).parents[1]


def load_script(name):
    spec = importlib.util.spec_from_file_location("northflux_test_" + name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("action", ["break_records", "restore_records"])
def test_demo_mutations_stop_before_credentials_or_network(monkeypatch, action):
    demo = load_script("demo_prep")
    credentials = Mock(side_effect=AssertionError("Must not read operator credentials"))
    monkeypatch.setattr(demo, "_get_cf_creds", credentials)
    with pytest.raises(RuntimeError, match="disabled"):
        getattr(demo, action)()
    credentials.assert_not_called()


@pytest.mark.parametrize("action,args", [("_delete_record", ("token", "zone", "id", "example.com")),
                                         ("_create_record", ("token", "zone", "example.com", "v=spf1 -all"))])
def test_demo_low_level_writes_are_disabled(monkeypatch, action, args):
    demo = load_script("demo_prep")
    for method in ("post", "put", "patch", "delete"):
        monkeypatch.setattr(demo.requests, method, Mock(side_effect=AssertionError("No network writes")))
    with pytest.raises(RuntimeError, match="disabled"):
        getattr(demo, action)(*args)


def test_demo_requires_explicit_dry_run_and_preview_never_reads_credentials(monkeypatch, capsys):
    demo = load_script("demo_prep")
    monkeypatch.setattr(demo, "_get_cf_creds", Mock(side_effect=AssertionError("No credential reads")))
    monkeypatch.setattr(demo.sys, "argv", ["demo_prep.py"])
    with pytest.raises(SystemExit) as error:
        demo.main()
    assert error.value.code != 0
    monkeypatch.setattr(demo.sys, "argv", ["demo_prep.py", "--dry-run"])
    demo.main()
    assert "No DNS records were changed" in capsys.readouterr().out


@pytest.mark.parametrize("action,args", [("run_full_experiment", ()), ("run_fix_test", ("SPF",))])
def test_lab_write_modes_are_quarantined(monkeypatch, action, args):
    lab = load_script("lab_experiment")
    monkeypatch.setattr(lab, "scan_domain", Mock(side_effect=AssertionError("No live scanner in write-mode test")))
    monkeypatch.setattr(lab.time, "sleep", Mock(side_effect=AssertionError("No propagation waits")))
    provider = Mock()
    experiment = lab.LabExperiment("example.com", provider)
    with pytest.raises(RuntimeError, match="disabled"):
        getattr(experiment, action)(*args)
    assert not provider.mock_calls


def test_lab_main_rejects_write_mode_before_loading_credentials(monkeypatch):
    lab = load_script("lab_experiment")
    provider = Mock(side_effect=AssertionError("No credentials before guard"))
    monkeypatch.setattr(lab, "get_cloudflare_client", provider)
    monkeypatch.setattr(lab.sys, "argv", ["lab_experiment.py", "--domain", "example.com"])
    with pytest.raises(SystemExit) as error:
        lab.main()
    assert error.value.code != 0
    provider.assert_not_called()


def test_lab_dry_run_does_not_load_provider_and_labels_incomplete(monkeypatch, capsys):
    lab = load_script("lab_experiment")
    monkeypatch.setattr(lab, "get_cloudflare_client", Mock(side_effect=AssertionError("No provider on dry run")))
    monkeypatch.setattr(lab, "scan_domain", lambda _: {"scan_incomplete": True, "notes": "DNS timed out"})
    monkeypatch.setattr(lab, "evaluate", lambda _: {"grade": "A+", "score": 99})
    monkeypatch.setattr(lab.sys, "argv", ["lab_experiment.py", "--domain", "example.com", "--dry-run"])
    lab.main()
    output = capsys.readouterr().out
    assert "Incomplete scan" in output
    assert "99" not in output
    assert "A+" not in output


def test_demo_menu_keeps_auth_and_uses_current_local_launcher():
    source = (ROOT / "scripts/demo.ps1").read_text(encoding="utf-8")
    launch = source.split("function Launch-Dashboard", 1)[1].split("function Open-TestHub", 1)[0]
    assert "$env:DASH_TOKEN" not in launch
    assert '"start.py"' in launch
    assert "uvicorn" not in launch
