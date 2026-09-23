"""Fallback-page evidence regressions; no browser, scans, or provider calls."""

import json
from pathlib import Path
import re
import shutil
import subprocess
from unittest.mock import MagicMock

import pytest

from app import dashboard


@pytest.fixture
def legacy_db(monkeypatch):
    db = MagicMock()
    db.get_managed_domains.return_value = []
    db.get_domain_history.return_value = []
    db.get_alerts.return_value = []
    db.get_alert_count.return_value = 0
    db.get_setting.side_effect = lambda key, default=None: default
    db.get_all_settings.return_value = {}
    monkeypatch.setattr(dashboard, "_spa_index_response", lambda: None)
    monkeypatch.setattr(dashboard, "HAS_DB", True)
    monkeypatch.setattr(dashboard, "get_database", lambda: db)
    monkeypatch.setattr(dashboard, "_latest_pair", lambda: (None, None))
    return db


def _text(response):
    return response.body.decode("utf-8")


def test_home_and_domains_do_not_score_incomplete_or_unscanned(legacy_db):
    legacy_db.get_managed_domains.return_value = [
        {"domain": "example.com", "last_scan_incomplete": True,
         "last_score": 99, "last_grade": "A+", "previous_score": 40},
        {"domain": "unscanned.example.com", "last_score": None, "last_grade": None},
    ]
    for response in (dashboard.home(), dashboard.domains_page()):
        html = _text(response)
        assert "Incomplete" in html
        assert "Not available" in html
        assert "99/100" not in html
        assert "0/100" not in html
    assert "All domains scoring well!" not in _text(dashboard.home())
    assert "Unknown" in _text(dashboard.home())


def test_home_average_preserves_real_zero_but_excludes_provisional(legacy_db):
    legacy_db.get_managed_domains.return_value = [
        {"domain": "example.com", "last_scan_incomplete": True,
         "last_score": 100, "last_grade": "A+"},
        {"domain": "complete.example.com", "last_score": 0, "last_grade": "F"},
    ]
    html = _text(dashboard.home())
    assert ">0/100" in html
    assert ">50</div>" not in html
    assert "100/100" not in html


def test_domain_detail_never_revives_csv_with_database_enabled(legacy_db, monkeypatch):
    monkeypatch.setattr(dashboard, "_latest_pair", lambda: (_ for _ in ()).throw(
        AssertionError("CSV must not be consulted when database is available")
    ))
    response = dashboard.domain_detail("example.com")
    assert response.status_code == 303


def test_domain_detail_uses_saved_evidence_and_masks_incomplete(legacy_db):
    legacy_db.get_domain_history.return_value = [{
        "domain": "example.com", "grade": None, "score": None,
        "scan_incomplete": 1, "severity": "ERROR",
        "raw_json": json.dumps({"bimi_present": True, "bimi_logo": "https://example.com/logo.svg",
                                "notes": "Lookup <timeout>"}),
    }]
    html = _text(dashboard.domain_detail("example.com"))
    assert "Incomplete" in html and "Not available" in html
    assert "https://example.com/logo.svg" in html
    assert "Lookup &lt;timeout&gt;" in html
    assert ">PASS<" not in html and "All checks passed" not in html
    assert 'id="autoFixBtn" disabled' in html


def test_legacy_batch_incomplete_and_error_are_not_green():
    html = dashboard._build_report_dashboard([
        {"domain": "example.com", "scan_incomplete": "True", "grade": "A+",
         "score": "99", "severity": "ERROR", "notes": "DNS <timeout>"},
        {"domain": "complete.example.com", "scan_incomplete": "False", "grade": "F",
         "score": "0", "severity": "CRITICAL"},
    ], Path("report.csv"), None, "<body></body>")
    assert "Incomplete" in html and "Not available" in html
    assert '>99<' not in html
    assert 'class="status-badge ok">ERROR' not in html
    assert 'class="status-badge ok">CRITICAL' not in html
    assert "DNS &lt;timeout&gt;" in html


def _node_script(script, payload):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the no-browser JavaScript checks")
    completed = subprocess.run(
        [node, "-e", script], input=json.dumps(payload), text=True, encoding="utf-8",
        capture_output=True, check=True, timeout=15,
    )
    return json.loads(completed.stdout)


@pytest.mark.parametrize("incomplete,violations", [(True, 0), (False, 2)])
def test_scan_result_empty_recommendations_do_not_mean_success(incomplete, violations):
    script = dashboard._test_js()
    script = script[script.index("function escapeDisplayData"):script.index("function getSeverityIcon")]
    html = _node_script("""const fs = require('fs');
const payload = JSON.parse(fs.readFileSync(0, 'utf8'));
const container = {innerHTML: '', querySelectorAll: () => [], querySelector: () => null};
const section = {style: {}, scrollIntoView: () => {}};
global.document = {getElementById: id => id === 'resultsContainer' ? container : section};
global.renderCheckEnhanced = () => '';
global.getSeverityIcon = () => '';
eval(payload.script);
displayResults({results: [payload.result]});
process.stdout.write(JSON.stringify(container.innerHTML));
""", {"script": script, "result": {
        "domain": "example.com", "scan": {"scan_incomplete": incomplete, "notes": "DNS <timeout>"},
        "evaluation": {"score": 95, "grade": "A+", "severity": "ERROR" if incomplete else "WARN",
                       "violation_count": violations}, "remediation": [],
    }})
    assert "All security checks passed" not in html
    if incomplete:
        assert "Incomplete" in html and "Not available" in html
        assert 'data-action="auto-fix"' not in html
        assert "DNS &lt;timeout&gt;" in html
        assert '>95<' not in html


@pytest.mark.parametrize("pct", ["0", "-1", "101", "0.5"])
def test_legacy_generator_keeps_ipv4_networks_and_checks_percentage(legacy_db, pct):
    html = _text(dashboard.generator_page())
    script = html[html.index("function genSPF"):html.index("function copyRec")]
    output = _node_script("""const fs = require('fs');
const payload = JSON.parse(fs.readFileSync(0, 'utf8'));
const outputs = {};
global.document = {getElementById: id => ({value: payload.values[id] || ''})};
global.setGeneratedOutput = (id, value) => {outputs[id] = value};
eval(payload.script);
genSPF(); genDMARC();
process.stdout.write(JSON.stringify(outputs));
""", {"script": script, "values": {
        "spf_domain": "example.com", "spf_ips": "198.51.100.0/24, 2001:db8::/32",
        "spf_all": "-all", "dmarc_domain": "example.com", "dmarc_policy": "none",
        "dmarc_pct": pct,
    }})
    assert "ip4:198.51.100.0/24" in output["spf_out"]
    assert "ip6:2001:db8::/32" in output["spf_out"]
    if pct == "0":
        assert "pct=0" in output["dmarc_out"]
    else:
        assert "Enter a whole percentage from 0 to 100" in output["dmarc_out"]
    assert "RFC-compliant" not in html
    assert "Draft" in html and "RFC 9989" in html


def test_legacy_generated_scripts_parse_without_browser(legacy_db):
    legacy_db.get_domain_history.return_value = [
        {"domain": "example.com", "score": 0, "grade": "F", "scanned_at": "2026-09-01"},
        {"domain": "example.com", "score": 99, "grade": "A+", "scan_incomplete": True},
    ]
    pages = [dashboard.home(), dashboard.domain_detail("example.com"),
             dashboard.domains_page(), dashboard.test_hub(), dashboard.generator_page(),
             dashboard.settings_page()]
    scripts = [script for page in pages for script in re.findall(
        r"<script(?:\s[^>]*)?>(.*?)</script>", _text(page), re.S
    ) if script.strip()]
    assert _node_script("""const fs = require('fs');
const payload = JSON.parse(fs.readFileSync(0, 'utf8'));
payload.scripts.forEach(script => new Function(script));
process.stdout.write(JSON.stringify(payload.scripts.length));
""", {"scripts": scripts}) >= 12


def test_domain_history_masks_provisional_score_and_presence_is_not_pass(legacy_db):
    legacy_db.get_domain_history.return_value = [
        {"domain": "example.com", "score": 0, "grade": "F", "spf_present": True,
         "scanned_at": "2026-09-02"},
        {"domain": "example.com", "score": 99, "grade": "A+", "scan_incomplete": True,
         "scanned_at": "2026-09-01"},
    ]
    html = _text(dashboard.domain_detail("example.com"))
    assert "Record found" in html and ">PASS<" not in html
    assert "data: [null, 0]" in html
    assert ">99<" not in html


def test_legacy_settings_distinguish_stored_credentials_from_verified_access(legacy_db):
    legacy_db.get_all_settings.return_value = {
        "cf_api_token": "private-token-not-for-rendering", "cf_zone_id": "a" * 32,
    }
    html = _text(dashboard.settings_page())
    visible = re.sub(r"<script(?:\s[^>]*)?>.*?</script>", "", html, flags=re.S)
    assert "Configured, not verified" in visible
    assert '>Connected</span>' not in visible
    assert "never leave this server" not in visible
    assert "sent to Cloudflare over HTTPS" in visible
    assert "plaintext" in visible and "runtime environment" in visible
    assert "private-token-not-for-rendering" not in html


def test_legacy_demo_guide_has_no_retired_mutation_controls(legacy_db, monkeypatch):
    monkeypatch.setenv("NORTHFLUX_DEMO_MODE", "true")
    html = _text(dashboard.test_hub())
    visible = re.sub(r"<script(?:\s[^>]*)?>.*?</script>", "", html, flags=re.S)
    assert "Live-DNS reset and restore are retired" in visible
    assert 'id="resetDemoBtn"' not in visible
    assert 'id="restoreDemoBtn"' not in visible
    assert "intentionally weakened" not in visible
    assert "to test Auto-Fix" not in visible
    assert "(Auto-Fix Demo)" not in html


def test_legacy_settings_describe_automatic_remediation_as_compatibility_only(legacy_db):
    html = _text(dashboard.settings_page())
    assert "Current generated recommendations require manual review" in html
    assert "monitoring may change authorised Cloudflare DNS zones" not in html
    assert "one-click DNS auto-fix" not in html
