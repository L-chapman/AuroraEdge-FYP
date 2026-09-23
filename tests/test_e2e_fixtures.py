"""The screenshot provenance notice must not execute scripts or alter assets."""

import importlib.util
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location(
    "northflux_e2e_fixtures", Path(__file__).resolve().parents[1] / "scripts/e2e_fixtures.py"
)
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def test_fixture_notice_preserves_compiled_assets_and_react_root():
    html = (
        '<html><head><link rel="stylesheet" href="/assets/index.css"></head>'
        '<body><div id="root"></div><script type="module" src="/assets/index.js"></script>'
        "</body></html>"
    )
    labelled = fixtures.label_fixture_html(html)
    assert labelled.replace(fixtures.FIXTURE_NOTICE, "") == html
    assert labelled.count(fixtures.FIXTURE_NOTICE) == 1
    assert "Fictional demonstration data — no live domain assessment." in labelled
    assert "<script" not in fixtures.FIXTURE_NOTICE
    assert "style=" not in fixtures.FIXTURE_NOTICE
    assert "<a " not in fixtures.FIXTURE_NOTICE


@pytest.mark.parametrize("html", ["<html></html>", "<body></body><body></body>"])
def test_fixture_notice_refuses_an_unexpected_document(html):
    with pytest.raises(ValueError, match="one React document body"):
        fixtures.label_fixture_html(html)
