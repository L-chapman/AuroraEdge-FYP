"""PDF export checks use synthetic records, never live domains or operator data."""

import asyncio
import json
from unittest.mock import Mock

from reportlab.platypus import Paragraph, Table

import app.dashboard as dashboard


def render_report(monkeypatch, record):
    database = Mock()
    database.get_domain_history.return_value = [record]
    monkeypatch.setattr(dashboard, "get_database", lambda: database)
    paragraphs, tables = [], []

    def paragraph(text, *args, **kwargs):
        result = Paragraph(text, *args, **kwargs)
        paragraphs.append(result)
        return result

    def table(*args, **kwargs):
        original_cells = [list(row) for row in args[0]]
        result = Table(*args, **kwargs)
        result._audit_cells = original_cells
        tables.append(result)
        return result

    monkeypatch.setattr("reportlab.platypus.Paragraph", paragraph)
    monkeypatch.setattr("reportlab.platypus.Table", table)
    response = dashboard.api_pdf_report("example.com")

    async def collect():
        return b"".join([chunk async for chunk in response.body_iterator])

    assert asyncio.run(collect()).startswith(b"%PDF-")
    return paragraphs, tables


def test_pdf_uses_full_saved_record_and_wraps_long_details(monkeypatch):
    record = {"score": 80, "grade": "B", "severity": "WARN", "spf_lookups": 0,
        "dkim_selectors": ", ".join(f"selector{i}.example.com" for i in range(30)),
        "raw_json": json.dumps({"bimi_present": True, "bimi_logo": "https://example.com/logo.svg"})}
    paragraphs, tables = render_report(monkeypatch, record)
    text = " ".join(item.getPlainText() for item in paragraphs)
    assert "https://example.com/logo.svg" in text
    assert "Lookups: 0" in text
    cells = tables[0]._audit_cells
    bimi_row = next(row for row in cells if row[0] == "BIMI")
    assert bimi_row[1] == "Found"
    assert all(isinstance(row[2], Paragraph) for row in cells[1:])


def test_incomplete_pdf_does_not_present_a_provisional_grade(monkeypatch):
    paragraphs, _ = render_report(monkeypatch, {"score": 99, "grade": "A+",
        "scan_incomplete": 1, "notes": "A DNS lookup timed out"})
    text = " ".join(item.getPlainText() for item in paragraphs)
    assert "Incomplete scan" in text
    assert "A DNS lookup timed out" in text
    assert "Grade: A+" not in text
    assert "99/100" not in text


def test_pdf_treats_saved_metadata_as_text_not_markup(monkeypatch):
    paragraphs, _ = render_report(monkeypatch, {"grade": "<b>not-a-grade</b>",
        "score": 10, "severity": "<broken", "scanned_at": "<broken"})
    text = " ".join(item.getPlainText() for item in paragraphs)
    assert "<b>not-a-grade</b>" in text
