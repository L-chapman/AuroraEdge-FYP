"""Visible provenance for the isolated browser harness, never the normal app."""

FIXTURE_SERVER_ID = "northflux-disposable-fixtures-v1"
FIXTURE_NOTICE = (
    '<aside class="notice notice--warning" aria-label="Fictional demonstration">'
    "<strong>Fictional demonstration data — no live domain assessment.</strong> "
    "Isolated browser-test workspace; DNS results are synthetic and provider access is disabled."
    "</aside>"
)


def label_fixture_html(html: str) -> str:
    """Add a harness-only notice without altering React assets or relaxing CSP."""
    if html.count("<body>") != 1:
        raise ValueError("Expected one React document body for the fixture notice")
    return html.replace("<body>", "<body>" + FIXTURE_NOTICE, 1)
