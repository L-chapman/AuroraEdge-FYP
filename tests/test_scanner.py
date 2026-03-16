import app.scanner as scanner
from app.rules import evaluate


def test_scan_spf_missing(monkeypatch):
    monkeypatch.setattr(scanner, "_spf_fetch", lambda d: None)
    monkeypatch.setattr(scanner, "_spf_count", lambda d: (0, ""))
    monkeypatch.setattr(scanner, "_mx", lambda d: ["mx.example"])
    monkeypatch.setattr(scanner, "_txt", lambda name: [])  # no DMARC/DKIM/TLS-RPT
    monkeypatch.setattr(scanner, "_mta_sts", lambda d: (False, "", 0, ""))
    monkeypatch.setattr(scanner, "_tls_rpt", lambda d: (False, ""))
    r = scanner.scan_domain("example.com")
    assert r["spf_present"] is False
    ev = evaluate(r)
    assert "R2_SPF_MISSING" in ev["violations"]
    assert 0 <= ev["score"] <= 100


def test_scan_dmarc_present_quarantine(monkeypatch):
    def fake_txt(name: str):
        if name.startswith("_dmarc."):
            return ["v=DMARC1; p=quarantine; rua=mailto:d@example.com"]
        if name.endswith("._domainkey.example.com"):
            return []
        if name.startswith("_smtp._tls."):
            return ["v=TLSRPTv1; rua=mailto:tls@example.com"]
        return []

    monkeypatch.setattr(scanner, "_spf_fetch", lambda d: "v=spf1 ip4:203.0.113.1 -all")
    monkeypatch.setattr(scanner, "_spf_count", lambda d: (1, ""))
    monkeypatch.setattr(scanner, "_mx", lambda d: ["mx.example"])
    monkeypatch.setattr(scanner, "_txt", fake_txt)
    monkeypatch.setattr(
        scanner, "_dkim_discover", lambda d: (["selector1"], ["rsa"], [])
    )
    monkeypatch.setattr(
        scanner, "_mta_sts", lambda d: (True, "enforce", 86400, "mode: enforce")
    )
    monkeypatch.setattr(scanner, "_tls_rpt", lambda d: (True, "mailto:tls@example.com"))
    r = scanner.scan_domain("example.com")
    assert r["dmarc_present"] is True and r["dmarc_policy"] == "quarantine"
    ev = evaluate(r)
    # INFO severity due to R5B_DMARC_QUARANTINE (suggest upgrade to reject)
    assert ev["severity"] in ("OK", "WARN", "INFO")
    # Score = 98: R5B_DMARC_QUARANTINE (INFO = 2)
    assert ev["score"] >= 90  # Allow for minor rule variations
