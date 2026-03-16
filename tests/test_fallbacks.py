import app.scanner as scanner


def test_scanner_handles_missing_dns_and_requests(monkeypatch):
    # Simulate environment where dns and requests imports failed
    monkeypatch.setattr(scanner, "dns", None)
    monkeypatch.setattr(scanner, "requests", None)

    # Should not raise and should return default-not-present values
    r = scanner.scan_domain("example.com")
    assert isinstance(r, dict)
    # With dns missing, MX/SPF/DMARC/DKIM/TLS checks should be treated as not present
    assert r.get("mx_present") is False
    assert r.get("spf_present") is False
    assert r.get("dmarc_present") is False
    assert r.get("dkim_present") is False
    assert r.get("mta_sts_present") is False
    assert r.get("tls_rpt_present") is False
