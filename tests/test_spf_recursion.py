import app.scanner as scanner


def test_spf_count_recursive(monkeypatch):
    # Simulate _spf_fetch returning different spf records per domain
    spf_map = {
        "example.com": "v=spf1 include:spf1.example -all",
        "spf1.example": "v=spf1 include:spf2.example include:spf3.example -all",
        "spf2.example": "v=spf1 a mx -all",
        "spf3.example": "v=spf1 include:spf4.example -all",
        "spf4.example": "v=spf1 a:mail.example -all",
    }

    def fake_fetch(d):
        return spf_map.get(d)

    monkeypatch.setattr(scanner, "_spf_fetch", fake_fetch)
    count, note = scanner._spf_count("example.com")
    # Count should reflect includes and mechanisms; ensure it's > 0 and sensible
    assert count >= 4
    assert note in ("", "spf_fetch_cap_hit")
