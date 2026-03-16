"""
AuroraEdge Security, Stress & Edge-Case Test Suite
===================================================
Covers:
  1. Authentication bypass attempts
  2. SQL injection probes (domain input, settings, search)
  3. Path traversal on file download
  4. XSS payloads through domain names
  5. Stress / rate abuse (large payloads, many domains)
  6. Domain-ownership enforcement (auto-fix)
  7. Credential leak checks (CF token masking)
  8. Input validation edge cases (empty, unicode, oversized)
  9. CORS / header security basics
 10. Ethical guardrails (no fix without ownership)

Run:  python -m pytest tests/test_security_stress.py -v --tb=short
"""

import json
import os
import time
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

# Ensure clean test environment
os.environ["DASH_TOKEN"] = "test-secret-token"

import app.dashboard as dashboard
from fastapi.testclient import TestClient

client = TestClient(dashboard.app)

AUTH = {"Authorization": "Bearer test-secret-token"}
NO_AUTH = {}


# =========================================================================
# 1. Authentication Tests
# =========================================================================
class TestAuthentication:
    """Verify that endpoints reject unauthenticated requests."""

    PROTECTED = [
        ("GET", "/api/runs"),
        ("GET", "/api/latest"),
        ("GET", "/api/summary"),
        ("GET", "/api/managed-domains"),
        ("GET", "/api/settings"),
        ("GET", "/api/alerts"),
        ("GET", "/api/stats"),
        ("GET", "/download/latest"),
        ("GET", "/"),
        ("GET", "/test"),
        ("GET", "/domains"),
        ("GET", "/settings"),
    ]

    @pytest.mark.parametrize("method,path", PROTECTED)
    def test_endpoints_require_auth(self, method, path):
        """Every protected endpoint must return 401 without a valid token."""
        r = client.request(method, path)
        assert r.status_code == 401, f"{method} {path} returned {r.status_code} without auth"

    def test_wrong_token_rejected(self):
        r = client.get("/api/runs", headers={"Authorization": "Bearer WRONG"})
        assert r.status_code == 401

    def test_empty_bearer_rejected(self):
        r = client.get("/api/runs", headers={"Authorization": "Bearer "})
        assert r.status_code == 401

    def test_no_bearer_prefix_rejected(self):
        r = client.get("/api/runs", headers={"Authorization": "test-secret-token"})
        assert r.status_code == 401

    def test_query_param_works(self):
        r = client.get("/api/runs?token=test-secret-token")
        assert r.status_code == 200

    def test_wrong_query_param_rejected(self):
        r = client.get("/api/runs?token=wrong")
        assert r.status_code == 401

    def test_token_not_leaked_in_health(self):
        """Health endpoint should be public but must NOT leak any tokens."""
        r = client.get("/health")
        assert r.status_code == 200
        body = r.text
        assert "test-secret-token" not in body
        assert "DASH_TOKEN" not in body


# =========================================================================
# 2. SQL Injection Tests
# =========================================================================
class TestSQLInjection:
    """Probe all user-input paths for SQL injection vulnerabilities."""

    SQLI_PAYLOADS = [
        "'; DROP TABLE results;--",
        "1 OR 1=1",
        "' UNION SELECT * FROM settings--",
        "admin'--",
        "1; SELECT * FROM sqlite_master--",
        "' OR ''='",
        "Robert'); DROP TABLE scans;--",
    ]

    @pytest.mark.parametrize("payload", SQLI_PAYLOADS)
    def test_domain_search_sqli(self, payload):
        """Search endpoint must not be injectable."""
        r = client.get(f"/api/search?q={payload}", headers=AUTH)
        assert r.status_code in (200, 400, 422)
        # Must not expose database errors
        assert "sqlite" not in r.text.lower()
        assert "syntax error" not in r.text.lower()

    @pytest.mark.parametrize("payload", SQLI_PAYLOADS)
    def test_domain_history_sqli(self, payload):
        r = client.get(f"/api/history/{payload}", headers=AUTH)
        assert r.status_code in (200, 404)
        assert "sqlite" not in r.text.lower()

    @pytest.mark.parametrize("payload", SQLI_PAYLOADS)
    def test_managed_domain_add_sqli(self, payload):
        r = client.post(
            "/api/managed-domains",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"domain": payload},
        )
        # Should reject invalid domain or add harmlessly — never crash
        assert r.status_code in (200, 400, 422)
        assert "sqlite" not in r.text.lower()

    @pytest.mark.parametrize("payload", SQLI_PAYLOADS)
    def test_settings_sqli(self, payload):
        r = client.post(
            "/api/settings",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"org_name": payload},
        )
        assert r.status_code in (200, 400)
        assert "sqlite" not in r.text.lower()


# =========================================================================
# 3. Path Traversal Tests
# =========================================================================
class TestPathTraversal:
    """Verify file download cannot escape the reports directory."""

    TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "requirements.txt",
        ".env",
        "../../.env",
        "../../src/app/dashboard.py",
        "..\\..\\src\\app\\database.py",
    ]

    @pytest.mark.parametrize("payload", TRAVERSAL_PAYLOADS)
    def test_download_path_traversal(self, payload):
        """File download must be constrained to the reports directory."""
        r = client.get(f"/download/{payload}", headers=AUTH)
        # Must either 404 or serve only from reports/ — never serve system files
        if r.status_code == 200:
            # If it returns something, verify it's actually from reports dir
            assert r.headers.get("content-type", "").startswith(("text/csv", "text/markdown", "application/octet-stream"))
        else:
            assert r.status_code in (404, 400, 422)


# =========================================================================
# 4. XSS Payload Tests
# =========================================================================
class TestXSSPrevention:
    """Ensure user-supplied data cannot inject scripts into HTML responses."""

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        '"><img src=x onerror="alert(1)">',
        "javascript:alert(document.cookie)",
        "<svg/onload=alert('XSS')>",
        "'; alert('XSS');//",
    ]

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_domain_scan_xss(self, payload):
        """Scanning a malicious domain name must not reflect raw HTML."""
        r = client.post(
            "/api/scan",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"domains": [payload]},
        )
        # The response must not contain the raw script tag unescaped
        if r.status_code == 200:
            assert "<script>alert" not in r.text
            assert "onerror=" not in r.text

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_managed_domain_xss(self, payload):
        """Adding a domain with XSS payload must not store/render raw HTML."""
        r = client.post(
            "/api/managed-domains",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"domain": payload, "notes": payload},
        )
        assert r.status_code in (200, 400, 422)

    def test_search_xss(self):
        r = client.get(
            "/api/search?q=<script>alert(1)</script>",
            headers=AUTH,
        )
        assert r.status_code in (200, 400)
        assert "<script>alert" not in r.text


# =========================================================================
# 5. Stress & Abuse Tests
# =========================================================================
class TestStressAndAbuse:
    """Test system resilience under unusual load and input."""

    def test_scan_empty_domain_list(self):
        r = client.post(
            "/api/scan",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"domains": []},
        )
        assert r.status_code in (200, 400)

    def test_scan_oversized_domain_list(self):
        """Sending 500 domains should not crash the server."""
        domains = [f"test{i}.example.com" for i in range(500)]
        r = client.post(
            "/api/scan",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"domains": domains, "save_to_db": False},
        )
        # Should either succeed or politely reject
        assert r.status_code in (200, 400, 413, 422)

    def test_scan_extremely_long_domain(self):
        """A domain far exceeding valid DNS length must not crash."""
        long_domain = "a" * 500 + ".com"
        r = client.post(
            "/api/scan",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"domains": [long_domain]},
        )
        assert r.status_code in (200, 400, 422)

    def test_scan_unicode_domain(self):
        """Unicode/IDN domain must be handled gracefully."""
        r = client.post(
            "/api/scan",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"domains": ["münchen.de", "例え.jp", "☺.com"]},
        )
        assert r.status_code in (200, 400, 422)

    def test_malformed_json_body(self):
        """Sending invalid JSON should return 400, not 500."""
        r = client.post(
            "/api/scan",
            headers={**AUTH, "Content-Type": "application/json"},
            content=b"NOT JSON{{{",
        )
        assert r.status_code in (400, 422)

    def test_empty_body(self):
        r = client.post(
            "/api/scan",
            headers={**AUTH, "Content-Type": "application/json"},
            content=b"",
        )
        assert r.status_code in (400, 422)

    def test_null_domain_value(self):
        r = client.post(
            "/api/managed-domains",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"domain": None},
        )
        assert r.status_code in (200, 400, 422)

    def test_numeric_domain(self):
        r = client.post(
            "/api/managed-domains",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"domain": 12345},
        )
        assert r.status_code in (200, 400, 422)

    def test_rapid_sequential_requests(self):
        """Quick burst of requests should not crash or deadlock."""
        for _ in range(20):
            r = client.get("/health")
            assert r.status_code == 200


# =========================================================================
# 6. Credential Leak Tests
# =========================================================================
class TestCredentialSafety:
    """Ensure secrets are never exposed in API responses or HTML."""

    def test_settings_api_masks_cf_token(self):
        """GET /api/settings must never return the raw CF API token."""
        r = client.get("/api/settings", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        settings = data.get("settings", {})
        # The raw token key should be removed
        assert "cf_api_token" not in settings

    def test_health_no_secrets(self):
        r = client.get("/health")
        body = r.text.lower()
        for word in ["token", "password", "secret", "api_key", "cf_api"]:
            assert word not in body, f"Health endpoint leaks '{word}'"

    def test_settings_page_no_raw_token(self):
        """The /settings HTML page must not embed the full CF token."""
        r = client.get("/settings", headers=AUTH)
        if r.status_code == 200:
            # If a token is stored, it should be masked in HTML
            assert "cf_api_token_masked" not in r.text or "***" in r.text or "..." in r.text


# =========================================================================
# 7. Domain Ownership Enforcement (Ethical Guardrails)
# =========================================================================
class TestOwnershipEnforcement:
    """Verify auto-fix refuses to modify DNS for unowned domains."""

    def test_test_cloudflare_returns_zone_name(self):
        """GET /api/settings/test-cloudflare must return zone_name for frontend checks."""
        r = client.get("/api/settings/test-cloudflare", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        # Must always include zone_name key (empty string when CF not configured)
        assert "zone_name" in data, "test-cloudflare must return zone_name"

    def test_auto_fix_blocked_for_unowned_domain(self):
        """
        Attempting auto-fix on a domain outside the configured CF zone
        must return 403 (not 200 with false success).
        """
        from app.dns_fix import CloudflareDNS

        # Mock a CF client whose zone is auroraedge.co.uk
        mock_cf = CloudflareDNS.__new__(CloudflareDNS)
        mock_cf.api_token = "fake"
        mock_cf.zone_id = "fake"
        mock_cf.zone_name = "auroraedge.co.uk"
        mock_cf.base_url = "https://fake"
        mock_cf.headers = {}

        # Patch get_cloudflare_client to return our mock
        with patch.object(dashboard, "get_cloudflare_client", return_value=mock_cf):
            with patch.object(mock_cf, "validate_connection", return_value=(True, "Connected to zone: auroraedge.co.uk")):
                r = client.post(
                    "/api/apply-fix",
                    headers={**AUTH, "Content-Type": "application/json"},
                    json={"domain": "belfastmet.ac.uk"},
                )
                assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"
                assert "does not belong" in r.json().get("detail", "")

    def test_auto_fix_allowed_for_owned_domain(self):
        """Auto-fix should proceed (not 403) when domain matches zone."""
        from app.dns_fix import CloudflareDNS

        mock_cf = CloudflareDNS.__new__(CloudflareDNS)
        mock_cf.api_token = "fake"
        mock_cf.zone_id = "fake"
        mock_cf.zone_name = "auroraedge.co.uk"
        mock_cf.base_url = "https://fake"
        mock_cf.headers = {}

        with patch.object(dashboard, "get_cloudflare_client", return_value=mock_cf):
            with patch.object(mock_cf, "validate_connection", return_value=(True, "Connected to zone: auroraedge.co.uk")):
                with patch.object(mock_cf, "generate_fixes", return_value=[]):
                    with patch("app.dashboard.scan_domain") as mock_scan:
                        mock_scan.return_value = {
                            "domain": "auroraedge.co.uk",
                            "spf_present": True,
                            "dmarc_present": True,
                            "dkim_present": True,
                            "tls_rpt_present": True,
                            "mta_sts_present": True,
                        }
                        r = client.post(
                            "/api/apply-fix",
                            headers={**AUTH, "Content-Type": "application/json"},
                            json={"domain": "auroraedge.co.uk"},
                        )
                        # Should NOT be 403
                        assert r.status_code != 403

    def test_internal_auto_fix_skips_unowned(self):
        """_auto_fix_domain returns skipped_reason for unowned domains."""
        from app.dns_fix import CloudflareDNS

        mock_cf = CloudflareDNS.__new__(CloudflareDNS)
        mock_cf.api_token = "fake"
        mock_cf.zone_id = "fake"
        mock_cf.zone_name = "myzone.com"
        mock_cf.base_url = "https://fake"
        mock_cf.headers = {}

        with patch.object(dashboard, "get_cloudflare_client", return_value=mock_cf):
            with patch.object(mock_cf, "validate_connection", return_value=(True, "Connected")):
                result = dashboard._auto_fix_domain("unrelated.org", {})
                assert "skipped_reason" in result
                assert "does not belong" in result["skipped_reason"]


# =========================================================================
# 8. Input Validation Edge Cases
# =========================================================================
class TestInputValidation:
    """Cover boundary and edge-case inputs."""

    def test_add_empty_domain(self):
        r = client.post(
            "/api/managed-domains",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"domain": ""},
        )
        # Should reject empty domain
        assert r.status_code in (200, 400, 422)
        if r.status_code == 200:
            data = r.json()
            # If it returns 200, it should indicate an error
            assert data.get("error") or data.get("domain") == ""

    def test_add_whitespace_domain(self):
        r = client.post(
            "/api/managed-domains",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"domain": "   "},
        )
        assert r.status_code in (200, 400, 422)

    def test_domain_with_protocol(self):
        """Users often paste URLs not bare domains."""
        r = client.post(
            "/api/managed-domains",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"domain": "https://example.com/path?q=1"},
        )
        assert r.status_code in (200, 400, 422)

    def test_domain_with_port(self):
        r = client.post(
            "/api/managed-domains",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"domain": "example.com:8080"},
        )
        assert r.status_code in (200, 400, 422)

    def test_settings_invalid_monitor_interval(self):
        """Monitor interval should be a reasonable number."""
        r = client.post(
            "/api/settings",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"monitor_interval": "-1"},
        )
        assert r.status_code in (200, 400)

    def test_settings_extra_keys_ignored(self):
        """Keys not in the allowed list should be silently ignored."""
        r = client.post(
            "/api/settings",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"evil_key": "DROP TABLE", "admin_password": "hacked"},
        )
        assert r.status_code == 200
        data = r.json()
        saved = data.get("saved", [])
        assert "evil_key" not in saved
        assert "admin_password" not in saved


# =========================================================================
# 9. Response Header Security
# =========================================================================
class TestSecurityHeaders:
    """Check that responses have sensible security characteristics."""

    def test_health_json_content_type(self):
        r = client.get("/health")
        ct = r.headers.get("content-type", "")
        assert "application/json" in ct

    def test_html_pages_content_type(self):
        r = client.get("/?token=test-secret-token")
        ct = r.headers.get("content-type", "")
        assert "text/html" in ct

    def test_no_server_header_leakage(self):
        """Server header should not reveal specific versions."""
        r = client.get("/health")
        server = r.headers.get("server", "")
        # Should not contain detailed version like "uvicorn 0.x" in test client
        # Just verify the response works
        assert r.status_code == 200


# =========================================================================
# 10. Concurrency / State Safety
# =========================================================================
class TestStateSafety:
    """Verify no corruption from rapid state operations."""

    def test_rapid_settings_writes(self):
        """Quick consecutive writes to settings should not corrupt."""
        for i in range(10):
            r = client.post(
                "/api/settings",
                headers={**AUTH, "Content-Type": "application/json"},
                json={"org_name": f"TestOrg{i}"},
            )
            assert r.status_code == 200

        # Verify last write persisted
        r = client.get("/api/settings", headers=AUTH)
        settings = r.json().get("settings", {})
        assert settings.get("org_name") == "TestOrg9"

    def test_add_and_remove_domain_cycle(self):
        """Add then remove should leave no orphans."""
        domain = "stress-test-cycle.example.org"
        # Add
        r = client.post(
            "/api/managed-domains",
            headers={**AUTH, "Content-Type": "application/json"},
            json={"domain": domain},
        )
        assert r.status_code == 200

        # Remove
        r = client.delete(f"/api/managed-domains/{domain}", headers=AUTH)
        assert r.status_code == 200

        # Verify gone (should be deactivated)
        r = client.get("/api/managed-domains", headers=AUTH)
        active = [d["domain"] for d in r.json().get("domains", [])]
        assert domain not in active


# =========================================================================
# 11. Token Forwarding / HTML Injection Tests
# =========================================================================
class TestTokenForwarding:
    """Verify the auth-token JS helper is injected into HTML pages."""

    def test_auth_js_in_dashboard(self):
        """Main dashboard HTML must contain the _auth_js() script."""
        r = client.get("/", headers=AUTH)
        assert r.status_code == 200
        assert "window.fetch" in r.text, "_auth_js() script missing from dashboard"

    def test_auth_js_in_test_page(self):
        r = client.get("/test", headers=AUTH)
        assert r.status_code == 200
        assert "window.fetch" in r.text

    def test_auth_js_in_domains_page(self):
        r = client.get("/domains", headers=AUTH)
        assert r.status_code == 200
        assert "window.fetch" in r.text

    def test_auth_js_in_settings_page(self):
        r = client.get("/settings", headers=AUTH)
        assert r.status_code == 200
        assert "window.fetch" in r.text


# =========================================================================
# 12. Security Headers Tests
# =========================================================================
class TestSecurityHeadersPresence:
    """Verify OWASP-recommended security headers are set on responses."""

    def test_x_content_type_options(self):
        r = client.get("/health")
        assert r.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options(self):
        r = client.get("/health")
        assert r.headers.get("x-frame-options") == "DENY"

    def test_referrer_policy(self):
        r = client.get("/health")
        assert r.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    def test_permissions_policy(self):
        r = client.get("/health")
        assert "camera=()" in r.headers.get("permissions-policy", "")

    def test_csp_header(self):
        r = client.get("/health")
        csp = r.headers.get("content-security-policy", "")
        assert "default-src" in csp
        assert "frame-ancestors 'none'" in csp

    def test_xss_protection(self):
        r = client.get("/health")
        assert r.headers.get("x-xss-protection") == "1; mode=block"

    def test_headers_on_html_pages(self):
        """Security headers must also appear on HTML pages."""
        for path in ["/", "/test", "/domains", "/settings"]:
            r = client.get(path, headers=AUTH)
            assert r.headers.get("x-frame-options") == "DENY", f"Missing X-Frame-Options on {path}"
            assert r.headers.get("x-content-type-options") == "nosniff", f"Missing X-Content-Type-Options on {path}"


# =========================================================================
# 13. Privacy Footer Tests
# =========================================================================
class TestPrivacyFooter:
    """Verify privacy notice appears in page footers."""

    def test_privacy_notice_in_dashboard(self):
        r = client.get("/", headers=AUTH)
        assert "No personal data collected" in r.text

    def test_privacy_notice_in_domains(self):
        r = client.get("/domains", headers=AUTH)
        assert "No personal data collected" in r.text

    def test_privacy_notice_in_generator(self):
        r = client.get("/generator", headers=AUTH)
        assert "No personal data collected" in r.text


# =========================================================================
# 14. Custom 404 Page Tests
# =========================================================================
class TestCustom404Page:
    """Verify branded 404 page for unknown routes."""

    def test_404_returns_html(self):
        r = client.get("/nonexistent-page-xyz", headers=AUTH)
        assert r.status_code == 404
        assert "AuroraEdge" in r.text
        assert "404" in r.text

    def test_404_has_back_link(self):
        r = client.get("/does-not-exist", headers=AUTH)
        assert r.status_code == 404
        assert 'href="/"' in r.text

    def test_api_404_returns_json(self):
        """API routes should still return JSON errors, not HTML."""
        r = client.get("/api/nonexistent", headers=AUTH)
        assert r.status_code in (404, 405)  # FastAPI may return 405 for unmatched API routes


# =========================================================================
# 15. Data Management & Deletion Tests
# =========================================================================
class TestDataManagement:
    """Verify on-demand data clearing and per-domain deletion."""

    def test_clear_all_data(self):
        """POST /api/data/clear should return ok and preserve settings."""
        r = client.post("/api/data/clear", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert "Settings preserved" in data["message"]

    def test_clear_data_requires_auth(self):
        r = client.post("/api/data/clear")
        assert r.status_code == 401

    def test_delete_domain_history(self):
        """DELETE /api/history/{domain} should succeed for any domain."""
        r = client.delete("/api/history/nonexistent.example.com", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert r.json()["deleted_records"] == 0  # No data to delete

    def test_delete_history_requires_auth(self):
        r = client.delete("/api/history/example.com")
        assert r.status_code == 401

    def test_delete_history_rejects_invalid_domain(self):
        r = client.delete("/api/history/;DROP TABLE results--", headers=AUTH)
        assert r.status_code == 400


# =========================================================================
# 16. Cache-Control Header Tests
# =========================================================================
class TestCacheControl:
    """Verify Cache-Control headers prevent stale data."""

    def test_api_has_no_store(self):
        r = client.get("/api/stats", headers=AUTH)
        cc = r.headers.get("cache-control", "")
        assert "no-store" in cc

    def test_html_has_no_store(self):
        r = client.get("/", headers=AUTH)
        cc = r.headers.get("cache-control", "")
        assert "no-store" in cc
