"""AuroraEdge Full System Audit — checks pages, APIs, headers, cache, errors."""
import httpx
import re
import time
import json

BASE = "http://127.0.0.1:8080"
time.sleep(2)
client = httpx.Client(base_url=BASE, timeout=30, follow_redirects=True)
issues = []

print("=" * 60)
print("   AURORAEDGE COMPREHENSIVE SYSTEM AUDIT")
print("=" * 60)

# ── 1. PAGE STATUS + HTML STRUCTURE ──────────────────────────────
print("\n[1] PAGE STATUS & HTML STRUCTURE")
pages = {
    "/": "Dashboard",
    "/test": "Test Hub",
    "/settings": "Settings",
    "/generator": "Generator",
    "/domains": "Domains",
}
for path, name in pages.items():
    r = client.get(path)
    html = r.text
    checks = []
    if "<!DOCTYPE html>" not in html[:50]:
        checks.append("no DOCTYPE")
    if "charset" not in html[:500].lower():
        checks.append("no charset")
    if "viewport" not in html[:500]:
        checks.append("no viewport")
    if "<title>" not in html:
        checks.append("no title")
    if "</body>" not in html:
        checks.append("no </body>")
    if "</html>" not in html:
        checks.append("no </html>")
    if "top-nav" not in html:
        checks.append("no nav")
    if "<footer>" not in html:
        checks.append("no footer")
    unclosed = html.count("<div") - html.count("</div>")
    if abs(unclosed) > 2:
        checks.append(f"div mismatch ({unclosed})")
    if checks:
        issues.extend([f"{name}: {c}" for c in checks])
        print(f"  [{r.status_code}] {name:12} WARN: {', '.join(checks)}")
    else:
        print(f"  [{r.status_code}] {name:12} OK - HTML valid")

# ── 2. API ENDPOINTS ─────────────────────────────────────────────
print("\n[2] API ENDPOINTS")
apis = [
    "/health",
    "/api/runs",
    "/api/latest",
    "/api/summary",
    "/api/stats",
    "/api/explanations/all",
    "/api/tools/comparison",
    "/api/managed-domains",
    "/api/settings",
    "/api/alerts",
    "/api/fix-status",
]
for path in apis:
    r = client.get(path)
    try:
        r.json()
        ok = True
    except Exception:
        ok = False
    sym = "OK" if r.status_code == 200 and ok else "FAIL"
    print(f"  [{r.status_code}] {path:35} {sym}")
    if r.status_code != 200:
        issues.append(f"API {path} returned {r.status_code}")
    elif not ok:
        issues.append(f"API {path} invalid JSON")

# ── 3. SECURITY HEADERS ─────────────────────────────────────────
print("\n[3] SECURITY HEADERS")
r = client.get("/")
headers_to_check = [
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Cache-Control",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Content-Security-Policy",
]
for h in headers_to_check:
    v = r.headers.get(h, "")
    if v:
        print(f"  [OK]   {h}: {v[:70]}")
    else:
        print(f"  [MISS] {h}")
        issues.append(f"Missing header: {h}")

# ── 4. CACHE CONTROL ────────────────────────────────────────────
print("\n[4] CACHE CONTROL")
for p in ["/", "/api/settings", "/health"]:
    r = client.get(p)
    cc = r.headers.get("Cache-Control", "(none)")
    sym = "OK" if "no-store" in cc else "WARN"
    print(f"  [{sym}] {p:30} {cc}")
    if sym == "WARN" and p.startswith("/api"):
        issues.append(f"Missing no-store on {p}")

# ── 5. ERROR HANDLING ────────────────────────────────────────────
print("\n[5] ERROR HANDLING")
r = client.get("/nonexistent-page", follow_redirects=False)
ok_404 = r.status_code == 404 and "404" in r.text
print(f"  HTML 404: status={r.status_code}, branded={'404' in r.text}")
if not ok_404:
    issues.append("HTML 404 page not working")

r = client.get("/api/nonexistent")
try:
    d = r.json()
    api_404_ok = r.status_code == 404 and "detail" in d
    print(f"  API 404:  status={r.status_code}, json_detail={'detail' in d}")
except Exception:
    api_404_ok = False
    print(f"  API 404:  status={r.status_code}, NOT JSON")
if not api_404_ok:
    issues.append("API 404 not returning proper JSON")

# ── 6. VISUAL: CSS VARIABLE CONSISTENCY ──────────────────────────
print("\n[6] CSS VARIABLE CONSISTENCY")
r = client.get("/")
html = r.text
used = set(re.findall(r"var\(--([a-z0-9-]+)\)", html))
defined = set(re.findall(r"--([a-z0-9-]+)\s*:", html))
undefined = used - defined
# Filter out variables defined in linked stylesheets we can't see
# (all ours are inline so should be fine)
if undefined:
    # Some may be defined in sub-pages; check the generator CSS vars too
    r2 = client.get("/generator")
    r3 = client.get("/settings")
    extra_defined = set(re.findall(r"--([a-z0-9-]+)\s*:", r2.text + r3.text))
    truly_undefined = undefined - extra_defined
    if truly_undefined:
        print(f"  [WARN] Undefined CSS vars: {truly_undefined}")
        for v in truly_undefined:
            issues.append(f"CSS var --{v} used but not defined")
    else:
        print(f"  [OK]   All CSS variables defined")
else:
    print(f"  [OK]   All CSS variables defined")

# ── 7. LINK INTEGRITY ───────────────────────────────────────────
print("\n[7] INTERNAL LINK INTEGRITY")
r = client.get("/")
html = r.text
links = set(re.findall(r'href="(/[^"]*?)"', html))
# Check each internal link
for link in sorted(links):
    if link.startswith("/download") or link.startswith("/domain/") or "{" in link:
        continue  # Skip dynamic/template links
    try:
        lr = client.get(link, follow_redirects=False)
        if lr.status_code in (200, 301, 302, 303, 307, 308):
            pass  # OK
        else:
            print(f"  [WARN] {link} -> {lr.status_code}")
            issues.append(f"Broken link on dashboard: {link} -> {lr.status_code}")
    except Exception as e:
        print(f"  [ERR]  {link} -> {e}")
print(f"  Checked {len(links)} internal links")

# ── 8. SCAN API STRESS TEST ─────────────────────────────────────
print("\n[8] SCAN API VALIDATION")
# Test with invalid input
test_cases = [
    ({"domains": []}, "empty domains"),
    ({"domains": ["<script>alert(1)</script>"]}, "XSS payload"),
    ({"domains": ["valid.com"], "save_to_db": True}, "valid domain"),
    ({}, "no domains key"),
    ("not json", "invalid body"),
]
for body, desc in test_cases:
    try:
        if isinstance(body, str):
            r = client.post("/api/scan", content=body, headers={"Content-Type": "application/json"})
        else:
            r = client.post("/api/scan", json=body)
        status = r.status_code
        print(f"  [{status}] {desc:30}")
        if desc == "valid domain" and status != 200:
            issues.append(f"Scan API rejected valid domain: status {status}")
        if desc == "XSS payload" and status == 200:
            data = r.json()
            results = data.get("results", [])
            if results and "<script>" in json.dumps(results):
                issues.append("XSS payload reflected in scan results!")
    except Exception as e:
        print(f"  [ERR] {desc:30} {e}")

# ── 9. FONT LOADING ────────────────────────────────────────────
print("\n[9] EXTERNAL RESOURCE CHECK")
r = client.get("/")
html = r.text
if "fonts.googleapis.com" in html:
    print("  [INFO] Google Fonts (Inter) referenced - requires internet")
if "cdn.jsdelivr.net" in html:
    print("  [INFO] Chart.js CDN referenced - requires internet for score timeline")
# Check if these are critical or graceful degradation
if "fonts.googleapis.com" in html:
    # Font is cosmetic - fallback to system fonts
    if "BlinkMacSystemFont" in html or "Segoe UI" in html:
        print("  [OK]   Font has system fallbacks")
    else:
        print("  [WARN] No font fallback")
        issues.append("No font fallback if Google Fonts unavailable")

# ── SUMMARY ──────────────────────────────────────────────────────
print("\n" + "=" * 60)
if issues:
    print(f"ISSUES FOUND: {len(issues)}")
    for i, iss in enumerate(issues, 1):
        print(f"  {i}. {iss}")
else:
    print("ALL CHECKS PASSED - NO ISSUES FOUND")
print("=" * 60)

client.close()
