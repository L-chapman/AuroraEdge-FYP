"""NorthFlux Security rules engine for RFC-based email security evaluation."""
from typing import Dict, List, Tuple

SEVERITY_ORDER = {"OK": 0, "INFO": 1, "WARN": 2, "HIGH": 3, "CRITICAL": 4, "ERROR": 5}
SCORE_BASE = 100

# Project-specific checklist weighting, not an RFC or commercial risk score.
# References: RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), RFC 8461 (MTA-STS)
SCORE_WEIGHTS = {
    "CRITICAL": 40,  # Fundamental failures
    "HIGH": 25,  # Major security gaps
    "WARN": 10,  # Best practice violations
    "INFO": 2,  # Minor recommendations
}

# Severity explanations for user education
SEVERITY_EXPLANATIONS = {
    "ERROR": {
        "title": "Incomplete scan",
        "description": "Some checks could not be completed or returned ambiguous evidence.",
        "impact": "This scan cannot establish a reliable overall grade or authorise automatic changes.",
        "urgency": "Review the scan notes and retry before changing DNS.",
        "color": "#64748b",
    },
    "CRITICAL": {
        "title": "Critical Security Issue",
        "description": "This represents a fundamental security failure that leaves your domain completely vulnerable to email attacks.",
        "impact": "Attackers can easily spoof emails from your domain, leading to phishing attacks, financial fraud, and reputation damage.",
        "urgency": "Fix immediately - your domain is actively exploitable",
        "color": "#dc2626",
    },
    "HIGH": {
        "title": "High Security Risk",
        "description": "A significant security gap that could allow email spoofing or other attacks.",
        "impact": "Your domain lacks essential protections. Sophisticated attackers could exploit this to impersonate your organisation.",
        "urgency": "Fix within 24-48 hours",
        "color": "#ef4444",
    },
    "WARN": {
        "title": "Security Warning",
        "description": "A best practice violation that weakens your email security posture.",
        "impact": "While not immediately critical, this leaves potential gaps that attackers could exploit in combination with other vulnerabilities.",
        "urgency": "Fix within 1-2 weeks",
        "color": "#f59e0b",
    },
    "INFO": {
        "title": "Recommendation",
        "description": "An optimisation opportunity to strengthen your email security.",
        "impact": "Implementing this would improve your security score and follow industry best practices.",
        "urgency": "Consider addressing in next maintenance window",
        "color": "#3b82f6",
    },
    "OK": {
        "title": "Passed",
        "description": "This check passed successfully.",
        "impact": "No action required.",
        "urgency": "None",
        "color": "#22c55e",
    },
}

# Rule explanations with why and how to fix
RULE_EXPLANATIONS = {
    "R1_MX_MISSING": {
        "why": "MX records identify incoming mail servers. Without MX, SMTP may fall back to the domain's A/AAAA addresses; that fallback is not tested here. A null MX explicitly declines incoming mail.",
        "fix": "Add MX records pointing to your email provider's mail servers (e.g., Google Workspace, Microsoft 365, or your own mail server).",
        "example": "example.com. IN MX 10 mail.example.com.",
        "rfc": "RFC 5321",
    },
    "R2_SPF_MISSING": {
        "why": "SPF (Sender Policy Framework) tells receiving servers which IPs are allowed to send email on your behalf. Without SPF, anyone can send emails pretending to be from your domain.",
        "fix": "Add a TXT record at your domain root listing authorised sending sources.",
        "example": "v=spf1 include:_spf.google.com ~all",
        "rfc": "RFC 7208",
    },
    "R3_SPF_LOOKUPS": {
        "why": "SPF has a hard limit of 10 DNS lookups. Exceeding this causes a 'permerror' which may result in email delivery failures or SPF being ignored entirely.",
        "fix": "Flatten your SPF record by replacing 'include' mechanisms with the actual IP addresses, or use an SPF flattening service.",
        "example": "Use tools like dmarcian SPF Surveyor to identify and reduce lookups",
        "rfc": "RFC 7208 Section 4.6.4",
    },
    "R3B_SPF_PERMISSIVE": {
        "why": "SPF +all returns Pass for any sender. SPF ?all returns Neutral, making no positive or negative assertion about other senders. Neither restricts them through SPF.",
        "fix": "Change to ~all (softfail) or preferably -all (hardfail) to restrict unauthorised senders.",
        "example": "v=spf1 include:_spf.google.com -all",
        "rfc": "RFC 7208",
    },
    "R3C_SPF_SOFTFAIL": {
        "why": "SPF ~all (softfail) marks unauthorised emails as suspicious but doesn't reject them. This is less strict than -all (hardfail).",
        "fix": "Consider changing from ~all to -all for stricter enforcement, but only after testing thoroughly.",
        "example": "v=spf1 include:_spf.google.com -all",
        "rfc": "RFC 7208",
    },
    "R4_DMARC_MISSING": {
        "why": "DMARC ties together SPF and DKIM, telling receivers what to do when authentication fails. Without DMARC, even with SPF/DKIM, receivers have no policy to follow.",
        "fix": "Add a DMARC TXT record at _dmarc.yourdomain.com. Start with p=none to monitor, then upgrade to quarantine/reject.",
        "example": "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
        "rfc": "RFC 7489",
    },
    "R5_DMARC_NONE": {
        "why": "DMARC p=none means authentication failures are reported but not blocked. Attackers can still spoof your domain - you're just monitoring them.",
        "fix": "Review actual mail reports and indirect-mail cases before choosing enforcement. Quarantine is a valid option; reject is not suitable for every domain.",
        "example": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        "rfc": "RFC 7489",
    },
    "R5B_DMARC_QUARANTINE": {
        "why": "DMARC p=quarantine requests enforcement for failing mail. Receivers retain local discretion; this policy does not guarantee inbox or spam-folder delivery.",
        "fix": "Quarantine is a valid enforcement choice. RFC 9989 advises against reject for general-purpose domains; review intended use and indirect-mail compatibility with the domain owner.",
        "example": "v=DMARC1; p=quarantine; rua=mailto:reports@example.com",
        "rfc": "RFC 9989 Section 7.4 (legacy checklist weighting retained)",
    },
    "R5C_DMARC_PCT": {
        "why": "Legacy DMARC pct requested partial enforcement under RFC 7489. RFC 9989 removes this tag, and receivers may ignore it; it is not a reliable delivery percentage.",
        "fix": "Review the current DMARC standard and actual mail reports before changing enforcement. Do not rely on pct for a safe rollout.",
        "example": "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com",
        "rfc": "RFC 7489",
    },
    "R5D_DMARC_NO_RUA": {
        "why": "The rua= tag tells receivers where to send DMARC aggregate reports. Without it, you have no visibility into who is sending email as your domain or whether authentication is passing.",
        "fix": "Add a rua= tag with a reporting mailbox to receive daily aggregate reports.",
        "example": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        "rfc": "RFC 7489",
    },
    "R6_DKIM_NOT_FOUND": {
        "why": "DKIM (DomainKeys Identified Mail) cryptographically signs emails, proving they haven't been tampered with. Without DKIM, emails can be modified in transit.",
        "fix": "Configure DKIM signing with your email provider. They'll give you a public key to publish in DNS.",
        "example": 'selector1._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIGf..."',
        "rfc": "RFC 6376",
    },
    "R7_DKIM_TEST": {
        "why": "A DKIM record with t=y is in test mode. Receivers may ignore DKIM failures during testing.",
        "fix": "Once DKIM is working correctly, remove the t=y flag to enforce full DKIM validation.",
        "example": "Remove t=y from the DKIM record",
        "rfc": "RFC 6376",
    },
    "R8_MTA_STS_MISSING": {
        "why": "MTA-STS enforces TLS encryption for incoming email. Without it, attackers could downgrade connections to unencrypted SMTP and intercept emails.",
        "fix": "Publish a _mta-sts TXT record and host a policy file at https://mta-sts.yourdomain/.well-known/mta-sts.txt",
        "example": '_mta-sts.example.com. IN TXT "v=STSv1; id=20260108"',
        "rfc": "RFC 8461",
    },
    "R9_MTA_STS_MODE": {
        "why": "MTA-STS mode 'testing' logs TLS failures but doesn't reject unencrypted connections. For full protection, use 'enforce'.",
        "fix": "Change MTA-STS policy mode from 'testing' to 'enforce' in your mta-sts.txt file.",
        "example": "mode: enforce",
        "rfc": "RFC 8461",
    },
    "R10_TLS_RPT_MISSING": {
        "why": "TLS-RPT enables receiving servers to report TLS failures back to you. Without it, you won't know if email delivery is failing due to TLS issues.",
        "fix": "Add a TLS-RPT TXT record at _smtp._tls.yourdomain.com with a reporting address.",
        "example": '_smtp._tls.example.com. IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"',
        "rfc": "RFC 8460",
    },
    "R11_STARTTLS_WEAK": {
        "why": "Your mail server's STARTTLS configuration is weak (grade D or F). This means encrypted connections may use outdated protocols or ciphers.",
        "fix": "Update your mail server's TLS configuration to use TLS 1.2+ and modern cipher suites. Disable SSLv3, TLS 1.0, and TLS 1.1.",
        "example": "Configure postfix: smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1",
        "rfc": "RFC 8996",
    },
    "R12_NO_STRICT_POLICY": {
        "why": "This legacy checklist notes when SPF -all and DMARC reject are both absent. It is not proof of unsafe delivery; quarantine is valid enforcement and SPF outcomes are not receiver disposition commands.",
        "fix": "Review policy choices against actual senders and domain use. Do not change to reject just to improve a checklist grade.",
        "example": "SPF: -all | DMARC: p=reject",
        "rfc": "RFC 7208 / RFC 7489",
    },
    "R13_BIMI_MISSING": {
        "why": "BIMI can display a brand logo in supporting mail clients. An enforcing DMARC policy at 100% is a prerequisite, not a guarantee of logo display or proof that a message is safe.",
        "fix": "Create a BIMI DNS record at default._bimi.yourdomain.com pointing to an SVG Tiny PS logo. For full support, obtain a Verified Mark Certificate (VMC).",
        "example": 'default._bimi.example.com. IN TXT "v=BIMI1; l=https://example.com/logo.svg; a="',
        "rfc": "BIMI Group implementation guide: https://bimigroup.org/implementation-guide/",
    },
    "R14_RBL_LISTED": {
        "why": "One or more IP addresses behind your MX servers are listed on email blacklists (DNSBLs). This can cause your outbound emails to be rejected or sent to spam by receiving servers.",
        "fix": "Investigate why your MX IPs are blacklisted. Common causes: compromised server sending spam, open relay, or shared hosting. Request delisting from each blacklist provider.",
        "example": "Check https://www.spamhaus.org/lookup/ and follow their delisting process",
        "rfc": "RFC 5782 - DNS Blacklists",
    },
    "R15_DMARC_SP_WEAK": {
        "why": "The DMARC subdomain policy (sp=) is weaker than the organisational domain policy (p=). Attackers can spoof subdomains (e.g. mail.example.com) to bypass your DMARC enforcement.",
        "fix": "Set sp= to match or exceed the parent policy. If p=reject, set sp=reject (or remove sp= to inherit).",
        "example": 'v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com',
        "rfc": "RFC 7489 Section 6.3",
    },
}


def get_severity_explanation(severity: str) -> Dict:
    """Get explanation for a severity level."""
    return SEVERITY_EXPLANATIONS.get(severity.upper(), SEVERITY_EXPLANATIONS["OK"])


def get_rule_explanation(rule_id: str) -> Dict:
    """Get explanation for a specific rule."""
    return RULE_EXPLANATIONS.get(
        rule_id,
        {
            "why": "This rule checks for a security best practice.",
            "fix": "Review the recommendation and apply the suggested fix.",
            "example": "",
            "rfc": "",
        },
    )


def rule_mx_missing(r: Dict) -> Tuple[str, str, str]:
    """R1: MX records are fundamental for receiving email (RFC 5321)."""
    if r.get("null_mx"):
        return ("", "OK", "")  # Intentional no-mail configuration, not a defect.
    return (
        ("R1_MX_MISSING", "HIGH", "No explicit MX records found - review incoming mail routing")
        if not r.get("mx_present", False)
        else ("", "OK", "")
    )


def rule_spf_missing(r: Dict) -> Tuple[str, str, str]:
    """R2: SPF prevents unauthorised senders (RFC 7208)."""
    return (
        ("R2_SPF_MISSING", "HIGH", "SPF record not published - enables spoofing")
        if not r.get("spf_present", False)
        else ("", "OK", "")
    )


def rule_spf_lookups(r: Dict) -> Tuple[str, str, str]:
    """R3: SPF has 10 DNS lookup limit (RFC 7208 Section 4.6.4)."""
    try:
        lookups = int(r.get("spf_lookups", 0))
    except (ValueError, TypeError):
        lookups = 0
    if r.get("spf_present", False) and lookups > 10:
        return (
            "R3_SPF_LOOKUPS",
            "WARN",
            f"SPF exceeds 10 DNS lookups ({lookups}) - may cause permerror",
        )
    return ("", "OK", "")


def rule_spf_all_permissive(r: Dict) -> Tuple[str, str, str]:
    """R3b: SPF +all or ?all is too permissive."""
    spf_all = (r.get("spf_all", "") or "").lower()
    if r.get("spf_present", False) and spf_all in ("+all", "?all"):
        outcome = "passes any sender" if spf_all == "+all" else "returns Neutral for other senders"
        return ("R3B_SPF_PERMISSIVE", "HIGH", f"SPF uses {spf_all} - {outcome}")
    return ("", "OK", "")


def rule_spf_softfail(r: Dict) -> Tuple[str, str, str]:
    """R3c: SPF ~all (softfail) is weaker than -all (hardfail)."""
    spf_all = (r.get("spf_all", "") or "").lower()
    if r.get("spf_present", False) and spf_all == "~all":
        return (
            "R3C_SPF_SOFTFAIL",
            "INFO",
            "SPF uses ~all (softfail) - consider -all for strict enforcement",
        )
    return ("", "OK", "")


def rule_dmarc_missing(r: Dict) -> Tuple[str, str, str]:
    """R4: DMARC enables policy enforcement and reporting (RFC 7489)."""
    return (
        (
            "R4_DMARC_MISSING",
            "HIGH",
            "DMARC not published - no policy enforcement or reporting",
        )
        if not r.get("dmarc_present", False)
        else ("", "OK", "")
    )


def rule_dmarc_none(r: Dict) -> Tuple[str, str, str]:
    """R5: DMARC p=none provides no protection (RFC 7489)."""
    pol = (r.get("dmarc_policy", "") or "").lower()
    if r.get("dmarc_present", False) and (pol == "" or pol == "none"):
        return (
            "R5_DMARC_NONE",
            "WARN",
            "DMARC policy is p=none - monitoring only, no enforcement",
        )
    return ("", "OK", "")


def rule_dmarc_quarantine(r: Dict) -> Tuple[str, str, str]:
    """R5b: Retained legacy checklist notice; quarantine is valid enforcement."""
    pol = (r.get("dmarc_policy", "") or "").lower()
    if r.get("dmarc_present", False) and pol == "quarantine":
        return (
            "R5B_DMARC_QUARANTINE",
            "INFO",
            "DMARC p=quarantine is an enforcement policy - retain or change only after a domain-use review",
        )
    return ("", "OK", "")


def rule_dmarc_pct(r: Dict) -> Tuple[str, str, str]:
    """R5c: DMARC pct<100 means policy doesn't apply to all messages."""
    try:
        pct = int(r.get("dmarc_pct", 100))
    except (ValueError, TypeError):
        return ("", "OK", "")
    if r.get("dmarc_present", False) and pct < 100:
        return (
            "R5C_DMARC_PCT",
            "WARN",
            f"Legacy DMARC pct={pct} - receiver behaviour varies; RFC 9989 removes this tag",
        )
    return ("", "OK", "")


def rule_dmarc_no_rua(r: Dict) -> Tuple[str, str, str]:
    """R5d: DMARC without rua= means no aggregate reports."""
    rua = r.get("dmarc_rua", "") or ""
    if r.get("dmarc_present", False) and not rua:
        return (
            "R5D_DMARC_NO_RUA",
            "WARN",
            "DMARC has no rua= tag - not receiving aggregate reports",
        )
    return ("", "OK", "")


def rule_dkim_missing(r: Dict) -> Tuple[str, str, str]:
    """R6: DKIM provides message integrity (RFC 6376)."""
    return (
        (
            "R6_DKIM_NOT_FOUND",
            "WARN",
            "No common DKIM selectors found - message integrity unverified",
        )
        if not r.get("dkim_present", False)
        else ("", "OK", "")
    )


def rule_dkim_test(r: Dict) -> Tuple[str, str, str]:
    """R7: DKIM t=y flag indicates testing mode (RFC 6376)."""
    notes = (r.get("notes", "") or "").lower()
    # Scanner marks test mode with "selector:test" format
    return (
        (
            "R7_DKIM_TEST",
            "WARN",
            "DKIM selector in test mode (t=y) - not production ready",
        )
        if ":test" in notes
        else ("", "OK", "")
    )


def rule_mta_sts_missing(r: Dict) -> Tuple[str, str, str]:
    """R8: MTA-STS enforces TLS for mail delivery (RFC 8461)."""
    if r.get("null_mx"):
        return ("", "OK", "")
    return (
        (
            "R8_MTA_STS_MISSING",
            "WARN",
            "MTA-STS policy not found - TLS not enforced for inbound mail",
        )
        if not r.get("mta_sts_present", False)
        else ("", "OK", "")
    )


def rule_mta_sts_mode(r: Dict) -> Tuple[str, str, str]:
    """R9: MTA-STS mode should be 'enforce' for protection."""
    mode = (r.get("mta_sts_mode", "") or "").lower()
    if r.get("mta_sts_present", False) and mode != "enforce":
        return (
            "R9_MTA_STS_MODE",
            "WARN",
            f"MTA-STS mode is '{mode}' - should be 'enforce' for protection",
        )
    return ("", "OK", "")


def rule_tls_rpt_missing(r: Dict) -> Tuple[str, str, str]:
    """R10: TLS-RPT enables TLS failure reporting (RFC 8460)."""
    if r.get("null_mx"):
        return ("", "OK", "")
    return (
        (
            "R10_TLS_RPT_MISSING",
            "WARN",
            "TLS-RPT record missing - not receiving TLS failure reports",
        )
        if not r.get("tls_rpt_present", False)
        else ("", "OK", "")
    )


def rule_starttls_weak(r: Dict) -> Tuple[str, str, str]:
    """R11: STARTTLS should use TLS 1.2+ with strong ciphers."""
    grade = (r.get("starttls_worst", "") or "").upper()
    if grade in ("D", "F"):
        return (
            "R11_STARTTLS_WEAK",
            "WARN",
            f"STARTTLS grade {grade} - weak or missing encryption on MX",
        )
    return ("", "OK", "")


def rule_no_reject_policy(r: Dict) -> Tuple[str, str, str]:
    """R12: Combined check - SPF and DMARC should have strict policies."""
    spf_all = (r.get("spf_all", "") or "").lower()
    dmarc_pol = (r.get("dmarc_policy", "") or "").lower()

    has_strict_spf = spf_all == "-all"
    has_strict_dmarc = dmarc_pol == "reject"

    if r.get("spf_present") and r.get("dmarc_present"):
        if not has_strict_spf and not has_strict_dmarc:
            return (
                "R12_NO_STRICT_POLICY",
                "INFO",
                "Legacy policy checklist: review domain needs; quarantine is valid and reject is not universally appropriate",
            )
    return ("", "OK", "")

def rule_bimi_missing(r: Dict) -> Tuple[str, str, str]:
    """R13: Suggest optional branding only when basic DMARC prerequisites hold."""
    dmarc_pol = (r.get("dmarc_policy", "") or "").lower()
    subpolicy = (r.get("dmarc_sp") or dmarc_pol).lower()
    if (dmarc_pol in ("reject", "quarantine") and subpolicy in ("reject", "quarantine")
            and str(r.get("dmarc_pct", 100)) == "100" and not r.get("bimi_present", False)):
        return (
            "R13_BIMI_MISSING",
            "INFO",
            "BIMI record not found - optional branding; check logo, certificate and mailbox-provider requirements",
        )
    return ("", "OK", "")


def rule_rbl_listed(r: Dict) -> Tuple[str, str, str]:
    """R14: MX server IPs should not appear on email blacklists (RFC 5782)."""
    listings = r.get("rbl_listings", 0)
    if isinstance(listings, int) and listings > 0:
        severity = "HIGH" if listings >= 3 else "WARN"
        return (
            "R14_RBL_LISTED",
            severity,
            f"MX IP(s) listed on {listings} blacklist(s) &#8212; may affect deliverability",
        )
    return ("", "OK", "")


def rule_dmarc_sp_weak(r: Dict) -> Tuple[str, str, str]:
    """R15: DMARC subdomain policy (sp=) should match or exceed the org policy."""
    if not r.get("dmarc_present", False):
        return ("", "OK", "")
    pol = (r.get("dmarc_policy", "") or "").lower()
    sp = (r.get("dmarc_sp", "") or "").lower()
    # If sp is not set, it inherits parent policy &#8212; no issue
    if not sp:
        return ("", "OK", "")
    strength = {"none": 0, "quarantine": 1, "reject": 2}
    parent_str = strength.get(pol, -1)
    sub_str = strength.get(sp, -1)
    if sub_str < parent_str and parent_str >= 0:
        return (
            "R15_DMARC_SP_WEAK",
            "WARN",
            f"DMARC subdomain policy sp={sp} is weaker than parent p={pol}",
        )
    return ("", "OK", "")


ALL_RULES = [
    rule_mx_missing,
    rule_spf_missing,
    rule_spf_lookups,
    rule_spf_all_permissive,
    rule_spf_softfail,
    rule_dmarc_missing,
    rule_dmarc_none,
    rule_dmarc_quarantine,
    rule_dmarc_pct,
    rule_dmarc_no_rua,
    rule_dkim_missing,
    rule_dkim_test,
    rule_mta_sts_missing,
    rule_mta_sts_mode,
    rule_tls_rpt_missing,
    rule_starttls_weak,
    rule_no_reject_policy,
    rule_bimi_missing,
    rule_rbl_listed,
    rule_dmarc_sp_weak,
]


def evaluate(result: Dict) -> Dict:
    """
    Evaluate scan results against all security rules.

    Returns a dictionary with:
    - severity: highest severity level triggered
    - violations: comma-separated list of rule IDs
    - advice: human-readable recommendations
    - score: 0-100 security score (higher is better)
    - grade: letter grade (A+ to F)
    """
    hits: List[Tuple[str, str, str]] = []
    top = ("", "OK", "")

    for rule in ALL_RULES:
        rid, sev, msg = rule(result)
        if sev != "OK":
            hits.append((rid, sev, msg))
            if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(top[1], 0):
                top = (rid, sev, msg)

    violations = ",".join([h[0] for h in hits]) if hits else ""
    advice = " | ".join([h[2] for h in hits]) if hits else "All checks passed"

    # Score calculation: start at 100, subtract weighted penalties, floor at 0
    penalty = sum(SCORE_WEIGHTS.get(h[1], 0) for h in hits)
    score = max(0, SCORE_BASE - penalty)

    # Letter grade based on score
    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    incomplete = bool(result.get("scan_incomplete"))
    if incomplete:
        advice = "Incomplete scan: observations and any calculated score are provisional. " + str(result.get("notes") or "Review the scan errors and retry.")

    return {
        "severity": "ERROR" if incomplete else top[1],
        "violations": violations,
        "advice": advice,
        "score": score,
        "grade": grade,
        "violation_count": len(hits),
        "scan_incomplete": incomplete,
    }


def generate_remediation(result: Dict) -> List[Dict[str, str]]:
    """
    Generate specific remediation recommendations with example DNS records.

    Returns list of remediation items with:
    - rule: rule ID
    - priority: HIGH/WARN/INFO
    - description: what to fix
    - example: example DNS record or configuration
    """
    domain = result.get("domain", "example.com")
    remediations = []

    # MX missing
    if not result.get("mx_present", False) and not result.get("null_mx"):
        remediations.append(
            {
                "rule": "R1_MX_MISSING",
                "priority": "HIGH",
                "description": "Add MX records so your domain can receive email",
                "example": f'{domain}. IN MX 10 mail.{domain}.',
                "reference": "RFC 5321 - Simple Mail Transfer Protocol",
            }
        )

    # SPF missing
    if not result.get("spf_present", False):
        remediations.append(
            {
                "rule": "R2_SPF_MISSING",
                "priority": "HIGH",
                "description": "Add SPF record to prevent email spoofing",
                "example": f'{domain}. IN TXT "v=spf1 include:_spf.google.com ~all"',
                "reference": "RFC 7208 - Sender Policy Framework",
            }
        )
    else:
        # SPF lookups
        try:
            lookups = int(result.get("spf_lookups", 0))
        except (ValueError, TypeError):
            lookups = 0
        if lookups > 10:
            remediations.append(
                {
                    "rule": "R3_SPF_LOOKUPS",
                    "priority": "WARN",
                    "description": f"Reduce SPF DNS lookups from {lookups} to 10 or fewer",
                    "example": "Flatten SPF includes or use an SPF flattening service",
                    "reference": "RFC 7208 Section 4.6.4",
                }
            )

        # SPF permissive
        spf_all = (result.get("spf_all", "") or "").lower()
        if spf_all in ("+all", "?all"):
            remediations.append(
                {
                    "rule": "R3B_SPF_PERMISSIVE",
                    "priority": "HIGH",
                    "description": f"SPF uses {spf_all} which allows any sender &#8212; change to -all",
                    "example": f'{domain}. IN TXT "v=spf1 include:_spf.google.com -all"',
                    "reference": "RFC 7208",
                }
            )
        elif spf_all == "~all":
            remediations.append(
                {
                    "rule": "R3C_SPF_SOFTFAIL",
                    "priority": "INFO",
                    "description": "Harden SPF from ~all (softfail) to -all (hardfail)",
                    "example": f'{domain}. IN TXT "v=spf1 include:_spf.google.com -all"',
                    "reference": "RFC 7208",
                }
            )

    # DMARC missing
    if not result.get("dmarc_present", False):
        remediations.append(
            {
                "rule": "R4_DMARC_MISSING",
                "priority": "HIGH",
                "description": "Add DMARC record to enforce email authentication policy",
                "example": f'_dmarc.{domain}. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}"',
                "reference": "RFC 7489 - DMARC",
            }
        )
    else:
        pol = (result.get("dmarc_policy", "") or "").lower()
        if pol == "" or pol == "none":
            remediations.append(
                {
                    "rule": "R5_DMARC_NONE",
                    "priority": "WARN",
                    "description": "Review sender reports before choosing an enforcement policy; quarantine may be appropriate",
                    "example": f'_dmarc.{domain}. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@{domain}"',
                    "reference": "NCSC recommends p=reject for full protection",
                }
            )
        elif pol == "quarantine":
            remediations.append(
                {
                    "rule": "R5B_DMARC_QUARANTINE",
                    "priority": "INFO",
                    "description": "Quarantine is valid enforcement; review domain use before any policy change",
                    "example": "General-purpose domains should not switch to reject solely for a higher score",
                    "reference": "RFC 9989 Section 7.4",
                }
            )

        pct = result.get("dmarc_pct", 100)
        if isinstance(pct, int) and pct < 100:
            remediations.append(
                {
                    "rule": "R5C_DMARC_PCT",
                    "priority": "WARN",
                    "description": f"Legacy DMARC pct={pct}; receivers may ignore this retired tag",
                    "example": "Review RFC 9989 and actual reports before changing enforcement",
                    "reference": "RFC 9989 Appendix A.6",
                }
            )

        rua = result.get("dmarc_rua", "") or ""
        if not rua:
            remediations.append(
                {
                    "rule": "R5D_DMARC_NO_RUA",
                    "priority": "WARN",
                    "description": "Add rua= tag to receive DMARC aggregate reports",
                    "example": f'rua=mailto:dmarc@{domain}',
                    "reference": "RFC 7489",
                }
            )

    # MTA-STS missing
    if not result.get("mta_sts_present", False) and not result.get("null_mx"):
        remediations.append(
            {
                "rule": "R8_MTA_STS_MISSING",
                "priority": "WARN",
                "description": "Deploy MTA-STS to enforce TLS for inbound mail",
                "example": f'_mta-sts.{domain}. IN TXT "v=STSv1; id=20260104"\nHost mta-sts.{domain} with /.well-known/mta-sts.txt',
                "reference": "RFC 8461 - MTA-STS",
            }
        )
    else:
        mode = (result.get("mta_sts_mode", "") or "").lower()
        if mode and mode != "enforce":
            remediations.append(
                {
                    "rule": "R9_MTA_STS_MODE",
                    "priority": "WARN",
                    "description": f"MTA-STS mode is '{mode}' &#8212; upgrade to 'enforce'",
                    "example": "mode: enforce",
                    "reference": "RFC 8461",
                }
            )

    # TLS-RPT missing
    if not result.get("tls_rpt_present", False) and not result.get("null_mx"):
        remediations.append(
            {
                "rule": "R10_TLS_RPT_MISSING",
                "priority": "WARN",
                "description": "Add TLS-RPT record to receive TLS failure reports",
                "example": f'_smtp._tls.{domain}. IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@{domain}"',
                "reference": "RFC 8460 - TLS Reporting",
            }
        )

    # DKIM not found
    if not result.get("dkim_present", False):
        remediations.append(
            {
                "rule": "R6_DKIM_NOT_FOUND",
                "priority": "WARN",
                "description": "Configure DKIM signing for your email provider",
                "example": f'selector1._domainkey.{domain}. IN TXT "v=DKIM1; k=rsa; p=<public_key>"',
                "reference": "RFC 6376 - DKIM Signatures",
            }
        )
    else:
        notes = (result.get("notes", "") or "").lower()
        if ":test" in notes:
            remediations.append(
                {
                    "rule": "R7_DKIM_TEST",
                    "priority": "WARN",
                    "description": "DKIM selector is in test mode (t=y) &#8212; remove t=y for production",
                    "example": "Remove t=y from DKIM TXT record",
                    "reference": "RFC 6376",
                }
            )

    # STARTTLS weak
    starttls_worst = (result.get("starttls_worst", "") or "").upper()
    if starttls_worst in ("D", "F"):
        remediations.append(
            {
                "rule": "R11_STARTTLS_WEAK",
                "priority": "WARN",
                "description": f"STARTTLS grade {starttls_worst} &#8212; upgrade TLS to 1.2+ with strong ciphers",
                "example": "Disable SSLv3, TLS 1.0, TLS 1.1 on your mail server",
                "reference": "RFC 8996",
            }
        )

    # No strict policy
    spf_all = (result.get("spf_all", "") or "").lower()
    dmarc_pol = (result.get("dmarc_policy", "") or "").lower()
    if result.get("spf_present") and result.get("dmarc_present"):
        if spf_all != "-all" and dmarc_pol != "reject":
            remediations.append(
                {
                    "rule": "R12_NO_STRICT_POLICY",
                    "priority": "INFO",
                    "description": "Review policy choices using sender evidence, not a checklist score",
                    "example": "Quarantine is valid enforcement; reject is context-dependent",
                    "reference": "RFC 7208 / RFC 9989 Section 7.4",
                }
            )

    # BIMI missing (only suggest if DMARC is quarantine or reject)
    if rule_bimi_missing(result)[1] != "OK":
        remediations.append(
            {
                "rule": "R13_BIMI_MISSING",
                "priority": "INFO",
                "description": "Add BIMI record to display your brand logo in email clients",
                "example": f'default._bimi.{domain}. IN TXT "v=BIMI1; l=https://{domain}/logo.svg; a="',
                "reference": "https://bimigroup.org/implementation-guide/",
            }
        )

    # Blacklist / RBL listings
    rbl_listings = result.get("rbl_listings", 0)
    if isinstance(rbl_listings, int) and rbl_listings > 0:
        rbl_details = result.get("rbl_details", [])
        detail_str = "; ".join(
            f"{d['ip']} on {', '.join(d['listed_on'])}"
            for d in (rbl_details if isinstance(rbl_details, list) else [])
        )
        remediations.append(
            {
                "rule": "R14_RBL_LISTED",
                "priority": "HIGH" if rbl_listings >= 3 else "WARN",
                "description": f"MX IP(s) listed on {rbl_listings} blacklist(s): {detail_str}",
                "example": "Request delisting at each blacklist provider's website",
                "reference": "RFC 5782 - DNS Blacklists",
            }
        )

    # DMARC subdomain policy weaker than parent
    sp = (result.get("dmarc_sp", "") or "").lower()
    if sp and result.get("dmarc_present", False):
        strength = {"none": 0, "quarantine": 1, "reject": 2}
        if strength.get(sp, -1) < strength.get(dmarc_pol, -1):
            remediations.append(
                {
                    "rule": "R15_DMARC_SP_WEAK",
                    "priority": "WARN",
                    "description": f"DMARC subdomain policy sp={sp} is weaker than p={dmarc_pol} &#8212; subdomains can be spoofed",
                    "example": f'_dmarc.{domain}. IN TXT "v=DMARC1; p={dmarc_pol}; sp={dmarc_pol}; rua=mailto:dmarc@{domain}"',
                    "reference": "RFC 7489 Section 6.3",
                }
            )

    return remediations
