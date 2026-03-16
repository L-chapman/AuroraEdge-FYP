# Stage 4 — Misconfiguration rules v1 + Rich console

Rules implemented:
- R1_MX_MISSING (HIGH): no MX records
- R2_SPF_MISSING (HIGH): SPF not published
- R3_SPF_LOOKUPS (WARN): SPF may exceed 10 DNS lookups
- R4_DMARC_MISSING (HIGH): DMARC not published
- R5_DMARC_NONE (WARN): DMARC policy p=none
- R6_DKIM_NOT_FOUND (WARN): no common DKIM selectors found
- R7_DKIM_TEST (WARN): DKIM selector in test mode (t=y)

Outputs: CSV adds `severity` and `violations`; Markdown includes a summary table. Console renders a Rich table.
