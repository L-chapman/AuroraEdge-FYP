# AuroraEdge Scan Results

**Scan Time:** 20260104_181232 UTC
**Domains Scanned:** 6

## Summary Statistics

| Metric | Value |
|--------|-------|
| Average Score | 68.3 |
| Min Score | 56 |
| Max Score | 80 |

### Grade Distribution

| Grade | Count |
|-------|-------|
| A+ | 0 |
| A | 0 |
| B | 1 |
| C | 4 |
| D | 1 |
| F | 0 |

### Severity Distribution

| Severity | Count |
|----------|-------|
| OK | 0 |
| INFO | 0 |
| WARN | 6 |
| HIGH | 0 |
| CRITICAL | 0 |

## Detailed Results

| Domain | Grade | Score | Severity | SPF | DMARC | DKIM | MTA-STS | TLS-RPT | Violations |
|--------|-------|-------|----------|-----|-------|------|---------|---------|------------|
| ﻿example.com | C | 70 | WARN | Y | reject | Y | N | N | 3 |
| openai.com | B | 80 | WARN | Y | reject | Y | N | N | 2 |
| bbc.co.uk | C | 68 | WARN | Y | reject | N | N | N | 4 |
| northflux.co.uk | C | 68 | WARN | Y | quarantine | N | N | N | 4 |
| belfastmet.ac.uk | D | 56 | WARN | Y | none | N | N | N | 6 |
| amazon.co.uk | C | 68 | WARN | Y | quarantine | N | N | N | 4 |

## Common Violations

| Violation | Count |
|-----------|-------|
| R8_MTA_STS_MISSING | 6 |
| R10_TLS_RPT_MISSING | 6 |
| R6_DKIM_NOT_FOUND | 4 |
| R3C_SPF_SOFTFAIL | 2 |
| R5B_DMARC_QUARANTINE | 2 |
| R5D_DMARC_NO_RUA | 1 |
| R5_DMARC_NONE | 1 |
| R12_NO_STRICT_POLICY | 1 |
