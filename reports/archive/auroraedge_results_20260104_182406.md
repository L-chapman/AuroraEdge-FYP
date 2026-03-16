# AuroraEdge Scan Results

**Scan Time:** 20260104_182406 UTC
**Domains Scanned:** 51

## Summary Statistics

| Metric | Value |
|--------|-------|
| Average Score | 68.5 |
| Min Score | 0 |
| Max Score | 100 |

### Grade Distribution

| Grade | Count |
|-------|-------|
| A+ | 2 |
| A | 5 |
| B | 13 |
| C | 22 |
| D | 5 |
| F | 4 |

### Severity Distribution

| Severity | Count |
|----------|-------|
| OK | 2 |
| INFO | 0 |
| WARN | 42 |
| HIGH | 7 |
| CRITICAL | 0 |

## Detailed Results

| Domain | Grade | Score | Severity | SPF | DMARC | DKIM | MTA-STS | TLS-RPT | Violations |
|--------|-------|-------|----------|-----|-------|------|---------|---------|------------|
| ﻿# AuroraEdge Academic Dataset | F | 0 | HIGH | N | N | N | N | N | 6 |
| belfastmet.ac.uk | D | 56 | WARN | Y | none | N | N | N | 6 |
| qub.ac.uk | C | 66 | WARN | Y | none | Y | N | N | 5 |
| ulster.ac.uk | A+ | 100 | OK | Y | reject | Y | enforce | Y | 0 |
| oxford.ac.uk | D | 45 | HIGH | Y | N | N | N | N | 4 |
| cam.ac.uk | A | 90 | WARN | Y | reject | Y | N | Y | 1 |
| imperial.ac.uk | D | 56 | WARN | Y | none | N | N | N | 6 |
| ucl.ac.uk | D | 43 | HIGH | Y | none | Y | N | N | 5 |
| ed.ac.uk | C | 66 | WARN | Y | none | Y | N | N | 5 |
| manchester.ac.uk | C | 66 | WARN | Y | none | Y | N | N | 5 |
| birmingham.ac.uk | F | 20 | HIGH | N | N | N | N | N | 5 |
| leeds.ac.uk | B | 84 | WARN | Y | quarantine | Y | N | Y | 4 |
| bristol.ac.uk | B | 84 | WARN | Y | quarantine | Y | N | Y | 4 |
| warwick.ac.uk | C | 74 | WARN | Y | quarantine | Y | N | N | 5 |
| glasgow.ac.uk | C | 66 | WARN | Y | none | Y | N | N | 5 |
| exeter.ac.uk | A | 90 | WARN | Y | reject | Y | N | Y | 1 |
| gov.uk | D | 45 | HIGH | Y | reject | N | N | N | 4 |
| nhs.uk | C | 70 | WARN | Y | reject | N | N | N | 3 |
| police.uk | F | 35 | HIGH | Y | none | N | N | N | 5 |
| bbc.co.uk | C | 68 | WARN | Y | reject | N | N | N | 4 |
| channel4.com | C | 68 | WARN | Y | reject | N | N | N | 4 |
| google.com | A | 88 | WARN | Y | reject | N | enforce | Y | 2 |
| microsoft.com | A+ | 100 | OK | Y | reject | Y | enforce | Y | 0 |
| amazon.co.uk | C | 68 | WARN | Y | quarantine | N | N | N | 4 |
| apple.com | C | 74 | WARN | Y | quarantine | Y | N | N | 5 |
| meta.com | C | 70 | WARN | Y | reject | N | N | N | 3 |
| openai.com | B | 80 | WARN | Y | reject | Y | N | N | 2 |
| github.com | B | 78 | WARN | Y | reject | Y | N | N | 3 |
| gitlab.com | C | 60 | WARN | Y | reject | Y | N | N | 4 |
| cloudflare.com | B | 80 | WARN | Y | reject | Y | N | N | 2 |
| digitalocean.com | B | 80 | WARN | Y | reject | Y | N | N | 2 |
| aws.amazon.com | F | 0 | HIGH | N | N | N | N | N | 6 |
| tesco.com | B | 80 | WARN | Y | reject | Y | N | N | 2 |
| sainsburys.co.uk | B | 78 | WARN | Y | reject | Y | N | N | 3 |
| asda.com | C | 70 | WARN | Y | none | Y | N | N | 3 |
| morrisons.co.uk | C | 66 | WARN | Y | none | Y | N | N | 5 |
| bt.com | B | 78 | WARN | Y | reject | Y | N | N | 3 |
| sky.com | C | 70 | WARN | Y | reject | N | N | N | 3 |
| vodafone.co.uk | B | 80 | WARN | Y | reject | Y | N | N | 2 |
| ee.co.uk | B | 78 | WARN | Y | reject | Y | N | N | 3 |
| three.co.uk | C | 74 | WARN | Y | quarantine | Y | N | N | 5 |
| virgin.com | A | 88 | WARN | Y | reject | Y | testing | Y | 2 |
| barclays.co.uk | C | 70 | WARN | Y | reject | N | N | N | 3 |
| hsbc.co.uk | C | 68 | WARN | Y | reject | N | N | N | 4 |
| lloydsbank.co.uk | C | 70 | WARN | Y | reject | N | N | N | 3 |
| natwest.com | B | 80 | WARN | Y | reject | Y | N | N | 2 |
| protonmail.com | C | 74 | WARN | Y | quarantine | N | enforce | Y | 5 |
| tutanota.com | A | 88 | WARN | Y | quarantine | Y | enforce | Y | 2 |
| fastmail.com | B | 76 | WARN | Y | none | Y | testing | Y | 4 |
| northflux.co.uk | C | 68 | WARN | Y | quarantine | N | N | N | 4 |
| example.com | C | 70 | WARN | Y | reject | Y | N | N | 3 |

## Common Violations

| Violation | Count |
|-----------|-------|
| R8_MTA_STS_MISSING | 44 |
| R10_TLS_RPT_MISSING | 40 |
| R3C_SPF_SOFTFAIL | 23 |
| R6_DKIM_NOT_FOUND | 20 |
| R12_NO_STRICT_POLICY | 15 |
| R5_DMARC_NONE | 11 |
| R5B_DMARC_QUARANTINE | 9 |
| R1_MX_MISSING | 4 |
| R4_DMARC_MISSING | 4 |
| R5D_DMARC_NO_RUA | 4 |
| R2_SPF_MISSING | 3 |
| R9_MTA_STS_MODE | 2 |
| R3B_SPF_PERMISSIVE | 1 |
| R3_SPF_LOOKUPS | 1 |
