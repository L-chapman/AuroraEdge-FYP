# Stage 5 — MTA-STS + TLS-RPT checks

Adds HTTPS fetch of policy at `https://mta-sts.<domain>/.well-known/mta-sts.txt` and DNS TXT for `_smtp._tls.<domain>`.
Outputs CSV/MD with new columns; Rich table shows STS/TLS status.
