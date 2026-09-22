# Stage 5 — MTA-STS + TLS-RPT checks

> **Historical academic snapshot:** This file records the pre-migration AuroraEdge final-year project and may contain obsolete commands, paths, test counts, capabilities, or operating assumptions. It is not current NorthFlux Security 4.0 guidance. Use the current [`README`](../../../README.md) and [`testing guide`](../../TESTING.md). Return to the [archive guide](../README.md).

Adds HTTPS fetch of policy at `https://mta-sts.<domain>/.well-known/mta-sts.txt` and DNS TXT for `_smtp._tls.<domain>`.
Outputs CSV/MD with new columns; Rich table shows STS/TLS status.
