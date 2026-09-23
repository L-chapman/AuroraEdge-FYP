# NorthFlux Security privacy and operating boundaries

NorthFlux Security evaluates public DNS records, public MTA-STS policy files, public mail-routing information, and externally visible SMTP transport behaviour. It does not log in to mailboxes, read messages, collect message bodies, or test mailbox credentials.

Local state can contain domain names, scan timestamps, findings, organisation settings, contact details entered by an operator, Cloudflare identifiers, and—in local development—Cloudflare credentials entered through Settings. Reports and logs can contain the same domain-security information. The `NORTHFLUX_STATE_DIR`, `NORTHFLUX_REPORTS_DIR`, and `NORTHFLUX_LOGS_DIR` settings can relocate these stores but do not encrypt or redact them.

In production, Cloudflare tokens, global API keys, and the associated account email are read from the runtime environment and are not copied into SQLite. If an older database contains one of those values, NorthFlux ignores it; once a replacement environment value is supplied, the legacy stored value is removed.

The Settings action **Clear All Scan Data** removes stored scan history, managed-domain and alert data, and recognised scan-report files in the configured report locations. It is not a general folder cleaner: unrelated files, unrecognised filenames, and arbitrary nested folders are preserved. Application settings and log files are also preserved. Per-domain deletion removes that domain's stored history and resets its managed-domain scan metadata, but it does not erase audit or application logs. Operators must manage retained settings and logs separately when their retention policy requires deletion.

Operators should:

- scan and remediate only within their authority;
- treat generated reports as security-sensitive operational data;
- restrict access to the application and its storage;
- set an appropriate retention period for scan history, reports, alerts, and logs;
- back up and securely delete data according to their own policy;
- supply production credentials through a protected runtime secret mechanism;
- review applicable law and organisational policy for their jurisdiction and use case.

NorthFlux does not make a categorical legal determination about scanning. Its technical scope is limited to public-facing configuration checks and explicitly authorised DNS changes.

The application is self-hosted. It does not intentionally send scan history or application analytics to the project maintainer. Network requests required for operation go to the target domain's public services, DNS resolvers, and configured Cloudflare APIs.

The production React frontend is built from repository-pinned dependencies and serves its scripts, styles, and fonts from the NorthFlux origin. It does not load browser analytics, third-party fonts, or frontend CDNs, and its Content Security Policy restricts browser connections to the application origin. The deprecated development fallback still references a Chart.js CDN; it is not the supported production interface.

The frontend bundle is public application code. Never place Cloudflare credentials, dashboard tokens, personal data, or environment-specific secrets in `frontend/`, Vite build variables, or `frontend/dist`. Authentication exchanges the operator token for an HttpOnly server session; the React client does not persist that token in local or session storage. A non-HttpOnly CSRF companion cookie is readable by the client by design and is not an authentication credential.

Current generated recommendations require manual review and do not change DNS.
Scheduled scanning is a separate opt-in; saving a managed domain does not enable
it. Alerts are displayed in the application, not sent by email or webhook.
Older stored contact/remediation preferences are preserved for compatibility,
not offered as active delivery or automatic-change controls.

For a demonstration, use the [isolated fictional fixtures](screenshots/README.md)
and no real provider credentials or operational data. Prefer a local walkthrough
or recording; never expose the development fixture server publicly. Public
service exposure requires a separately reviewed deployment and access policy.
