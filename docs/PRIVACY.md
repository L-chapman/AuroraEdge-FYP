# NorthFlux Security privacy and operating boundaries

NorthFlux Security evaluates public DNS records, public MTA-STS policy files, public mail-routing information, and externally visible SMTP transport behaviour. It does not log in to mailboxes, read messages, collect message bodies, or test credentials.

Local state can contain domain names, scan timestamps, findings, organisation settings, contact details entered by an operator, Cloudflare identifiers, and—in local development—Cloudflare credentials entered through Settings. Reports and logs can contain the same domain-security information.

In production, Cloudflare tokens, global API keys, and the associated account email are read from the runtime environment and are not copied into SQLite. If an older database contains one of those values, NorthFlux ignores it; once a replacement environment value is supplied, the legacy stored value is removed.

Operators should:

- scan and remediate only within their authority;
- treat generated reports as security-sensitive operational data;
- restrict access to the application and its storage;
- set an appropriate retention period for scan history, reports, alerts, and logs;
- back up and securely delete data according to their own policy;
- supply production credentials through a protected runtime secret mechanism;
- review applicable law and organisational policy for their jurisdiction and use case.

NorthFlux does not make a categorical legal determination about scanning. Its technical scope is limited to public-facing configuration checks and explicitly authorised DNS changes.

The application is self-hosted. It does not intentionally send scan history or application analytics to the project maintainer. Network requests required for operation go to the target domain's public services, DNS resolvers, configured Cloudflare APIs, and any external resources explicitly used by the dashboard such as the Chart.js CDN.

For a public demonstration, disable Cloudflare credentials and automatic remediation, use a dedicated non-sensitive dataset, and avoid exposing internal domain names or infrastructure details.
