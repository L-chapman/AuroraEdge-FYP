# NorthFlux Security: deep-debug review

Review date: 22 September 2026. Starting point: published revision `38e9e8b`.

## The short answer

NorthFlux is materially safer and more honest about its results after this review. The important changes are not extra decoration: failed checks no longer masquerade as reliable grades, DNS changes have stronger safeguards, cancelled monitoring work is checked before further changes, and reports preserve the actual evidence.

It is a substantial single-operator security tool with a React interface, repeatable tests and a Windows/Linux release process. It is **not** yet an independently audited, multi-customer security service. Passing tests do not mean every possible fault has been found, and a high score does not prove that email cannot be spoofed or that a domain is fully secure.

This review builds on AuroraEdge's existing scanner, policy rules, reporting, monitoring and Cloudflare integration. Those capabilities existed before the NorthFlux rename. The React migration, safer operating defaults, deployment work and this review strengthen that foundation; they should not be described as replacing a project that had no substance.

## What was reviewed

The investigation covered authentication and request handling; DNS, HTTPS and optional SMTP checks; rule interpretation; Cloudflare prerequisites and ownership; scheduled monitoring; SQLite persistence; React session and form behaviour; report exports; Windows/Linux launchers; source packaging; and GitHub Actions.

Confirmed problems received focused regression tests. Where practical, the new test was run against the unfixed behaviour first, then rerun after the correction. Independent code review found additional gaps in incomplete-scan handling, provider reads and monitoring cancellation, which were also reproduced and corrected.

Provider operations and scanner failure cases were mocked. Browser checks used disposable storage, synthetic domain responses and a disabled DNS write layer. The operator's live DNS, server configuration and existing project documents were not modified by these tests.

## Confirmed problems fixed

### 1. A failed check could look like a reliable result

Some DNS, SMTP and blocklist errors previously became ordinary missing records or apparently clean results. That could produce a misleading grade and leave automatic fixes available.

Scans now carry an explicit incomplete flag and an explanation when required observations cannot finish. This applies to timeouts, connection failures, refused destinations and blocklist service errors, including Spamhaus access/error responses that are not real listings. Ordinary negative DNS answers remain distinct from operational failures. The retired SORBS service was also removed from active queries; its operator [announced the shutdown in June 2024](https://www.mail-archive.com/mailop@mailop.org/msg22064.html).

Incomplete results keep their observations, but their saved grade and score are empty. They do not affect score averages or appear as an ordinary failing grade. The React scanner, domain cards, detail/history pages and PDFs show the uncertainty. Automatic remediation is not generated for an incomplete scan.

Existing databases gain the new flags without losing rows. Earlier saved grades are retained because older versions did not record enough information to retrospectively classify every scan. Run a fresh scan before relying on older evidence.

Evidence: [scanner regressions](../tests/test_scanner_deep_debug.py), [storage and migration tests](../tests/test_incomplete_scan_storage.py), [operator browser journeys](../frontend/e2e/operator-journeys.spec.ts).

### 2. Outbound checks needed stronger network boundaries

The scanner now validates public destinations before connecting and connects to the vetted numeric address. Private, mixed public/private and special-purpose destinations are rejected. MTA-STS HTTPS checks use certificate and hostname verification, do not follow redirects, do not inherit HTTP proxy environment settings, and limit response size and time. DNS and socket work share a bounded scan deadline.

These restrictions help prevent a submitted domain from turning the scanner into a way to reach private services. They are not a substitute for restricting server network access at the operating-system or hosting level.

Compatibility trade-off: a network that requires an outbound HTTP proxy, blocks public DNS or blocks SMTP port 25 may produce incomplete results. The scanner currently uses public DNS resolvers; this does not bypass those resolvers' caches or guarantee instant propagation. Connection attempts currently use the first vetted address, so a host with one broken address can fail despite another working address.

Evidence: [scanner implementation](../src/app/scanner.py) and [transport regressions](../tests/test_scanner_deep_debug.py).

### 3. Policy interpretation and DNS changes were too optimistic in several cases

The review corrected qualified SPF lookup counting, permissive bare `all`, duplicate SPF/DMARC handling, invalid DMARC values, revoked DKIM keys and MTA-STS policy validation. A returned web page is not accepted merely because the request succeeded.

Failed, paginated, malformed or ambiguous prerequisite DNS reads now stop a change rather than being treated as an absent record. Low-level mutation helpers enforce zone ownership. Worker preparation refuses conflicting host records or routes and requires observed mail hosts rather than a guessed wildcard policy. An absent SPF record no longer produces an automatic Google-mail assumption; DKIM setup remains manual because the correct provider key and selector cannot safely be guessed.

The connection-test response now distinguishes DNS read access from untested write permission. Listing records or Worker scripts does not prove that a token can edit them.

Evidence: [DNS safety regressions](../tests/test_dns_fix_deep_debug.py), [remediation and monitoring tests](../tests/test_remediation_monitoring.py), [integration guide](INTEGRATIONS.md).

### 4. Post-change verification could choose the most flattering result

The previous verification loop could select a higher provisional score from an incomplete scan, discard a later worse observation, and say that DNS changes were verified. An isolated reproduction returned grade A and a success message from an incomplete verification scan.

Verification now reports and stores the latest observation, including a lower score. An incomplete or failed verification cannot claim a post-change grade and reports a partial outcome. Cloudflare's reported records are described separately from public observations. An increased score is described as an observed improvement, not proof that every submitted change was verified. Cache-expiry advice no longer promises a universal 60-second propagation window.

Slow manual remediation runs outside the web request event loop, so propagation waits do not freeze ordinary page requests. Invalid or empty fix selections are rejected before contacting the provider.

Evidence: [request-boundary tests](../tests/test_request_boundaries.py) and [verification tests](../tests/test_remediation_monitoring.py).

### 5. Stopping monitoring needed checks after slow work

Scheduled work now rechecks the operator's monitoring setting and data generation before advancing, after a scan, before remediation, after slow provider validation and before each fix callback. Disabling automatic remediation or removing a domain while provider validation is underway prevents the subsequent queued change.

This is cooperative cancellation, not rollback. A provider request already sent cannot be recalled. A multi-step provider operation can still partially succeed, and changes made externally at the same time are not transactionally coordinated. Keep automatic remediation off until a controlled live trial and recovery exercise are complete.

Evidence: [scheduled-work regressions](../tests/test_remediation_monitoring.py).

### 6. Bad requests and partial settings writes caused avoidable failures

Wrong non-ASCII credentials no longer trigger an internal comparison error. Malformed/non-object JSON, invalid collection types, invalid safety switches and oversized values are rejected clearly. Request bodies are bounded before parsing, including bodies without a trustworthy declared length.

Settings are validated as a whole and saved in one database transaction. A bad field or database error cannot silently leave half of a settings change applied. Domain validation also enforces the total DNS name length.

Evidence: [request-boundary tests](../tests/test_request_boundaries.py).

### 7. Browser sessions, forms and generated records had edge cases

Pending session requests are cancelled during sign-out and authentication failure handling, preventing stale responses from restoring an old logged-in view. Cancelled API responses cannot incorrectly sign out a newer session. Domain detail state resets when navigating to another domain, avoiding stale confirmation targets.

Generated DNS text now respects TXT chunk limits, validates reporting-address edge cases and encodes mail addresses without double encoding. Incomplete results are visibly uncertain rather than green successes. The existing keyboard, narrow-screen, reduced-motion and security-policy checks remain in place.

The browser harness now quotes Python executable paths containing spaces on Windows and Linux. A new end-to-end journey checks incomplete scanning, onboarding, stored history and PDF access. Its navigation waits target the arriving page rather than typing into the outgoing page's identically named field. The first Linux pass also caught an incorrect helper expectation during the expired-session test: the application correctly redirected to login, while the helper expected the protected page. That expectation was corrected rather than weakening the application's session handling or adding automatic retries.

Evidence: [frontend tests](TESTING.md#frontend-unit-and-component-suite), [browser journeys](../frontend/e2e/operator-journeys.spec.ts), [launch-command tests](../frontend/test-support/launch-command.test.ts).

### 8. Exports lost values or overstated what was known

Visual PDF review found long details running outside the page and saved BIMI fields missing from the report. Details now wrap, stored raw evidence is merged with authoritative database fields, metadata is escaped, and incomplete reports clearly omit the grade. Record-presence labels say “Found”, not “PASS”: existence is not proof of a secure policy. Very long details have an explicit truncation notice.

CSV exports preserve `0`, `False` and empty values separately. Incomplete CSV rows have an explicit flag and no score/grade; Markdown marks them incomplete and excludes them from score summaries and grade distributions. Both retain uncertainty notes and storage warnings. Markdown escapes external text that could otherwise create extra rows or HTML. CLI storage failures no longer create a second contradictory scan row or discard completed reports; they preserve the result with a warning. Chart/statistics handling rejects non-finite scores and uses the configured report folder.

Evidence: [PDF tests](../tests/test_pdf_reports.py), [CLI tests](../tests/test_cli.py), [analysis tests](../tests/test_analysis.py). Complete and incomplete PDF samples were rendered and visually inspected during the local review.

### 9. Fresh setup and source releases needed more realistic checks

Launch checks now detect installed dependency drift rather than trusting a cache marker and successful imports alone. Source packaging handles Unicode/special filenames, rejects source links and unsafe output targets, and excludes additional database, log and environment-backup files. Tests exercise the real packager inside disposable Git projects.

CI still runs for pull requests and the default branch, but no longer duplicates the same feature-branch work on both a push and its pull request. A feature branch must have a pull request, or a manually requested workflow run, to receive the full remote checks. A later default-branch run after merging is intentional.

Evidence: [launcher tests](../tests/test_start.py), [packaging tests](../tests/test_release_packaging.py), [CI trigger tests](../tests/test_ci_triggers.py).

## Validation record

Local validation uses Windows, Python 3.12.10 and Node.js 24. The final evidence belongs to the exact reviewed revision, not automatically to future edits. The [GitHub workflow history](https://github.com/L-chapman/AuroraEdge-FYP/actions/workflows/ci.yml) records the separate Windows/Linux release gates; only a completed successful run is a pass.

| Check | Local review evidence |
|---|---|
| Python tests | 614 passed; 2 platform/privilege-dependent packaging cases skipped on this Windows host |
| Frontend unit/component tests | 111 passed across 16 files |
| Browser tests | 39 passed: 13 each in Chromium, WebKit and mobile Chromium; Linux CI is required for Firefox |
| Frontend quality | Type checking, lint, production build and scoped coverage checks |
| Python quality | Ruff and high-severity Bandit checks |
| Dependencies | Runtime/development Python sets and npm audit checked for known vulnerabilities |
| Secrets | Full Git history and changed source inspected with redacted secret scanning; clean release contents checked separately |
| Reports | Complete and incomplete PDF samples rendered and visually inspected |

The measured backend coverage is approximately **65% including branches**, not 100%. Important areas remain only partly covered, especially Cloudflare multi-step operations, older routes and analysis/chart paths. Frontend coverage is deliberately scoped to the client, domain validation and DNS generation modules: 93.85% statements, 90.17% branches, 97.87% functions and 96.65% lines. It is not whole-application coverage.

The local test framework emits an upstream deprecation warning; package audits can emit cache warnings while rebuilding stale cache entries. Those are not passing evidence for unsupported environments, but neither is an upstream warning automatically an application crash. No known dependency vulnerability was reported by the completed audits in this review. Recheck before subsequent releases.

Windows Firefox could not launch on this machine in the earlier local checks; it must not be counted as passed here. CI additionally covers Python 3.10/3.12 on Windows and Ubuntu, clean launch with Node 22.12/24, Linux's four browser profiles, Windows Chromium, and the restricted production container. The same backend suite runs 616 cases on Ubuntu, 615 with one filename-related skip on Windows CI, and 611 with five packaging-tool skips inside the restricted container. See [Testing](TESTING.md) for commands and the exact supported matrix.

## What should improve next

### Before enabling real automatic changes

1. **Run a controlled Cloudflare trial and recovery exercise.** Use an authorised test zone, least-privilege credentials and recorded original values. Test provider failures between steps and verify both DNS and audit records. This review did not perform a live write or Worker deployment.
2. **Make blocklist access deployable.** Public resolvers can be refused by blocklist providers. NorthFlux now reports that honestly as incomplete, but an operator-configured, provider-compatible resolver/access method needs explicit design and testing. Do not hide the error to regain a green score.
3. **Exercise backup, restore and rollback on the intended server.** Confirm restart behaviour, disk-full handling, retention and recovery with realistic history volumes. Keep a known-good application revision and data backup together.
4. **Get an independent security review before a public service launch.** Confirm reverse-proxy trust, HTTPS, rate limits, session behaviour and outbound network restrictions on the real deployment. No penetration-test or compliance certification is claimed here.

### Engineering priorities after that

5. **Split the large dashboard module into smaller units.** Separate authentication, scan jobs, monitoring, reports and provider orchestration. Preserve compatibility routes with contract tests. This will make future faults easier to isolate than continuing to add code to one large module.
6. **Introduce a bounded job queue and progress/cancellation model.** Long batches still occupy request workers; settings changes do not instantly wake an already sleeping monitoring cycle. Add explicit concurrency limits, per-domain change coordination, time budgets and operator-visible job status before scaling usage.
7. **Expand failure-path coverage before chasing a headline percentage.** Prioritise provider timeouts, partial multi-step success, token rotation during work, delayed responses, backup restoration, disk errors and simultaneous operator actions. Add broader accessibility checks and selected visual regression snapshots.
8. **Strengthen protocol completeness.** SPF checking is not a full sender-specific evaluator; DKIM uses common-selector discovery rather than verifying a signed message; organisational-domain DMARC inheritance is not implemented; optional STARTTLS grading checks capability/cipher, not SMTP certificate trust. The project does not ingest aggregate DMARC reports or simulate real mail delivery.
9. **Make installation more reproducible.** The frontend is locked, but Python's transitive dependencies are not fully locked. Add a deliberate update/lock process and test intended architectures/distributions; do not advertise every computer or runtime as certified.

### Business decisions, not automatic code changes

10. **Choose the intended product boundary.** A private operator console and a multi-customer hosted service need very different account isolation, permissions, billing, support and recovery designs. The current shared-token, single-process SQLite model suits the former, not the latter.
11. **Choose licensing and support terms.** No licence was invented on the owner's behalf. Public GitHub visibility alone does not establish a suitable commercial/open-source licensing policy.
12. **Keep claims tied to evidence.** Describe NorthFlux as an email-security assessment and controlled remediation tool. Avoid “100% secure”, “fully compliant” or “works on any computer”. Clear limitations make the project more credible to reviewers and prospective users.

## Bottom line

This release improves the project's most important qualities: safer changes, clearer uncertainty, more reliable state, more readable evidence and repeatable setup. It is better prepared for a controlled pilot and serious code review. The next milestone should be a documented live deployment/recovery trial, not a claim that all future bugs or production risks have been eliminated.
