# NorthFlux Security: function and feature audit

Review date: 23 September 2026. Starting revision: `099a0e2` (the previous deep-debug release).

This document records the audited snapshot, not a fresh test run for every later revision. The retired academic demo scripts and their script-specific tests were removed during the subsequent product cleanup. Their references below link to the preserved [audited source snapshot](https://github.com/L-chapman/AuroraEdge-FYP/tree/c94064f4a91b1e19ec14771e91bdfd4626ae9b19); historical review counts and test results are unchanged.

## What this review means

This is a second code review and debugging pass, not a repetition of yesterday's test run. It examines the application by feature and implementation function, checks failure paths, researches current primary sources, and adds regression tests for confirmed faults.

The result is a safer configuration-assessment tool. It is **not** proof that every possible input or line execution has been tested, a penetration-test certificate, or a claim of feature parity with a commercial mail-security service. Reading a function, testing one path, and testing every branch are different kinds of evidence. The inventory below distinguishes them. The previous [deep-debug review](DEEP_DEBUG_REVIEW.md) remains the record for the earlier revision.

No live DNS changes, Worker deployment, production-server changes or paid product subscriptions were made. Provider writes in regression tests are simulated. One early legacy-script reproduction made read-only lookups against the reserved example domain before its missing scanner mock was corrected; it did not write DNS. The suite now isolates storage and credentials before imports and blocks unmocked external HTTP, resolver calls and external socket connections. Loopback remains available for local test infrastructure.

## Comparison with working products

The comparison uses the products' own documentation, not an invented feature checklist or a copied score. No identical-domain head-to-head benchmark or paid account evaluation is claimed.

| Reference | What its documentation establishes | What that means for NorthFlux |
|---|---|---|
| [dmarcian Domain Checker](https://dmarcian.com/domain-checker/) | Inspects SPF, DKIM and DMARC records, distinguishes inherited DMARC policies, and allows a specific DKIM selector when common-selector discovery finds nothing. | NorthFlux's direct-record checks and common-selector search are narrower. Not finding a selector is not proof that a sender never signs mail. Inherited-policy discovery is still a gap. |
| [MXToolbox Email Health](https://mxtoolbox.com/emailhealth) | Combines checks across email, DNS, web and reputation configuration. | There is useful overlap, but a NorthFlux grade is not an MXToolbox verdict. Compare individual observed records and failures, not headline scores. |
| [Internet.nl email test](https://internet.nl/test-mail/) | Tests IPv6, DNSSEC, mail authentication, STARTTLS/DANE and RPKI. | NorthFlux does not implement the full transport, routing or DNSSEC assessment. Its optional STARTTLS check is not certificate-identity validation or a DANE test. |
| [Red Sift OnDMARC reports](https://knowledge.ondmarc.redsift.com/en/articles/1245210-what-data-does-ondmarc-process-and-store) | Processes aggregate reports containing sender information, message counts and authentication results. | NorthFlux does not ingest those reports or inspect real messages. Its scan history records configuration observations, not delivered-message compliance. |
| [Microsoft's DMARC rollout guidance](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dmarc-configure) | Recommends a staged rollout with monitoring and sender review before enforcement. | A scan must not invent authorised senders, reporting mailboxes or evidence that stricter enforcement is safe. These recommendations now require manual review. |

The most important alignment is behavioural: preserve evidence, explain unknown results, validate protocols, and avoid changes that cannot be justified. Matching a vendor's appearance or score would not establish correctness.

## Current standards: an important compatibility limit

[RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html), published in May 2026, supersedes RFC 7489 and RFC 9091. It changes policy discovery to a DNS tree walk, adds `np`, `psd` and `t`, and removes `pct`, `rf` and `ri` from the current specification. It also warns against treating `p=reject` as a universal policy for general-purpose domains.

NorthFlux is not a complete RFC 9989 receiver implementation. It retains direct-record inspection and legacy compatibility; newer unsupported policy tags require review rather than a confident grade. The generator labels percentage controls as legacy: they cannot guarantee that modern receivers enforce a chosen fraction. Full policy discovery, message alignment and aggregate-report processing need a separate designed migration, not a hurried parser change.

Other protocol corrections are based on [SMTP reply framing and routing, RFC 5321](https://www.rfc-editor.org/rfc/rfc5321), [SPF evaluation, RFC 7208](https://www.rfc-editor.org/rfc/rfc7208), [DKIM key records, RFC 6376](https://www.rfc-editor.org/rfc/rfc6376), [null MX, RFC 7505](https://www.rfc-editor.org/rfc/rfc7505), and [TLS reporting, RFC 8460](https://www.rfc-editor.org/rfc/rfc8460). NorthFlux's limited inspection must not be presented as full conformance with all of those protocols.

## Confirmed defects and corrections

### Scanner and record interpretation

- SMTP replies can arrive in fragments and span several lines. The scanner now reads complete bounded replies and checks the actual STARTTLS extension, not a substring.
- SPF lookup estimation now counts repeated evaluated include branches and stops at unreachable terms after `all`. It remains an estimate, not sender-specific SPF evaluation.
- DKIM inspection accepts an omitted optional version tag, checks duplicate/invalid fields and key encoding, and recognises the testing flag as a token rather than a substring. Finding a record does not verify a signed message.
- TLS-RPT requires one usable record and valid reporting destinations. Existing HTTPS destinations must not be rewritten into invented mail addresses.
- DMARC whitespace is interpreted consistently. Newly unsupported policy semantics are surfaced rather than silently scored.
- Intentional null MX is identified as “no incoming mail”, not an empty hostname. Receiving-only checks become inapplicable, while outgoing identity controls remain independently assessed.
- Address-only subdomains are no longer assumed nonexistent just because they have no NS or MX record.
- Provider detection uses domain-label boundaries, not substrings that an unrelated hostname can imitate. Google DKIM guidance no longer invents a CNAME requirement.

Evidence: [protocol regressions](../tests/test_protocol_standards.py), [scanner](../src/app/scanner.py), [rules](../src/app/rules.py).

### DNS changes and operator control

- Every currently generated DNS recommendation is manual: sender inventory, a real reporting destination, or verified TLS/certificate readiness cannot be established from this scan alone. A higher hypothetical score is not authority to change mail handling. Manual-only guidance has its own `manual_review` outcome, not a false failure or success.
- Onboarding rechecks operator cancellation after slow provider reads. Disabling remediation, deleting history or removing a domain prevents subsequent queued changes.
- Manual changes capture cancellation state before provider checks and stop when that state changes. Failed settings reads do not fall back to stale credentials.
- Manual and scheduled changes for the same domain cannot run concurrently within the supported single application process. A second attempt receives a conflict instead of queuing a stale change.
- An incomplete post-onboarding verification does not receive a score, grade or “improved” claim.
- Worker naming includes the full domain identity, avoiding dot/hyphen collisions. Existing infrastructure is not silently overwritten; malformed or incomplete provider inventories block deployment and legacy deployments require review.
- At the audited snapshot, legacy scripts that deliberately weaken a live demo domain were quarantined. Their write entry points stopped before provider access; the web reset endpoint was retired. Offline demonstrations and explicit read-only lab checks were retained then; the standalone demo scripts have since been removed from the current product.

These are cooperative checks, not transactional rollback. An already submitted provider request cannot be recalled. A multi-step change can still partially succeed, and another application or administrator is outside the in-process lock.

Evidence: [API/storage regressions](../tests/test_function_audit.py), [legacy-script safeguards at the audited snapshot](https://github.com/L-chapman/AuroraEdge-FYP/blob/c94064f4a91b1e19ec14771e91bdfd4626ae9b19/tests/test_legacy_script_safety.py), [provider implementation](../src/app/dns_fix.py).

### Storage, search and authentication

- Search handles unknown scores and grades without crashing, never treats an unknown score as zero, and does not resurrect deleted results from an old CSV when the database is authoritative.
- A database failure is an error, not an empty successful search result.
- Saved detail/history/search responses retain newer observations from the extensible snapshot; the database's persisted grade and timestamps remain authoritative.
- An individual failed save rolls back both the result and its domain summary. An unrelated later write cannot commit half of the failed operation.
- Deleting one domain's history preserves unrelated in-progress scans and recounts surviving batch results.
- Even an intentionally open local-development instance rejects browser write requests from unrelated origins. Existing authenticated session/CSRF checks remain in place; this follows the origin-checking principles in [OWASP's CSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
- An existing event stream rechecks authority and stops sending report updates after sign-out, expiry or token rotation.
- Report downloads reject unrelated file types, escaped paths and Windows alternate streams. Latest-report discovery excludes directories and links escaping report storage. Download and PDF responses are not cacheable.

Evidence: [function-audit regressions](../tests/test_function_audit.py), [request-boundary tests](../tests/test_request_boundaries.py), [database](../src/app/database.py).

### Interface and reports

- A successful HTTP response no longer makes every DNS outcome green. The interface separately shows submitted actions, failures, manual steps and uncertain verification. Pre-change grades are not left looking like post-change grades.
- Unsaved scan results no longer link to an older, unrelated saved result for the same domain.
- Login preserves the intended destination's query and fragment. The scan tabs support arrow, Home and End navigation.
- A pending domain-enrolment request cannot silently discard a new draft; validation errors are readable without echoing sensitive input.
- BIMI URLs cannot inject additional tags through literal semicolon delimiters.
- Console and aggregate reports, like CSV/Markdown, exclude incomplete provisional grades. All-unknown results remain unknown rather than becoming a false zero average.
- Console colour formatting no longer mutates the log record shared with file/JSON handlers. Repeated logging setup does not duplicate owned handlers or suppress audit entries at a warning-level root setting.
- Development-only fallback pages now preserve incomplete evidence, distinguish record presence from correctness, and no longer advertise the retired live-DNS demo. Their generator no longer mistakes IPv4 CIDR for IPv6 or replaces `pct=0` with 100.
- Stored credentials are labelled configured, not verified; the interface explains that local database credentials are plaintext and provider requests transmit credentials over HTTPS. The offline smoke output no longer claims to test authentication or competing products.

Evidence: [frontend component and browser tests](TESTING.md), [CLI tests](../tests/test_cli.py), [analysis tests](../tests/test_analysis.py), [logging regressions](../tests/test_logging_config.py).

### Setup, packaging and test safety

- Tests previously capable of using the operator's default database now use disposable storage. Process credentials and runtime locations are isolated before application imports; unmocked external network calls are blocked during the Python suite.
- CLI domain input is validated before creating output; UTF-8 BOM domain lists are read correctly. An older test using the wrong fake-scanner signature was corrected to verify actual successful rows.
- The demo launcher no longer clears an inherited access token.
- Source ZIP exclusions cover case-insensitive environment files and SQLite sidecars. Literal backslash filenames on Linux are rejected before ZIP path conversion can turn them into extraction paths.
- The core Windows/Linux launcher's functions, requirements checks, cache validation and shutdown flow were reviewed again. No new launcher logic defect was confirmed in this pass; the full fresh-start matrix is separate execution evidence.

Evidence: [test isolation](../tests/conftest.py), [packaging regressions](../tests/test_release_packaging.py), [launcher tests](../tests/test_start.py).

## Function-review inventory

The following groups identify the functions inspected and the relevant test suites. This is a review map, **not** a statement that every branch of every function was executed. Nested helpers belong to their containing function. Data-only model/branding modules were inspected as contracts/configuration, not counted as tested functions. Test functions themselves were reviewed for fixtures, assertions and side effects; dependencies in virtual environments and generated build files are outside this source review.

| Source / function group | Review focus and execution evidence |
|---|---|
| `scanner.py`: domain validation, resolver/deadline helpers, public-address connections, SMTP reply/STARTTLS helpers, TXT/MX/SPF/DKIM/MTA-STS/TLS-RPT/BIMI/DNSBL helpers, `_domain_exists`, `_usable_dmarc`, `_empty_result`, `_scan_domain`, `scan_domain` | Protocol boundaries, safe destinations, record ambiguity, budgets and incomplete results. Scanner, recursion, misconfiguration and protocol suites. |
| `rules.py`: every `rule_*`, `evaluate`, `generate_remediation`, explanation lookups | Whether evidence justifies a finding, grade or proposed change; null-MX applicability and explicit uncertainty. Rules, remediation, protocol and misconfiguration suites. |
| `dns_fix.py`: every `CloudflareDNS` method; client factory and comparison report | Authentication, ownership, prerequisite reads, protocol-specific targeting, direct writers, provider guidance, Worker steps and generated recommendations. Mocked provider/safety suites; no live certification. |
| `database.py`: connection lifecycle/locking, schema setup, every scan/result/history/statistics/domain/settings/alert method, singleton factory | Transaction boundaries, additive schema changes, concurrent reads, deletion generation, partial saves and batch consistency. Database, API, incomplete-storage and function-audit suites. |
| `dashboard.py`: domain/environment/escaping helpers, sessions/origin/CSRF, login throttling, `require_token`, lifecycle and security middleware | Authentication boundaries, browser authority, configuration loading and safe defaults. Auth, business-safety, request-boundary and API suites. |
| `dashboard.py`: all `api_v1_*`, metadata/normalisation helpers, `api_*` scan/history/search/settings/domain/alert functions | Typed contracts, honest storage errors, explicit actions and extended evidence. API, request-boundary, incomplete-storage and function-audit suites. |
| `dashboard.py`: `_serialise_domain_remediation`, `_auto_fix_domain`, `_apply_fix_sync`, `_monitoring_loop` and their route wrappers | Provider work off the event loop, cancellation, overlap prevention and honest verification. Remediation/monitoring and function-audit suites. |
| `dashboard.py`: CSV/statistics helpers, event stream, report downloads, `api_pdf_report`, readiness and React serving helpers | Read-only navigation, summaries, file boundaries, cache policy and session revocation. Dashboard, PDF, React-serving and function-audit suites. PDF formatting was reviewed in the previous pass; no new independent visual PDF certification is claimed here. |
| `dashboard.py`: legacy HTML/JavaScript generators and page functions | Static template review and focused regression checks. These are deprecated development-only pages, not a second fully supported UI or a full legacy-browser test matrix. |
| `request_security.py`: credential comparison, JSON-object parsing, request-size middleware and replay helpers | Malformed text, non-object JSON and bounded body handling. Request-boundary and authentication suites. |
| `cli.py`: every function including concurrent scan worker, fix application, CSV/Markdown/console/remediation output and entry point | Input validation, incomplete results, persistence errors and explicit provider actions. CLI/domain-list suites; provider writes mocked. |
| `analysis.py`: every loader/statistics/chart/report helper and entry point | Missing/nonfinite/incomplete data, denominators, output paths and escaping. Analysis suite; not a pixel-by-pixel review of every chart permutation. |
| `logging_config.py`: both formatters, handler factories/setup, module configuration, event helpers and `ScanLogger` methods | Handler ownership, shared-record mutation and audit visibility. Logging and CLI suites. |
| `runtime_paths.py`, `start.py`: all path and launcher functions | Portable path resolution, prerequisites, setup reuse, environment preservation, port/readiness/assets and shutdown. Launcher/runtime tests and separate fresh-start CI. |
| `scripts/`, shell launchers, `verify_system.py`, Docker/Compose and CI | Legacy mutation hazards, isolated browser fixture, source packaging, launch environment and release gates. Script-safety, packaging, launcher, offline smoke and CI tests. |
| `frontend/src/`: API client, session provider, routing, all page/components and domain/DNS-generator utilities | State transitions, errors, draft retention, unknown data, dangerous-action outcomes, keyboard behaviour and escaping. Unit/component suites and isolated real-browser journeys; no claim that all render combinations are exercised. |

<details>
<summary>Named Python review index (316 top-level functions and class methods)</summary>

Names are listed from the reviewed source, grouped by module; nested callbacks are covered with their parent. This is an inspection index, not a per-function coverage certification.

- [src/app/analysis.py](../src/app/analysis.py): `ensure_figures_dir`, `load_latest_csv`, `_median`, `_scores`, `_present`, `_chart_output`, `_report_cell`, `calculate_statistics`, `generate_grade_chart`, `generate_check_presence_chart`, `generate_violation_chart`, `generate_dmarc_policy_chart`, `generate_score_histogram`, `generate_all_charts`, `generate_summary_report`, `main`.

- [src/app/cli.py](../src/app/cli.py): `get_severity_color`, `get_grade_color`, `apply_dns_fixes`, `scan_domains`, `_incomplete_result`, `_report_notes`, `write_csv`, `_markdown_cell`, `write_markdown`, `print_summary`, `print_remediation`, `main`.

- [src/app/dashboard.py](../src/app/dashboard.py): `_sanitize_domain`, `_is_enabled`, `_is_production`, `_escape`, `_escape_record`, `_token_fingerprint`, `_create_session`, `_get_session`, `_expected_origin`, `_require_session_csrf`, `_load_cf_runtime_settings`, `lifespan`, `SecurityHeadersMiddleware.dispatch`, `_rate_check`, `_login_rate_check`, `_record_login_failure`, `_clear_login_failures`, `_custom_http_exception`, `_react_frontend_enabled`, `_react_frontend_available`, `_spa_index_response`, `_env`, `require_token`, `login_page`, `privacy_page`, `login`, `logout`, `_auth_state`, `_parse_api_timestamp`, `_normalise_score`, `_normalise_grade`, `_dashboard_settings`, `api_v1_auth_session`, `api_v1_auth_login`, `api_v1_auth_logout`, `api_v1_bootstrap`, `api_v1_dashboard`, `_contained_report`, `list_csvs`, `load_csv`, `_latest_pair`, `_severity_counts`, `_grade_counts`, `_score_stats`, `_check_for_updates`, `health`, `_directory_writable`, `readiness`, `stream_updates`, `api_runs`, `api_latest`, `api_summary`, `_saved_scan_evidence`, `api_domain`, `api_search`, `api_stats`, `api_severity_explanation`, `api_rule_explanation`, `api_all_explanations`, `api_tool_comparison`, `api_history`, `api_delete_history`, `_validated_reports_root`, `_clear_generated_reports`, `api_clear_all_data`, `api_rescan_domain`, `download_latest`, `download_file`, `api_pdf_report`, `api_managed_domains`, `api_add_managed_domain`, `api_remove_managed_domain`, `api_get_settings`, `api_save_settings`, `_apply_cf_settings`, `_serialise_domain_remediation`, `_auto_fix_domain`, `api_test_cloudflare`, `api_get_alerts`, `api_acknowledge_alert`, `_monitoring_loop`, `_auth_js`, `_css`, `_js`, `home`, `_build_report_dashboard`, `_test_css`, `_test_js`, `api_scan`, `api_apply_fix`, `_apply_fix_sync`, `api_demo_reset`, `api_fix_status`, `test_hub`, `domain_detail`, `_nav_html`, `_footer_html`, `domains_page`, `generator_page`, `settings_page`, `react_asset`, `react_spa_fallback`.

- [src/app/database.py](../src/app/database.py): `_with_connection_lock`, `_default_db_path`, `NorthFluxDatabase.__init__`, `NorthFluxDatabase.__enter__`, `NorthFluxDatabase.__exit__`, `NorthFluxDatabase._init_db`, `NorthFluxDatabase.start_scan`, `NorthFluxDatabase.save_result`, `NorthFluxDatabase._save_result_inner`, `NorthFluxDatabase.complete_scan`, `NorthFluxDatabase.get_data_generation`, `NorthFluxDatabase.write_scan_results`, `NorthFluxDatabase.snapshot`, `NorthFluxDatabase.ping`, `NorthFluxDatabase.get_latest_results`, `NorthFluxDatabase.get_domain_history`, `NorthFluxDatabase.get_scan_results`, `NorthFluxDatabase.get_scans`, `NorthFluxDatabase.get_statistics`, `NorthFluxDatabase.get_domains_by_grade`, `NorthFluxDatabase.get_improvement_candidates`, `NorthFluxDatabase.close`, `NorthFluxDatabase.add_managed_domain`, `NorthFluxDatabase.add_managed_domain_if_generation`, `NorthFluxDatabase.remove_managed_domain`, `NorthFluxDatabase.get_managed_domains`, `NorthFluxDatabase.update_managed_domain_scan`, `NorthFluxDatabase._update_managed_domain_scan_inner`, `NorthFluxDatabase.get_setting`, `NorthFluxDatabase.set_setting`, `NorthFluxDatabase.set_settings`, `NorthFluxDatabase.delete_setting`, `NorthFluxDatabase.clear_scan_data`, `NorthFluxDatabase.delete_domain_history`, `NorthFluxDatabase.get_all_settings`, `NorthFluxDatabase.create_alert`, `NorthFluxDatabase.get_alerts`, `NorthFluxDatabase.acknowledge_alert`, `NorthFluxDatabase.get_alert_count`, `get_database`.

- [src/app/dns_fix.py](../src/app/dns_fix.py): `CloudflareDNS.__init__`, `CloudflareDNS._extract_error`, `CloudflareDNS._log_audit`, `CloudflareDNS._request`, `CloudflareDNS.validate_connection`, `CloudflareDNS.verify_domain_ownership`, `CloudflareDNS.get_txt_records`, `CloudflareDNS.get_txt_record`, `CloudflareDNS._matches_txt_protocol`, `CloudflareDNS.create_or_update_txt`, `CloudflareDNS._ensure_ownership`, `CloudflareDNS.fix_spf`, `CloudflareDNS.fix_dmarc`, `CloudflareDNS.fix_tls_rpt`, `CloudflareDNS.fix_mta_sts_dns`, `CloudflareDNS.detect_email_provider`, `CloudflareDNS.get_cname_record`, `CloudflareDNS.create_or_update_cname`, `CloudflareDNS.get_a_record`, `CloudflareDNS.create_or_update_a`, `CloudflareDNS._delete_a_record`, `CloudflareDNS.fix_dkim`, `CloudflareDNS.get_account_id`, `CloudflareDNS._mta_worker_name`, `CloudflareDNS._complete_inventory`, `CloudflareDNS.deploy_mta_sts_worker`, `CloudflareDNS.generate_fixes`, `get_cloudflare_client`, `generate_comparison_report`.

- [src/app/logging_config.py](../src/app/logging_config.py): `ColoredFormatter.format`, `JSONFormatter.format`, `create_rotating_handler`, `_remove_owned_handlers`, `setup_logging`, `configure_module_loggers`, `get_logger`, `ScanLogger.__init__`, `ScanLogger.__enter__`, `ScanLogger.__exit__`, `ScanLogger.info`, `ScanLogger.warning`, `ScanLogger.error`, `log_scan_event`, `log_audit_event`.

- [src/app/request_security.py](../src/app/request_security.py): `constant_time_equal`, `json_object`, `RequestSizeLimitMiddleware.__init__`, `RequestSizeLimitMiddleware.__call__`.

- [src/app/rules.py](../src/app/rules.py): `get_severity_explanation`, `get_rule_explanation`, `rule_mx_missing`, `rule_spf_missing`, `rule_spf_lookups`, `rule_spf_all_permissive`, `rule_spf_softfail`, `rule_dmarc_missing`, `rule_dmarc_none`, `rule_dmarc_quarantine`, `rule_dmarc_pct`, `rule_dmarc_no_rua`, `rule_dkim_missing`, `rule_dkim_test`, `rule_mta_sts_missing`, `rule_mta_sts_mode`, `rule_tls_rpt_missing`, `rule_starttls_weak`, `rule_no_reject_policy`, `rule_bimi_missing`, `rule_rbl_listed`, `rule_dmarc_sp_weak`, `evaluate`, `generate_remediation`.

- [src/app/runtime_paths.py](../src/app/runtime_paths.py): `resolve_runtime_dir`, `get_state_dir`, `get_reports_dir`, `get_logs_dir`.

- [src/app/scanner.py](../src/app/scanner.py): `_scan_error`, `_remaining_timeout`, `_fresh_resolver`, `is_valid_domain`, `_public_addresses`, `_connect_public`, `_socket_deadline`, `_smtp_reply`, `_starttls_check`, `_check_mx_starttls`, `_txt`, `_mx`, `_spf_fetch`, `_spf_count`, `_parse_tags`, `_dkim_discover`, `_fetch_mta_sts_policy`, `_mta_sts`, `is_valid_tls_report_uri`, `_tls_rpt`, `_bimi`, `_resolve_a`, `_check_rbl`, `_mx_blacklist_check`, `_empty_result`, `_domain_exists`, `_usable_dmarc`, `_scan_domain`, `scan_domain`.

- [start.py](../start.py): `run`, `node_version`, `prerequisites`, `npm_command`, `venv_python`, `ensure_venv`, `fingerprint`, `environment_signature`, `prepare`, `local_environment`, `check_port`, `wait_ready`, `stop_server`, `verify_react_assets`, `serve`, `main`.

- [verify_system.py](../verify_system.py): `setup_stdout_logging`, `parse_args`, `build_fallback_result`, `redirect_logging_to_stdout`, `choose_scan_result`, `main`.

- [scripts/demo_prep.py (retired; audited snapshot)](https://github.com/L-chapman/AuroraEdge-FYP/blob/c94064f4a91b1e19ec14771e91bdfd4626ae9b19/scripts/demo_prep.py): `_db_path`, `_get_cf_creds`, `_cf_headers`, `_find_records`, `_delete_record`, `_create_record`, `break_records`, `restore_records`, `main`.

- [scripts/e2e_server.py](../scripts/e2e_server.py): `_clean_runtime_root`, `_close_test_database`, `deterministic_scan`.

- [scripts/lab_experiment.py (retired; audited snapshot)](https://github.com/L-chapman/AuroraEdge-FYP/blob/c94064f4a91b1e19ec14771e91bdfd4626ae9b19/scripts/lab_experiment.py): `LabExperiment.__init__`, `LabExperiment.run_detection_test`, `LabExperiment.run_fix_test`, `LabExperiment.wait_for_dns_propagation`, `LabExperiment.run_full_experiment`, `LabExperiment.generate_report`, `main`.

</details>

The React review also covered every production component and its callbacks: routing/session protection, shell/navigation, dashboard, scan, domain list/detail, settings, sign-in, privacy/not-found pages, shared controls, API decoding, domain validation and each SPF/DMARC/MTA-STS/TLS-RPT/BIMI generator. Entry/configuration files and styles were inspected; dependency implementations were not line-audited.

## Verification record

The final local integration snapshot on Windows with Python 3.12.10 passed **741 Python tests**, with **5 skips** and one dependency deprecation warning. The skips are three unavailable file-symlink cases and two Linux-only filename cases; those require the Linux CI run. The warning concerns Starlette's use of an older AnyIO alias and is not a failing test.

Measured backend coverage is **71.42% combined statement/branch coverage**: 3,427/4,622 statements (74.15%) and 1,021/1,606 branches (63.57%). This is not 100% coverage. The isolated logging-loader tests execute separately from the measured `app` module identity, so their file is conservatively reported at 0% in this run. Lower-coverage areas include optional chart/report generation, provider deployment and legacy orchestration.

The React suite passed **140 tests in 19 files**, type checking, linting and the production build. Coverage gates cover only the API client, domain utilities and DNS generator: 93.91% statements, 89.59% branches, 98% functions and 97.23% lines. They are not whole-interface coverage figures. Windows browser runs passed **45 tests** (15 each in Chromium, WebKit and mobile Chromium) twice before the final manual-review wording adjustment; final wording is unit-tested and the published revision must pass its own browser CI.

Python syntax/undefined-name checks, high-severity static security checks, declared Python runtime/development dependency audits, the frontend dependency audit and isolated offline smoke check passed. These tools reported no known dependency vulnerabilities, not an absence of all possible security faults. Documentation-link and archive-safety regressions are included in the Python suite.

The [GitHub workflow](https://github.com/L-chapman/AuroraEdge-FYP/actions/workflows/ci.yml) records cross-platform execution for each published revision: Windows/Linux Python 3.10/3.12, clean launchers with Node 22.12/24, Linux Chromium/Firefox/WebKit/mobile and Windows Chromium, container startup, full-history secret scanning and release packaging. Use the matching revision's completed checks, not the existence of a configured job or a previous green badge. The local figures above do not substitute for that CI evidence.

## What still needs work

1. **Current DMARC policy discovery and real-message evidence.** Design RFC 9989 tree-walk handling and compatibility tests, configurable DKIM selectors, and reporting ingestion if a managed-service feature set is the goal. Do not market this as already implemented.
2. **A guided, approved change plan.** Collect authorised senders and real reporting destinations, show the exact proposed change, retain original values, and validate TLS readiness before allowing enforcement. Existing low-level writers are not a substitute for that approval workflow.
3. **Controlled live provider and recovery testing.** Use an authorised disposable zone and a rollback plan; exercise partial Worker/DNS failure, backup restoration, credential rotation and restart on the actual server.
4. **Reduce the large dashboard module.** Separate routing, authentication, monitoring, persistence orchestration and reporting behind contract tests. Retire the deprecated interface through a deliberate compatibility plan.
5. **Capacity and failure-path work.** Add a bounded job queue with progress/cancellation, improve provider-compatible blocklist access, and expand tests for disk failure, delayed responses and shutdown. The single-process domain lock does not make this horizontally scalable.
6. **Production assurance.** Independent security review, deployment-specific HTTPS/access controls, licensing decisions and unsupported-platform testing remain necessary. Named users, roles and customer isolation are still absent.

## Cursor attribution request

The repository collaborator list and contributors API showed only `L-chapman` during this review. Five older published commits contain a Cursor co-author trailer. That is historical commit metadata, not current repository access.

Removing those trailers requires rewriting published history and changes descendant commit IDs. A backed-up rewrite and force-push were offered as a separate choice; no history rewrite was performed without that confirmation. GitHub also documents that [contributor displays can take time to refresh after history changes](https://docs.github.com/en/repositories/viewing-activity-and-data-for-your-repository/viewing-a-projects-contributors). Do not treat deleting a collaborator or editing the README as removal of historical co-authorship.
