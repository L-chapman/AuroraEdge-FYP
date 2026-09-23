# NorthFlux improvement plan

Started 23 September 2026. This is an implementation tracker, not a claim that
the entire backlog is complete. Historical academic documents remain evidence
of earlier work, not current product requirements.

## Baseline and first review

- Starting branch: `master`, clean working tree.
- Starting revision: `b93e003974a753f0ac5f91ea57e5b80a79febe16`.
- [Matching independent Windows/Linux run](https://github.com/L-chapman/AuroraEdge-FYP/actions/runs/35810621797): all 15 jobs passed.
- The proposed brief reviewed `c94064f4a91b1e19ec14771e91bdfd4626ae9b19`.
  The newer revision removes retired standalone demo tools, preserves their
  historical evidence and improves release cleanup. It does not implement the
  remaining feature backlog.
- The first increment was developed in a separate checkout on
  `codex/nf-01-02-capability-evidence`. After owner approval it was merged as
  `9e12eed5e98b1907548e648103743d9332bc4a14` on 23 September 2026.
  The next bounded extraction uses `codex/nf-03-auth-state`; tests never use
  the installed application's data.

Confirmed defects: React exposed an active-looking automatic-remediation
control and an editable reserved email field; other pages confused a saved
managed domain with an enabled scanning schedule. Current recommendations are
manual-only and notifications remain in-app.

Already present: React, FastAPI, SQLite history, reporting, scheduled scanning,
authentication, CSRF protection, Windows/Linux launchers, container packaging
and cross-platform tests. These do not need another rewrite.

Not established: a deployed homelab instance, live provider-write validation,
macOS/ARM operation, message-level DMARC reporting, named users or multi-customer
isolation. Larger design improvements below are proposals, not all defects.

## Delivery stages

| Ticket | Scope | Status / gate |
|---|---|---|
| NF-00 | Reconfirm source, guidance, clean state and test evidence | Baseline recorded; current-change tests recorded separately |
| NF-01 | Truthful controls and labels; preserve compatibility settings | Verified and merged with owner approval in PR #7 |
| NF-02 | Fictional-data demonstration, screenshots and readable evidence | Verified and merged with owner approval in PR #7 |
| NF-03 | Extract backend responsibilities behind characterisation tests | First authentication-state extraction implemented and locally verified; separate PR checks/review gate. Broader router/service extraction remains separate |
| NF-04 | Validate important API responses and keep contracts aligned | Planned after agreed boundaries; preserve existing paths and error semantics |
| NF-05 | Bounded scan jobs, real progress, cooperative cancellation | Separate design/review; preserve deletion and persistence safeguards |
| NF-06 | Cross-platform Python locking and stronger test evidence | Separate dependency-only/reliability reviews; no global installs or lowered gates |
| NF-07 | Consistent backups, isolated restore and tested migrations | Separate data-safety review; never replace live state in a test |
| NF-08 | Private homelab deployment and recovery exercise | Requires an approved host, storage and exposure scope |
| NF-09 | Private metrics and monitoring examples | Requires NF-08 for actual deployment/alert evidence; no real notification without an approved destination |
| NF-10 | Bounded selectors, policy discovery and honest provider limits | Separate protocol increments with primary-source research and deterministic fixtures |
| NF-11 | Bounded authenticated DMARC XML import | Optional major feature; requires parser/data-model review and abuse-case tests |
| NF-12 | Optional disabled-by-default webhook delivery | Separate feature; mock delivery first, approved destination before any real send |
| NF-13 | Dry-run DNS plans, explicit approval and conflict handling | Separate consequential design; no live write without approved zone, records, credential and recovery plan |
| NF-14 | Licensing, users/roles, scaling and repository policy | Owner decisions; deliberately not enabled by this backlog |

## First pull request

NF-01 and NF-02 belong together: the screenshots and reviewer path should show
the corrected interface. This stage does not add an API schema, enable DNS
writes, deliver email, alter a database schema or deploy a service.

1. Remove unsupported capabilities from the editable form and omit their keys
   from saves, retaining old values without using them as a feature promise.
2. Align supported pages and guides with scheduled scans, manual review,
   in-app alerts and read-only connection checks.
3. Cover legacy settings, scan/domain workflows and no-write behaviour with
   component, API and browser regressions using disposable state.
4. Refresh fictional-data screenshots from the tested build, inspect them and
   add an explainable reviewer path. Do not claim a recording was made.
5. Run the complete CI matrix on the review revision. Record failures and
   limits as well as passes in [Release evidence](RELEASE_EVIDENCE.md).

Each stage is a small reviewable pull request. A successful check is not merge
approval. Do not merge, publish a release, change repository policy, rewrite
history or update a deployed/master-folder installation without the owner's
approval. Keep a known-good release available until an approved update passes.

Tests use temporary databases, synthetic network/provider responses and no
inherited account credentials. No paid services, public demo exposure or
changes to unrelated infrastructure are part of this work.

## Review handoff

[Pull request #7](https://github.com/L-chapman/AuroraEdge-FYP/pull/7) contains the
first increment. Implementation revision `2e8b3c0ce204ffc821b5aae631fa30196e229355`
passed [all 15 hosted checks](https://github.com/L-chapman/AuroraEdge-FYP/actions/runs/35813436909),
alongside the local checks and seven-image visual review recorded in
[Release evidence](RELEASE_EVIDENCE.md). Subsequent evidence-only commits do not
change that implementation, but their final pull-request checks must also pass.
The final evidence-only head `200d7f21301f6c88419ad57209fa84f29a64dc95` also
passed [all 15 checks](https://github.com/L-chapman/AuroraEdge-FYP/actions/runs/35813970959).
PR #7 was then merged with owner approval; its merged source tree is identical
to that tested final head. The owner also approved syncing the clean master
copy and beginning the limited authentication-state extraction below. This is
not approval for deployment, provider writes, broader architecture changes or
merging an unreviewed later pull request. No GitHub release/tag was published.
NF-03 through NF-14 are not completed by that first increment.

### Approved first NF-03 boundary (implemented for review)

The first extraction places one `AuthenticationState` owner on
`app.state.authentication`, with no singleton in the state module and no mutable
dictionary aliases. Routes, cookies, request parsing and response semantics stay
in the dashboard adapter. Dynamic token/origin reads still revoke sessions and
open event streams as before. Test fixtures replace that single owner; injectable
clocks exercise expiry and failed-login windows without mutating shared records.

Do not move the scheduler, provider settings, legacy templates or all route
groups in the same change. Preserve the existing single-process lifecycle and
characterise login/logout, expiry, rotation, CSRF, body limits, stream revocation
and one-monitor startup/shutdown before extraction. The current monitor receives
cancellation at shutdown; a fully awaited graceful join is not yet established.
This boundary was approved on 23 September 2026. Any broader extraction still
needs a separately scoped review; this step does not make the application
multi-process or add named-user authentication.

The unchanged characterization set passed both before and after extraction;
additional owner, concurrency and lifecycle tests passed afterwards. Exact local
results are recorded in [Release evidence](RELEASE_EVIDENCE.md). Independent
review found no introduced regression. It did identify the existing separation
between login-rate checking and failure recording: concurrent requests can pass
the check before failures are recorded. Atomic admission is separate hardening,
not a property established by these state-integrity tests. The monitor's
unawaited cleanup and broader dashboard decomposition also remain explicit limits.

Each pull request records its exact source revision, rationale, compatibility,
tests actually executed, screenshots where useful, remaining limits and a
rollback route. A code review or configured workflow is not execution evidence.
The [interview guide](INTERVIEW_GUIDE.md) explains how to demonstrate and discuss
the first increment without overstating the product.
