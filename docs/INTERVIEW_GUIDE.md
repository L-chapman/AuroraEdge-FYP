# NorthFlux reviewer and interview guide

NorthFlux started as Leon Chapman's independent home project, AuroraEdge, and later became his Belfast Metropolitan College final-year project. The current repository is [L-chapman/Northflux-security](https://github.com/L-chapman/Northflux-security); its AuroraEdge development history remains preserved.

This is a suggested two-to-three-minute walkthrough and recording script, **not evidence that a recording or manual review has been completed**. Use the [release evidence](RELEASE_EVIDENCE.md) for checks actually performed against a named revision.

## Prepare a safe demonstration

Follow the [isolated showcase instructions](screenshots/README.md), using fictional fixtures rather than the normal application database. Show the fictional-data label. Do not include real access tokens, provider credentials, private infrastructure addresses or customer reports. Do not expose the development harness publicly or use it to demonstrate live DNS changes.

The showcase covers a populated overview, complete and incomplete scans, saved history, the generator and Settings. Its results demonstrate interface behaviour, not the security of a real domain. If using the saved images instead of the running showcase, say so. Do not replace a failed live demonstration with a screenshot while implying it is live.

## Two-to-three-minute route

Adapt this suggested narration to what you can explain and what is actually on screen.

| Time | Show | Suggested explanation |
|---|---|---|
| 0:00–0:20 | Overview and fictional-data label | “This started as my home project, AuroraEdge, before becoming my final-year project. NorthFlux brings public email-configuration checks, explanations and saved history into one workspace. These are fictional demonstration results.” |
| 0:20–0:55 | A complete scan, then the incomplete example | “The scanner gathers observations and the rules turn them into findings. A grade is a summary, not a security guarantee. If a lookup cannot finish, the result stays incomplete rather than receiving a misleading grade.” |
| 0:55–1:25 | Domain detail and history | “Results are stored in SQLite so changes can be reviewed. An incomplete result remains visibly different from a genuine low score. Refreshing the overview every 60 seconds reads saved data; it does not perform another scan.” |
| 1:25–1:50 | DNS generator | “This produces a draft to review, not a DNS change. Sending services, reporting addresses and server readiness must be confirmed before publishing anything.” |
| 1:50–2:15 | Settings capability explanations | “Monitoring can create in-app alerts, but email delivery is not implemented. Generated recommendations are manual-only. A Cloudflare connection check reads provider data; it does not prove write permission.” |
| 2:15–2:50 | Architecture and revision-specific evidence | “React and TypeScript handle the interface; FastAPI handles requests and scanning. SQLite keeps deployment small, with one operator and one process. I used AI coding assistance, so I explain changes through their code, tests and limits rather than claiming every line was manually written.” |

Do not enter real credentials or run provider checks during a public recording. Finish by pointing to the matching [release evidence](RELEASE_EVIDENCE.md), not an unrelated green build or a whole-product coverage claim.

## Architecture and trade-offs to explain

- **React + FastAPI:** the interface is separate from scanning and storage. This supports focused interface tests and a shared backend for the browser and CLI. The large dashboard module remains a refactoring target, not a completed modular architecture.
- **SQLite + one process:** simple local storage and deployment suit this personal, single-operator tool. Multiple workers, separate customer accounts and high availability need additional design; they are not configuration switches.
- **Manual recommendations:** a DNS snapshot cannot establish every authorised sender or whether stricter policy would interrupt mail. Guarded low-level provider methods exist, but a full approved-change workflow is not implemented.
- **Controlled fixtures:** repeatable examples exercise the interface without depending on live DNS or changing a zone. They do not validate a real provider integration or production deployment.

See [Architecture](ARCHITECTURE.md) for the component map and [Implementation plan](IMPLEMENTATION_PLAN.md) for the current bounded work and deferred scope.

## Two fixes with inspectable evidence

### 1. Incomplete scans looked like dependable grades

An interrupted scan can still contain partial observations. Treating its provisional score as final misleads the operator and contaminates averages. The [database implementation](../src/app/database.py) now stores an explicit incomplete flag with null score and grade, while preserving the observations.

In [the regression tests](../tests/test_incomplete_scan_storage.py), `test_incomplete_results_are_saved_without_grades_or_average_contamination` saves a complete result followed by an incomplete one. It checks that the newer result is ungraded, the previous complete score remains available, and the average excludes the incomplete scan. `test_dashboard_exposes_incomplete_state_without_a_failing_grade` checks the API representation too.

Explain the decision as **unknown is not zero**. These tests demonstrate specific failure handling, not perfect protocol coverage.

### 2. A late response could undo sign-out in the interface

A session request may start before sign-out but finish afterwards. If its old “authenticated” response is accepted, the interface can incorrectly appear signed in again. The [session provider](../frontend/src/auth/SessionProvider.tsx) cancels older session reads before accepting the signed-out state and clears protected cached data.

In [the session-race tests](../frontend/src/auth/SessionProvider.test.tsx), `does not let an older read restore authentication after %s` deliberately holds a response, signs out or returns an authorisation failure, and then releases the old response. The interface must remain signed out. This is a browser-state fix; server-side authentication remains a separate safeguard.

## Describe AI assistance honestly

AI coding assistance contributed to the React modernisation, defect investigation, implementation, tests and documentation. The earlier AuroraEdge scanner, rules and reporting were already part of the project; do not credit the later migration with inventing them. Do not claim that every line was manually authored, that an independent security auditor certified it, or that using AI during development makes NorthFlux an AI-powered security product.

For an interview, choose a change you can trace from problem to implementation to regression test. Explain the trade-off and remaining limitation, and acknowledge anything you would need to investigate further. Published source and revision-specific checks make that discussion verifiable; they do not replace understanding the code.
