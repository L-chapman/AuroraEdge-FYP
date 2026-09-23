# Fictional demonstration and interface screenshots

These captures use the real compiled React interface and the real local API/storage flow, with fictional scanner results. They are not customers, live scans or evidence of any domain's actual security. Every capture carries **“Fictional demonstration data — no live domain assessment.”** The isolated browser harness adds this notice to the served HTML; it is not part of the deployed product, and screenshot code does not rewrite the interface or remove warnings.

## What the demonstration covers

| Capture | Page and fictional scenario | What it demonstrates |
|---|---|---|
| [Sign-in](sign-in.png) | `/login`, empty token field | The normal sign-in interface; no private token in the image |
| [Overview](overview.png) | `/`, four saved managed domains | A populated overview with complete, weak and incomplete results; scheduled monitoring paused |
| [Complete scan](scan-complete.png) | `/scan?domain=weak.example.com`, explicitly run the scan | Completed assessment with findings, guidance and saved-detail access; “complete” does not mean secure |
| [Incomplete scan](scan-incomplete.png) | `/scan?domain=incomplete.example.com`, explicitly run the scan | A simulated lookup timeout, no grade, and unavailable recommendation review |
| [History](history.png) | `/domain/weak.example.com` | Two persisted fixture scans and the history table, not an invented improvement trend |
| [Generator](generator.png) | `/generator` | Local draft generation using reserved example addresses and a monitor-only DMARC draft; nothing published |
| [Settings](settings.png) | `/settings` | Fictional workspace, truthful capability descriptions, paused monitoring and no provider credentials |

The fixture names are `example.com`, `weak.example.com`, `mail.example.com` and `incomplete.example.com`. Their records and scores are synthetic. The generator uses documentation-only addresses `198.51.100.0/24` and `2001:db8::/32`; these are not configuration recommendations for a real mail system.

## Refresh the captures

Install the development dependencies and Chromium as described in [Testing](../TESTING.md). From `frontend/`, build the exact source being reviewed and run only the explicit showcase scenario:

```powershell
# Windows PowerShell, from frontend/
Remove-Item Env:NORTHFLUX_E2E_URL -ErrorAction SilentlyContinue
Remove-Item Env:NORTHFLUX_E2E_REUSE_SERVER -ErrorAction SilentlyContinue
npm run build
if ($LASTEXITCODE -ne 0) { throw 'The frontend build failed.' }
$env:NORTHFLUX_CAPTURE_SHOWCASE = 'true'
try {
    npx playwright test e2e/presentation.spec.ts --project=chromium -g 'fictional reviewer journey'
    if ($LASTEXITCODE -ne 0) { throw 'The showcase did not finish; do not publish partial captures.' }
} finally {
    Remove-Item Env:NORTHFLUX_CAPTURE_SHOWCASE -ErrorAction SilentlyContinue
}
```

```bash
# Linux, from frontend/; overrides are cleared only in this subshell.
(
  unset NORTHFLUX_E2E_URL NORTHFLUX_E2E_REUSE_SERVER
  npm run build &&
  NORTHFLUX_CAPTURE_SHOWCASE=true npx playwright test e2e/presentation.spec.ts --project=chromium -g 'fictional reviewer journey'
)
```

If Python is not on the command path, set `NORTHFLUX_PYTHON` to the project's Python executable first. Keep port 4173 free; do not point the showcase at an existing operational installation. The showcase checks the fixture-server identity header before signing in or clearing/seeding data.

Only `NORTHFLUX_CAPTURE_SHOWCASE=true` **and** the Chromium project write these seven files. Ordinary test runs exercise the same journey without updating committed screenshots. Captures use a 1440 × 1050 viewport, full-page output and reduced motion. The journey clicks the main heading and scrolls to the top before each image so active fields and sticky navigation do not obscure the page. Times are generated when the disposable scans are saved, so two runs need not be pixel-identical. The generator's example policy ID is fixed to `fixturedemo001`; the journey checks that its MTA-STS output is present and that no validation-error summary is shown.

After all captures finish, inspect all seven images for layout, truthful labels and absence of secrets. Record the exact source revision, browser/OS and commands in the release evidence; screenshots alone are not a passing test report. A failed run can leave a partial set: do not commit it as a complete refresh. Other traces, videos and failure screenshots remain ignored local test output.

## Try the safe local example yourself

After installing the development dependencies and building `frontend/`, run this from the project root in a separate terminal:

```text
python scripts/e2e_server.py
```

Open `http://127.0.0.1:4173/` and check that the fictional-data notice is visible. Sign in with the harness-only token `northflux-e2e-operator-token-0123456789`. This public test value is not a deployment credential and must never be used for a real installation.

To populate the workspace, open **Scan → Batch scan**, enter the four fixture domains listed above, and enable saving history and adding the results to the managed list before scanning. Leave scheduled monitoring off. Run `weak.example.com` a second time to give its detail page two history entries. The complete/incomplete scan, history, generator and Settings routes in the table are then ready to demonstrate. See the [reviewer walkthrough](../INTERVIEW_GUIDE.md) for a proposed short narration; it is not evidence that a recording has already been made.

The harness resets only `frontend/.e2e-data/`, with separate state, reports and logs. It clears inherited Cloudflare environment credentials before importing the application, explicitly disables the old demo mode, replaces scanning with deterministic fixtures and disables provider access. Normal authentication and content-security rules remain active. Stopping normally removes the disposable data; a forced stop may leave that ignored directory until the next harness start.

Do not run a manual harness and the automated suite simultaneously: they intentionally share the disposable directory and port. Never expose this development server publicly, enter real credentials, use a production database, or present its output as a live security assessment. Use the ordinary launcher for the actual application, not this harness.
