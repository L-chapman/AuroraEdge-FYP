# Interface screenshots

These images show the real React interface: [overview](overview.png) and [sign-in](sign-in.png). The example domains and scan results come from the isolated browser-test server. They are fictional demonstration data, not customers, live scans or evidence of a domain's current security.

To refresh them after a UI change, install the development dependencies and Chromium as described in [Testing](../TESTING.md), then run from `frontend/`:

```powershell
# Windows PowerShell
$env:NORTHFLUX_CAPTURE_SHOWCASE = 'true'
npm run build
npx playwright test e2e/presentation.spec.ts --project=chromium -g 'presents real saved results'
Remove-Item Env:NORTHFLUX_CAPTURE_SHOWCASE
```

```bash
# Linux
npm run build
NORTHFLUX_CAPTURE_SHOWCASE=true npx playwright test e2e/presentation.spec.ts --project=chromium -g 'presents real saved results'
```

If Python is not on the command path, set `NORTHFLUX_PYTHON` to its executable first. Only this explicit screenshot mode updates these files; ordinary test runs leave them unchanged. Inspect both images before committing them. Other browser traces, videos and failure screenshots remain ignored local test output.
