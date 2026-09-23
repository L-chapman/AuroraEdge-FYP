import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'

const token = 'northflux-e2e-operator-token-0123456789'

async function signIn(page: Page) {
  await page.goto('/login')
  await page.getByLabel('Operator token').fill(token)
  await page.getByRole('button', { name: 'Sign in securely' }).click()
  await expect(page).toHaveURL(/\/$/)
  await expect(page.getByRole('heading', { name: 'Email security, at a glance' })).toBeVisible()
}

async function clearData(page: Page) {
  const statuses = await page.evaluate(async () => {
    const csrf = document.cookie.split('; ').find((item) => item.startsWith('northflux_csrf='))?.split('=')[1]
    const headers = {
      ...(csrf ? { 'X-CSRF-Token': decodeURIComponent(csrf) } : {}),
      'Content-Type': 'application/json',
    }
    const response = await fetch('/api/data/clear', {
      method: 'POST',
      headers,
    })
    const settings = await fetch('/api/settings', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        org_name: 'NorthFlux E2E Operator',
        alert_email: '',
        monitor_interval: '24',
        monitoring_enabled: false,
        automatic_remediation: false,
        cf_zone_id: '',
        cf_account_id: '',
      }),
    })
    return [response.status, settings.status]
  })
  expect(statuses).toEqual([200, 200])
}

async function navigateTo(page: Page, name: 'Scan' | 'Domains' | 'Generator' | 'Settings', expectedPath = name.toLowerCase()) {
  const link = page.getByRole('navigation').getByRole('link', { name, exact: true })
  if (!(await link.isVisible())) await page.getByRole('button', { name: 'Menu' }).click()
  await link.click()
  await expect(page).toHaveURL(new RegExp(`/${expectedPath}$`))
  // Scan and Domains both have a textbox named Domain. Wait for the new page
  // before filling it, otherwise a fast test can type into the outgoing page.
  await expect(page.getByRole('heading', { level: 1 })).not.toHaveText('Email security, at a glance')
}

test.beforeEach(async ({ page }) => {
  await signIn(page)
  await clearData(page)
})

test('rejects a bad token, signs in without browser storage, and signs out', async ({ page, context }) => {
  await context.clearCookies()
  await page.goto('/login')
  await page.getByLabel('Operator token').fill('incorrect-token')
  await page.getByRole('button', { name: 'Sign in securely' }).click()
  await expect(page.getByRole('alert')).toContainText('Invalid access token')
  await page.getByLabel('Operator token').fill(token)
  await page.getByRole('button', { name: 'Sign in securely' }).click()
  await expect(page).toHaveURL(/\/$/)
  await expect(page.getByRole('heading', { name: 'Email security, at a glance' })).toBeVisible()
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 })

  // Expired cookies must invalidate the cached React session as soon as a
  // protected query receives a 401, rather than leaving a stale dashboard.
  await context.clearCookies()
  await navigateTo(page, 'Domains', 'login')
  await expect(page).toHaveURL(/\/login$/)
  await expect(page.getByRole('heading', { name: 'Operator sign in' })).toBeVisible()
  await page.getByLabel('Operator token').fill(token)
  await page.getByRole('button', { name: 'Sign in securely' }).click()
  await expect(page).toHaveURL(/\/domains$/)

  const signOut = page.getByRole('button', { name: 'Sign out' })
  const menu = page.getByRole('button', { name: 'Menu' })
  if (await menu.isVisible()) await menu.click()
  await expect(signOut).toBeVisible()
  await signOut.click()
  await expect(page).toHaveURL(/\/login$/)
})

test('shows an empty dashboard and has no serious accessibility violations', async ({ page }) => {
  await page.reload()
  await expect(page.getByText('No managed domains yet')).toBeVisible()
  const results = await new AxeBuilder({ page }).analyze()
  expect(results.violations.filter((item) => ['critical', 'serious'].includes(item.impact ?? ''))).toEqual([])
})

test('runs an explicit scan without silently enrolling the domain', async ({ page }) => {
  await navigateTo(page, 'Scan')
  await page.getByRole('textbox', { name: 'Domain', exact: true }).fill('https://Example.com/path')
  await page.getByRole('button', { name: 'Run security scan' }).click()
  await expect(page.getByRole('heading', { name: 'example.com' })).toBeVisible()
  await expect(page.getByText('SPF', { exact: true })).toBeVisible()
  await navigateTo(page, 'Domains')
  await expect(page.getByText('No domains under management')).toBeVisible()
})

test('submits a batch in one request and validates the 20-domain limit', async ({ page }) => {
  await navigateTo(page, 'Scan')
  await page.getByRole('tab', { name: 'Single domain' }).focus()
  await page.keyboard.press('ArrowRight')
  await expect(page.getByRole('tab', { name: 'Batch scan' })).toBeFocused()
  await expect(page.getByRole('tabpanel', { name: 'Batch scan' })).toBeVisible()
  const requests: string[] = []
  page.on('request', (request) => { if (request.url().endsWith('/api/scan')) requests.push(request.url()) })
  await page.getByRole('textbox', { name: 'Domains', exact: true }).fill('example.com\nweak.example.com')
  await page.getByRole('button', { name: 'Run security scan' }).click()
  await expect(page.getByRole('heading', { name: 'example.com', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'weak.example.com', exact: true })).toBeVisible()
  expect(requests).toHaveLength(1)
  await page.getByRole('textbox', { name: 'Domains', exact: true }).fill(Array.from({ length: 21 }, (_, index) => `d${index}.example.com`).join('\n'))
  await page.getByRole('button', { name: 'Run security scan' }).click()
  await expect(page.getByRole('alert')).toContainText('no more than 20')
})

test('returns to the requested scan and its domain after sign-in', async ({ page, context }) => {
  await context.clearCookies()
  await page.goto('/scan?domain=example.com#scan-single-panel')
  await expect(page.getByRole('heading', { name: 'Operator sign in' })).toBeVisible()
  await page.getByLabel('Operator token').fill(token)
  await page.getByRole('button', { name: 'Sign in securely' }).click()
  await expect(page).toHaveURL(/\/scan\?domain=example.com#scan-single-panel$/)
  await expect(page.getByRole('textbox', { name: 'Domain', exact: true })).toHaveValue('example.com')
})

test('shows partial DNS-change failures and manual actions without an old grade', async ({ page }) => {
  // Exercise presentation only; no request reaches the disabled provider layer.
  await page.route('**/api/apply-fix', (route) => route.fulfill({
    json: {
      domain: 'example.com', status: 'partial', verification_status: 'incomplete', history_saved: false,
      verification: 'The latest verification scan was incomplete.',
      applied: [{ type: 'DMARC', message: 'DMARC change submitted.' }],
      failed: [{ type: 'TLS-RPT', message: 'Provider refused the report record.' }],
      manual_actions: [{ type: 'SPF', description: 'Confirm every sending service.', steps: 'Review provider instructions before changing SPF.' }],
    },
  }))
  await navigateTo(page, 'Scan')
  await page.getByRole('textbox', { name: 'Domain', exact: true }).fill('example.com')
  await page.getByRole('button', { name: 'Run security scan' }).click()
  await expect(page.getByRole('heading', { name: 'example.com' })).toBeVisible()
  await page.getByRole('button', { name: 'Plan DNS fix' }).click()
  await expect(page.getByRole('dialog')).toContainText('This review does not change DNS records.')
  await page.getByRole('button', { name: 'Review recommendations' }).click()
  const outcome = page.getByRole('region', { name: 'DNS change outcome for example.com' })
  await expect(outcome).toBeVisible()
  await expect(outcome).toContainText('Provider refused the report record.')
  await expect(outcome).toContainText('Review provider instructions before changing SPF.')
  await expect(outcome.locator('.notice--success')).toHaveCount(0)
  await expect(page.locator('.score-lockup')).toHaveCount(0)
  await expect(outcome.getByRole('link', { name: 'Review saved verification' })).toHaveCount(0)
})

test('enrols, rescans, opens, and removes a managed domain with confirmation', async ({ page }) => {
  await navigateTo(page, 'Domains')
  await page.getByRole('textbox', { name: 'Domain', exact: true }).fill('example.com')
  await page.getByLabel('Notes (optional)').fill('Primary mail domain')
  const addResponse = page.waitForResponse((response) => response.url().endsWith('/api/managed-domains') && response.request().method() === 'POST')
  await page.getByRole('button', { name: 'Add domain' }).click()
  const added = await addResponse
  expect(added.status()).toBe(200)
  expect((await added.json()).initial_scan).toEqual({ grade: 'A+', score: 98, severity: 'INFO' })
  await expect(page.getByText(/example.com is now monitored/)).toBeVisible()
  await page.getByRole('link', { name: 'Details' }).click()
  await expect(page.getByRole('heading', { name: 'Email authentication coverage' })).toBeVisible()
  const rescanResponse = page.waitForResponse((response) => response.url().includes('/api/rescan/'))
  await page.getByRole('button', { name: 'Rescan now' }).click()
  expect((await rescanResponse).status()).toBe(200)
  await expect(page.getByText(/Rescan complete/)).toBeVisible()
  await navigateTo(page, 'Domains')
  await page.getByRole('button', { name: 'Remove' }).click()
  await expect(page.getByRole('dialog')).toContainText('Stop monitoring example.com')
  await page.getByRole('button', { name: 'Remove from monitoring' }).click()
  await expect(page.getByText('No domains under management')).toBeVisible()
})

test('preserves generator edge cases and uses keyboard-operable output copy', async ({ page }) => {
  await navigateTo(page, 'Generator')
  const spf = page.getByRole('region', { name: 'SPF record' })
  await spf.getByLabel('IPv4 or IPv6 addresses and CIDR ranges').fill('198.51.100.0/24\n2001:db8::/32')
  await expect(spf.getByLabel('DNS TXT record')).toContainText('ip4:198.51.100.0/24')
  await expect(spf.getByLabel('DNS TXT record')).toContainText('ip6:2001:db8::/32')
  const dmarc = page.getByRole('region', { name: 'DMARC record' })
  await dmarc.getByLabel('Policy percentage').fill('0')
  await expect(dmarc.getByLabel('DNS TXT record')).toContainText('pct=0')
  await expect(page.getByText(/RFC 9495/i)).toHaveCount(0)
})

test('keeps incomplete scans visibly uncertain through onboarding, history and reports', async ({ page }) => {
  await navigateTo(page, 'Scan')
  await page.getByRole('textbox', { name: 'Domain', exact: true }).fill('incomplete.example.com')
  await page.getByRole('button', { name: 'Run security scan' }).click()
  await expect(page.getByRole('heading', { name: 'incomplete.example.com' })).toBeVisible()
  await expect(page.getByRole('status').filter({ hasText: 'This scan is incomplete.' })).toContainText('DNS lookup timed out')
  await expect(page.getByText('98/100', { exact: true })).toHaveCount(0)
  await navigateTo(page, 'Domains')
  await expect(page.getByRole('heading', { name: 'Managed domains', exact: true })).toBeVisible()
  await page.getByRole('textbox', { name: 'Domain', exact: true }).fill('incomplete.example.com')
  await page.getByRole('button', { name: 'Add domain' }).click()
  await expect(page.getByText(/initial scan was incomplete/)).toBeVisible()
  await expect(page.getByText('Incomplete', { exact: true })).toBeVisible()
  await page.getByRole('link', { name: 'Details' }).click()
  await expect(page.getByRole('status').filter({ hasText: 'This scan is incomplete.' })).toContainText('DNS lookup timed out')
  await expect(page.getByRole('table')).not.toContainText('A+')
  const pdf = await page.request.get('/api/report/pdf/incomplete.example.com')
  expect(pdf.status()).toBe(200)
  expect(pdf.headers()['content-type']).toContain('application/pdf')
  expect((await pdf.body()).subarray(0, 5).toString()).toBe('%PDF-')
  const dashboard = await page.request.get('/api/v1/dashboard')
  expect((await dashboard.json()).stats.score_stats.avg_score).toBeNull()
})

test('saves independent monitoring settings and protects destructive deletion', async ({ page }) => {
  await navigateTo(page, 'Settings')
  await page.getByLabel('Organisation name').fill('NorthFlux Test Operator')
  await page.getByText('Continuous monitoring', { exact: true }).click()
  await page.getByRole('button', { name: 'Save settings' }).click()
  await expect(page.getByRole('status').filter({ hasText: /Saved/ })).toBeVisible()
  await page.getByRole('button', { name: 'Test saved connection' }).click()
  await expect(page.getByText('Connection unavailable.')).toBeVisible()
  await page.getByRole('button', { name: 'Clear all scan data' }).click()
  await expect(page.getByRole('dialog')).toContainText('cannot be undone')
  await page.getByRole('button', { name: 'Cancel' }).click()
  await expect(page.getByRole('dialog')).not.toBeVisible()

  const seeded = await page.evaluate(async () => {
    const csrf = document.cookie.split('; ').find((item) => item.startsWith('northflux_csrf='))?.split('=')[1]
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: {
        ...(csrf ? { 'X-CSRF-Token': decodeURIComponent(csrf) } : {}),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        domains: ['example.com'],
        save_to_db: true,
        manage_domains: true,
        remediation: false,
      }),
    })
    return { status: response.status, body: await response.json() }
  })
  expect(seeded.status).toBe(200)
  expect(seeded.body.results[0].saved).toBe(true)

  await page.getByRole('button', { name: 'Clear all scan data' }).click()
  await page.getByRole('button', { name: 'Permanently clear data' }).click()
  await expect(page.getByRole('status').filter({ hasText: /generated reports/i })).toBeVisible()

  const retainedState = await page.evaluate(async () => {
    const [domainsResponse, settingsResponse] = await Promise.all([
      fetch('/api/managed-domains'),
      fetch('/api/settings'),
    ])
    const domains = await domainsResponse.json()
    const settings = await settingsResponse.json()
    return {
      domainCount: domains.count,
      organisation: settings.settings.org_name,
    }
  })
  expect(retainedState).toEqual({ domainCount: 0, organisation: 'NorthFlux Test Operator' })
})

test('rejects a cookie-authenticated mutation without CSRF and supports public privacy', async ({ page }) => {
  const response = await page.evaluate(async () => {
    const result = await fetch('/api/data/clear', { method: 'POST', headers: { 'X-CSRF-Token': '' } })
    return { status: result.status, body: await result.json() }
  })
  expect(response.status).toBe(403)
  expect(response.body.detail).toContain('CSRF')
  await page.goto('/privacy')
  await expect(page.getByRole('heading', { name: 'Operator-controlled by design' })).toBeVisible()
})

test('keeps navigation usable at a narrow mobile viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.reload()
  const menu = page.getByRole('button', { name: 'Menu' })
  await expect(menu).toBeVisible()
  await menu.click()
  await expect(page.getByRole('navigation').getByRole('link', { name: 'Domains' })).toBeVisible()
})
