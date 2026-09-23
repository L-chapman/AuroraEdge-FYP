import AxeBuilder from '@axe-core/playwright'
import { expect, test } from '@playwright/test'

// This server supplies synthetic results only: no real DNS or customer data.
const token = 'northflux-e2e-operator-token-0123456789'
const env = (globalThis as typeof globalThis & {
  process?: { env?: Record<string, string | undefined> }
}).process?.env ?? {}

test('keeps every main page accessible at 320px with reduced motion', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  await page.setViewportSize({ width: 320, height: 800 })
  await page.emulateMedia({ reducedMotion: 'reduce' })
  const response = await page.goto('/login')
  expect(response?.headers()['x-northflux-fixture-server']).toBe('northflux-disposable-fixtures-v1')
  await expect(page.getByRole('heading', { name: 'Operator sign in' })).toBeVisible()
  const loginAudit = await new AxeBuilder({ page }).analyze()
  expect(loginAudit.violations.filter((item) => ['critical', 'serious'].includes(item.impact ?? ''))).toEqual([])
  await page.getByLabel('Operator token').fill(token)
  await page.getByRole('button', { name: 'Sign in securely' }).click()
  await expect(page).toHaveURL(/\/$/)

  for (const route of ['/', '/scan', '/domains', '/generator', '/settings', '/privacy']) {
    await page.goto(route)
    await expect(page.locator('h1')).toBeVisible()
    await expect(page.getByText('Loading…', { exact: true })).toHaveCount(0)
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
    const audit = await new AxeBuilder({ page }).analyze()
    expect(audit.violations.filter((item) => ['critical', 'serious'].includes(item.impact ?? '')), route).toEqual([])
    const continuousMotion = await page.evaluate(() => document.getAnimations().filter((animation) => {
      const timing = animation.effect?.getComputedTiming()
      return timing?.iterations === Infinity && animation.playState === 'running'
    }).length)
    expect(continuousMotion, `Reduced motion on ${route}`).toBe(0)
  }
  expect(errors).toEqual([])
})

test('lets keyboard users dismiss and reopen the mobile menu', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.emulateMedia({ reducedMotion: 'no-preference' })
  const response = await page.goto('/login')
  expect(response?.headers()['x-northflux-fixture-server']).toBe('northflux-disposable-fixtures-v1')
  // Smooth document scrolling can move a control between pointer down and up.
  // Keep clicks stable even when the user has not requested reduced motion.
  expect(await page.evaluate(() => getComputedStyle(document.documentElement).scrollBehavior)).toBe('auto')
  await page.getByLabel('Operator token').fill(token)
  await page.getByRole('button', { name: 'Sign in securely' }).click()
  await expect(page).toHaveURL(/\/$/)
  const menu = page.getByRole('button', { name: 'Menu' })
  await menu.focus()
  await page.keyboard.press('Enter')
  await expect(menu).toHaveAttribute('aria-expanded', 'true')
  await page.keyboard.press('Tab')
  await page.keyboard.press('Escape')
  await expect(menu).toHaveAttribute('aria-expanded', 'false')
  await expect(menu).toBeFocused()
  await page.keyboard.press('Enter')
  await page.getByRole('navigation').getByRole('link', { name: 'Generator' }).click()
  await expect(page).toHaveURL(/\/generator$/)
  await expect(menu).toHaveAttribute('aria-expanded', 'false')
})

test('presents the fictional reviewer journey without browser errors or CSP violations', async ({ page }, testInfo) => {
  test.setTimeout(90_000)
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  await page.addInitScript(() => {
    const violations: string[] = []
    Object.defineProperty(window, '__northfluxCspViolations', { value: violations })
    document.addEventListener('securitypolicyviolation', (event) => violations.push(`${event.violatedDirective}: ${event.blockedURI}: ${event.sourceFile}`))
  })
  await page.setViewportSize({ width: 1440, height: 1050 })
  await page.emulateMedia({ reducedMotion: 'reduce' })
  const response = await page.goto('/login')
  // Refuse to sign in, clear data or seed results against an ordinary server,
  // even if a maintainer accidentally sets the URL/reuse-server overrides.
  expect(response?.headers()['x-northflux-fixture-server']).toBe('northflux-disposable-fixtures-v1')
  await expect(page.getByRole('heading', { name: 'Operator sign in' })).toBeVisible()
  const capture = env.NORTHFLUX_CAPTURE_SHOWCASE === 'true' && testInfo.project.name === 'chromium'
  async function inspectAndCapture(name: string) {
    await expect(page.locator('[aria-label="Fictional demonstration"]')).toContainText('Fictional demonstration data — no live domain assessment.')
    await expect(page.getByText('Loading…', { exact: true })).toHaveCount(0)
    // This observes the rendered page; it never rewrites product text or styles.
    await page.evaluate(() => document.fonts.ready)
    const violations = await page.evaluate(() => (window as typeof window & { __northfluxCspViolations: string[] }).__northfluxCspViolations)
    expect(violations, `Content security policy on ${name}`).toEqual([])
    // End field editing like a user, then return to the document's true top.
    // Full-page captures otherwise preserve a sticky header mid-document.
    await page.getByRole('heading', { level: 1 }).click()
    await page.evaluate(() => window.scrollTo(0, 0))
    await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0)
    if (capture) await page.screenshot({ path: `../docs/screenshots/${name}.png`, fullPage: true, animations: 'disabled' })
  }
  await inspectAndCapture('sign-in')
  await page.getByLabel('Operator token').fill(token)
  await page.getByRole('button', { name: 'Sign in securely' }).click()
  await expect(page).toHaveURL(/\/$/)
  const statuses = await page.evaluate(async () => {
    const csrf = document.cookie.split('; ').find((value) => value.startsWith('northflux_csrf='))?.split('=')[1]
    const headers = { 'Content-Type': 'application/json', 'X-CSRF-Token': decodeURIComponent(csrf ?? '') }
    const cleared = await fetch('/api/data/clear', { method: 'POST', headers })
    const settings = await fetch('/api/settings', {
      method: 'POST', headers,
      body: JSON.stringify({
        org_name: 'Fictional demonstration workspace',
        monitoring_enabled: false,
        automatic_remediation: false,
        alert_email: '',
        cf_zone_id: '',
        cf_account_id: '',
      }),
    })
    const scanned = await fetch('/api/scan', {
      method: 'POST', headers,
      body: JSON.stringify({ domains: ['example.com', 'weak.example.com', 'mail.example.com', 'incomplete.example.com'], save_to_db: true, manage_domains: true, remediation: false }),
    })
    return [cleared.status, settings.status, scanned.status]
  })
  expect(statuses).toEqual([200, 200, 200])
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Email security, at a glance' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'View weak.example.com', exact: true })).toBeVisible()
  await expect(page.getByRole('link', { name: 'View incomplete.example.com', exact: true })).toBeVisible()
  await expect(page.getByText('Scheduled monitoring is paused')).toBeVisible()
  // Assert the application's CSP before axe injects its own audit scripts.
  await inspectAndCapture('overview')
  const audit = await new AxeBuilder({ page }).analyze()
  expect(audit.violations.filter((item) => ['critical', 'serious'].includes(item.impact ?? ''))).toEqual([])

  await page.goto('/scan?domain=weak.example.com')
  await expect(page.getByRole('textbox', { name: 'Domain', exact: true })).toHaveValue('weak.example.com')
  await page.getByRole('button', { name: 'Run security scan' }).click()
  await expect(page.getByRole('heading', { name: 'weak.example.com', exact: true })).toBeVisible()
  await expect(page.getByRole('link', { name: 'View detail', exact: true })).toBeVisible()
  await page.getByText('Findings and guidance', { exact: true }).click()
  await inspectAndCapture('scan-complete')

  await page.goto('/scan?domain=incomplete.example.com')
  await page.getByRole('button', { name: 'Run security scan' }).click()
  await expect(page.getByRole('heading', { name: 'incomplete.example.com', exact: true })).toBeVisible()
  await expect(page.getByRole('status').filter({ hasText: 'This scan is incomplete.' })).toContainText('fictional fixture')
  await expect(page.getByLabel('Scan incomplete; no security grade is available')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Review DNS recommendations' })).toBeDisabled()
  await inspectAndCapture('scan-incomplete')

  await page.goto('/domain/weak.example.com')
  await expect(page.getByRole('heading', { name: 'weak.example.com', exact: true })).toBeVisible()
  await expect(page.getByRole('table', { name: 'Scan history for weak.example.com' }).getByRole('row')).toHaveCount(3)
  await inspectAndCapture('history')

  await page.goto('/generator')
  await expect(page.getByRole('heading', { name: 'DNS record generator' })).toBeVisible()
  const spf = page.getByRole('region', { name: 'SPF record', exact: true })
  await spf.getByLabel('Provider include domains').fill('')
  await spf.getByLabel('IPv4 or IPv6 addresses and CIDR ranges').fill('198.51.100.0/24\n2001:db8::/32')
  await expect(spf.getByLabel('DNS TXT record')).toContainText('ip4:198.51.100.0/24')
  await page.getByRole('region', { name: 'DMARC record', exact: true }).getByLabel('Policy', { exact: true }).selectOption('none')
  await page.getByLabel('Policy ID', { exact: true }).fill('fixturedemo001')
  await expect(page.getByText('Check these fields:', { exact: true })).toHaveCount(0)
  await expect(page.getByLabel('MTA-STS DNS TXT record', { exact: true })).toContainText('id=fixturedemo001')
  await expect(page.getByLabel('MTA-STS policy file', { exact: true })).toContainText('mode: enforce')
  await inspectAndCapture('generator')

  await page.goto('/settings')
  await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible()
  await expect(page.getByLabel('Organisation name')).toHaveValue('Fictional demonstration workspace')
  await expect(page.getByLabel('API token', { exact: true })).toHaveValue('')
  await expect(page.getByText('Not configured', { exact: true })).toBeVisible()
  await inspectAndCapture('settings')
  expect(errors).toEqual([])
})
