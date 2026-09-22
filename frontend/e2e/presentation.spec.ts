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
  await page.goto('/login')
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
  await page.goto('/login')
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

test('presents real saved results without browser errors or CSP violations', async ({ page }, testInfo) => {
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  await page.addInitScript(() => {
    const violations: string[] = []
    Object.defineProperty(window, '__northfluxCspViolations', { value: violations })
    document.addEventListener('securitypolicyviolation', (event) => violations.push(`${event.violatedDirective}: ${event.blockedURI}: ${event.sourceFile}`))
  })
  await page.setViewportSize({ width: 1440, height: 1050 })
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.goto('/login')
  await expect(page.getByRole('heading', { name: 'Operator sign in' })).toBeVisible()
  const capture = env.NORTHFLUX_CAPTURE_SHOWCASE === 'true' && testInfo.project.name === 'chromium'
  if (capture) await page.screenshot({ path: '../docs/screenshots/sign-in.png', fullPage: true, animations: 'disabled' })
  await page.getByLabel('Operator token').fill(token)
  await page.getByRole('button', { name: 'Sign in securely' }).click()
  await expect(page).toHaveURL(/\/$/)
  const statuses = await page.evaluate(async () => {
    const csrf = document.cookie.split('; ').find((value) => value.startsWith('northflux_csrf='))?.split('=')[1]
    const headers = { 'Content-Type': 'application/json', 'X-CSRF-Token': decodeURIComponent(csrf ?? '') }
    const cleared = await fetch('/api/data/clear', { method: 'POST', headers })
    const settings = await fetch('/api/settings', {
      method: 'POST', headers,
      body: JSON.stringify({ org_name: 'NorthFlux example workspace', monitoring_enabled: false, automatic_remediation: false }),
    })
    const scanned = await fetch('/api/scan', {
      method: 'POST', headers,
      body: JSON.stringify({ domains: ['example.com', 'weak.example.com', 'mail.example.com'], save_to_db: true, manage_domains: true, remediation: false }),
    })
    return [cleared.status, settings.status, scanned.status]
  })
  expect(statuses).toEqual([200, 200, 200])
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Email security, at a glance' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'View weak.example.com', exact: true })).toBeVisible()
  // Assert the application's CSP before axe injects its own audit scripts.
  const violations = await page.evaluate(() => (window as typeof window & { __northfluxCspViolations: string[] }).__northfluxCspViolations)
  expect(violations).toEqual([])
  const audit = await new AxeBuilder({ page }).analyze()
  expect(audit.violations.filter((item) => ['critical', 'serious'].includes(item.impact ?? ''))).toEqual([])
  if (capture) await page.screenshot({ path: '../docs/screenshots/overview.png', fullPage: true, animations: 'disabled' })
  expect(errors).toEqual([])
})
