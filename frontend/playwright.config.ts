import { defineConfig, devices } from '@playwright/test'

const env = (globalThis as typeof globalThis & {
  process?: { env?: Record<string, string | undefined> }
}).process?.env ?? {}
const baseURL = env.NORTHFLUX_E2E_URL ?? 'http://127.0.0.1:4173'
const pythonCommand = env.NORTHFLUX_PYTHON ?? 'python'
const firefoxExecutablePath = env.NORTHFLUX_FIREFOX_PATH
const reuseExistingServer = env.NORTHFLUX_E2E_REUSE_SERVER === 'true'

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: Boolean(env.CI),
  retries: 0,
  workers: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    {
      name: 'firefox',
      use: {
        ...devices['Desktop Firefox'],
        ...(firefoxExecutablePath ? { launchOptions: { executablePath: firefoxExecutablePath } } : {}),
      },
    },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
    { name: 'mobile-chromium', use: { ...devices['Pixel 7'] } },
  ],
  webServer: {
    command: `${pythonCommand} ../scripts/e2e_server.py`,
    url: `${baseURL}/health`,
    reuseExistingServer,
    timeout: 120_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
})
