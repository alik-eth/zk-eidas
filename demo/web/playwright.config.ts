import { defineConfig } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'https://zk-eidas.com'

export default defineConfig({
  testDir: './e2e',
  timeout: 180_000, // 3 min per test (proof gen is slow on shared CPU)
  expect: { timeout: 120_000 },
  fullyParallel: false, // sequential — shared backend state
  retries: 1,
  reporter: 'list',
  use: {
    baseURL: BASE_URL,
    headless: true,
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
  ],
})
